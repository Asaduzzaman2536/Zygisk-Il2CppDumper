//
// Created by Perfare on 2020/7/4.
// Modified: Added script.json output (ScriptMethod + ScriptString + ScriptMetadata + Addresses)
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>   // std::sort
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"
#include "xdl.h"
#include <thread>
#include <unistd.h>

#define DO_API(r, n, p) r (*n) p
#include "il2cpp-api-functions.h"
#undef DO_API

static void *il2cpp_handle = nullptr;
static uint64_t il2cpp_base = 0;

// ─────────────────────────────────────────────
//  JSON helper – minimal, no extra library needed
// ─────────────────────────────────────────────
static std::string json_escape(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ─────────────────────────────────────────────
//  script.json data holders
// ─────────────────────────────────────────────
struct ScriptMethod {
    uint64_t address;   // RVA
    std::string name;
    std::string signature;
};

struct ScriptString {
    uint64_t address;   // RVA of the string literal pointer
    std::string value;
};

struct ScriptMetadata {
    uint64_t address;   // RVA of Il2CppClass* metadata pointer
    std::string name;
};

struct ScriptMetadataMethod {
    uint64_t address;        // RVA of MethodInfo* metadata pointer
    std::string name;
    uint64_t methodAddress;  // RVA of the actual function
};

static std::vector<ScriptMethod>         g_scriptMethods;
static std::vector<ScriptString>         g_scriptStrings;
static std::vector<ScriptMetadata>       g_scriptMetadata;
static std::vector<ScriptMetadataMethod> g_scriptMetadataMethods;
static std::vector<uint64_t>             g_addresses;  // all unique RVAs (for Addresses array)

// ─────────────────────────────────────────────
//  Existing helpers (unchanged)
// ─────────────────────────────────────────────
void il2cpp_api_init(void *handle) {
    il2cpp_handle = handle;
    int missing = 0;
#define DO_API(r, n, p) \
    n = (r (*) p)xdl_sym(il2cpp_handle, #n, nullptr); \
    if (!n) { n = (r (*) p)dlsym(RTLD_DEFAULT, #n); } \
    if (!n) { missing++; LOGW("il2cpp api missing: %s", #n); }
#include "il2cpp-api-functions.h"
#undef DO_API
    LOGI("il2cpp_api_init: %d symbols missing", missing);
}

uint64_t get_module_base(const char *module_name) {
    uint64_t addr = 0;
    char line[1024];
    uint64_t start = 0, end = 0;
    char flags[5], path[PATH_MAX];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp != nullptr) {
        while (fgets(line, sizeof(line), fp)) {
            strcpy(path, "");
            sscanf(line, "%" PRIx64"-%" PRIx64" %s %*" PRIx64" %*x:%*x %*u %s\n",
                   &start, &end, flags, path);
#if defined(__aarch64__)
            if (strstr(flags, "x") == 0) continue;
#endif
            if (strstr(path, module_name)) { addr = start; break; }
        }
        fclose(fp);
    }
    return addr;
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream o;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:        o << "private ";            break;
        case METHOD_ATTRIBUTE_PUBLIC:         o << "public ";             break;
        case METHOD_ATTRIBUTE_FAMILY:         o << "protected ";          break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:  o << "internal ";           break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:   o << "protected internal "; break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC)   o << "static ";
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        o << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
            o << "override ";
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT)
            o << "sealed override ";
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT)
            o << "virtual ";
        else
            o << "override ";
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) o << "extern ";
    return o.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) byref = il2cpp_type_is_byref(type);
    return byref;
}

// ─────────────────────────────────────────────
//  Build a human-readable method signature
//  (used for the "Signature" field in script.json)
// ─────────────────────────────────────────────
static std::string build_signature(const MethodInfo *method) {
    std::stringstream sig;
    auto return_type  = il2cpp_method_get_return_type(method);
    auto return_class = il2cpp_class_from_type(return_type);
    sig << il2cpp_class_get_name(return_class) << " ";
    sig << il2cpp_method_get_name(method) << "(";
    auto param_count = il2cpp_method_get_param_count(method);
    for (int i = 0; i < param_count; ++i) {
        auto param        = il2cpp_method_get_param(method, i);
        auto param_class  = il2cpp_class_from_type(param);
        if (i > 0) sig << ", ";
        sig << il2cpp_class_get_name(param_class) << " "
            << il2cpp_method_get_param_name(method, i);
    }
    sig << ")";
    return sig.str();
}

// ─────────────────────────────────────────────
//  dump_method — original dump.cs output +
//                populate g_scriptMethods
// ─────────────────────────────────────────────
std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        if (method->methodPointer) {
            uint64_t va  = (uint64_t)method->methodPointer;
            uint64_t rva = va - il2cpp_base;

            outPut << "\t// RVA: 0x" << std::hex << rva
                   << " VA: 0x"       << std::hex << va;

            // ── collect for script.json ──────────────────
            // Build full qualified name: ClassName$$MethodName
            std::string className  = il2cpp_class_get_name(klass);
            std::string methodName = il2cpp_method_get_name(method);
            std::string fullName   = className + "$$" + methodName;

            g_scriptMethods.push_back({ rva, fullName, build_signature(method) });

            // Track in Addresses array (unique, sorted later)
            g_addresses.push_back(rva);
            // ─────────────────────────────────────────────
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        auto return_type  = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) outPut << "ref ";
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " "
               << il2cpp_method_get_name(method) << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param  = il2cpp_method_get_param(method, i);
            auto attrs  = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if      (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) outPut << "out ";
                else if (attrs & PARAM_ATTRIBUTE_IN  && !(attrs & PARAM_ATTRIBUTE_OUT)) outPut << "in ";
                else outPut << "ref ";
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN)  outPut << "[In] ";
                if (attrs & PARAM_ATTRIBUTE_OUT) outPut << "[Out] ";
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i) << ", ";
        }
        if (param_count > 0) outPut.seekp(-2, outPut.cur);
        outPut << ") { }\n";
    }
    return outPut.str();
}

// ─────────────────────────────────────────────
//  dump_property / dump_field (unchanged)
// ─────────────────────────────────────────────
std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        auto prop      = const_cast<PropertyInfo *>(prop_const);
        auto get       = il2cpp_property_get_get_method(prop);
        auto set       = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_param(set, 0));
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) outPut << "get; ";
            if (set) outPut << "set; ";
            outPut << "}\n";
        } else {
            if (prop_name) outPut << " // unknown property " << prop_name;
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter   = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        outPut << "\t";
        auto attrs  = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:        outPut << "private ";            break;
            case FIELD_ATTRIBUTE_PUBLIC:         outPut << "public ";             break;
            case FIELD_ATTRIBUTE_FAMILY:         outPut << "protected ";          break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:  outPut << "internal ";           break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:   outPut << "protected internal "; break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC)    outPut << "static ";
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) outPut << "readonly ";
        }
        auto field_class = il2cpp_class_from_type(il2cpp_field_get_type(field));
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

// ─────────────────────────────────────────────
//  dump_type — original output +
//              populate ScriptMetadata
// ─────────────────────────────────────────────
std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);

    // ── collect ScriptMetadata ───────────────
    // The class pointer itself IS the metadata pointer used by IDA/Ghidra scripts
    uint64_t klassPtr = (uint64_t)klass;
    if (klassPtr && klassPtr > il2cpp_base) {
        std::string ns   = il2cpp_class_get_namespace(klass);
        std::string name = il2cpp_class_get_name(klass);
        std::string full = ns.empty() ? name : (ns + "." + name);
        g_scriptMetadata.push_back({ klassPtr - il2cpp_base, full });
    }
    // ─────────────────────────────────────────

    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) outPut << "[Serializable]\n";

    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum      = il2cpp_class_is_enum(klass);
    auto visibility   = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:      outPut << "public ";            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:    outPut << "internal ";          break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:     outPut << "private ";           break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:      outPut << "protected ";         break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: outPut << "protected internal "; break;
    }
    if      (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) outPut << "static ";
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) outPut << "abstract ";
    else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) outPut << "sealed ";

    if      (flags & TYPE_ATTRIBUTE_INTERFACE) outPut << "interface ";
    else if (is_enum)                          outPut << "enum ";
    else if (is_valuetype)                     outPut << "struct ";
    else                                       outPut << "class ";

    outPut << il2cpp_class_get_name(klass);

    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT)
            extends.emplace_back(il2cpp_class_get_name(parent));
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter))
        extends.emplace_back(il2cpp_class_get_name(itf));

    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (int i = 1; i < (int)extends.size(); ++i) outPut << ", " << extends[i];
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    outPut << "}\n";
    return outPut.str();
}

// ─────────────────────────────────────────────
//  Write script.json
// ─────────────────────────────────────────────
static void write_script_json(const std::string &outDir) {
    // Sort + deduplicate Addresses
    std::sort(g_addresses.begin(), g_addresses.end());
    g_addresses.erase(std::unique(g_addresses.begin(), g_addresses.end()), g_addresses.end());

    auto jsonPath = outDir + "/files/script.json";
    std::ofstream js(jsonPath);
    if (!js.is_open()) {
        LOGE("Failed to open script.json for writing: %s", jsonPath.c_str());
        return;
    }

    js << "{\n";

    // ── ScriptMethod ──────────────────────────
    js << "\t\"ScriptMethod\": [\n";
    for (size_t i = 0; i < g_scriptMethods.size(); ++i) {
        const auto &m = g_scriptMethods[i];
        js << "\t\t{"
           << "\"Address\": "    << m.address << ", "
           << "\"Name\": \""     << json_escape(m.name) << "\", "
           << "\"Signature\": \"" << json_escape(m.signature) << "\""
           << "}";
        if (i + 1 < g_scriptMethods.size()) js << ",";
        js << "\n";
    }
    js << "\t],\n";

    // ── ScriptString ─────────────────────────
    // NOTE: Zygisk does not iterate string literals via the il2cpp C API
    // because il2cpp_string_* API only creates/reads managed strings, not
    // the raw Il2CppString* literal table. The array is emitted empty here;
    // to populate it you would need to walk Il2CppMetadataRegistration::
    // metadataUsages or the string-literal table directly.
    js << "\t\"ScriptString\": [],\n";

    // ── ScriptMetadata ───────────────────────
    js << "\t\"ScriptMetadata\": [\n";
    for (size_t i = 0; i < g_scriptMetadata.size(); ++i) {
        const auto &m = g_scriptMetadata[i];
        js << "\t\t{"
           << "\"Address\": " << m.address << ", "
           << "\"Name\": \""  << json_escape(m.name) << "\""
           << "}";
        if (i + 1 < g_scriptMetadata.size()) js << ",";
        js << "\n";
    }
    js << "\t],\n";

    // ── ScriptMetadataMethod ─────────────────
    // Empty: populating this requires walking Il2CppMetadataRegistration
    // (methodPointers / invokerPointers arrays) which needs the
    // Il2CppCodeRegistration pointer — beyond what the C API exposes.
    js << "\t\"ScriptMetadataMethod\": [],\n";

    // ── Addresses ────────────────────────────
    js << "\t\"Addresses\": [\n";
    for (size_t i = 0; i < g_addresses.size(); ++i) {
        js << "\t\t" << g_addresses[i];
        if (i + 1 < g_addresses.size()) js << ",";
        js << "\n";
    }
    js << "\t]\n";

    js << "}\n";
    js.close();
    LOGI("script.json written to %s", jsonPath.c_str());
}

// ─────────────────────────────────────────────
//  il2cpp_dump — main entry point (unchanged
//  structure; script.json written at the end)
// ─────────────────────────────────────────────
static void do_dump(const char *outDir) {
    LOGI("il2cpp_handle: %p", il2cpp_handle);

    if (il2cpp_domain_get_assemblies) {
        Dl_info dlInfo;
        if (dladdr((void *)il2cpp_domain_get_assemblies, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        } else {
            LOGW("dladdr error, using get_module_base.");
            il2cpp_base = get_module_base("libil2cpp.so");
        }
        LOGI("il2cpp_base: %" PRIx64, il2cpp_base);
    } else {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }

    auto domain = il2cpp_domain_get();
    il2cpp_thread_attach(domain);

    LOGI("dumping...");

    size_t size;
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);

    std::stringstream imageOutput;
    for (int i = 0; i < (int)size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }

    std::vector<std::string> outPuts;

    if (il2cpp_image_get_class) {
        LOGI("Version >= 2018.3");
        for (int i = 0; i < (int)size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < (int)classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type  = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                outPuts.push_back(imageStr.str() + dump_type(type));
            }
        }
    } else {
        LOGI("Version < 2018.3");
        auto corlib        = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad  = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);

        if (!assemblyLoad || !assemblyLoad->methodPointer) { LOGI("miss Assembly::Load"); return; }
        if (!assemblyGetTypes || !assemblyGetTypes->methodPointer) { LOGI("miss Assembly::GetTypes"); return; }

        typedef void           *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray    *(*Assembly_GetTypes_ftn)(void *, void *);

        for (int i = 0; i < (int)size; ++i) {
            auto image      = il2cpp_assembly_get_image(assemblies[i]);
            auto image_name = il2cpp_image_get_name(image);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << image_name;

            auto imageName      = std::string(image_name);
            auto pos            = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.c_str());

            auto reflectionAssembly =
                ((Assembly_Load_ftn)assemblyLoad->methodPointer)(nullptr, assemblyFileName, nullptr);
            auto reflectionTypes =
                ((Assembly_GetTypes_ftn)assemblyGetTypes->methodPointer)(reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;

            for (int j = 0; j < (int)reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *)items[j]);
                auto type  = il2cpp_class_get_type(klass);
                outPuts.push_back(imageStr.str() + dump_type(type));
            }
        }
    }

    // ── Write dump.cs (unchanged) ────────────
    LOGI("writing dump.cs");
    mkdir((std::string(outDir) + "/files").c_str(), 0777);
    auto outPath = std::string(outDir) + "/files/dump.cs";
    std::ofstream outStream(outPath);
    outStream << imageOutput.str();
    for (const auto &s : outPuts) outStream << s;
    outStream.close();

    // ── Write script.json (new) ──────────────
    LOGI("writing script.json");
    write_script_json(std::string(outDir));

    LOGI("dump done!");
}

// Public entry: never block the caller, wait for il2cpp to be ready.
void il2cpp_dump(const char *outDir) {
    std::string dir(outDir);
    std::thread([dir]() {
        // wait until the il2cpp runtime is initialized (max ~20 s)
        bool ready = false;
        for (int i = 0; i < 200 && il2cpp_domain_get; ++i) {
            if (il2cpp_domain_get()) { ready = true; break; }
            usleep(100 * 1000);  // 100 ms
        }
        if (!ready) {
            LOGE("il2cpp runtime not initialized, aborting dump");
            return;
        }
        // make sure the output directory exists
        mkdir((dir + "/files").c_str(), 0777);
        do_dump(dir.c_str());
    }).detach();
}
