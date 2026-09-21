//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"

#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <cstdio>

#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <utility>

#include <unistd.h>

#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API


/*
 * ============================================================
 * Globals
 * ============================================================
 */

static uint64_t il2cpp_base = 0;


/*
 * ============================================================
 * Forward declaration
 * ============================================================
 */

bool _il2cpp_type_is_byref(
        const Il2CppType *type);


/*
 * ============================================================
 * Runtime class information
 * ============================================================
 */

struct RuntimeScriptClass {

    /*
     * Runtime Il2CppClass* address.
     */
    uint64_t classAddress;

    /*
     * Runtime Il2CppType* address.
     */
    uint64_t typeAddress;

    /*
     * ClassAddress - il2cpp_base.
     *
     * Stored as decimal in script.json.
     */
    uint64_t address;

    std::string name;

    std::string namespaceName;
};


/*
 * ============================================================
 * Runtime method information
 * ============================================================
 */

struct RuntimeScriptMethod {

    /*
     * Method RVA:
     *
     * methodPointer - il2cpp_base
     */
    uint64_t address;

    std::string name;

    std::string signature;

    std::string typeSignature;
};


static std::vector<RuntimeScriptClass>
        g_scriptClasses;


static std::vector<RuntimeScriptMethod>
        g_scriptMethods;


/*
 * ============================================================
 * IL2CPP API initialization
 * ============================================================
 */

void init_il2cpp_api(void *handle) {

#define DO_API(r, n, p) {                                      \
        n = (r (*) p)xdl_sym(handle, #n, nullptr);             \
        if (!n) {                                              \
            LOGW("api not found %s", #n);                      \
        }                                                       \
    }

#include "il2cpp-api-functions.h"

#undef DO_API
}


/*
 * ============================================================
 * JSON escape
 * ============================================================
 */

static std::string json_escape(
        const char *str) {

    if (!str) {
        return "";
    }

    std::string out;

    const unsigned char *p =
            reinterpret_cast<
                    const unsigned char *
            >(str);

    while (*p) {

        switch (*p) {

            case '\"':
                out += "\\\"";
                break;

            case '\\':
                out += "\\\\";
                break;

            case '\b':
                out += "\\b";
                break;

            case '\f':
                out += "\\f";
                break;

            case '\n':
                out += "\\n";
                break;

            case '\r':
                out += "\\r";
                break;

            case '\t':
                out += "\\t";
                break;

            default:

                if (*p < 0x20) {

                    char buffer[8];

                    snprintf(
                            buffer,
                            sizeof(buffer),
                            "\\u%04x",
                            *p
                    );

                    out += buffer;

                } else {

                    out +=
                            static_cast<char>(*p);
                }

                break;
        }

        ++p;
    }

    return out;
}


/*
 * ============================================================
 * Safe class name
 * ============================================================
 */

static std::string get_class_name_safe(
        Il2CppClass *klass) {

    if (!klass) {
        return "void";
    }

    const char *name =
            il2cpp_class_get_name(klass);

    if (!name) {
        return "void";
    }

    return name;
}


/*
 * ============================================================
 * Safe type name
 * ============================================================
 */

static std::string get_type_name_safe(
        const Il2CppType *type) {

    if (!type) {
        return "void";
    }

    auto klass =
            il2cpp_class_from_type(type);

    if (!klass) {
        return "void";
    }

    return get_class_name_safe(klass);
}


/*
 * ============================================================
 * Script type character
 * ============================================================
 */

static char get_script_type(
        const Il2CppType *type) {

    if (!type) {
        return 'v';
    }

    switch (type->type) {

        case IL2CPP_TYPE_VOID:
            return 'v';

        case IL2CPP_TYPE_BOOLEAN:
        case IL2CPP_TYPE_I1:
        case IL2CPP_TYPE_U1:
        case IL2CPP_TYPE_I2:
        case IL2CPP_TYPE_U2:
        case IL2CPP_TYPE_CHAR:
        case IL2CPP_TYPE_I4:
        case IL2CPP_TYPE_U4:
            return 'i';

        case IL2CPP_TYPE_I8:
        case IL2CPP_TYPE_U8:
            return 'l';

        case IL2CPP_TYPE_R4:
            return 'f';

        case IL2CPP_TYPE_R8:
            return 'd';

        case IL2CPP_TYPE_I:
        case IL2CPP_TYPE_U:
        case IL2CPP_TYPE_PTR:
        case IL2CPP_TYPE_CLASS:
        case IL2CPP_TYPE_VALUETYPE:
        case IL2CPP_TYPE_OBJECT:
        case IL2CPP_TYPE_STRING:
        case IL2CPP_TYPE_ARRAY:
        case IL2CPP_TYPE_SZARRAY:
        case IL2CPP_TYPE_GENERICINST:
            return 'p';

        default:
            return 'p';
    }
}


/*
 * ============================================================
 * ByRef
 * ============================================================
 */

bool _il2cpp_type_is_byref(
        const Il2CppType *type) {

    if (!type) {
        return false;
    }

    auto byref =
            type->byref;

    if (il2cpp_type_is_byref) {

        byref =
                il2cpp_type_is_byref(type);
    }

    return byref;
}


/*
 * ============================================================
 * Collect class
 *
 * script.json:
 *
 * {
 *     "Address": 123456,
 *     "Name": "GameFacade",
 *     "Namespace": "Game"
 * }
 *
 * ClassAddress / TypeAddress are NOT written to JSON.
 * ============================================================
 */

static void collect_script_class(
        Il2CppClass *klass,
        const Il2CppType *type) {

    if (!klass || !type) {
        return;
    }


    RuntimeScriptClass result{};


    /*
     * Runtime Il2CppClass address.
     */
    result.classAddress =
            reinterpret_cast<uint64_t>(
                    klass
            );


    /*
     * Runtime Il2CppType address.
     */
    result.typeAddress =
            reinterpret_cast<uint64_t>(
                    type
            );


    /*
     * Class RVA.
     *
     * This is the class runtime address
     * relative to libil2cpp base.
     */
    if (result.classAddress >= il2cpp_base) {

        result.address =
                result.classAddress -
                il2cpp_base;

    } else {

        result.address = 0;
    }


    const char *className =
            il2cpp_class_get_name(
                    klass
            );


    const char *namespaceName =
            il2cpp_class_get_namespace(
                    klass
            );


    if (!className) {
        className = "Unknown";
    }


    if (!namespaceName) {
        namespaceName = "";
    }


    result.name =
            className;


    result.namespaceName =
            namespaceName;


    g_scriptClasses.emplace_back(
            std::move(result)
    );
}


/*
 * ============================================================
 * Collect method
 *
 * script.json:
 *
 * {
 *     "Address": 12345678,
 *     "Name": "GameFacade$$Init",
 *     "Signature": "...",
 *     "TypeSignature": "vpp"
 * }
 *
 * ClassAddress / TypeAddress are NOT written to JSON.
 * ============================================================
 */

static void collect_script_method(
        const MethodInfo *method,
        Il2CppClass *klass) {

    if (!method ||
        !klass ||
        !method->methodPointer) {

        return;
    }


    RuntimeScriptMethod result{};


    /*
     * Method RVA.
     *
     * Address =
     * methodPointer - il2cpp_base
     */
    uint64_t methodPointer =
            reinterpret_cast<uint64_t>(
                    method->methodPointer
            );


    if (methodPointer >= il2cpp_base) {

        result.address =
                methodPointer -
                il2cpp_base;

    } else {

        result.address = 0;
    }


    /*
     * Class name
     */
    const char *className =
            il2cpp_class_get_name(
                    klass
            );


    if (!className) {
        className = "Unknown";
    }


    /*
     * Method name
     */
    const char *methodName =
            il2cpp_method_get_name(
                    method
            );


    if (!methodName) {
        methodName = "Unknown";
    }


    /*
     * Name:
     *
     * GameFacade$$Init
     */
    result.name =
            std::string(className)
            + "$$"
            + methodName;


    /*
     * Flags
     */
    uint32_t iflags = 0;


    uint32_t flags =
            il2cpp_method_get_flags(
                    method,
                    &iflags
            );


    bool isStatic =
            (flags &
             METHOD_ATTRIBUTE_STATIC) != 0;


    /*
     * Return type
     */
    auto returnType =
            il2cpp_method_get_return_type(
                    method
            );


    std::string returnTypeName =
            get_type_name_safe(
                    returnType
            );


    /*
     * Signature
     */
    std::stringstream signature;


    signature
            << returnTypeName
            << " "
            << result.name
            << " (";


    /*
     * Type signature
     */
    std::stringstream typeSignature;


    typeSignature
            << get_script_type(
                    returnType
            );


    bool hasArgument = false;


    /*
     * this
     */
    if (!isStatic) {

        signature
                << "void* __this";

        typeSignature
                << "p";

        hasArgument = true;
    }


    /*
     * Parameters
     */
    uint32_t paramCount =
            il2cpp_method_get_param_count(
                    method
            );


    for (uint32_t i = 0;
         i < paramCount;
         ++i) {

        auto param =
                il2cpp_method_get_param(
                        method,
                        i
                );


        if (!param) {
            continue;
        }


        if (hasArgument) {
            signature << ", ";
        }


        auto parameterClass =
                il2cpp_class_from_type(
                        param
                );


        std::string parameterType =
                get_class_name_safe(
                        parameterClass
                );


        const char *parameterName =
                il2cpp_method_get_param_name(
                        method,
                        i
                );


        if (!parameterName) {
            parameterName = "arg";
        }


        /*
         * ref / out / in
         */
        if (_il2cpp_type_is_byref(
                param)) {

            uint16_t attrs =
                    param->attrs;


            if ((attrs &
                 PARAM_ATTRIBUTE_OUT) &&
                !(attrs &
                  PARAM_ATTRIBUTE_IN)) {

                signature
                        << "out "
                        << parameterType
                        << " "
                        << parameterName;

            } else if (
                    (attrs &
                     PARAM_ATTRIBUTE_IN) &&
                    !(attrs &
                      PARAM_ATTRIBUTE_OUT)) {

                signature
                        << "in "
                        << parameterType
                        << " "
                        << parameterName;

            } else {

                signature
                        << "ref "
                        << parameterType
                        << " "
                        << parameterName;
            }

        } else {

            signature
                    << parameterType
                    << " "
                    << parameterName;
        }


        typeSignature
                << get_script_type(
                        param
                );


        hasArgument = true;
    }


    /*
     * MethodInfo argument
     */
    if (hasArgument) {
        signature << ", ";
    }


    signature
            << "const MethodInfo* method)";


    typeSignature
            << "p";


    result.signature =
            signature.str();


    result.typeSignature =
            typeSignature.str();


    g_scriptMethods.emplace_back(
            std::move(result)
    );
}


/*
 * ============================================================
 * Write script.json
 * ============================================================
 *
 * IMPORTANT:
 *
 * ClassAddress is NOT included.
 * TypeAddress is NOT included.
 *
 * Method ClassAddress is NOT included.
 * Method TypeAddress is NOT included.
 *
 * Only RVA Address values are stored.
 * ============================================================
 */

static void write_script_json(
        const char *outDir) {

    if (!outDir) {
        return;
    }


    std::string path =
            std::string(outDir)
            + "/files/script.json";


    std::ofstream out(
            path,
            std::ios::out |
            std::ios::trunc
    );


    if (!out.is_open()) {

        LOGE(
                "Failed to open script.json: %s",
                path.c_str()
        );

        return;
    }


    out << "{\n";


    /*
     * ========================================================
     * ScriptClass
     * ========================================================
     */

    out << "  \"ScriptClass\": [\n";


    for (size_t i = 0;
         i < g_scriptClasses.size();
         ++i) {

        const auto &item =
                g_scriptClasses[i];


        out << "    {\n";


        /*
         * Class RVA.
         *
         * Decimal.
         */
        out << "      \"Address\": "
            << item.address
            << ",\n";


        out << "      \"Name\": \""
            << json_escape(
                    item.name.c_str()
            )
            << "\",\n";


        out << "      \"Namespace\": \""
            << json_escape(
                    item.namespaceName.c_str()
            )
            << "\"\n";


        out << "    }";


        if (i + 1 <
            g_scriptClasses.size()) {

            out << ",";
        }


        out << "\n";
    }


    out << "  ],\n";


    /*
     * ========================================================
     * ScriptMethod
     * ========================================================
     */

    out << "  \"ScriptMethod\": [\n";


    for (size_t i = 0;
         i < g_scriptMethods.size();
         ++i) {

        const auto &method =
                g_scriptMethods[i];


        out << "    {\n";


        /*
         * Method RVA.
         *
         * Decimal.
         */
        out << "      \"Address\": "
            << method.address
            << ",\n";


        out << "      \"Name\": \""
            << json_escape(
                    method.name.c_str()
            )
            << "\",\n";


        out << "      \"Signature\": \""
            << json_escape(
                    method.signature.c_str()
            )
            << "\",\n";


        out << "      \"TypeSignature\": \""
            << json_escape(
                    method.typeSignature.c_str()
            )
            << "\"\n";


        out << "    }";


        if (i + 1 <
            g_scriptMethods.size()) {

            out << ",";
        }


        out << "\n";
    }


    out << "  ],\n";


    /*
     * ========================================================
     * Runtime-only sections
     * ========================================================
     */

    out << "  \"ScriptString\": [],\n";

    out << "  \"ScriptMetadata\": [],\n";

    out << "  \"ScriptMetadataMethod\": []\n";


    out << "}\n";


    out.close();


    LOGI(
            "script.json written: %s",
            path.c_str()
    );


    LOGI(
            "classes: %zu methods: %zu",
            g_scriptClasses.size(),
            g_scriptMethods.size()
    );
}


/*
 * ============================================================
 * Method modifier
 * ============================================================
 */

std::string get_method_modifier(
        uint32_t flags) {

    std::stringstream outPut;


    auto access =
            flags &
            METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;


    switch (access) {

        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;

        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;

        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;

        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;

        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }


    if (flags &
        METHOD_ATTRIBUTE_STATIC) {

        outPut << "static ";
    }


    if (flags &
        METHOD_ATTRIBUTE_ABSTRACT) {

        outPut << "abstract ";

        if ((flags &
             METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK)
            ==
            METHOD_ATTRIBUTE_REUSE_SLOT) {

            outPut << "override ";
        }

    } else if (
            flags &
            METHOD_ATTRIBUTE_FINAL) {

        if ((flags &
             METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK)
            ==
            METHOD_ATTRIBUTE_REUSE_SLOT) {

            outPut
                    << "sealed override ";
        }

    } else if (
            flags &
            METHOD_ATTRIBUTE_VIRTUAL) {

        if ((flags &
             METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK)
            ==
            METHOD_ATTRIBUTE_NEW_SLOT) {

            outPut << "virtual ";

        } else {

            outPut << "override ";
        }
    }


    if (flags &
        METHOD_ATTRIBUTE_PINVOKE_IMPL) {

        outPut << "extern ";
    }


    return outPut.str();
}


/*
 * ============================================================
 * dump_method
 * ============================================================
 */

std::string dump_method(
        Il2CppClass *klass) {

    std::stringstream outPut;


    outPut
            << "\n\t// Methods\n";


    void *iter = nullptr;


    while (auto method =
                   il2cpp_class_get_methods(
                           klass,
                           &iter)) {


        /*
         * Add method to script.json.
         */
        collect_script_method(
                method,
                klass
        );


        /*
         * RVA / VA
         */
        if (method->methodPointer) {

            uint64_t methodAddress =
                    reinterpret_cast<uint64_t>(
                            method->methodPointer
                    );


            uint64_t methodRva = 0;


            if (methodAddress >= il2cpp_base) {

                methodRva =
                        methodAddress -
                        il2cpp_base;
            }


            outPut
                    << "\t// RVA: 0x"
                    << std::hex
                    << methodRva
                    << " VA: 0x"
                    << methodAddress;

        } else {

            outPut
                    << "\t// RVA: 0x VA: 0x0";
        }


        outPut
                << "\n\t";


        uint32_t iflags = 0;


        auto flags =
                il2cpp_method_get_flags(
                        method,
                        &iflags
                );


        outPut
                << get_method_modifier(
                        flags
                );


        /*
         * Return type
         */
        auto return_type =
                il2cpp_method_get_return_type(
                        method
                );


        if (_il2cpp_type_is_byref(
                return_type)) {

            outPut << "ref ";
        }


        auto return_class =
                il2cpp_class_from_type(
                        return_type
                );


        outPut
                << get_class_name_safe(
                        return_class
                )
                << " "
                << il2cpp_method_get_name(
                        method
                )
                << "(";


        /*
         * Parameters
         */
        auto param_count =
                il2cpp_method_get_param_count(
                        method
                );


        for (uint32_t i = 0;
             i < param_count;
             ++i) {

            auto param =
                    il2cpp_method_get_param(
                            method,
                            i
                    );


            if (!param) {
                continue;
            }


            auto attrs =
                    param->attrs;


            if (_il2cpp_type_is_byref(
                    param)) {

                if ((attrs &
                     PARAM_ATTRIBUTE_OUT)
                    &&
                    !(attrs &
                      PARAM_ATTRIBUTE_IN)) {

                    outPut << "out ";

                } else if (
                        (attrs &
                         PARAM_ATTRIBUTE_IN)
                        &&
                        !(attrs &
                          PARAM_ATTRIBUTE_OUT)) {

                    outPut << "in ";

                } else {

                    outPut << "ref ";
                }

            } else {

                if (attrs &
                    PARAM_ATTRIBUTE_IN) {

                    outPut << "[In] ";
                }

                if (attrs &
                    PARAM_ATTRIBUTE_OUT) {

                    outPut << "[Out] ";
                }
            }


            auto parameter_class =
                    il2cpp_class_from_type(
                            param
                    );


            outPut
                    << get_class_name_safe(
                            parameter_class
                    )
                    << " "
                    << il2cpp_method_get_param_name(
                            method,
                            i
                    );


            outPut
                    << ", ";
        }


        if (param_count > 0) {

            outPut.seekp(
                    -2,
                    outPut.cur
            );
        }


        outPut
                << ") { }\n";
    }


    return outPut.str();
}


/*
 * ============================================================
 * dump_property
 * ============================================================
 */

std::string dump_property(
        Il2CppClass *klass) {

    std::stringstream outPut;


    outPut
            << "\n\t// Properties\n";


    void *iter = nullptr;


    while (auto prop_const =
                   il2cpp_class_get_properties(
                           klass,
                           &iter)) {

        auto prop =
                const_cast<PropertyInfo *>(
                        prop_const
                );


        auto get =
                il2cpp_property_get_get_method(
                        prop
                );


        auto set =
                il2cpp_property_get_set_method(
                        prop
                );


        auto prop_name =
                il2cpp_property_get_name(
                        prop
                );


        outPut
                << "\t";


        Il2CppClass *prop_class =
                nullptr;


        uint32_t iflags = 0;


        if (get) {

            outPut
                    << get_method_modifier(
                            il2cpp_method_get_flags(
                                    get,
                                    &iflags
                            )
                    );


            prop_class =
                    il2cpp_class_from_type(
                            il2cpp_method_get_return_type(
                                    get
                            )
                    );

        } else if (set) {

            outPut
                    << get_method_modifier(
                            il2cpp_method_get_flags(
                                    set,
                                    &iflags
                            )
                    );


            auto param =
                    il2cpp_method_get_param(
                            set,
                            0
                    );


            prop_class =
                    il2cpp_class_from_type(
                            param
                    );
        }


        if (prop_class) {

            outPut
                    << get_class_name_safe(
                            prop_class
                    )
                    << " "
                    << prop_name
                    << " { ";


            if (get) {
                outPut << "get; ";
            }


            if (set) {
                outPut << "set; ";
            }


            outPut
                    << "}\n";

        } else if (prop_name) {

            outPut
                    << " // unknown property "
                    << prop_name
                    << "\n";
        }
    }


    return outPut.str();
}


/*
 * ============================================================
 * dump_field
 * ============================================================
 */

std::string dump_field(
        Il2CppClass *klass) {

    std::stringstream outPut;


    outPut
            << "\n\t// Fields\n";


    auto is_enum =
            il2cpp_class_is_enum(
                    klass
            );


    void *iter = nullptr;


    while (auto field =
                   il2cpp_class_get_fields(
                           klass,
                           &iter)) {

        outPut << "\t";


        auto attrs =
                il2cpp_field_get_flags(
                        field
                );


        auto access =
                attrs &
                FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;


        switch (access) {

            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;

            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;

            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;

            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;

            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }


        if (attrs &
            FIELD_ATTRIBUTE_LITERAL) {

            outPut << "const ";

        } else {

            if (attrs &
                FIELD_ATTRIBUTE_STATIC) {

                outPut << "static ";
            }


            if (attrs &
                FIELD_ATTRIBUTE_INIT_ONLY) {

                outPut << "readonly ";
            }
        }


        auto field_type =
                il2cpp_field_get_type(
                        field
                );


        auto field_class =
                il2cpp_class_from_type(
                        field_type
                );


        outPut
                << get_class_name_safe(
                        field_class
                )
                << " "
                << il2cpp_field_get_name(
                        field
                );


        if ((attrs &
             FIELD_ATTRIBUTE_LITERAL)
            &&
            is_enum) {

            uint64_t val = 0;


            il2cpp_field_static_get_value(
                    field,
                    &val
            );


            outPut
                    << " = "
                    << std::dec
                    << val;
        }


        outPut
                << "; // 0x"
                << std::hex
                << il2cpp_field_get_offset(
                        field
                )
                << "\n";
    }


    return outPut.str();
}


/*
 * ============================================================
 * dump_type
 *
 * Class header only:
 *
 * // ClassAddress: 0x7A12345678
 * // TypeAddress: 0x7A12346000
 * // Address: 12345678
 * // Namespace: Game
 * public class GameFacade
 *
 * No ClassAddress / TypeAddress are added to methods
 * or fields.
 * ============================================================
 */

std::string dump_type(
        const Il2CppType *type) {

    std::stringstream outPut;


    auto *klass =
            il2cpp_class_from_type(
                    type
            );


    if (!klass) {
        return "";
    }


    /*
     * ========================================================
     * Runtime addresses
     * ========================================================
     */

    uint64_t classAddress =
            reinterpret_cast<uint64_t>(
                    klass
            );


    uint64_t typeAddress =
            reinterpret_cast<uint64_t>(
                    type
            );


    /*
     * Class RVA:
     *
     * ClassAddress - il2cpp_base
     */
    uint64_t classAddressRva = 0;


    if (classAddress >= il2cpp_base) {

        classAddressRva =
                classAddress -
                il2cpp_base;
    }


    /*
     * Save class information for script.json.
     */
    collect_script_class(
            klass,
            type
    );


    /*
     * ========================================================
     * ClassAddress
     * ========================================================
     */

    outPut
            << "\n// ClassAddress: 0x"
            << std::hex
            << classAddress
            << "\n";


    /*
     * ========================================================
     * TypeAddress
     * ========================================================
     */

    outPut
            << "// TypeAddress: 0x"
            << std::hex
            << typeAddress
            << "\n";


    /*
     * ========================================================
     * Address
     *
     * IMPORTANT:
     * Decimal, just like script.json.
     * ========================================================
     */

    outPut
            << "// Address: "
            << std::dec
            << classAddressRva
            << "\n";


    /*
     * ========================================================
     * Namespace
     * ========================================================
     */

    const char *namespaceName =
            il2cpp_class_get_namespace(
                    klass
            );


    if (!namespaceName) {
        namespaceName = "";
    }


    outPut
            << "// Namespace: "
            << namespaceName
            << "\n";


    auto flags =
            il2cpp_class_get_flags(
                    klass
            );


    if (flags &
        TYPE_ATTRIBUTE_SERIALIZABLE) {

        outPut
                << "[Serializable]\n";
    }


    auto is_valuetype =
            il2cpp_class_is_valuetype(
                    klass
            );


    auto is_enum =
            il2cpp_class_is_enum(
                    klass
            );


    auto visibility =
            flags &
            TYPE_ATTRIBUTE_VISIBILITY_MASK;


    switch (visibility) {

        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:

            outPut
                    << "public ";
            break;


        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:

            outPut
                    << "internal ";
            break;


        case TYPE_ATTRIBUTE_NESTED_PRIVATE:

            outPut
                    << "private ";
            break;


        case TYPE_ATTRIBUTE_NESTED_FAMILY:

            outPut
                    << "protected ";
            break;


        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:

            outPut
                    << "protected internal ";
            break;
    }


    /*
     * static / abstract / sealed
     */
    if ((flags &
         TYPE_ATTRIBUTE_ABSTRACT)
        &&
        (flags &
         TYPE_ATTRIBUTE_SEALED)) {

        outPut
                << "static ";

    } else if (
            !(flags &
              TYPE_ATTRIBUTE_INTERFACE)
            &&
            (flags &
             TYPE_ATTRIBUTE_ABSTRACT)) {

        outPut
                << "abstract ";

    } else if (
            !is_valuetype
            &&
            !is_enum
            &&
            (flags &
             TYPE_ATTRIBUTE_SEALED)) {

        outPut
                << "sealed ";
    }


    /*
     * class / struct / enum / interface
     */
    if (flags &
        TYPE_ATTRIBUTE_INTERFACE) {

        outPut
                << "interface ";

    } else if (is_enum) {

        outPut
                << "enum ";

    } else if (is_valuetype) {

        outPut
                << "struct ";

    } else {

        outPut
                << "class ";
    }


    /*
     * Class name
     */
    const char *className =
            il2cpp_class_get_name(
                    klass
            );


    if (!className) {
        className = "Unknown";
    }


    outPut
            << className;


    /*
     * ========================================================
     * Parent
     * ========================================================
     */

    std::vector<std::string> extends;


    auto parent =
            il2cpp_class_get_parent(
                    klass
            );


    if (!is_valuetype &&
        !is_enum &&
        parent) {

        auto parent_type =
                il2cpp_class_get_type(
                        parent
                );


        if (parent_type &&
            parent_type->type !=
            IL2CPP_TYPE_OBJECT) {

            extends.emplace_back(
                    get_class_name_safe(
                            parent
                    )
            );
        }
    }


    /*
     * ========================================================
     * Interfaces
     * ========================================================
     */

    void *iter = nullptr;


    while (auto itf =
                   il2cpp_class_get_interfaces(
                           klass,
                           &iter)) {

        extends.emplace_back(
                get_class_name_safe(
                        itf
                )
        );
    }


    if (!extends.empty()) {

        outPut
                << " : "
                << extends[0];


        for (size_t i = 1;
             i < extends.size();
             ++i) {

            outPut
                    << ", "
                    << extends[i];
        }
    }


    outPut
            << "\n{";


    /*
     * Fields
     */
    outPut
            << dump_field(
                    klass
            );


    /*
     * Properties
     */
    outPut
            << dump_property(
                    klass
            );


    /*
     * Methods
     */
    outPut
            << dump_method(
                    klass
            );


    outPut
            << "}\n";


    return outPut.str();
}


/*
 * ============================================================
 * il2cpp_api_init
 * ============================================================
 */

void il2cpp_api_init(
        void *handle) {

    LOGI(
            "il2cpp_handle: %p",
            handle
    );


    init_il2cpp_api(
            handle
    );


    if (il2cpp_domain_get_assemblies) {

        Dl_info dlInfo;


        if (dladdr(
                (void *) il2cpp_domain_get_assemblies,
                &dlInfo)) {

            il2cpp_base =
                    reinterpret_cast<uint64_t>(
                            dlInfo.dli_fbase
                    );
        }


        LOGI(
                "il2cpp_base: %" PRIx64,
                il2cpp_base
        );

    } else {

        LOGE(
                "Failed to initialize il2cpp API."
        );

        return;
    }


    while (!il2cpp_is_vm_thread(nullptr)) {

        LOGI(
                "Waiting for il2cpp_init..."
        );

        sleep(1);
    }


    auto domain =
            il2cpp_domain_get();


    il2cpp_thread_attach(
            domain
    );
}


/*
 * ============================================================
 * il2cpp_dump
 * ============================================================
 */

void il2cpp_dump(
        const char *outDir) {

    LOGI(
            "dumping..."
    );


    /*
     * Clear previous runtime data.
     */
    g_scriptClasses.clear();

    g_scriptMethods.clear();


    /*
     * Domain
     */
    size_t size = 0;


    auto domain =
            il2cpp_domain_get();


    auto assemblies =
            il2cpp_domain_get_assemblies(
                    domain,
                    &size
            );


    if (!assemblies) {

        LOGE(
                "il2cpp_domain_get_assemblies failed"
        );

        return;
    }


    /*
     * Image header
     */
    std::stringstream imageOutput;


    for (size_t i = 0;
         i < size;
         ++i) {

        auto image =
                il2cpp_assembly_get_image(
                        assemblies[i]
                );


        if (!image) {
            continue;
        }


        imageOutput
                << "// Image "
                << i
                << ": "
                << il2cpp_image_get_name(
                        image
                )
                << "\n";
    }


    /*
     * dump.cs output
     */
    std::vector<std::string> outPuts;


    /*
     * ========================================================
     * New IL2CPP
     * ========================================================
     */

    if (il2cpp_image_get_class) {

        LOGI(
                "Version greater than 2018.3"
        );


        for (size_t i = 0;
             i < size;
             ++i) {

            auto image =
                    il2cpp_assembly_get_image(
                            assemblies[i]
                    );


            if (!image) {
                continue;
            }


            std::stringstream imageStr;


            imageStr
                    << "\n// Dll : "
                    << il2cpp_image_get_name(
                            image
                    );


            size_t classCount =
                    il2cpp_image_get_class_count(
                            image
                    );


            for (size_t j = 0;
                 j < classCount;
                 ++j) {

                auto klass =
                        il2cpp_image_get_class(
                                image,
                                j
                        );


                if (!klass) {
                    continue;
                }


                auto type =
                        il2cpp_class_get_type(
                                const_cast<Il2CppClass *>(
                                        klass
                                )
                        );


                if (!type) {
                    continue;
                }


                std::string output =
                        imageStr.str()
                        +
                        dump_type(
                                type
                        );


                outPuts.push_back(
                        std::move(output)
                );
            }
        }

    } else {

        /*
         * ====================================================
         * Old IL2CPP
         * ====================================================
         */

        LOGI(
                "Version less than 2018.3"
        );


        auto corlib =
                il2cpp_get_corlib();


        auto assemblyClass =
                il2cpp_class_from_name(
                        corlib,
                        "System.Reflection",
                        "Assembly"
                );


        auto assemblyLoad =
                il2cpp_class_get_method_from_name(
                        assemblyClass,
                        "Load",
                        1
                );


        auto assemblyGetTypes =
                il2cpp_class_get_method_from_name(
                        assemblyClass,
                        "GetTypes",
                        0
                );


        if (!assemblyLoad ||
            !assemblyLoad->methodPointer) {

            LOGI(
                    "miss Assembly::Load"
            );

            return;
        }


        if (!assemblyGetTypes ||
            !assemblyGetTypes->methodPointer) {

            LOGI(
                    "miss Assembly::GetTypes"
            );

            return;
        }


        typedef void *(*Assembly_Load_ftn)(
                void *,
                Il2CppString *,
                void *
        );


        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(
                void *,
                void *
        );


        for (size_t i = 0;
             i < size;
             ++i) {

            auto image =
                    il2cpp_assembly_get_image(
                            assemblies[i]
                    );


            if (!image) {
                continue;
            }


            std::stringstream imageStr;


            const char *image_name =
                    il2cpp_image_get_name(
                            image
                    );


            imageStr
                    << "\n// Dll : "
                    << image_name;


            std::string imageName =
                    image_name
                    ? image_name
                    : "";


            auto pos =
                    imageName.rfind('.');


            std::string imageNameNoExt;


            if (pos != std::string::npos) {

                imageNameNoExt =
                        imageName.substr(
                                0,
                                pos
                        );

            } else {

                imageNameNoExt =
                        imageName;
            }


            auto assemblyFileName =
                    il2cpp_string_new(
                            imageNameNoExt.data()
                    );


            auto reflectionAssembly =
                    ((Assembly_Load_ftn)
                            assemblyLoad->methodPointer)(
                            nullptr,
                            assemblyFileName,
                            nullptr
                    );


            auto reflectionTypes =
                    ((Assembly_GetTypes_ftn)
                            assemblyGetTypes->methodPointer)(
                            reflectionAssembly,
                            nullptr
                    );


            if (!reflectionTypes) {
                continue;
            }


            auto items =
                    reflectionTypes->vector;


            for (int j = 0;
                 j < reflectionTypes->max_length;
                 ++j) {

                auto klass =
                        il2cpp_class_from_system_type(
                                (Il2CppReflectionType *)
                                items[j]
                        );


                if (!klass) {
                    continue;
                }


                auto type =
                        il2cpp_class_get_type(
                                klass
                        );


                if (!type) {
                    continue;
                }


                std::string output =
                        imageStr.str()
                        +
                        dump_type(
                                type
                        );


                outPuts.push_back(
                        std::move(output)
                );
            }
        }
    }


    /*
     * ========================================================
     * Write dump.cs
     * ========================================================
     */

    std::string outPath =
            std::string(outDir)
            + "/files/dump.cs";


    std::ofstream outStream(
            outPath,
            std::ios::out |
            std::ios::trunc
    );


    if (!outStream.is_open()) {

        LOGE(
                "Failed to open dump.cs: %s",
                outPath.c_str()
        );

        return;
    }


    outStream
            << imageOutput.str();


    for (const auto &output :
         outPuts) {

        outStream
                << output;
    }


    outStream.close();


    /*
     * ========================================================
     * Write script.json
     * ========================================================
     */

    write_script_json(
            outDir
    );


    /*
     * ========================================================
     * Done
     * ========================================================
     */

    LOGI(
            "dump done!"
    );


    LOGI(
            "classes: %zu",
            g_scriptClasses.size()
    );


    LOGI(
            "methods: %zu",
            g_scriptMethods.size()
    );
}
