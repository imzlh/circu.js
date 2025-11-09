declare namespace CModuleFFI {
    /**
     * FFI 类型枚举
     */
    const enum FfiType {
        /** void 类型 */
        VOID = 'void',
        /** 8位无符号整数 */
        UINT8 = 'uint8',
        /** 8位有符号整数 */
        SINT8 = 'sint8',
        /** 16位无符号整数 */
        UINT16 = 'uint16',
        /** 16位有符号整数 */
        SINT16 = 'sint16',
        /** 32位无符号整数 */
        UINT32 = 'uint32',
        /** 32位有符号整数 */
        SINT32 = 'sint32',
        /** 64位无符号整数 */
        UINT64 = 'uint64',
        /** 64位有符号整数 */
        SINT64 = 'sint64',
        /** 单精度浮点数 */
        FLOAT = 'float',
        /** 双精度浮点数 */
        DOUBLE = 'double',
        /** 指针类型 */
        POINTER = 'pointer',
        /** 长双精度浮点数 */
        LONGDOUBLE = 'longdouble',
        /** 无符号字符 */
        UCHAR = 'uchar',
        /** 有符号字符 */
        SCHAR = 'schar',
        /** 无符号短整型 */
        USHORT = 'ushort',
        /** 有符号短整型 */
        SSHORT = 'sshort',
        /** 无符号整型 */
        UINT = 'uint',
        /** 有符号整型 */
        SINT = 'sint',
        /** 无符号长整型 */
        ULONG = 'ulong',
        /** 有符号长整型 */
        SLONG = 'slong',
        /** 大小类型 */
        SIZE = 'size',
        /** 有符号大小类型 */
        SSIZE = 'ssize',
        /** 无符号长长整型 */
        ULL = 'ull',
        /** 有符号长长整型 */
        SLL = 'sll'
    }

    /**
     * FFI 类型对象
     */
    interface FfiTypeObject {
        /**
         * 将 JavaScript 值转换为缓冲区
         * @param value 要转换的值
         * @returns 返回包含转换后数据的 Uint8Array
         */
        toBuffer(value: any): Uint8Array;

        /**
         * 从缓冲区读取 JavaScript 值
         * @param buffer 包含数据的缓冲区
         * @returns 返回转换后的 JavaScript 值
         */
        fromBuffer(buffer: Uint8Array): any;

        /**
         * 获取类型名称
         */
        readonly name: string;

        /**
         * 获取类型大小（字节）
         */
        readonly size: number;
    }

    /**
     * FFI 调用接口对象
     */
    interface FfiCif {
        /**
         * 调用外部函数
         * @param func 要调用的函数指针
         * @param args 参数数组
         * @returns 返回包含结果的 Uint8Array
         */
        call(func: FfiPointer, args: (Uint8Array | FfiPointer)[]): Uint8Array;
    }

    /**
     * 动态库对象
     */
    interface UvLib {
        /**
         * 获取符号地址
         * @param name 符号名称
         * @returns 返回符号指针
         */
        symbol(name: string): FfiPointer;
    }

    /**
     * 符号指针对象
     */
    interface UvDlSym {
        /**
         * 获取指针地址
         */
        readonly addr: FfiPointer;
    }

    /**
     * FFI 闭包对象
     */
    interface FfiClosure {
        /**
         * 获取闭包地址
         */
        readonly addr: FfiPointer;
    }

    /**
     * 指针类型（表示为 bigint）
     */
    type FfiPointer = bigint;

    /**
     * 加载本地库
     * @returns 返回 FFI 模块对象
     */
    function ffi_load_native(): {
        /**
         * 基本类型
         */
        type_void: FfiTypeObject;
        type_uint8: FfiTypeObject;
        type_sint8: FfiTypeObject;
        type_uint16: FfiTypeObject;
        type_sint16: FfiTypeObject;
        type_uint32: FfiTypeObject;
        type_sint32: FfiTypeObject;
        type_uint64: FfiTypeObject;
        type_sint64: FfiTypeObject;
        type_float: FfiTypeObject;
        type_double: FfiTypeObject;
        type_pointer: FfiTypeObject;
        type_longdouble: FfiTypeObject;
        type_uchar: FfiTypeObject;
        type_schar: FfiTypeObject;
        type_ushort: FfiTypeObject;
        type_sshort: FfiTypeObject;
        type_uint: FfiTypeObject;
        type_sint: FfiTypeObject;
        type_ulong: FfiTypeObject;
        type_slong: FfiTypeObject;
        type_size: FfiTypeObject;
        type_ssize: FfiTypeObject;
        type_ull: FfiTypeObject;
        type_sll: FfiTypeObject;

        /**
         * 创建 FFI 类型
         */
        FfiType: {
            /**
             * 创建结构体类型
             * @param types 结构体成员类型数组
             * @returns 返回结构体类型对象
             */
            createStruct(types: FfiTypeObject[]): FfiTypeObject;

            /**
             * 创建数组类型
             * @param count 数组元素数量
             * @param type 数组元素类型
             * @returns 返回数组类型对象
             */
            createArray(count: number, type: FfiTypeObject): FfiTypeObject;
        };

        /**
         * 创建 FFI 调用接口
         */
        FfiCif: {
            /**
             * 创建调用接口
             * @param retType 返回类型
             * @param argTypes 参数类型数组
             * @param fixedArgs 固定参数数量（可选）
             * @returns 返回调用接口对象
             */
            new(retType: FfiTypeObject, argTypes: FfiTypeObject[], fixedArgs?: number): FfiCif;
        };

        /**
         * 加载动态库
         */
        UvLib: {
            /**
             * 打开动态库
             * @param path 库文件路径
             * @returns 返回动态库对象
             */
            new(path: string): UvLib;
        };

        /**
         * 创建 FFI 闭包
         */
        FfiClosure: {
            /**
             * 创建闭包
             * @param cif 调用接口
             * @param func JavaScript 回调函数
             * @returns 返回闭包对象
             */
            new(cif: FfiCif, func: (...args: any[]) => any): FfiClosure;
        };

        /**
         * 实用函数
         */
        utils: {
            /**
             * 获取当前错误码
             * @returns 返回错误码
             */
            errno(): number;

            /**
             * 获取错误描述
             * @param errnum 错误码
             * @returns 返回错误描述
             */
            strerror(errnum: number): string;

            /**
             * 获取 ArrayBuffer 指针
             * @param buffer 缓冲区
             * @returns 返回指针
             */
            getArrayBufPtr(buffer: ArrayBuffer | Uint8Array): FfiPointer;

            /**
             * 获取 C 字符串
             * @param ptr 字符串指针
             * @param maxLen 最大长度（可选）
             * @returns 返回字符串
             */
            getCString(ptr: FfiPointer, maxLen?: number): string;

            /**
             * 解引用指针
             * @param ptr 指针
             * @param times 解引用次数（默认1）
             * @returns 返回解引用后的指针
             */
            derefPtr(ptr: FfiPointer, times?: number): FfiPointer;

            /**
             * 将指针转换为缓冲区
             * @param ptr 指针
             * @param size 缓冲区大小
             * @returns 返回缓冲区
             */
            ptrToBuffer(ptr: FfiPointer, size: number): Uint8Array;
        };

        /**
         * 系统库名称
         */
        LIBC_NAME: string;
        LIBM_NAME: string;
    };

    // 导出 FFI 模块
    export const ffi: {
        /**
         * 加载本地 FFI 功能
         */
        loadNative(): ReturnType<typeof ffi_load_native>;
    };
}
