declare namespace CModuleFFI {
    /**
     * FFI 类型枚举（仅用于类型提示，实际使用 FfiTypeObject 实例）
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
     * FFI 类型对象 - 表示C语言中的类型
     */
    interface FfiTypeObject {
        /**
         * 将 JavaScript 值转换为 C 语言缓冲区
         * @param value 要转换的 JS 值（数字、bigint或数组）
         * @returns 包含转换后数据的 Uint8Array
         */
        toBuffer(value: any): Uint8Array;

        /**
         * 从 C 语言缓冲区读取 JavaScript 值
         * @param buffer 包含数据的 Uint8Array
         * @returns 转换后的 JS 值
         */
        fromBuffer(buffer: Uint8Array): any;

        /** 类型名称（如 "uint32", "pointer"） */
        readonly name: string;

        /** 类型大小（字节） */
        readonly size: number;
    }

    /**
     * FFI 调用接口对象 - 描述函数签名
     */
    interface FfiCif {
        /**
         * 调用外部函数
         * @param func 要调用的函数（UvDlSym对象，包含函数地址）
         * @param args 参数数组，可以是原始指针（bigint）或类型化缓冲区（Uint8Array）
         * @returns 包含返回值的 Uint8Array
         * @throws {TypeError} func不是UvDlSym对象或参数数量不匹配
         * @throws {RangeError} 参数数组长度与函数签名不匹配
         */
        call(func: UvDlSym, args: (Uint8Array | FfiPointer)[]): Uint8Array;
    }

    /**
     * 动态库对象 - 表示已加载的共享库
     */
    interface UvLib {
        /**
         * 获取符号（函数或变量）地址
         * @param name 符号名称（如 "printf", "sin"）
         * @returns 符号对象（包含地址信息）
         * @throws {InternalError} 符号查找失败
         */
        symbol(name: string): UvDlSym;
    }

    /**
     * 符号指针对象 - 包装函数或变量地址
     */
    interface UvDlSym {
        /** 获取原始指针地址（bigint） */
        readonly addr: FfiPointer;
    }

    /**
     * FFI 闭包对象 - 用于将 JS 函数暴露给 C 代码
     * @warning 闭包回调的参数Buffer仅在回调期间有效，禁止在回调外持有引用
     */
    interface FfiClosure {
        /** 获取闭包的可调用地址 */
        readonly addr: FfiPointer;
    }

    /** 
     * 指针类型 - 在 JS 中以 bigint 表示内存地址
     * @example 0x7fff12345678n
     */
    type FfiPointer = bigint;

    /**
     * FFI 闭包回调函数签名
     * @param args C函数传递的参数，每个参数都是Uint8Array视图
     * @returns 必须是Uint8Array，表示返回值缓冲区
     */
    type FfiClosureCallback = (...args: Uint8Array[]) => Uint8Array;

    /**
     * 加载本地FFI模块
     * @returns FFI 模块对象，包含所有FFI功能
     */
    function ffi_load_native(): {
        // 基本类型实例
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
         * FFI 类型构造函数
         * @overload 创建结构体类型: new FfiType(...memberTypes: FfiTypeObject[])
         * @overload 创建数组类型: new FfiType(count: number, elementType: FfiTypeObject)
         */
        FfiType: {
            new(...types: FfiTypeObject[]): FfiTypeObject;
            new(count: number, type: FfiTypeObject): FfiTypeObject;
        };

        /** FFI 调用接口构造函数 */
        FfiCif: {
            /**
             * 创建函数调用接口
             * @param retType 返回类型对象
             * @param argTypes 参数类型对象数组
             * @param fixedArgs 可变参数函数的固定参数数量（可选）
             * @example new FfiCif(type_void, [type_int, type_pointer]) // void func(int, void*)
             * @example new FfiCif(type_int, [type_int], 1) // int printf(const char*, ...)
             */
            new(retType: FfiTypeObject, argTypes: FfiTypeObject[], fixedArgs?: number): FfiCif;
        };

        /** 动态库加载器 */
        UvLib: {
            /**
             * 打开动态库
             * @param path 库文件路径（如 "libc.so.6", "libm.so"）
             * @returns 动态库对象
             * @throws {InternalError} 加载失败（文件不存在或格式错误）
             */
            new(path: string): UvLib;
        };

        /** FFI 闭包构造函数 */
        FfiClosure: {
            /**
             * 创建可调用闭包（将JS函数暴露给C代码）
             * @param cif 函数接口描述
             * @param func JS回调函数，接收Uint8Array参数，返回Uint8Array
             * @warning 闭包创建后需手动管理生命周期，避免内存泄漏
             */
            new(cif: FfiCif, func: FfiClosureCallback): FfiClosure;
        };

        /** 实用工具函数 */
        utils: {
            /** 获取当前线程的错误码（errno） */
            errno(): number;

            /**
             * 获取错误码描述字符串
             * @param errnum 错误码（如 errno() 的返回值）
             */
            strerror(errnum: number): string;

            /**
             * 获取 ArrayBuffer/Uint8Array 的内存指针
             * @param buffer 类型化数组
             * @returns 指向数组底层内存的指针
             */
            getArrayBufPtr(buffer: ArrayBuffer | Uint8Array): FfiPointer;

            /**
             * 从C字符串指针读取字符串
             * @param ptr 指向C字符串的指针
             * @param maxLen 最大读取长度（防止读取超长字符串）
             */
            getCString(ptr: FfiPointer, maxLen?: number): string;

            /**
             * 解引用指针（获取指针指向的地址）
             * @param ptr 指针地址
             * @param times 解引用次数（默认1）
             */
            derefPtr(ptr: FfiPointer, times?: number): FfiPointer;

            /**
             * 将指针转换为 Uint8Array 视图
             * @warning ⚠️ **内存安全警告**：
             * - 返回的Buffer是**视图**，不拥有内存所有权
             * - 若指针指向的内存被释放，Buffer将变为野指针
             * - **禁止**在指针所有者生命周期外持有此Buffer
             * @param ptr 内存地址
             * @param size 缓冲区大小（字节）
             */
            ptrToBuffer(ptr: FfiPointer, size: number): Uint8Array;
        };

        /** 当前平台C标准库名称 */
        LIBC_NAME: string;
        /** 当前平台数学库名称 */
        LIBM_NAME: string;
    };

    /** FFI模块入口 */
    export const ffi: {
        /** 加载本地FFI功能，返回模块对象 */
        loadNative(): ReturnType<typeof ffi_load_native>;
    };
}