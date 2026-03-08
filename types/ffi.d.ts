declare namespace CModuleFFI {
    /**
     * FFI 类型对象 - 表示 C 语言中的类型
     */
    class FfiType {
        /**
         * 创建结构体类型
         * @param types 成员类型数组
         * @example new FfiType(type_uint32, type_pointer) // 创建包含 uint32 和 pointer 的结构体
         */
        constructor(...types: FfiType[]);

        /**
         * 创建数组类型
         * @param count 数组元素数量
         * @param type 元素类型
         * @example new FfiType(10, type_uint8) // 创建 10 个 uint8 的数组
         */
        constructor(count: number, type: FfiType);

        /**
         * 将 JavaScript 值转换为 C 语言缓冲区
         * @param value 要转换的 JS 值（数字、bigint 或数组）
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

        // 预定义的类型实例（静态属性）
        static type_void: FfiType;
        static type_uint8: FfiType;
        static type_sint8: FfiType;
        static type_uint16: FfiType;
        static type_sint16: FfiType;
        static type_uint32: FfiType;
        static type_sint32: FfiType;
        static type_uint64: FfiType;
        static type_sint64: FfiType;
        static type_float: FfiType;
        static type_double: FfiType;
        static type_pointer: FfiType;
        static type_longdouble: FfiType;
        static type_uchar: FfiType;
        static type_schar: FfiType;
        static type_ushort: FfiType;
        static type_sshort: FfiType;
        static type_uint: FfiType;
        static type_sint: FfiType;
        static type_ulong: FfiType;
        static type_slong: FfiType;
        static type_size: FfiType;
        static type_ssize: FfiType;
        static type_ull: FfiType;
        static type_sll: FfiType;
    }

    /**
     * 符号指针对象 - 包装函数或变量地址
     */
    class UvDlSym {
        /** 获取原始指针地址（bigint） */
        readonly addr: bigint;
    }

    /**
     * FFI 调用接口对象 - 描述函数签名
     */
    class FfiCif {
        /**
         * 创建函数调用接口
         * @param retType 返回类型对象
         * @param argTypes 参数类型对象数组
         * @param fixedArgs 可变参数函数的固定参数数量（可选）
         * @example new FfiCif(type_void, [type_uint32, type_pointer]) // void func(int, void*)
         * @example new FfiCif(type_int, [type_int], 1) // int printf(const char*, ...)
         */
        constructor(retType: FfiType, argTypes: FfiType[], fixedArgs?: number);

        /**
         * 调用外部函数
         * @param func 要调用的函数（UvDlSym 对象，包含函数地址）
         * @param args 参数数组，可以是原始指针（bigint）或类型化缓冲区（Uint8Array）
         * @returns 包含返回值的 Uint8Array
         * @throws {TypeError} func 不是 UvDlSym 对象或参数数量不匹配
         * @throws {RangeError} 参数数组长度与函数签名不匹配
         */
        call(func: UvDlSym, ...args: (Uint8Array | bigint)[]): Uint8Array;
    }

    /**
     * 动态库对象 - 表示已加载的共享库
     */
    class UvLib {
        /**
         * 打开动态库
         * @param path 库文件路径（如 "libc.so.6", "libm.so"）
         * @returns 动态库对象
         * @throws {InternalError} 加载失败（文件不存在或格式错误）
         */
        constructor(path: string);

        /**
         * 获取符号（函数或变量）地址
         * @param name 符号名称（如 "printf", "sin"）
         * @returns 符号对象（包含地址信息）
         * @throws {InternalError} 符号查找失败
         */
        symbol(name: string): UvDlSym;
    }

    /** 
     * FFI 闭包对象 - 用于将 JS 函数暴露给 C 代码
     * @warning 闭包回调的参数 Buffer 仅在回调期间有效，禁止在回调外持有引用
     */
    class FfiClosure {
        /**
         * 创建可调用闭包（将 JS 函数暴露给 C 代码）
         * @param cif 函数接口描述
         * @param func JS 回调函数，接收 Uint8Array 参数，返回 Uint8Array
         * @warning 闭包创建后需手动管理生命周期，避免内存泄漏
         */
        constructor(cif: FfiCif, func: (...args: Uint8Array[]) => Uint8Array);

        /** 获取闭包的可调用地址 */
        readonly addr: bigint;
    }

    /**
     * FFI 模块接口
     */
    interface FFIModule {
        // 基本类型实例
        type_void: FfiType;
        type_uint8: FfiType;
        type_sint8: FfiType;
        type_uint16: FfiType;
        type_sint16: FfiType;
        type_uint32: FfiType;
        type_sint32: FfiType;
        type_uint64: FfiType;
        type_sint64: FfiType;
        type_float: FfiType;
        type_double: FfiType;
        type_pointer: FfiType;
        type_longdouble: FfiType;
        type_uchar: FfiType;
        type_schar: FfiType;
        type_ushort: FfiType;
        type_sshort: FfiType;
        type_uint: FfiType;
        type_sint: FfiType;
        type_ulong: FfiType;
        type_slong: FfiType;
        type_size: FfiType;
        type_ssize: FfiType;
        type_ull: FfiType;
        type_sll: FfiType;

        /** FFI 类型构造函数 */
        FfiType: typeof FfiType;

        /** FFI 调用接口构造函数 */
        FfiCif: typeof FfiCif;

        /** 动态库加载器 */
        UvLib: typeof UvLib;

        /** FFI 闭包构造函数 */
        FfiClosure: typeof FfiClosure;

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
        getArrayBufPtr(buffer: ArrayBuffer | Uint8Array): bigint;

        /**
         * 从 C 字符串指针读取字符串
         * @param ptr 指向 C 字符串的指针
         * @param maxLen 最大读取长度（防止读取超长字符串）
         */
        getCString(ptr: bigint, maxLen?: number): string;

        /**
         * 解引用指针（获取指针指向的地址）
         * @param ptr 指针地址
         * @param times 解引用次数（默认 1）
         */
        derefPtr(ptr: bigint, times?: number): bigint;

        /**
         * 将指针转换为 Uint8Array 视图
         * @warning ⚠️ **内存安全警告**：
         * - 返回的 Buffer 是**视图**，不拥有内存所有权
         * - 若指针指向的内存被释放，Buffer 将变为野指针
         * - **禁止**在指针所有者生命周期外持有此 Buffer
         * @param ptr 内存地址
         * @param size 缓冲区大小（字节）
         */
        ptrToBuffer(ptr: bigint, size: number): Uint8Array;

        /** 当前平台 C 标准库名称 */
        LIBC_NAME: string;

        /** 当前平台数学库名称 */
        LIBM_NAME: string;
    }

    /**
     * 加载本地 FFI 模块
     * @returns FFI 模块对象，包含所有 FFI 功能
     */
    function ffi_load_native(): FFIModule;
}