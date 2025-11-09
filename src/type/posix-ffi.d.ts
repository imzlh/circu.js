declare namespace CModulePosixFFI {
    // Please note this numbers is not real.
    // It is only used for type checking.
    type _AUTO = 0;
    type _VOID = 1;
    type _INT = 2;
    type _FLOAT = 3;
    type _DOUBLE = 4;
    type _LONGDOUBLE = 5;
    type _UINT8 = 6;
    type _SINT8 = 7;
    type _UINT16 = 8;
    type _SINT16 = 9;
    type _UINT32 = 10;
    type _SINT32 = 11;
    type _UINT64 = 12;
    type _SINT64 = 13;
    type _POINTER = 14;
    type _R_PTR = 15;
    type _RM_STRING = 16;
    type _RM_BUFFER_MALLOC = 17;
    type _RM_BUFFER_FROM_ARG = 18;

    interface CTypes {
        AUTO: _AUTO;
        VOID: _VOID;
        INT: _INT;
        FLOAT: _FLOAT;
        DOUBLE: _DOUBLE;
        LONGDOUBLE: _LONGDOUBLE;
        UINT8: _UINT8;
        SINT8: _SINT8;
        UINT16: _UINT16;
        SINT16: _SINT16;
        UINT32: _UINT32;
        SINT32: _SINT32;
        UINT64: _UINT64;
        SINT64: _SINT64;
        POINTER: _R_PTR;

        // 注意： 如果需要释放C函数内malloc的内存使用R_PTR("free")，传入的ArrayBuffer/TypedArray则需要使用R_PTR("jsfree")
        R_STRING: _RM_STRING;
        R_BUFFER_MALLOC: _RM_BUFFER_MALLOC;
        R_BUFFER_FROM_ARG: _RM_BUFFER_FROM_ARG;
        PTR: (flag?: "free" | "jsfree" | undefined) => _R_PTR;
    }

    type CTypesVal = _AUTO | _VOID | _INT | _FLOAT | _DOUBLE | _LONGDOUBLE | _UINT8 | _SINT8 | _UINT16 | _SINT16 | _UINT32 | _SINT32 | _UINT64 | _SINT64 | _POINTER | _R_PTR;

    type InferFrom<T extends CTypesVal> =
        T extends _AUTO ? any :
        T extends _VOID ? void :
        T extends _INT ? number :
        T extends _FLOAT ? number :
        T extends _DOUBLE ? number :
        T extends _LONGDOUBLE ? number :
        T extends _UINT8 ? number :
        T extends _SINT8 ? number :
        T extends _UINT16 ? number :
        T extends _SINT16 ? number :
        T extends _UINT32 ? number :
        T extends _SINT32 ? number :
        T extends _UINT64 ? bigint :
        T extends _SINT64 ? number :
        T extends _POINTER ? number :
        T extends _R_PTR ? (length: number, shared?: boolean) => ArrayBuffer :
        never;

    type InferTuple<T extends any[]> = {
        [K in keyof T]: InferFrom<T[K]>;
    };

    type Handler = <R extends CTypesVal, P extends (CTypesVal)[], T extends [R, string, ...P]>(this: T, ...args: InferTuple<P>) => InferFrom<R>

    export interface DLHandler extends Handler {
        /**
         * 推荐做法：绑定类型和函数名，方便后续调用。自动类型推导，减少类型定义。
         */
        bind<R extends CTypesVal, P extends CTypesVal[]>(
            thisArg: [R, string, ...P]
        ): (...args: InferTuple<P>) => InferFrom<R>;
    }

    /**
     * 打开一个动态库，通常是.so文件<br>
     *  - LightJS的ffi不支持类型缓存，对于传入变量较多的函数注意性能损耗！
     *  - 如果你不明白/不熟悉何为C指针，千万不要使用`types.POINTER`作为返回值
     *    LightJS需要你手动指定POINTER目标内存空间大小和如何处理这片空间
     * 
     * @example - 打开一个动态库
     * ```typescript
     * const lib = ffi.dlopen("./libtest.so");  // 返回一个JS函数
     * // 绑定thisArg，第一个参数是返回值类型，第二个参数是函数名，后面是参数类型
     * const add = lib.bind([types.INT, "test_add", types.INT, types.INT]);
     * add(1, 2);  // 调用动态库的test_add函数，传入参数1和2，返回3
     * // 同样的，使用指针则需要额外处理，防止资源泄漏(小心！)
     * const malloc = lib.bind([types.PTR("free"), "test_malloc", types.INT]);
     * malloc(10); // 调用动态库的test_malloc函数，传入参数10，返回一个ArrayBuffer
     * // 当lib变量被回收时，自动释放资源
     * ```
     * @param path 动态库的路径
     */
    export function dlopen(path: string): DLHandler;
    export const types: CTypes;
}