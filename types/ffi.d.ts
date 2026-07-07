/**
 * FFI (Foreign Function Interface) module - Call C functions from JavaScript
 * 
 * @example
 * ```typescript
 * const ffi = import.meta.use('ffi');
 * const { Encoder } = import.meta.use('text');
 * 
 * // Load libc and call puts(char*)
 * const libc = new ffi.UvLib(ffi.LIBC_NAME);
 * const puts = libc.symbol('puts');
 * 
 * const cif = new ffi.FfiCif(ffi.type_sint, ffi.type_pointer);
 * const msg = new Encoder().encode('Hello!\0');
 * cif.call(puts, ffi.getArrayBufPtr(msg));
 * ```
 */
declare namespace CModuleFFI {
    export type Pointer = bigint;
    export type FfiPrimitiveValue = number | bigint | null;
    export type FfiValue = FfiPrimitiveValue | FfiValue[];

    /**
     * FFI type descriptor for a C type.
     */
    export class FfiType {
        /**
         * Create a struct type.
         * @param types Field type descriptors
         * @example new FfiType(type_uint32, type_pointer) // struct { uint32_t; void*; }
         */
        constructor(...types: FfiType[]);

        /**
         * Create an array type.
         * @param count Element count
         * @param type Element type descriptor
         * @example new FfiType(10, type_uint8) // uint8_t[10]
         */
        constructor(count: number, type: FfiType);

        /**
         * Pack a JavaScript value into a C value buffer.
         * @param value JS value to pack: number, bigint, null pointer, or nested array
         * @returns Bytes with exactly this FFI type's size
         */
        toBuffer(value: FfiValue): Uint8Array;

        /**
         * Unpack a C value buffer into a JavaScript value.
         *
         * Struct and array types cannot currently be unpacked and throw.
         * @param buffer Bytes containing one value of this type
         * @returns Unpacked JS value
         */
        fromBuffer(buffer: Uint8Array): FfiPrimitiveValue | undefined;

        /** Type name, such as "uint32" or "pointer". */
        readonly name: string;

        /** Type size in bytes. */
        readonly size: number;

        /** Struct field offsets. Present only on dynamic struct types. */
        readonly offsets?: number[];

    }

    /**
     * Symbol pointer returned from a dynamic library lookup.
     */
    export class UvDlSym {
        /** Raw symbol address. */
        readonly addr: Pointer;
    }

    /**
     * Prepared FFI call interface.
     */
    export class FfiCif {
        /**
         * Create a function call interface.
         * @param retType Return type descriptor
         * @param argTypes Argument type descriptors
         * @param fixedArgs Fixed argument count for variadic functions
         * @example new FfiCif(type_void, type_uint32, type_pointer) // void func(int, void*)
         * @example new FfiCif(type_int, type_int, 1) // int printf(const char*, ...)
         */
        constructor(retType: FfiType, ...argTypes: FfiType[]);
        constructor(retType: FfiType, ...argTypesAndFixed: [...FfiType[], number | undefined]);

        /**
         * Call an external function.
         * @param func Function symbol to call
         * @param args Raw pointer values or Uint8Array buffers packed for each argument type
         * @returns Raw return bytes; decode with the return type's fromBuffer()
         * @throws {TypeError} `func` is not a UvDlSym object or the argument count is wrong
         * @throws {RangeError} Argument buffer size does not match the function signature
         */
        call(func: UvDlSym, ...args: (Uint8Array | Pointer)[]): Uint8Array;
    }

    /**
     * Loaded shared library.
     */
    export class UvLib {
        /**
         * Open a shared library.
         * @param path Library path or loader name, such as "libc.so.6" or "libm.so"
         * @throws {InternalError} Loading failed
         */
        constructor(path: string);

        /**
         * Look up a function or variable symbol.
         * @param name Symbol name, such as "puts" or "sin"
         * @returns Symbol address wrapper
         * @throws {InternalError} Symbol lookup failed
         */
        symbol(name: string): UvDlSym;
    }

    /** 
     * FFI closure that exposes a JavaScript callback to C code.
     *
     * Callback arguments are copied ArrayBuffers. The return value must be a
     * Uint8Array whose length exactly matches the configured return type size.
     * Keep the FfiClosure object alive for as long as C may call `addr`; when
     * this object is collected, the closure address is released too.
     */
    export class FfiClosure {
        /**
         * Create a callable closure.
         * @param cif Function interface descriptor
         * @param func JS callback; receives copied ArrayBuffer arguments and returns raw return bytes
         * @warning Manage the closure lifetime manually. C must not call `addr` after this object is collected.
         */
        constructor(cif: FfiCif, func: (...args: ArrayBuffer[]) => Uint8Array);

        /** Callable closure address. */
        readonly addr: Pointer;
    }

    // Primitive type descriptors.
    export const type_void: FfiType;
    export const type_uint8: FfiType;
    export const type_sint8: FfiType;
    export const type_uint16: FfiType;
    export const type_sint16: FfiType;
    export const type_uint32: FfiType;
    export const type_sint32: FfiType;
    export const type_uint64: FfiType;
    export const type_sint64: FfiType;
    export const type_float: FfiType;
    export const type_double: FfiType;
    export const type_pointer: FfiType;
    export const type_longdouble: FfiType;
    export const type_uchar: FfiType;
    export const type_schar: FfiType;
    export const type_ushort: FfiType;
    export const type_sshort: FfiType;
    export const type_uint: FfiType;
    export const type_sint: FfiType;
    export const type_ulong: FfiType;
    export const type_slong: FfiType;
    export const type_size: FfiType;
    export const type_ssize: FfiType;
    export const type_ull: FfiType;
    export const type_sll: FfiType;

    /** Get the current thread errno. */
    export function errno(): number;

    /**
     * Convert an errno value to a platform error message.
     * @param errnum Error number, such as the value returned by errno()
     */
    export function strerror(errnum: number): string;

    /**
     * Get a pointer to a Uint8Array's backing memory.
     * @param buffer Typed array whose backing memory must stay alive
     * @returns Pointer to the typed array data
     */
    export function getArrayBufPtr(buffer: Uint8Array): Pointer;

    /**
     * Read a NUL-terminated C string.
     * @param ptr Pointer to a C string
     * @param maxLen Maximum number of bytes to scan
     */
    export function getCString(ptr: Pointer, maxLen?: number): string;

    /**
     * Dereference a pointer value one or more times.
     * @param ptr Pointer address
     * @param times Dereference count, defaults to 1
     */
    export function derefPtr(ptr: Pointer, times?: number): Pointer;

    /**
     * Create a Uint8Array view over foreign memory.
     *
     * @warning The returned Uint8Array does not own the memory. If the pointed
     * memory is freed or mutated by C, the view immediately reflects that
     * state. Do not keep this view beyond the owner's lifetime.
     *
     * @param ptr Memory address
     * @param size Buffer size in bytes
     */
    export function ptrToBuffer(ptr: Pointer, size: number): Uint8Array;

    /** Platform C standard library name. */
    export const LIBC_NAME: string;

    /** Platform math library name. */
    export const LIBM_NAME: string;
}
