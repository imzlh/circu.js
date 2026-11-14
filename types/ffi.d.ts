/**
 * Foreign function interface.
 *
 * A signature is prepared once and the returned function can then be called
 * like an ordinary JavaScript function:
 *
 * @example
 * ```ts
 * const ffi = import.meta.use('ffi');
 * const t = ffi.types;
 *
 * using libc = ffi.open(ffi.libraries.c);
 * const strlen = libc.bind([t.usize, 'strlen', t.buffer]);
 * const length = strlen(new TextEncoder().encode('hello\0')); // bigint
 * ```
 */
declare namespace CModuleFFI {
    const pointerBrand: unique symbol;
    const typeTokenBrand: unique symbol;
    const boundFunctionBrand: unique symbol;

    /** An opaque, non-null native address. Use `unsafe.address()` to expose it. */
    export interface Pointer {
        readonly [pointerBrand]: never;
    }

    /** Binary data whose backing store can be passed to a synchronous call. */
    export type BufferSource = ArrayBuffer | ArrayBufferView;

    /** Values supported by aggregate type `pack()` and `unpack()`. */
    export type FfiValue = number | bigint | boolean | Pointer | null | readonly FfiValue[];

    export type TypeKind =
        | 'void'
        | 'boolean'
        | 'number'
        | 'bigint'
        | 'platform-integer'
        | 'pointer'
        | 'buffer'
        | 'function'
        | 'aggregate';

    /**
     * An immutable native type token. Tokens are created only by this module;
     * plain JavaScript objects are not valid type tokens at runtime.
     *
     * `TValue` is the value used when this type crosses the FFI call boundary.
     */
    export interface TypeToken<TValue = unknown, TKind extends TypeKind = TypeKind> {
        /** Native type name. */
        readonly name: string;

        /** ABI size in bytes. */
        readonly size: number;

        /** ABI alignment in bytes. */
        readonly alignment: number;

        readonly [typeTokenBrand]: {
            readonly value: TValue;
            readonly kind: TKind;
        };
    }

    export type VoidType = TypeToken<void, 'void'>;
    export type NumberType = TypeToken<number, 'number'>;
    export type BooleanType = TypeToken<boolean, 'boolean'>;
    export type BigIntType = TypeToken<bigint, 'bigint'>;
    export type PlatformIntegerType = TypeToken<number | bigint, 'platform-integer'>;
    export type PointerType = TypeToken<Pointer | null, 'pointer'>;
    export type BufferType = TypeToken<BufferSource | null, 'buffer'>;
    export type FunctionType = TypeToken<Pointer | null, 'function'>;

    /** A type valid as an FFI function parameter. C arrays are fields only. */
    export type ArgumentType =
        | TypeToken<unknown, Exclude<TypeKind, 'void' | 'aggregate'>>
        | StructType<any>;

    /** A type valid as an FFI function result. `buffer` and C arrays are excluded. */
    export type ResultType =
        | TypeToken<unknown, Exclude<TypeKind, 'buffer' | 'aggregate'>>
        | StructType<any>;

    /** A non-void type that can be read exactly from a static symbol. */
    export type ReadableType =
        | TypeToken<unknown, Exclude<TypeKind, 'void' | 'buffer' | 'aggregate'>>
        | StructType<any>
        | ArrayType<any, any>;

    /** A type valid as an aggregate field or array element. */
    export type FieldType = ReadableType;

    export type TypeValue<T extends TypeToken> =
        T extends TypeToken<infer TValue, TypeKind> ? TValue : never;

    export type PackedValue<T extends FieldType> =
        T extends AggregateType<infer TValue> ? TValue : TypeValue<T>;

    export type StructValue<TFields extends readonly FieldType[]> = {
        readonly [TIndex in keyof TFields]:
            TFields[TIndex] extends FieldType ? PackedValue<TFields[TIndex]> : never;
    };

    type ArrayValueTuple<
        TElement extends FieldType,
        TLength extends number,
        TAccumulator extends readonly unknown[] = [],
    > = TAccumulator['length'] extends TLength
        ? TAccumulator
        : TAccumulator['length'] extends 32
            ? readonly PackedValue<TElement>[]
            : ArrayValueTuple<TElement, TLength, readonly [...TAccumulator, PackedValue<TElement>]>;

    /**
     * Structured value of a fixed-size native array. Literal lengths up to 32
     * produce tuples; dynamic, invalid, or larger lengths safely fall back to
     * a readonly array and are validated by `types.array()` at runtime.
     */
    export type ArrayValue<TElement extends FieldType, TLength extends number> =
        number extends TLength
            ? readonly PackedValue<TElement>[]
            : TLength extends 0
                ? readonly PackedValue<TElement>[]
                : TLength extends TLength
                    ? ArrayValueTuple<TElement, TLength>
                    : never;

    type ArrayOffsetsTuple<
        TLength extends number,
        TAccumulator extends readonly number[] = [],
    > = TAccumulator['length'] extends TLength
        ? TAccumulator
        : TAccumulator['length'] extends 32
            ? readonly number[]
            : ArrayOffsetsTuple<TLength, readonly [...TAccumulator, number]>;

    /** ABI byte offsets of every element in a fixed-size native array. */
    export type ArrayOffsets<TLength extends number> =
        number extends TLength
            ? readonly number[]
            : TLength extends 0
                ? readonly number[]
                : TLength extends TLength
                    ? ArrayOffsetsTuple<TLength>
                    : never;

    /** A struct or fixed-size array descriptor. */
    export interface AggregateType<TValue = FfiValue>
        extends TypeToken<Uint8Array, 'aggregate'> {
        /** Encode one structured value into exactly `size` bytes. */
        readonly pack: (value: TValue) => Uint8Array;

        /** Decode exactly `size` bytes into its structured representation. */
        readonly unpack: (buffer: Uint8Array) => TValue;
    }

    export interface StructType<TFields extends readonly FieldType[] = readonly FieldType[]>
        extends AggregateType<StructValue<TFields>> {
        /** ABI byte offset for every field, in declaration order. */
        readonly offsets: {
            readonly [TIndex in keyof TFields]: number;
        };
    }

    export interface ArrayType<
        TElement extends FieldType = FieldType,
        TLength extends number = number,
    > extends AggregateType<ArrayValue<TElement, TLength>> {
        /** ABI byte offset for every element, in declaration order. */
        readonly offsets: ArrayOffsets<TLength>;
    }

    /** Frozen collection of primitive tokens and aggregate factories. */
    export interface Types {
        readonly void: VoidType;
        readonly bool: BooleanType;

        readonly i8: NumberType;
        readonly u8: NumberType;
        readonly i16: NumberType;
        readonly u16: NumberType;
        readonly i32: NumberType;
        readonly u32: NumberType;
        readonly i64: BigIntType;
        readonly u64: BigIntType;
        readonly f32: NumberType;
        readonly f64: NumberType;

        readonly pointer: PointerType;
        readonly buffer: BufferType;
        readonly function: FunctionType;

        readonly schar: NumberType;
        readonly uchar: NumberType;
        readonly short: NumberType;
        readonly ushort: NumberType;
        readonly int: NumberType;
        readonly uint: NumberType;
        /** `number` on 32-bit-long ABIs and `bigint` on 64-bit-long ABIs. */
        readonly long: PlatformIntegerType;
        /** `number` on 32-bit-long ABIs and `bigint` on 64-bit-long ABIs. */
        readonly ulong: PlatformIntegerType;
        readonly longLong: BigIntType;
        readonly ulongLong: BigIntType;
        readonly usize: BigIntType;
        readonly isize: BigIntType;
        readonly longDouble: NumberType;

        readonly struct: <const TFields extends readonly FieldType[]>(
            fields: TFields,
        ) => StructType<TFields>;

        readonly array: <const TElement extends FieldType, const TLength extends number>(
            element: TElement,
            count: TLength,
        ) => ArrayType<TElement, TLength>;
    }

    export const types: Types;

    export type FunctionSignature = readonly [result: ResultType, ...parameters: ArgumentType[]];
    export type LibrarySignature = readonly [result: ResultType, symbol: string, ...parameters: ArgumentType[]];

    export type SignatureArguments<TSignature extends FunctionSignature> =
        TSignature extends readonly [ResultType, ...infer TParameters]
            ? {
                [TIndex in keyof TParameters]:
                    TParameters[TIndex] extends ArgumentType ? TypeValue<TParameters[TIndex]> : never;
            }
            : never;

    export type CallbackArguments<TSignature extends FunctionSignature> =
        TSignature extends readonly [ResultType, ...infer TParameters]
            ? {
                [TIndex in keyof TParameters]: TParameters[TIndex] extends TypeToken<unknown, 'buffer'>
                    ? Pointer | null
                    : TParameters[TIndex] extends ArgumentType
                        ? TypeValue<TParameters[TIndex]>
                        : never;
            }
            : never;

    export type SignatureResult<TSignature extends FunctionSignature> = TypeValue<TSignature[0]>;

    export type FunctionSignatureOf<TSignature extends LibrarySignature> =
        TSignature extends readonly [infer TResult, string, ...infer TParameters]
            ? TResult extends ResultType
                ? TParameters extends ArgumentType[]
                    ? readonly [TResult, ...TParameters]
                    : never
                : never
            : never;

    /** Callable native function prepared from a signature. */
    export type BoundFunction<TSignature extends FunctionSignature = FunctionSignature> =
        ((...args: SignatureArguments<TSignature>) => SignatureResult<TSignature>) & {
            /** Address of the bound function. */
            readonly pointer: Pointer;

            readonly [boundFunctionBrand]: TSignature;
        };

    export interface BindOptions {
        /** Number of fixed parameters in a variadic signature. */
        readonly fixed?: number;
    }

    export interface Library extends Disposable {
        /** Prepare and bind an exported function. */
        bind<const TSignature extends LibrarySignature>(
            signature: TSignature,
            options?: BindOptions,
        ): BoundFunction<FunctionSignatureOf<TSignature>>;

        /** Resolve a function or variable without assigning a call signature. */
        symbol(name: string): Pointer;

        /** Read a typed value from an exported static symbol. */
        read<const TType extends ReadableType>(signature: readonly [type: TType, symbol: string]): TypeValue<TType>;

        /** Logically close the library. Repeated calls are safe. */
        close(): void;

        [Symbol.dispose](): void;
    }

    /** Open a dynamic library. */
    export function open(path: string): Library;

    /** Create a callable wrapper around an arbitrary function address. */
    function function_<const TSignature extends FunctionSignature>(
        pointer: Pointer,
        signature: TSignature,
        options?: BindOptions,
    ): BoundFunction<TSignature>;

    export { function_ as function };

    export interface Callback<TSignature extends FunctionSignature = FunctionSignature> extends Disposable {
        /** Address passed to native code. */
        readonly pointer: Pointer;

        /** Invalidate and release the callback. Repeated calls are safe. */
        close(): void;

        [Symbol.dispose](): void;
    }

    /**
     * Expose a synchronous JavaScript callback to native code.
     *
     * A `buffer` callback parameter is a pointer because native code provides
     * no length with which to reconstruct a `BufferSource`.
     *
     * The callback may only run on the thread where it was created. A call
     * from another thread does not enter JavaScript, returns the ABI zero
     * value, and is reported as an unsupported-thread error.
     */
    export function callback<
        const TSignature extends FunctionSignature,
        TCallback extends (...args: CallbackArguments<TSignature>) => SignatureResult<TSignature>,
    >(
        signature: TSignature,
        callback: TCallback & (
            Extract<ReturnType<TCallback>, PromiseLike<unknown>> extends never ? unknown : never
        ),
    ): Callback<TSignature>;

    /** A `void (void *)` function accepted as an owned-pointer disposer. */
    export type PointerDisposer = BoundFunction<readonly [VoidType, PointerType]>;

    /** Pointer with an attached native disposer. */
    export interface OwnedPointer extends Pointer, Disposable {
        /** Run the disposer exactly once. Repeated calls are safe. */
        close(): void;

        /** Detach the disposer and return the still-live raw pointer. */
        release(): Pointer;

        [Symbol.dispose](): void;
    }

    export interface Unsafe {
        /** Expose a pointer as a numeric address. */
        address(pointer: Pointer): bigint;

        /** Convert a numeric address to a pointer; zero becomes `null`. */
        fromAddress(address: bigint): Pointer | null;

        /** Borrow the start address of a buffer without copying it. */
        pointerOf(buffer: BufferSource): Pointer | null;

        /** Add a byte offset to a pointer. */
        offset(pointer: Pointer, bytes: number): Pointer | null;

        /** Follow a pointer value `count` times (once by default). */
        deref(pointer: Pointer, count?: number): Pointer | null;

        /** Create a non-owning view over foreign memory. */
        view(pointer: Pointer, length: number): Uint8Array;

        /** Read a NUL-terminated UTF-8 string from foreign memory. */
        readCString(pointer: Pointer, maxBytes?: number): string;

        /** Address of the current runtime thread's libuv event loop. */
        currentEventLoop(): Pointer;

        /** Attach an already-bound `void (void *)` disposer to a pointer. */
        adopt(pointer: Pointer, disposer: PointerDisposer): OwnedPointer;
    }

    export const unsafe: Unsafe;

    /** errno captured immediately after the most recent FFI call. */
    export function errno(): number;

    /** Convert an errno value to a platform error message. */
    export function strerror(errnum: number): string;

    export const libraries: {
        /** Platform C standard library loader name. */
        readonly c: string;

        /** Platform math library loader name. */
        readonly m: string;
    };
}
