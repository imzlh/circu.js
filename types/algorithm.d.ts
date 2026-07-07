/**
 * Algorithm module - C-implemented algorithms for performance
 * Provides WebSocket masking, FNV/xxHash/MurmurHash, and Xoshiro RNG
 */
declare namespace CModuleAlgorithm {
    /**
     * Applies or removes a WebSocket masking key.
     * XOR is symmetric, so masking and unmasking use the same operation.
     * @param data The data to mask/unmask.
     * @param key The 4-byte masking key.
     * @returns The masked/unmasked data.
     */
    export function wsMask(data: Uint8Array, key: Uint8Array): Uint8Array;

    /**
     * Applies or removes a WebSocket masking key into an existing output buffer.
     * @param data The data to mask/unmask.
     * @param key The 4-byte masking key.
     * @param output The buffer that receives the masked/unmasked bytes.
     * @param outputOffset The byte offset in output. Defaults to 0.
     * @returns The output buffer.
     */
    export function wsMaskInto(
        data: Uint8Array,
        key: Uint8Array,
        output: Uint8Array,
        outputOffset?: number,
    ): Uint8Array;

    /**
     * Compares two byte arrays lexicographically.
     * @returns -1 if a < b, 1 if a > b, otherwise 0.
     */
    export function bytesCompare(a: Uint8Array, b: Uint8Array): -1 | 0 | 1;

    /**
     * Checks whether two byte arrays are equal without early exit.
     */
    export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;

    /**
     * Checks whether all bytes are in the 7-bit ASCII range.
     */
    export function bytesIsAscii(data: Uint8Array): boolean;

    /**
     * Checks whether bytes are valid UTF-8.
     */
    export function bytesIsUtf8(data: Uint8Array): boolean;

    /**
     * Inverts all bytes in place.
     */
    export function bytesInvert(data: Uint8Array): Uint8Array;

    /**
     * Reverses bytes in place.
     */
    export function bytesReverse(data: Uint8Array): Uint8Array;

    /**
     * Decodes base64/base64url with Node Buffer-compatible loose parsing.
     */
    export function base64DecodeLoose(data: string): Uint8Array;

    /**
     * Encodes bytes as unpadded base64url.
     */
    export function base64UrlEncode(data: Uint8Array): string;

    /**
     * Encodes flat source-map segment tuples as mappings.
     * Input layout is repeated [line, generatedColumn, sourceLine, sourceColumn].
     */
    export function sourceMapMappingsEncode(segments: Int32Array, valueCount?: number): string;

    /**
     * Copies array-like numeric values into bytes using value & 0xff.
     */
    export function bytesFromArrayLike(data: ArrayLike<number>): Uint8Array;

    /**
     * Decodes hex with Node Buffer-compatible loose parsing.
     */
    export function hexDecodeLoose(data: string): Uint8Array;

    /**
     * Encodes string code units to bytes using c & 0x7f.
     */
    export function asciiEncodeLoose(data: string): Uint8Array;

    /**
     * Encodes string code units to bytes using c & 0xff.
     */
    export function latin1EncodeLoose(data: string): Uint8Array;

    /**
     * Encodes string code units to bytes, replacing values >= 0x80 with '?'.
     */
    export function asciiEncodeReplace(data: string): Uint8Array;

    /**
     * Encodes string code units to bytes, replacing values >= 0x100 with '?'.
     */
    export function latin1EncodeReplace(data: string): Uint8Array;

    /**
     * Decodes bytes to a string using b & 0x7f.
     */
    export function asciiDecodeLoose(data: Uint8Array): string;

    /**
     * Decodes bytes to a string using one Unicode code point per byte.
     */
    export function latin1DecodeLoose(data: Uint8Array): string;

    /**
     * Concatenates byte chunks into a new Uint8Array.
     */
    export function bytesConcat(chunks: readonly Uint8Array[]): Uint8Array;

    /**
     * Repeats pattern bytes into target from start up to end.
     */
    export function bytesRepeatInto(
        target: Uint8Array,
        pattern: Uint8Array,
        start?: number,
        end?: number,
    ): Uint8Array;

    /**
     * Swaps each 16-bit lane in place.
     * Throws RangeError unless the byte length is a multiple of 2.
     */
    export function bytesSwap16(data: Uint8Array): Uint8Array;

    /**
     * Swaps each 32-bit lane in place.
     * Throws RangeError unless the byte length is a multiple of 4.
     */
    export function bytesSwap32(data: Uint8Array): Uint8Array;

    /**
     * Swaps each 64-bit lane in place.
     * Throws RangeError unless the byte length is a multiple of 8.
     */
    export function bytesSwap64(data: Uint8Array): Uint8Array;

    /**
     * Finds the first occurrence of needle in haystack at or after offset.
     * @returns The byte index, or -1 when not found.
     */
    export function bytesIndexOf(
        haystack: Uint8Array,
        needle: Uint8Array | number,
        offset?: number,
    ): number;

    /**
     * Finds the last occurrence of needle in haystack at or before offset.
     * @returns The byte index, or -1 when not found.
     */
    export function bytesLastIndexOf(
        haystack: Uint8Array,
        needle: Uint8Array | number,
        offset?: number,
    ): number;

    /**
     * Computes the FNV-1a 32-bit hash of the given data.
     * @param data The data to hash.
     * @returns The 32-bit hash value.
     */
    export function fnv1a32(data: Uint8Array): number;

    /**
     * Computes the FNV-1a 64-bit hash of the given data.
     * @param data The data to hash.
     * @returns The 64-bit hash value as a BigInt.
     */
    export function fnv1a64(data: Uint8Array): bigint;

    /**
     * Computes the MurmurHash3 32-bit hash of the given data.
     * @param data The data to hash.
     * @param seed The seed value. Defaults to 0.
     * @returns The 32-bit hash value.
     */
    export function murmur3(data: Uint8Array, seed?: number): number;

    /**
     * Computes the xxHash32 hash of the given data.
     * @param data The data to hash.
     * @param seed The seed value. Defaults to 0.
     * @returns The 32-bit hash value.
     */
    export function xxHash32(data: Uint8Array, seed?: number): number;

    /**
     * A class for generating random numbers using the Xoshiro256++ algorithm.
     */
    export class XoshiroRNG {
        /**
         * Creates a new XoshiroRNG instance.
         * @param seed The seed to use for initializing the RNG. If not provided, a random seed will be generated.
         */
        constructor(seed?: number | number[]);

        /**
         * Generates the next random number in the sequence.
         * @returns The next random number in the sequence.
         */
        next(): bigint;

        /**
         * Generates the next random double in the sequence.
         * @returns The next random double in the sequence.
         */
        nextDouble(): number;

        /**
         * Jumps the RNG sequence
         */
        jump(): void;

        /**
         * Long jumps the RNG sequence
         */
        longJump(): void;

        /**
         * Clones the RNG instance.
         * @returns A new XoshiroRNG instance with the same state as the current instance.
         */
        clone(): XoshiroRNG;
    }
}
