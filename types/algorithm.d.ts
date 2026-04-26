declare namespace CModuleAlgorithm {
    /**
     * Applies or removes a WebSocket masking key.
     * XOR is symmetric, so masking and unmasking use the same operation.
     * @param data The data to mask/unmask.
     * @param key The 4-byte masking key.
     * @returns The masked/unmasked data.
     */
    export function ws_mask(data: Uint8Array<ArrayBuffer>, key: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer>;

    /**
     * Computes the FNV-1a 32-bit hash of the given data.
     * @param data The data to hash.
     * @returns The 32-bit hash value.
     */
    export function fnv1a32(data: Uint8Array<ArrayBuffer>): number;

    /**
     * Computes the FNV-1a 64-bit hash of the given data.
     * @param data The data to hash.
     * @returns The 64-bit hash value as a BigInt.
     */
    export function fnv1a64(data: Uint8Array<ArrayBuffer>): bigint;

    /**
     * Computes the MurmurHash3 32-bit hash of the given data.
     * @param data The data to hash.
     * @param seed The seed value. Defaults to 0.
     * @returns The 32-bit hash value.
     */
    export function murmur3(data: Uint8Array<ArrayBuffer>, seed?: number): number;

    /**
     * Computes the xxHash32 hash of the given data.
     * @param data The data to hash.
     * @param seed The seed value. Defaults to 0.
     * @returns The 32-bit hash value.
     */
    export function xxhash32(data: Uint8Array<ArrayBuffer>, seed?: number): number;

    /**
     * A class for generating random numbers using the Xoshiro256** algorithm.
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
        next(): number | bigint;

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