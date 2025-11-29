declare namespace CModuleAlgorithm {
    /**
     * Unpacks a WebSocket message using the given key.
     * @param data The WebSocket message to unpack.
     * @param key The key to use for unpacking.
     * @returns The unpacked message.
     */
    export function ws_unpack(data: Uint8Array, key: Uint8Array): Uint8Array;

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
        next(): number;

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