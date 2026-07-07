declare namespace CModuleBJSON {
    /**
     * Encode a JS value into stable CNOBJSON v1 bytes.
     */
    export function encode(value: unknown): Uint8Array;

    /**
     * Decode bytes produced by encode().
     */
    export function decode<T = unknown>(bytes: Uint8Array | ArrayBufferLike): T;
}
