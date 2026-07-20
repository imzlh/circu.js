/**
 * Brotli compression/decompression module for circu.js
 *
 * Available when the runtime is built against system libbrotli
 * (`CJS_HAVE_BROTLI`). Check `available` at runtime.
 *
 * @example  One-shot round trip
 * ```typescript
 * const brotli = import.meta.use('brotli')
 *
 * const data = import.meta.use('engine').encodeString('Hello, World!'.repeat(100));
 * const compressed = brotli.compress(data, { quality: 11, mode: brotli.MODE_TEXT });
 * const original = brotli.decompress(compressed);
 * ```
 * @example  Streaming
 * ```typescript
 * const brotli = import.meta.use('brotli')
 *
 * const enc = brotli.createCompress({ quality: 9 });
 * const head = enc.compress(chunk1);
 * const tail = enc.finish(chunk2);
 * ```
 */
declare namespace CModuleBrotli {
    type BufferSource = ArrayBuffer | ArrayBufferView;

    /** Encoder mode: matches BROTLI_MODE_* */
    type BrotliMode = number;
    /** Stream operation: matches BROTLI_OPERATION_* */
    type BrotliOperation = number;

    /** Options for compression (one-shot and streaming) */
    interface CompressOptions {
        /** Compression quality 0..11 (default 11) */
        quality?: number;
        /** Window size in bits, 10..24 (30 with largeWindow) */
        lgwin?: number;
        /** Content mode: MODE_GENERIC / MODE_TEXT / MODE_FONT */
        mode?: BrotliMode;
        /** Input block size in bits, 16..24, or 0 for encoder default */
        lgblock?: number;
        /** Expected input size; improves ratio. One-shot auto-fills from input. */
        sizeHint?: number;
        /** Enable the large-window (up to 30-bit) format extension */
        largeWindow?: boolean;
    }

    /** Options for decompression */
    interface DecompressOptions {
        /** Accept the large-window format extension */
        largeWindow?: boolean;
    }

    /** Streaming Brotli encoder */
    interface BrotliCompress {
        /** Feed data, returning any compressed bytes produced so far */
        compress(data?: BufferSource): Uint8Array;
        /** Flush buffered output; the result is a decodable prefix */
        flush(): Uint8Array;
        /** Finish the stream, emitting the final bytes */
        finish(data?: BufferSource): Uint8Array;
        /** Total bytes fed in */
        getTotalIn(): number;
        /** Total compressed bytes produced */
        getTotalOut(): number;
    }

    /** Streaming Brotli decoder */
    interface BrotliDecompress {
        /** Feed compressed data, returning any decoded bytes produced so far */
        decompress(data: BufferSource): Uint8Array;
        /** Finish and reject a truncated compressed stream. */
        finish(): Uint8Array;
        /** Total compressed bytes consumed */
        getTotalIn(): number;
        /** Total decoded bytes produced */
        getTotalOut(): number;
    }

    /** True when built with libbrotli (always true in this module namespace) */
    export const available: boolean;
    /** libbrotli version string, e.g. "1.1.0" */
    export const version: string;

    /**
     * Compress data with Brotli.
     * @param data - Input data
     * @param options - Quality number (shorthand) or an options object
     */
    export function compress(data: BufferSource, options?: number | CompressOptions): Uint8Array;

    /**
     * Decompress Brotli-compressed data (max 256MB output).
     * @param data - Compressed input
     */
    export function decompress(data: BufferSource, options?: DecompressOptions): Uint8Array;

    /** Create a streaming encoder */
    export function createCompress(options?: number | CompressOptions): BrotliCompress;

    /** Create a streaming decoder */
    export function createDecompress(options?: DecompressOptions): BrotliDecompress;

    /** Upper bound on the compressed size of `length` input bytes */
    export function maxCompressedSize(length: number): number;

    // Quality
    export const MIN_QUALITY: number;
    export const MAX_QUALITY: number;
    export const DEFAULT_QUALITY: number;

    // Window bits
    export const MIN_WINDOW_BITS: number;
    export const MAX_WINDOW_BITS: number;
    export const LARGE_MAX_WINDOW_BITS: number;
    export const DEFAULT_WINDOW: number;

    // Input block bits (lgblock)
    export const MIN_INPUT_BLOCK_BITS: number;
    export const MAX_INPUT_BLOCK_BITS: number;

    // Mode
    export const MODE_GENERIC: BrotliMode;
    export const MODE_TEXT: BrotliMode;
    export const MODE_FONT: BrotliMode;

    // Stream operations
    export const OPERATION_PROCESS: BrotliOperation;
    export const OPERATION_FLUSH: BrotliOperation;
    export const OPERATION_FINISH: BrotliOperation;
}
