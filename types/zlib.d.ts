/**
 * ZLib compression/decompression module for circu.js
 * 
 * @example  Simple compression and decompression
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const original = import.meta.use('engine').encodeString('Hello, World!'.repeat(100));
 * 
 * // Compress
 * const compressed = zlib.deflate(original);
 * console.log(`Original: ${original.length} bytes`);
 * console.log(`Compressed: ${compressed.byteLength} bytes`);
 * 
 * // Decompress
 * const decompressed = zlib.inflate(compressed);
 * const text = import.meta.use('engine').decodeString(decompressed);
 * ```
 * @example  GZIP compression
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const data = import.meta.use('engine').encodeString('Large data...');
 * 
 * // Compress with gzip (includes header/footer)
 * const gzipped = zlib.gzip(data, zlib.BEST_COMPRESSION);
 * 
 * // Decompress
 * const ungzipped = zlib.gunzip(gzipped);
 * ```
 * @example  Streaming compression
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const deflate = zlib.createDeflate(zlib.BEST_SPEED);
 * 
 * // Process data in chunks
 * const chunk1 = deflate.deflate(new Uint8Array([1, 2, 3]));
 * const chunk2 = deflate.deflate(new Uint8Array([4, 5, 6]));
 * 
 * // Finish and get final output
 * const final = deflate.finish();
 * 
 * console.log(`Compressed ${deflate.getTotalIn()} bytes to ${deflate.getTotalOut()} bytes`);
 * ```
 * @example  Streaming decompression
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const inflate = zlib.createInflate();
 * 
 * // Process compressed data in chunks
 * const compressed = zlib.deflate(import.meta.use('engine').encodeString('test'));
 * const output = inflate.inflate(compressed);
 * 
 * const text = import.meta.use('engine').decodeString(output);
 * console.log(text); // 'test'
 * ```
 * @example  CRC32 checksum
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const data = import.meta.use('engine').encodeString('Hello, World!');
 * const crc = zlib.crc32(data);
 * console.log(`CRC32: 0x${crc.toString(16)}`);
 * 
 * // Incremental CRC32
 * let crc2 = zlib.crc32(import.meta.use('engine').encodeString('Hello, '));
 * crc2 = zlib.crc32(import.meta.use('engine').encodeString('World!'), crc2);
 * console.log(crc === crc2); // true
 * ```
 * @example  Compression with different levels
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const data = import.meta.use('engine').encodeString('Test data'.repeat(1000));
 * 
 * // Fast compression
 * const fast = zlib.deflate(data, zlib.BEST_SPEED);
 * 
 * // Best compression
 * const best = zlib.deflate(data, zlib.BEST_COMPRESSION);
 * 
 * console.log(`Fast: ${fast.byteLength} bytes`);
 * console.log(`Best: ${best.byteLength} bytes`);
 * ```
 * @example  Dynamic compression parameters
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const deflate = zlib.createDeflate(zlib.DEFAULT_COMPRESSION);
 * 
 * // Compress some data
 * deflate.deflate(new Uint8Array(100));
 * 
 * // Change to best compression for important data
 * deflate.params(zlib.BEST_COMPRESSION, zlib.DEFAULT_STRATEGY);
 * 
 * // Continue compressing
 * deflate.deflate(new Uint8Array(100));
 * const result = deflate.finish();
 * ```
 * @example File compression (with hypothetical file API)
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * import * as fs from '@tjs/fs';
 * 
 * // Read file
 * const data = await fs.readFile('input.txt');
 * 
 * // Compress
 * const compressed = zlib.gzip(data);
 * 
 * // Write compressed file
 * await fs.writeFile('output.txt.gz', compressed);
 * 
 * // Calculate checksum
 * const crc = zlib.crc32(data);
 * console.log(`CRC32: ${crc}`);
 * ```
 * @example Streaming large file compression
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const gzip = zlib.createGzip(zlib.DEFAULT_COMPRESSION);
 * const output: Uint8Array[] = [];
 * 
 * // Simulate reading file in chunks
 * const chunks = [
 *   new Uint8Array(1024),
 *   new Uint8Array(1024),
 *   new Uint8Array(1024)
 * ];
 * 
 * for (const chunk of chunks) {
 *   const compressed = gzip.deflate(chunk);
 *   if (compressed.byteLength > 0) {
 *     output.push(new Uint8Array(compressed));
 *   }
 * }
 * 
 * // Finish
 * const final = gzip.finish();
 * if (final.byteLength > 0) {
 *   output.push(new Uint8Array(final));
 * }
 * 
 * console.log(`Total output: ${gzip.getTotalOut()} bytes`);
 * ```
 * @example Memory-efficient compression with strategy
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * // For text data, use default strategy
 * const textDeflate = zlib.createDeflate(
 *   zlib.DEFAULT_COMPRESSION,
 *   zlib.DEFAULT_STRATEGY,
 *   8  // memory level
 * );
 * 
 * // For image data, RLE strategy might work better
 * const imageDeflate = zlib.createDeflate(
 *   zlib.DEFAULT_COMPRESSION,
 *   zlib.RLE,
 *   9  // higher memory for better compression
 * );
 * ```
 * @example Verify data integrity with checksums
 * ```typescript
 * const zlib = import.meta.use('zlib')
 * 
 * const original = import.meta.use('engine').encodeString('Important data');
 * 
 * // Calculate checksums before compression
 * const originalCrc = zlib.crc32(original);
 * const originalAdler = zlib.adler32(original);
 * 
 * // Compress and transmit...
 * const compressed = zlib.deflate(original);
 * 
 * // Decompress
 * const decompressed = zlib.inflate(compressed);
 * 
 * // Verify integrity
 * const newCrc = zlib.crc32(decompressed);
 * const newAdler = zlib.adler32(decompressed);
 * 
 * if (originalCrc === newCrc && originalAdler === newAdler) {
 *   console.log('Data integrity verified!');
 * } else {
 *   console.error('Data corruption detected!');
 * }
 * ```
 */
declare namespace CModuleZLib {
    // ============================================================================
    // Compression Levels
    // ============================================================================

    /** No compression */
    export const NO_COMPRESSION: number;

    /** Fastest compression */
    export const BEST_SPEED: number;

    /** Best compression ratio */
    export const BEST_COMPRESSION: number;

    /** Default compression level (usually 6) */
    export const DEFAULT_COMPRESSION: number;

    // ============================================================================
    // Compression Strategies
    // ============================================================================

    /** Default strategy for normal data */
    export const DEFAULT_STRATEGY: number;

    /** Strategy for filtered data */
    export const FILTERED: number;

    /** Huffman coding only (no string match) */
    export const HUFFMAN_ONLY: number;

    /** Run-length encoding strategy */
    export const RLE: number;

    /** Fixed Huffman codes */
    export const FIXED: number;

    // ============================================================================
    // Flush Modes
    // ============================================================================

    /** No flush, default behavior */
    export const NO_FLUSH: number;

    /** Partial flush */
    export const PARTIAL_FLUSH: number;

    /** Sync flush - flushes all pending output */
    export const SYNC_FLUSH: number;

    /** Full flush - resets compression state */
    export const FULL_FLUSH: number;

    /** Finish compression */
    export const FINISH: number;

    /** Block flush */
    export const BLOCK: number;

    // ============================================================================
    // One-Shot Compression
    // ============================================================================

    /**
     * Compress data using DEFLATE algorithm
     * @param data - Input data to compress
     * @param level - Compression level (0-9, default: -1 for default)
     * @returns Compressed data
     */
    export function deflate(
        data: ArrayBuffer | Uint8Array,
        level?: number
    ): ArrayBuffer;

    /**
     * Compress data using GZIP format
     * @param data - Input data to compress
     * @param level - Compression level (0-9, default: -1 for default)
     * @returns Compressed data with gzip header/footer
     */
    export function gzip(
        data: ArrayBuffer | Uint8Array,
        level?: number
    ): ArrayBuffer;

    /**
     * Compress data using raw DEFLATE (no zlib header)
     * @param data - Input data to compress
     * @param level - Compression level (0-9, default: -1 for default)
     * @returns Compressed data without headers
     */
    export function deflateRaw(
        data: ArrayBuffer | Uint8Array,
        level?: number
    ): ArrayBuffer;

    // ============================================================================
    // One-Shot Decompression
    // ============================================================================

    /**
     * Decompress DEFLATE compressed data
     * @param data - Compressed data
     * @returns Decompressed data
     */
    export function inflate(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Decompress GZIP compressed data
     * @param data - Compressed data with gzip header/footer
     * @returns Decompressed data
     */
    export function gunzip(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    /**
     * Decompress raw DEFLATE compressed data (no zlib header)
     * @param data - Compressed data without headers
     * @returns Decompressed data
     */
    export function inflateRaw(data: ArrayBuffer | Uint8Array): ArrayBuffer;

    // ============================================================================
    // Streaming Compression
    // ============================================================================

    /**
     * Deflate stream for incremental compression
     */
    export interface Deflate {
        /**
         * Process input data (incremental compression)
         * @param data - Input data chunk
         * @param flush - Flush mode (optional)
         * @returns Compressed output chunk
         */
        deflate(data: ArrayBuffer | Uint8Array, flush?: number): ArrayBuffer;

        /**
         * Flush pending output
         * @param flush - Flush mode (optional, default: SYNC_FLUSH)
         * @returns Flushed compressed data
         */
        flush(flush?: number): ArrayBuffer;

        /**
         * Finish compression and flush all remaining data
         * @param data - Final input data (optional)
         * @returns Final compressed output
         */
        finish(data?: ArrayBuffer | Uint8Array): ArrayBuffer;

        /**
         * Reset compression state for reuse
         */
        reset(): void;

        /**
         * Change compression parameters on the fly
         * @param level - New compression level
         * @param strategy - New compression strategy
         */
        params(level: number, strategy: number): void;

        /**
         * Get total bytes processed (input)
         * @returns Total input bytes
         */
        getTotalIn(): number;

        /**
         * Get total bytes produced (output)
         * @returns Total output bytes
         */
        getTotalOut(): number;
    }

    /**
     * Create DEFLATE compression stream
     * @param level - Compression level (0-9, default: -1)
     * @param strategy - Compression strategy (default: DEFAULT_STRATEGY)
     * @param memLevel - Memory level 1-9 (default: 8)
     * @returns Deflate stream object
     */
    export function createDeflate(
        level?: number,
        strategy?: number,
        memLevel?: number
    ): Deflate;

    /**
     * Create GZIP compression stream
     * @param level - Compression level (0-9, default: -1)
     * @param strategy - Compression strategy (default: DEFAULT_STRATEGY)
     * @param memLevel - Memory level 1-9 (default: 8)
     * @returns Deflate stream object with gzip format
     */
    export function createGzip(
        level?: number,
        strategy?: number,
        memLevel?: number
    ): Deflate;

    /**
     * Create raw DEFLATE compression stream (no zlib header)
     * @param level - Compression level (0-9, default: -1)
     * @param strategy - Compression strategy (default: DEFAULT_STRATEGY)
     * @param memLevel - Memory level 1-9 (default: 8)
     * @returns Deflate stream object without headers
     */
    export function createDeflateRaw(
        level?: number,
        strategy?: number,
        memLevel?: number
    ): Deflate;

    // ============================================================================
    // Streaming Decompression
    // ============================================================================

    /**
     * Inflate stream for incremental decompression
     */
    export interface Inflate {
        /**
         * Process compressed input data (incremental decompression)
         * @param data - Compressed input chunk
         * @returns Decompressed output chunk
         */
        inflate(data: ArrayBuffer | Uint8Array): ArrayBuffer;

        /**
         * Flush pending output
         * @returns Flushed decompressed data
         */
        flush(): ArrayBuffer;

        /**
         * Reset decompression state for reuse
         */
        reset(): void;

        /**
         * Get total bytes processed (input)
         * @returns Total input bytes
         */
        getTotalIn(): number;

        /**
         * Get total bytes produced (output)
         * @returns Total output bytes
         */
        getTotalOut(): number;
    }

    /**
     * Create DEFLATE decompression stream
     * @returns Inflate stream object
     */
    export function createInflate(): Inflate;

    /**
     * Create GZIP decompression stream
     * @returns Inflate stream object for gzip format
     */
    export function createGunzip(): Inflate;

    /**
     * Create raw DEFLATE decompression stream (no zlib header)
     * @returns Inflate stream object without headers
     */
    export function createInflateRaw(): Inflate;

    // ============================================================================
    // Checksums
    // ============================================================================

    /**
     * Calculate CRC32 checksum
     * @param data - Input data
     * @param crc - Initial CRC value (optional, default: 0)
     * @returns CRC32 checksum as 32-bit unsigned integer
     */
    export function crc32(
        data: ArrayBuffer | Uint8Array,
        crc?: number
    ): number;

    /**
     * Calculate Adler-32 checksum
     * @param data - Input data
     * @param adler - Initial Adler-32 value (optional, default: 1)
     * @returns Adler-32 checksum as 32-bit unsigned integer
     */
    export function adler32(
        data: ArrayBuffer | Uint8Array,
        adler?: number
    ): number;
}