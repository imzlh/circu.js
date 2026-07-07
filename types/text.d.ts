/**
 * txiki.js Text Module - TypeScript Definitions
 * Based on libiconv for character encoding conversion
 */

/**
 * Examples focus on the native text module, not global TextEncoder/TextDecoder.
 *
 * @example UTF-8 encode/decode
 * ```ts
 * const text = import.meta.use('text');
 *
 * const encoder = new text.Encoder('utf-8');
 * const decoder = new text.Decoder('utf-8', { fatal: true });
 *
 * const bytes = encoder.encode('hello');
 * const value = decoder.decode(bytes);
 * ```
 *
 * @example Streaming decode
 * ```ts
 * const text = import.meta.use('text');
 *
 * const decoder = new text.Decoder('utf-8');
 * const part = decoder.decode(new Uint8Array([0xe4, 0xb8]), { stream: true });
 * const rest = decoder.decode(new Uint8Array([0xad]));
 * const final = decoder.decode();
 * ```
 *
 * @example Encode into an existing buffer
 * ```ts
 * const text = import.meta.use('text');
 *
 * const encoder = new text.Encoder('utf-8');
 * const target = new Uint8Array(16);
 * const result = encoder.encodeInto('hello', target);
 * const written = target.subarray(0, result.written);
 * ```
 *
 * @example Convert between encodings
 * ```ts
 * const text = import.meta.use('text');
 *
 * const gbkBytes = new Uint8Array([0xc4, 0xe3, 0xba, 0xc3]);
 * const utf8Text = text.convert('GBK', 'UTF-8', gbkBytes);
 *
 * const utf8Bytes = new text.Encoder().encode('hello');
 * const utf16Bytes = text.convert('UTF-8', 'UTF-16LE', utf8Bytes);
 * ```
 */

declare namespace CModuleText {
    export type Uint8Array = globalThis.Uint8Array<ArrayBuffer>;

    /**
     * text.Decoder Options
     */
    export interface TextDecoderOptions {
        /** If true, throw on invalid sequences instead of replacing */
        fatal?: boolean;
        /** If true, ignore byte order mark (BOM) */
        ignoreBOM?: boolean;
        /** If true, maintain state for streaming decode */
        stream?: boolean;
    }

    /**
     * text.Decoder Stream Options
     */
    export interface TextDecodeOptions {
        /** If true, maintain state for streaming decode */
        stream?: boolean;
    }

    /**
     * text.Decoder - Decodes binary data to strings
     * Supports various character encodings via libiconv
     */
    export class Decoder {
        /**
         * Create a new text decoder
         * @param encoding Character encoding (default: "utf-8")
         * @param options Decoder options
         */
        constructor(encoding?: string, options?: TextDecoderOptions);

        /**
         * Decode binary data to string
         * @param buffer Binary data to decode
         * @param options Decode options
         * @returns Decoded string
         */
        decode(buffer?: ArrayBuffer | ArrayBufferView | null, options?: TextDecodeOptions): string;

        /**
         * The encoding name
         */
        readonly encoding: string;

        /**
         * Whether fatal mode is enabled
         */
        readonly fatal: boolean;

        /**
         * Whether BOM should be ignored
         */
        readonly ignoreBOM: boolean;
    }

    /**
     * text.Encoder Result
     */
    export interface TextEncodeIntoResult {
        /** Number of UTF-8 code units read */
        read: number;
        /** Number of bytes written */
        written: number;
    }

    /**
     * text.Encoder - Encodes strings to binary data
     * Supports various character encodings via libiconv
     */
    export class Encoder {
        /**
         * Create a new text encoder
         * @param encoding Character encoding (default: "utf-8")
         */
        constructor(encoding?: string);

        /**
         * Encode string to binary data
         * @param input String to encode
         * @returns ArrayBuffer containing encoded data
         */
        encode(input?: string): Uint8Array;

        /**
         * Encode string into existing buffer
         * @param input String to encode
         * @param buffer Target buffer
         * @returns Object with read/written counts
         */
        encodeInto(input: string, buffer: ArrayBufferView): TextEncodeIntoResult;

        /**
         * The encoding name
         */
        readonly encoding: string;
    }

    /**
     * Convert between encodings
     * @param from Source encoding
     * @param to Target encoding
     * @param data Data to convert
     * @returns Converted data (string if to=UTF-8, Uint8Array otherwise)
     */
    export function convert(
        from: string,
        to: string,
        data: ArrayBuffer | ArrayBufferView
    ): string | Uint8Array;

    /**
     * List supported encodings
     * @returns Array of supported encoding names
     */
    export function listEncodings(): string[];
}
