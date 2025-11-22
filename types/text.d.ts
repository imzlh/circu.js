/**
 * txiki.js Text Module - TypeScript Definitions
 * Based on libiconv for character encoding conversion
 */

/**
 * USAGE EXAMPLES
 * 
 * @example
 * ```ts
 * // Example 1: 基本UTF-8解码
 * import { TextDecoder } from "@tjs/text";
 * 
 * const decoder = new TextDecoder("utf-8");
 * const bytes = new Uint8Array([72, 101, 108, 108, 111]);  // "Hello"
 * const text = decoder.decode(bytes);
 * 
 * console.log(text);  // 输出: "Hello"
 * console.log(decoder.encoding);  // 输出: "utf-8"
 * ```
 * 
 * @example
 * ```ts
 * // Example 2: 使用不同编码解码
 * import { TextDecoder } from "@tjs/text";
 * 
 * // 解码ISO-8859-1 (Latin-1)
 * const latin1Decoder = new TextDecoder("ISO-8859-1");
 * const latin1Bytes = new Uint8Array([0xC1, 0xE9, 0xED, 0xF3, 0xFA]);  // Áéíóú
 * const latin1Text = latin1Decoder.decode(latin1Bytes);
 * console.log(latin1Text);
 * 
 * // 解码GBK (中文)
 * const gbkDecoder = new TextDecoder("GBK");
 * const gbkBytes = new Uint8Array([0xC4, 0xE3, 0xBA, 0xC3]);  // 你好
 * const gbkText = gbkDecoder.decode(gbkBytes);
 * console.log(gbkText);
 * 
 * // 解码Shift_JIS (日文)
 * const sjisDecoder = new TextDecoder("SHIFT_JIS");
 * const sjisBytes = new Uint8Array([0x82, 0xB1, 0x82, 0xF1, 0x82, 0xC9, 0x82, 0xBF, 0x82, 0xCD]);  // こんにちは
 * const sjisText = sjisDecoder.decode(sjisBytes);
 * console.log(sjisText);
 * ```
 * 
 * @example
 * ```ts
 * // Example 3: 致命模式和错误处理
 * import { TextDecoder } from "@tjs/text";
 * 
 * // 非致命模式 (默认) - 替换无效序列
 * const lenientDecoder = new TextDecoder("utf-8", { fatal: false });
 * const invalidBytes = new Uint8Array([0xFF, 0xFE]);  // 无效的UTF-8
 * const replacedText = lenientDecoder.decode(invalidBytes);
 * console.log(replacedText);  // 包含替换字符
 * 
 * // 致命模式 - 在无效序列时抛出错误
 * const strictDecoder = new TextDecoder("utf-8", { fatal: true });
 * try {
 *   strictDecoder.decode(invalidBytes);
 * } catch (err) {
 *   console.error("解码错误:", err.message);
 * }
 * ```
 * 
 * @example
 * ```ts
 * // Example 4: 处理BOM (字节顺序标记)
 * import { TextDecoder } from "@tjs/text";
 * 
 * const utf8WithBOM = new Uint8Array([0xEF, 0xBB, 0xBF, 0x48, 0x69]);  // BOM + "Hi"
 * 
 * // 默认情况下，BOM不被忽略
 * const decoder1 = new TextDecoder("utf-8");
 * console.log(decoder1.decode(utf8WithBOM));  // BOM + "Hi"
 * 
 * // 忽略BOM
 * const decoder2 = new TextDecoder("utf-8", { ignoreBOM: true });
 * console.log(decoder2.decode(utf8WithBOM));  // "Hi"
 * ```
 * 
 * @example
 * ```ts
 * // Example 5: 流式解码
 * import { TextDecoder } from "@tjs/text";
 * 
 * const decoder = new TextDecoder("utf-8");
 * 
 * // 解码多字节字符，分块传输
 * const chunk1 = new Uint8Array([0xE4, 0xB8]);  // "中" 的前2字节
 * const chunk2 = new Uint8Array([0xAD]);        // "中" 的最后1字节
 * 
 * // 流模式在调用之间保持状态
 * const part1 = decoder.decode(chunk1, { stream: true });
 * const part2 = decoder.decode(chunk2, { stream: false });
 * 
 * console.log(part1 + part2);  // "中"
 * ```
 * 
 * @example
 * ```ts
 * // Example 6: 基本UTF-8编码
 * import { TextEncoder } from "@tjs/text";
 * 
 * const encoder = new TextEncoder("utf-8");
 * const text = "Hello, 世界!";
 * const bytes = encoder.encode(text);
 * 
 * console.log(new Uint8Array(bytes));
 * // 输出: UTF-8字节数组
 * ```
 * 
 * @example
 * ```ts
 * // Example 7: 编码到不同编码
 * import { TextEncoder } from "@tjs/text";
 * 
 * // 编码到GBK
 * const gbkEncoder = new TextEncoder("GBK");
 * const gbkBytes = gbkEncoder.encode("你好");
 * console.log(new Uint8Array(gbkBytes));
 * 
 * // 编码到ISO-8859-1
 * const latin1Encoder = new TextEncoder("ISO-8859-1");
 * const latin1Bytes = latin1Encoder.encode("Héllo");
 * console.log(new Uint8Array(latin1Bytes));
 * 
 * // 编码到UTF-16LE
 * const utf16Encoder = new TextEncoder("UTF-16LE");
 * const utf16Bytes = utf16Encoder.encode("Hello");
 * console.log(new Uint8Array(utf16Bytes));
 * ```
 * 
 * @example
 * ```ts
 * // Example 8: 使用encodeInto()进行零拷贝编码
 * import { TextEncoder } from "@tjs/text";
 * 
 * const encoder = new TextEncoder("utf-8");
 * const text = "Hello";
 * const buffer = new Uint8Array(10);
 * 
 * const result = encoder.encodeInto(text, buffer);
 * 
 * console.log(`读取: ${result.read} 代码单元`);
 * console.log(`写入: ${result.written} 字节`);
 * console.log(buffer.slice(0, result.written));
 * ```
 * 
 * @example
 * ```ts
 * // Example 9: 直接编码转换
 * import { convert } from "@tjs/text";
 * 
 * // 将GBK转换为UTF-8
 * const gbkBytes = new Uint8Array([0xC4, 0xE3, 0xBA, 0xC3]);  // "你好" in GBK
 * const utf8Text = convert("GBK", "UTF-8", gbkBytes);
 * console.log(utf8Text);  // "你好"
 * 
 * // 将UTF-8转换为UTF-16LE
 * const utf8Bytes = new TextEncoder().encode("Hello");
 * const utf16Bytes = convert("UTF-8", "UTF-16LE", utf8Bytes);
 * console.log(new Uint8Array(utf16Bytes as ArrayBuffer));
 * ```
 * 
 * @example
 * ```ts
 * // Example 10: 列出可用的编码
 * import { listEncodings } from "@tjs/text";
 * 
 * const encodings = listEncodings();
 * console.log("支持的编码:", encodings);
 * 
 * // 检查特定编码是否被支持
 * const isSupported = (encoding: string) => {
 *   return encodings.some(e => e.toLowerCase() === encoding.toLowerCase());
 * };
 * 
 * console.log("GBK支持:", isSupported("GBK"));
 * console.log("UTF-8支持:", isSupported("UTF-8"));
 * ```
 * 
 * @example
 * ```ts
 * // Example 11: 文件编码检测和转换
 * import { TextDecoder, convert } from "@tjs/text";
 * 
 * async function detectAndConvert(buffer: ArrayBuffer): Promise<string> {
 *   const bytes = new Uint8Array(buffer);
 *   
 *   // 检查UTF-8 BOM
 *   if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
 *     const decoder = new TextDecoder("utf-8");
 *     return decoder.decode(bytes);
 *   }
 *   
 *   // 检查UTF-16 LE BOM
 *   if (bytes[0] === 0xFF && bytes[1] === 0xFE) {
 *     const decoder = new TextDecoder("utf-16le");
 *     return decoder.decode(bytes);
 *   }
 *   
 *   // 检查UTF-16 BE BOM
 *   if (bytes[0] === 0xFE && bytes[1] === 0xFF) {
 *     const decoder = new TextDecoder("utf-16be");
 *     return decoder.decode(bytes);
 *   }
 *   
 *   // 尝试UTF-8
 *   try {
 *     const decoder = new TextDecoder("utf-8", { fatal: true });
 *     return decoder.decode(bytes);
 *   } catch {
 *     // 回退到GBK处理中文文件
 *     const decoder = new TextDecoder("GBK");
 *     return decoder.decode(bytes);
 *   }
 * }
 * ```
 * 
 * @example
 * ```ts
 * // Example 12: 二进制到文本编码的实用工具
 * import { TextEncoder, TextDecoder } from "@tjs/text";
 * 
 * class EncodingUtils {
 *   // 将字符串编码为Base64
 *   static toBase64(str: string): string {
 *     const encoder = new TextEncoder("utf-8");
 *     const bytes = new Uint8Array(encoder.encode(str));
 *     let binary = '';
 *     for (let i = 0; i < bytes.length; i++) {
 *       binary += String.fromCharCode(bytes[i]);
 *     }
 *     return btoa(binary);
 *   }
 *   
 *   // 将Base64解码为字符串
 *   static fromBase64(b64: string): string {
 *     const binary = atob(b64);
 *     const bytes = new Uint8Array(binary.length);
 *     for (let i = 0; i < binary.length; i++) {
 *       bytes[i] = binary.charCodeAt(i);
 *     }
 *     const decoder = new TextDecoder("utf-8");
 *     return decoder.decode(bytes);
 *   }
 * }
 * 
 * const encoded = EncodingUtils.toBase64("Hello, 世界!");
 * console.log("Base64:", encoded);
 * 
 * const decoded = EncodingUtils.fromBase64(encoded);
 * console.log("解码:", decoded);
 * ```
 */

declare namespace CModuleText {
    /**
     * TextDecoder Options
     */
    export interface TextDecoderOptions {
        /** If true, throw on invalid sequences instead of replacing */
        fatal?: boolean;
        /** If true, ignore byte order mark (BOM) */
        ignoreBOM?: boolean;
    }

    /**
     * TextDecoder Stream Options
     */
    export interface TextDecodeOptions {
        /** If true, maintain state for streaming decode */
        stream?: boolean;
    }

    /**
     * TextDecoder - Decodes binary data to strings
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
        decode(buffer: ArrayBuffer | ArrayBufferView, options?: TextDecodeOptions): string;

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
     * TextEncoder Result
     */
    export interface TextEncodeIntoResult {
        /** Number of UTF-8 code units read */
        read: number;
        /** Number of bytes written */
        written: number;
    }

    /**
     * TextEncoder - Encodes strings to binary data
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
        encode(input: string): ArrayBuffer;

        /**
         * Encode string into existing buffer
         * @param input String to encode
         * @param buffer Target buffer
         * @returns Object with read/written counts
         */
        encodeInto(input: string, buffer: Uint8Array): TextEncodeIntoResult;

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
     * @returns Converted data (string if to=UTF-8, ArrayBuffer otherwise)
     */
    export function convert(
        from: string,
        to: string,
        data: ArrayBuffer | ArrayBufferView
    ): string | ArrayBuffer;

    /**
     * List supported encodings
     * @returns Array of supported encoding names
     */
    export function listEncodings(): string[];
}