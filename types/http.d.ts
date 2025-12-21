/**
 * txiki.js HTTP Parser Module - TypeScript Definitions
 * 
 * A thin wrapper around llhttp for high-performance, event-driven HTTP parsing.
 * Supports both request and response parsing with streaming capabilities.
 * 
 * Complete example: Parsing a chunked response
 * 
 * @example
 * ```typescript
 * const { Parser, RESPONSE } = import.meta.use('http');
 * 
 * const parser = new Parser(RESPONSE);
 * const chunks: string[] = [];
 * const headers: Record<string, string> = {};
 * let currentHeader = '';
 * 
 * parser.onHeaderField = (ev, buf, off, len) => {
 *   currentHeader = new TextDecoder().decode(
 *     buf.slice(off, off + len)
 *   ).toLowerCase();
 * };
 * 
 * parser.onHeaderValue = (ev, buf, off, len) => {
 *   headers[currentHeader] = new TextDecoder().decode(
 *     buf.slice(off, off + len)
 *   );
 * };
 * 
 * parser.onChunkHeader = () => {
 *   console.log('New chunk detected');
 * };
 * 
 * parser.onBody = (ev, buf, off, len) => {
 *   chunks.push(new TextDecoder().decode(
 *     buf.slice(off, off + len)
 *   ));
 * };
 * 
 * parser.onMessageComplete = () => {
 *   console.log('Message complete!');
 * };
 * 
 * // Simulated chunked HTTP response
 * const data = new TextEncoder().encode(
 *   'HTTP/1.1 200 OK\r\n' +
 *   'Transfer-Encoding: chunked\r\n' +
 *   'Content-Type: text/plain\r\n' +
 *   '\r\n' +
 *   '5\r\n' +
 *   'Hello\r\n' +
 *   '6\r\n' +
 *   ' World\r\n' +
 *   '0\r\n' +
 *   '\r\n'
 * );
 * 
 * const result = parser.execute(data);
 * if (result.errno === 0) {
 *   console.log('Body:', chunks.join('')); // "Hello World"
 *   console.log('Headers:', headers);
 * }
 * ```
 */
declare namespace CModuleHTTP {
    export const REQUEST: 0;
    export const RESPONSE: 1;

    /**
     * Result from {@link Parser.execute}
     */
    export interface ParserExecuteResult {
        /** Parser error number (0 = success) */
        errno: number;
        /** Error name string (e.g., "HPE_OK") */
        name: string;
        /** Human-readable error reason or null */
        reason: string | null;
        /** Bytes consumed from input buffer */
        bytesConsumed: number;
    }

    /**
     * Result from {@link Parser.finish}
     */
    export interface ParserFinishResult {
        errno: number;
        name: string;
        reason: string | null;
    }

    /**
     * Current parser state snapshot
     */
    export interface ParserState {
        /** Parser type: 0=REQUEST, 1=RESPONSE */
        type: 0 | 1;
        /** HTTP major version (e.g., 1 for HTTP/1.1) */
        httpMajor: number;
        /** HTTP minor version (e.g., 1 for HTTP/1.1) */
        httpMinor: number;
        /** HTTP status code (responses only) */
        status: number;
        /** HTTP method enum (requests only) */
        method: number;
        /** Whether this is an upgrade request (e.g., WebSocket) */
        upgrade: boolean;
        /** Whether connection should be kept alive */
        keepAlive: boolean;
        /** Current error number */
        errno: number;
        /** Whether message needs EOF to complete */
        eof: boolean;
    }

    /** 
     * All TypedArray types that can be passed to the parser
     */
    export type TypedArray =
        | Uint8Array
        | Int8Array
        | Uint16Array
        | Int16Array
        | Uint32Array
        | Int32Array
        | Float32Array
        | Float64Array
        | BigUint64Array
        | BigInt64Array;

    /**
     * Buffer types accepted by the parser
     */
    export type BufferSource = ArrayBuffer | TypedArray | DataView;

    /**
     * Event callback signature
     * 
     * @param event - Event type enum value
     * @param buffer - Original buffer passed to execute()
     * @param offset - Byte offset into buffer
     * @param length - Byte length of data
     */
    export type HttpCallback = (
        event: number,
        buffer: BufferSource,
        offset: number,
        length: number
    ) => void | Promise<void>;

    /**
     * HTTP Parser for requests and responses
     * 
     * @example
     * ```typescript
     * const { Parser, REQUEST } = import.meta.use('http');
     * 
     * // Parse a simple HTTP request
     * const parser = new Parser(REQUEST);
     * const buf = new TextEncoder().encode(
     *   'GET /api/data HTTP/1.1\r\n' +
     *   'Host: example.com\r\n' +
     *   '\r\n'
     * );
     * 
     * const result = parser.execute(buf);
     * console.log(`Consumed ${result.bytesConsumed} bytes`);
     * ```
     */
    export class Parser {
        /**
         * @param type - Parser type: REQUEST (0) or RESPONSE (1). Defaults to RESPONSE.
         */
        constructor(type?: typeof REQUEST | typeof RESPONSE);

        /**
         * Process a buffer of HTTP data
         * 
         * @example
         * ```typescript
         * const { Parser, RESPONSE } = import.meta.use('http');
         * 
         * const parser = new Parser(RESPONSE);
         * let body = '';
         * 
         * parser.onBody = (ev, buf, off, len) => {
         *   body += new TextDecoder().decode(
         *     buf.slice(off, off + len)
         *   );
         * };
         * 
         * const data = new TextEncoder().encode(
         *   'HTTP/1.1 200 OK\r\n' +
         *   'Content-Length: 5\r\n\r\n' +
         *   'hello'
         * );
         * 
         * const res = parser.execute(data);
         * console.log(body); // "hello"
         * ```
         */
        execute(buffer: BufferSource): ParserExecuteResult;

        /** Pause parsing (useful for backpressure) */
        pause(): void;

        /** Resume a paused parser */
        resume(): void;

        /**
         * Reset parser state for a new message
         * @param type - Optionally change parser type
         */
        reset(type?: typeof REQUEST | typeof RESPONSE): void;

        /** Signal EOF to the parser */
        finish(): ParserFinishResult;

        /** Get current parser state */
        get state(): ParserState;

        // Event callbacks
        onMessageBegin: HttpCallback | undefined;
        onUrl: HttpCallback | undefined;
        onStatus: HttpCallback | undefined;
        onHeaderField: HttpCallback | undefined;
        onHeaderValue: HttpCallback | undefined;
        onHeadersComplete: HttpCallback | undefined;
        onBody: HttpCallback | undefined;
        onMessageComplete: HttpCallback | undefined;
        onChunkHeader: HttpCallback | undefined;
        onChunkComplete: HttpCallback | undefined;
    }

    /**
     * Get error name from error number
     * 
     * @example
     * ```typescript
     * const { strerr } = import.meta.use('http');
     * 
     * console.log(strerr(0)); // "HPE_OK"
     * console.log(strerr(-10)); // "HPE_CLOSED_CONNECTION"
     * ```
     */
    export function strerr(errno: number): string;

    /**
     * Get standard HTTP status text
     * 
     * @example
     * ```typescript
     * const { strstatus } = import.meta.use('http');
     * 
     * console.log(strstatus(200)); // "OK"
     * console.log(strstatus(404)); // "Not Found"
     * ```
     */
    export function strstatus(statusCode: number): string;
}