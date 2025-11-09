/**
 * HTTP Server module for TJS
 * Built on llhttp + libuv for high-performance async HTTP handling
 */

declare namespace CModuleServer {
    /**
     * HTTP request object
     */
    export interface HttpRequest {
        /** HTTP method (GET, POST, etc.) */
        method: string;

        /** URL information */
        url: {
            /** URL pathname */
            pathname: string;
            /** Query parameters object */
            query: Record<string, string>;
        };

        /** HTTP headers (lowercase keys) */
        headers: Record<string, string>;

        /** HTTP version (1.0 or 1.1) */
        httpVersion: string;

        /** Request body as ArrayBuffer (if present) */
        body?: ArrayBuffer;
    }

    /**
     * HTTP response object
     */
    export interface HttpResponse {
        /**
         * Write response headers
         * @param statusCode HTTP status code
         * @param headers Response headers
         */
        writeHead(statusCode: number, headers?: Record<string, string>): void;

        /**
         * Write response data
         * @param data Data to write (string or ArrayBuffer)
         */
        write(data: string | ArrayBuffer): void;

        /**
         * End the response
         * @param data Optional final data to write
         */
        end(data?: string | ArrayBuffer): void;

        /**
         * Send a complete response (shorthand for writeHead + write + end)
         * @param statusCode HTTP status code
         * @param body Response body (string or ArrayBuffer)
         */
        send(statusCode: number, body?: string | ArrayBuffer): void;
    }

    /**
     * HTTP server options
     */
    export interface ServerOptions {
        /** Port to listen on */
        port: number;

        /**
         * Request handler callback
         * @param req HTTP request object
         * @param res HTTP response object
         */
        onRequest: (req: HttpRequest, res: HttpResponse) => void;

        /**
         * Optional upgrade handler for WebSocket/raw socket
         * @param socket Upgraded socket connection
         * @param extraData Any extra data received during upgrade
         */
        onUpgrade?: (socket: UpgradedSocket, extraData?: ArrayBuffer) => void;
    }

    /**
     * Upgraded socket connection for WebSocket/custom protocols
     */
    export interface UpgradedSocket {
        /** Raw file descriptor */
        fd: number;

        /**
         * Write data to socket
         * @param data Data to write
         * @returns Number of bytes written
         */
        write(data: string | ArrayBuffer): number;

        /**
         * Close the socket
         */
        close(): void;

        /**
         * Register event handler
         * @param event Event name
         * @param callback Event callback
         */
        on(event: 'data', callback: (data: ArrayBuffer) => void): void;
        on(event: 'close', callback: () => void): void;
    }

    /**
     * HTTP server instance
     */
    export interface HttpServer {
        /**
         * Close the server
         */
        close(): void;
    }

    /**
     * Create an HTTP server
     * 
     * @param options Server configuration
     * @returns HTTP server instance
     * @example Basic HTTP server
     * ```typescript
     * import { createServer } from 'http';
     * 
     * const server = createServer({
     *   port: 8080,
     *   onRequest: (req, res) => {
     *     console.log(`${req.method} ${req.url.pathname}`);
     *     
     *     if (req.url.pathname === '/') {
     *       res.send(200, 'Hello World');
     *     } else if (req.url.pathname === '/json') {
     *       res.writeHead(200, {
     *         'Content-Type': 'application/json'
     *       });
     *       res.end(JSON.stringify({ message: 'Hello' }));
     *     } else {
     *       res.send(404, 'Not Found');
     *     }
     *   }
     * });
     * ```
     * 
     * @example Streaming response
     * ```typescript
     * const server = createServer({
     *   port: 8080,
     *   onRequest: (req, res) => {
     *     res.writeHead(200, {
     *       'Content-Type': 'text/plain',
     *       'Transfer-Encoding': 'chunked'
     *     });
     *     
     *     let count = 0;
     *     const interval = setInterval(() => {
     *       res.write(`Chunk ${count++}\n`);
     *       if (count >= 10) {
     *         clearInterval(interval);
     *         res.end();
     *       }
     *     }, 100);
     *   }
     * });
     * ```
     * 
     * @example Server-Sent Events
     * ```typescript
     * const server = createServer({
     *   port: 8080,
     *   onRequest: (req, res) => {
     *     if (req.url.pathname === '/events') {
     *       res.writeHead(200, {
     *         'Content-Type': 'text/event-stream',
     *         'Cache-Control': 'no-cache',
     *         'Connection': 'keep-alive'
     *       });
     *       
     *       const sendEvent = (data: any) => {
     *         res.write(`data: ${JSON.stringify(data)}\n\n`);
     *       };
     *       
     *       setInterval(() => {
     *         sendEvent({ time: Date.now() });
     *       }, 1000);
     *     }
     *   }
     * });
     * ```
     * 
     * @example WebSocket upgrade (manual implementation)
     * ```typescript
     * import { createServer } from 'http';
     * import { createHash } from 'crypto';
     * 
     * const server = createServer({
     *   port: 8080,
     *   onRequest: (req, res) => {
     *     // Handle regular HTTP requests
     *     res.send(200, 'Use WebSocket');
     *   },
     *   onUpgrade: (socket, extraData) => {
     *     // Now you have raw socket access
     *     // Implement WebSocket protocol in JS:
     *     
     *     socket.on('data', (data) => {
     *       // Parse WebSocket frames
     *       const frame = parseWebSocketFrame(data);
     *       
     *       if (frame.opcode === 0x8) {
     *         // Close frame
     *         socket.close();
     *       } else if (frame.opcode === 0x1) {
     *         // Text frame
     *         const response = encodeWebSocketFrame({
     *           opcode: 0x1,
     *           data: 'Echo: ' + frame.data
     *         });
     *         socket.write(response);
     *       }
     *     });
     *     
     *     socket.on('close', () => {
     *       console.log('WebSocket closed');
     *     });
     *   }
     * });
     * 
     * // Helper functions for WebSocket protocol
     * function parseWebSocketFrame(data: ArrayBuffer) {
     *   // Implement WebSocket frame parsing
     *   // See RFC 6455
     * }
     * 
     * function encodeWebSocketFrame(frame: { opcode: number, data: string }) {
     *   // Implement WebSocket frame encoding
     *   // See RFC 6455
     * }
     * ```
     * 
     * @example POST request with body
     * ```typescript
     * const server = createServer({
     *   port: 8080,
     *   onRequest: (req, res) => {
     *     if (req.method === 'POST' && req.body) {
     *       const text = new TextDecoder().decode(req.body);
     *       const json = JSON.parse(text);
     *       
     *       res.writeHead(200, { 'Content-Type': 'application/json' });
     *       res.end(JSON.stringify({ received: json }));
     *     } else {
     *       res.send(400, 'Bad Request');
     *     }
     *   }
     * });
     * ```
    */
    export function createServer(options: ServerOptions): HttpServer;
}