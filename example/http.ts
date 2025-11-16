/**
 * circu.js 服务端Response封装
 * 支持: SSE、WebSocket升级、文件传输（完善压缩）
 */

import { STATUS, MIMEMAP } from './define';

// ============================================================================
// 顶层导入原生模块（符合circu.js最佳实践）
// ============================================================================

const { encodeString, decodeString } = import.meta.use('engine');
const { base64Encode, sha1 } = import.meta.use('crypto');
const { open } = import.meta.use('asyncfs');
const $zlib = import.meta.use('zlib');
const { Pipe } = import.meta.use('streams');
const console = import.meta.use('console');

const {
    deflate,
    gzip,
    createDeflate,
    createGzip,
    BEST_COMPRESSION,
    BEST_SPEED,
    DEFAULT_COMPRESSION,
    DEFAULT_STRATEGY
} = $zlib;

// ============================================================================
// 类型定义
// ============================================================================

interface FileSendOptions {
    path: string
    compress?: boolean | 'gzip' | 'deflate'
    compressLevel?: number // 0-9
    compressStrategy?: number // zlib策略常量
    chunkSize?: number
    onProgress?: (sent: number, total: number) => void
    filename?: string
    range?: { start: number; end?: number }
}

interface SSEvent {
    event?: string
    data: string
    id?: string
    retry?: number
}

interface WebSocketFrame {
    opcode: number
    payload: Uint8Array<ArrayBuffer>
    fin?: boolean
}

// ============================================================================
// 基础Response封装
// ============================================================================

export class Response {
    protected $res: CModuleServer.HttpResponse;
    protected $sent = false;
    protected $headers = new Map<string, string[]>();

    constructor(res: CModuleServer.HttpResponse) {
        this.$res = res;
    }

    /** 设置头部（链式调用） */
    setHeader(name: string, value: string | string[]): this {
        const $key = name.toLowerCase();
        this.$headers.set($key, Array.isArray(value) ? value : [value]);
        return this;
    }

    /** 获取头部 */
    getHeader(name: string): string | undefined {
        return this.$headers.get(name.toLowerCase())?.[0];
    }

    /** 删除头部（链式调用） */
    removeHeader(name: string): this {
        this.$headers.delete(name.toLowerCase());
        return this;
    }

    /** 发送JSON响应 */
    async json(data: any, status = 200): Promise<void> {
        if (this.$sent) throw new Error('Response already sent');

        const $body = encodeString(JSON.stringify(data));
        this.setHeader('content-type', 'application/json');
        this.setHeader('content-length', $body.length.toString());

        this.$res.writeHead(status, this.$compileHeaders());
        this.$res.end($body.buffer);
        this.$sent = true;
    }

    /** 发送文本响应 */
    async text(text: string, status = 200): Promise<void> {
        if (this.$sent) throw new Error('Response already sent');

        const $body = encodeString(text);
        this.setHeader('content-type', 'text/plain; charset=utf-8');
        this.setHeader('content-length', $body.length.toString());

        this.$res.writeHead(status, this.$compileHeaders());
        this.$res.end($body.buffer);
        this.$sent = true;
    }

    /** 发送二进制响应 */
    async bytes(data: Uint8Array<ArrayBuffer>, status = 200, contentType = 'application/octet-stream'): Promise<void> {
        if (this.$sent) throw new Error('Response already sent');

        this.setHeader('content-type', contentType);
        this.setHeader('content-length', data.length.toString());

        this.$res.writeHead(status, this.$compileHeaders());
        this.$res.end(data.buffer);
        this.$sent = true;
    }

    /** 编译头部对象为Record */
    protected $compileHeaders(): Record<string, string> {
        const $obj: Record<string, string> = {};
        for (const [$key, $values] of this.$headers) {
            $obj[$key] = $values.join(', ');
        }
        return $obj;
    }

    /** 是否已发送 */
    get sent(): boolean {
        return this.$sent;
    }
}

// ============================================================================
// SSE响应封装 - 服务器推送
// ============================================================================

export class SSEResponse extends Response {
    private $firstChunk = true;
    private $closed = false;

    /** 初始化SSE连接 */
    async init(): Promise<void> {
        if (this.$sent) throw new Error('Response already sent');

        this.setHeader('content-type', 'text/event-stream');
        this.setHeader('cache-control', 'no-cache');
        this.setHeader('connection', 'keep-alive');

        this.removeHeader('content-length');
        this.removeHeader('transfer-encoding');

        this.$res.writeHead(200, this.$compileHeaders());
        this.$sent = true;
    }

    /** 发送SSE事件 */
    async send(event: SSEvent): Promise<void> {
        if (this.$closed) throw new Error('SSE connection closed');
        if (!this.$sent) await this.init();

        let $payload = '';

        if (event.id) {
            $payload += `id: ${event.id}\n`;
        }

        if (event.event) {
            $payload += `event: ${event.event}\n`;
        }

        if (event.retry) {
            $payload += `retry: ${event.retry}\n`;
        }

        const $lines = event.data.split('\n');
        for (const $line of $lines) {
            $payload += `data: ${$line}\n`;
        }

        $payload += '\n';

        this.$res.write(encodeString($payload).buffer);
    }

    /** 便捷发送数据 */
    async sendData(data: string, event?: string, id?: string): Promise<void> {
        await this.send({ data, event: event ?? 'message', id: id ?? '0' });
    }

    /** 关闭SSE连接 */
    close(): void {
        if (!this.$closed) {
            this.$closed = true;
            this.$res.end();
        }
    }

    get closed(): boolean {
        return this.$closed;
    }
}

// ============================================================================
// WebSocket响应封装 - 协议升级
// ============================================================================

export class WSResonse extends Response {
    private $upgraded = false;
    private $closed = false;
    private $receivedClose = false;
    private $stream: CModuleStreams.Pipe | null = null;

    /** 执行WebSocket握手升级 */
    async upgrade(key: string): Promise<boolean> {
        if (this.$sent) throw new Error('Response already sent');

        const $version = this.getHeader('sec-websocket-version');
        if ($version !== '13') {
            await this.text('Unsupported WebSocket version', 426);
            return false;
        }

        if (!key) {
            await this.text('Missing Sec-WebSocket-Key', 400);
            return false;
        }

        const $accept = this.$computeAcceptKey(key);

        this.setHeader('upgrade', 'websocket');
        this.setHeader('connection', 'upgrade');
        this.setHeader('sec-websocket-accept', $accept);

        this.$res.writeHead(101, this.$compileHeaders());

        // 获取底层流并包装
        const $fd = this.$res.upgrade();
        this.$stream = new Pipe();
        this.$stream.open($fd);

        this.$sent = true;
        this.$upgraded = true;

        return true;
    }

    /** 计算Sec-WebSocket-Accept */
    private $computeAcceptKey(key: string): string {
        const $GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
        const $hash = sha1(encodeString(key + $GUID));
        return base64Encode(new Uint8Array($hash));
    }

    /** 发送WebSocket帧（服务端不掩码） */
    private async $sendFrame(opcode: number, payload: Uint8Array<ArrayBuffer>, fin = true): Promise<void> {
        if (!this.$upgraded) throw new Error('WebSocket not upgraded');
        if (this.$closed) throw new Error('WebSocket closed');
        if (!this.$stream) throw new Error('Stream not available');

        const $frame = this.$buildFrame(opcode, payload, fin);
        const $buffer = new Uint8Array($frame);
        await this.$stream.write($buffer);
    }

    private $buildFrame(opcode: number, payload: Uint8Array<ArrayBuffer>, fin: boolean): Uint8Array<ArrayBuffer> {
        const $header: number[] = [];
        $header.push((fin ? 0x80 : 0x00) | opcode);

        let $byte2 = 0x00; // 服务端不掩码

        if (payload.length < 126) {
            $byte2 |= payload.length;
            $header.push($byte2);
        } else if (payload.length < 65536) {
            $byte2 |= 126;
            $header.push($byte2);
            $header.push((payload.length >> 8) & 0xFF);
            $header.push(payload.length & 0xFF);
        } else {
            $byte2 |= 127;
            $header.push($byte2);
            for (let $i = 7; $i >= 0; $i--) {
                $header.push((payload.length >> ($i * 8)) & 0xFF);
            }
        }

        const $frame = new Uint8Array($header.length + payload.length);
        $frame.set(new Uint8Array($header), 0);
        $frame.set(payload, $header.length);

        return $frame;
    }

    /** 发送文本消息 */
    async sendText(text: string): Promise<void> {
        const $payload = encodeString(text);
        await this.$sendFrame(0x1, $payload);
    }

    /** 发送二进制消息 */
    async sendBinary(data: Uint8Array<ArrayBuffer>): Promise<void> {
        await this.$sendFrame(0x2, data);
    }

    /** 发送Ping */
    async ping(data: Uint8Array<ArrayBuffer> = new Uint8Array(0)): Promise<void> {
        await this.$sendFrame(0x9, data);
    }

    /** 接收消息帧（异步迭代器） */
    async *receiveFrames(): AsyncIterableIterator<WebSocketFrame> {
        if (!this.$upgraded) throw new Error('WebSocket not upgraded');
        if (!this.$stream) throw new Error('Stream not available');

        while (!this.$closed && !this.$receivedClose) {
            const $frame = await this.$readFrame();
            if (!$frame) break;

            if ($frame.opcode >= 0x8) {
                switch ($frame.opcode) {
                    case 0x8: // CLOSE
                        this.$receivedClose = true;
                        await this.$sendFrame(0x8, $frame.payload);
                        this.close();
                        return;

                    case 0x9: // PING
                        await this.$sendFrame(0xA, $frame.payload);
                        continue;

                    case 0xA: // PONG
                        continue;
                }
            }

            yield $frame;
        }
    }

    private async $readFrame(): Promise<WebSocketFrame | null> {
        if (this.$closed || !this.$stream) return null;

        const $head = new Uint8Array(2);
        const $n = await this.$stream.read($head);
        if (!$n) {
            this.$closed = true;
            return null;
        }

        const $byte1 = $head[0]!;
        const $byte2 = $head[1]!;

        const $fin = ($byte1 & 0x80) !== 0;
        const $opcode = $byte1 & 0x0F;
        const $masked = ($byte2 & 0x80) !== 0;
        let $len = $byte2 & 0x7F;

        if ($len === 126) {
            const $ext = new Uint8Array(2);
            const $n2 = await this.$stream.read($ext);
            if (!$n2) { this.$closed = true; return null; }
            $len = ($ext[0]! << 8) | $ext[1]!;
        } else if ($len === 127) {
            const $ext = new Uint8Array(8);
            const $n2 = await this.$stream.read($ext);
            if (!$n2) { this.$closed = true; return null; }
            $len = 0;
            for (let $i = 4; $i < 8; $i++) {
                $len = ($len << 8) | $ext[$i]!;
            }
        }

        if (!$masked) {
            this.$closed = true;
            throw new Error('Client frame must be masked');
        }

        const $maskKey = new Uint8Array(4);
        const $n2 = await this.$stream.read($maskKey);
        if (!$n2) { this.$closed = true; return null; }

        const $payload = new Uint8Array($len);
        const $n3 = await this.$stream.read($payload);
        if (!$n3 || $n3 !== $len) {
            this.$closed = true;
            return null;
        }

        for (let $i = 0; $i < $payload.length; $i++) {
            // @ts-ignore
            $payload[$i] ^= $maskKey[$i % 4];
        }

        return { opcode: $opcode, payload: $payload, fin: $fin };
    }

    /** 关闭WebSocket连接 */
    close(): void {
        if (!this.$closed) {
            this.$closed = true;
            if (!this.$receivedClose) {
                const $closeFrame = new Uint8Array(2);
                $closeFrame[0] = 0x03; // 1000
                $closeFrame[1] = 0xE8;
                this.$sendFrame(0x8, $closeFrame, true).catch(() => { });
            }
            if (this.$stream) {
                this.$stream.close();
            }
        }
    }

    get closed(): boolean {
        return this.$closed;
    }
}

// ============================================================================
// 文件传输响应封装 - 支持完善压缩
// ============================================================================

export class FileResponse extends Response {

    /** 发送文件（支持压缩、断点续传） */
    async send(options: FileSendOptions): Promise<void> {
        if (this.$sent) throw new Error('Response already sent');

        const $handle = await open(options.path, 'r');

        try {
            const $stat = await $handle.stat();
            const $fileSize = $stat.size;
            let $start = 0;
            let $end = $fileSize - 1;
            let $status = 200;

            // 处理Range请求
            const $rangeHeader = this.getHeader('range');
            if ($rangeHeader) {
                const $match = $rangeHeader.match(/bytes=(\d+)-(\d*)/);
                if ($match) {
                    $start = parseInt($match[1]!);
                    $end = $match[2] ? parseInt($match[2]!) : $fileSize - 1;

                    this.setHeader('content-range', `bytes ${$start}-${$end}/${$fileSize}`);
                    this.setHeader('content-length', ($end - $start + 1).toString());
                    $status = 206;
                }
            } else {
                this.setHeader('content-length', $fileSize.toString());
            }

            // MIME类型
            const $ext = options.path.split('.').pop()?.toLowerCase() || '';
            const $mime = MIMEMAP[$ext] || 'application/octet-stream';
            this.setHeader('content-type', $mime);

            // 压缩处理
            const $shouldCompress = options.compress && !$rangeHeader && this.$shouldCompress($ext);
            if ($shouldCompress) {
                const $encoding = typeof options.compress === 'string' ? options.compress : 'deflate';
                this.setHeader('content-encoding', $encoding);
            }

            this.$res.writeHead($status, this.$compileHeaders());
            this.$sent = true;

            if ($shouldCompress) {
                await this.$sendCompressed($handle, $start, $end, options);
            } else {
                await this.$sendRaw($handle, $start, $end, options);
            }
        } finally {
            await $handle.close();
        }
    }

    /** 判断是否适合压缩 */
    private $shouldCompress(ext: string): boolean {
        const $noCompress = ['zip', 'rar', '7z', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mp3', 'pdf', 'woff', 'woff2'];
        return !$noCompress.includes(ext);
    }

    /** 发送原始文件 */
    private async $sendRaw(handle: any, start: number, end: number, options: FileSendOptions): Promise<void> {
        const $chunkSize = options.chunkSize || 65536;

        if (start > 0) {
            await handle.seek(start, 0); // 假设fs支持seek
        }

        let $sent = 0;
        const $total = end - start + 1;

        while ($sent < $total) {
            const $toRead = Math.min($chunkSize, $total - $sent);
            const $buffer = new Uint8Array($toRead);
            const $n = await handle.read($buffer);
            if (!$n || $n === 0) break;

            this.$res.write($buffer.slice(0, $n).buffer);
            $sent += $n;

            if (options.onProgress) {
                options.onProgress($sent, $total);
            }
        }

        this.$res.end();
    }

    /** 发送压缩文件 */
    private async $sendCompressed(handle: any, start: number, end: number, options: FileSendOptions): Promise<void> {
        const $encoding = typeof options.compress === 'string' ? options.compress : 'deflate';
        const $level = options.compressLevel ?? DEFAULT_COMPRESSION;
        const $strategy = options.compressStrategy ?? DEFAULT_STRATEGY;

        const $compressor = $encoding === 'gzip'
            ? createGzip($level, $strategy)
            : createDeflate($level, $strategy);

        if (start > 0) {
            await handle.seek(start, 0);
        }

        const $chunkSize = options.chunkSize || 8192;
        let $inputSize = 0;
        let $outputSize = 0;

        while (true) {
            const $buffer = new Uint8Array($chunkSize);
            const $n = await handle.read($buffer);
            if (!$n || $n === 0) break;

            $inputSize += $n;
            const $chunk = $buffer.slice(0, $n);
            const $compressed = $compressor.deflate($chunk);

            if ($compressed.byteLength > 0) {
                $outputSize += $compressed.byteLength;
                this.$res.write($compressed);
            }
        }

        const $final = $compressor.finish();
        if ($final.byteLength > 0) {
            $outputSize += $final.byteLength;
            this.$res.write($final);
        }

        this.$res.end();

        console.log(`${$encoding}压缩: ${$inputSize} -> ${$outputSize} bytes (ratio: ${(100 * $outputSize / $inputSize).toFixed(1)}%)`);
    }

    /** 静态便捷方法 */
    static async send(res: CModuleServer.HttpResponse, options: FileSendOptions): Promise<void> {
        const $wrapper = new FileResponse(res);
        await $wrapper.send(options);
    }
}