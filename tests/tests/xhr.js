// @ts-check
const { use } = import.meta;
const { XMLHttpRequest } = use('xhr');
const _server = use('server');
const { randomBytes } = use('crypto');
const { Encoder: TextEncoder, Decoder: TextDecoder } = use('text');
const timer = use('timers');
const { memoryUsage } = use('os');

if (!_server) throw new Error('server module not built');
const { createServer } = _server;

// ---------- 辅助 ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- 启动测试服务器 ----------
const srv = createServer({
    port: 3242,
    onRequest(req, res) {
        const path = req.url;

        // 1. 流式下载大文件（10 MB）
        if (path === '/stream/10mb') {
            res.writeHead(200, { 
                'content-type': 'application/octet-stream',
                'content-length': '10485760',
            });
            const total = 10 * 1024 * 1024;
            let sent = 0;
            const chunk = 64 * 1024;
            while (sent < total) {
                res.write(randomBytes(Math.min(chunk, total - sent)));
                sent += chunk;
            }
            res.end();
            return;
        }

        // 2. 上传大小校验
        if (path === '/upload/size') {
            //  have body, handle in onBody
            return;
        }

        // 3. 纯文本
        if (path === '/text/hello') {
            res.send(200, 'hello');
            return;
        }

        // 4. 延迟响应
        if (path.startsWith('/delay/')) {
            const ms = parseInt(path.split('/')[2], 10);
            timer.setTimeout(() => res.send(200, 'ok'), ms);
            return;
        }

        // 404
        res.send(404, 'Not Found');
    },

    onBody(req, res, inf) {
        if (req.url == '/upload/size') {
            res.writeHead(200, { 'x-received-size': String(req.body?.byteLength) });
            res.end();
        }
    },
});

const port = 3242;
const BASE = `http://localhost:${port}`;

// ---------- 测试 ----------
await test('1 流式下载：逐块接收，内存不累积', async () => {
    const xhr = new XMLHttpRequest();
    let chunks = 0;
    let bytes = 0;

    xhr.responseType = 'stream';
    xhr.onbody = (chk) => {
        chunks++;
        bytes += chk.byteLength;
    };

    await new Promise ((res, rej) => {
        xhr.onload = () => res();
        xhr.onerror = () => rej(new Error('dl fail'));
        xhr.open('GET', `${BASE}/stream/10mb`);
        xhr.send();
    });

    assert(xhr.status === 200, 'status 200');
    assert(chunks > 100, 'many chunks');
    assert(bytes === 10 * 1024 * 1024, '10 MB');
    console.log('Summary: size=', bytes);
});

await test('2 流式上传：Promise 拉取', async () => {
    const xhr = new XMLHttpRequest();
    const CHUNK = 64 * 1024;
    const TOTAL = 5 * 1024 * 1024;
    let uploaded = 0;

    await new Promise((res, rej) => {
        xhr.onload = () => res();
        xhr.onerror = () => rej(new Error('ul fail'));
        xhr.open('POST', `${BASE}/upload/size`);
        xhr.send(async () => {
            if (uploaded >= TOTAL) return null; // EOF
            uploaded += CHUNK;
            return randomBytes(CHUNK);
        });
    });

    assert(xhr.status === 200, 'status 200');
    const recv = parseInt(xhr.getResponseHeader('x-received-size') || '-1', 10);
    assert(recv === TOTAL, 'server got 5 MB');
    console.log('Summary: uploaded=', uploaded, 'bytes');
});

await test('3 传统缓冲：responseText 正常', async () => {
    const xhr = new XMLHttpRequest();
    xhr.responseType = 'text';
    await new Promise((res, rej) => {
        xhr.onload = () => res();
        xhr.onerror = rej;
        xhr.open('GET', `${BASE}/text/hello`);
        xhr.send();
    });
    assert(xhr.responseText === 'hello', 'text match');
    console.log('responseText:', xhr.responseText);
});

await test('4 状态机完整路径', async () => {
    const xhr = new XMLHttpRequest();
    const states = [];
    xhr.onreadystatechange = () => states.push(xhr.readyState);

    xhr.open('GET', `${BASE}/delay/50`);
    xhr.send();
    await new Promise(res => xhr.onload = res);

    assert(JSON.stringify(states) === JSON.stringify([1, 2, 3, 4]), 'UNSENT→OPENED→HRS→LOADING→DONE');
    console.log('readyState:', xhr.readyState);
});

await test('5 abort() 立即终止', async () => {
    const xhr = new XMLHttpRequest();
    let aborted = false;
    xhr.onabort = () => { aborted = true; };

    xhr.open('GET', `${BASE}/delay/1000`);
    xhr.send();
    await new Promise(resolve => timer.setTimeout(resolve, 10));
    xhr.abort();
    await new Promise(resolve => timer.setTimeout(resolve, 50));

    assert(aborted, 'abort event fired');
    assert(xhr.readyState === 0, 'back to UNSENT');
    console.log('readyState:', xhr.readyState);
});

await test('6 大文件流式上传：内存恒定', async () => {
    const MB = 1024 * 1024;
    const TOTAL = 200 * MB;
    let sent = 0;

    const before = memoryUsage()["buffer.used"];

    await new Promise((res, rej) => {
        const xhr = new XMLHttpRequest();
        xhr.onload = () => res();
        xhr.onerror = rej;
        xhr.open('POST', `${BASE}/upload/size`);
        xhr.send(async () => {
            if (sent >= TOTAL) return null;
            sent += MB;
            return randomBytes(MB);
        });
    });

    const after = memoryUsage()['buffer.used'];
    const delta = after - before;
    assert(delta < 50 * MB, `heap delta < 50MB (actual ${(delta / MB).toFixed(1)}MB)`);
    console.log('Summary: sent=', sent, 'bytes');
});

// ---------- 收尾 ----------
srv.close();
console.log('✅ 全部通过');