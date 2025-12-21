const { TCP } = import.meta.use('streams');
const { resolve } = import.meta.use('dns');
const { Parser, REQUEST, RESPONSE, strerr, strstatus } = import.meta.use('http');
const { Encoder: TextEncoder, Decoder: TextDecoder } = import.meta.use('text');
const { AF_INET } = import.meta.use('os');

// 辅助函数：字符串转 Uint8Array
function encode(str) {
    return new TextEncoder().encode(str);
}

/**
 * 
 * @param {CModuleHTTP.Parser} parser 
 */
function initHandler(parser) {
    parser.onBody = () => void 0;
    parser.onHeaderField = () => void 0;
    parser.onHeaderValue = () => void 0;
    parser.onHeadersComplete = () => void 0;
    parser.onMessageBegin = () => void 0;
    parser.onMessageComplete = () => void 0;
    parser.onStatus = () => void 0;
    parser.onUrl = () => void 0;
    parser.onChunkHeader = () => void 0;
    parser.onChunkComplete = () => void 0;
}

// ----------------------------- 单元测试 -----------------------------

// 测试1: 基本请求解析
test(async () => {
    console.log('Running testBasicRequest...');
    const parser = new Parser(REQUEST);
    const request = 'GET /path?query=value HTTP/1.1\r\nHost: example.com\r\n\r\n';
    const buf = encode(request);
    initHandler(parser);

    let urlCalled = false;
    parser.onUrl = (ev, buffer, off, len) => {
        urlCalled = true;
        const url = new TextDecoder().decode(buf.slice(off, off + len));
        assertEquals(url, '/path?query=value', 'URL mismatch');
    };

    const result = parser.execute(buf);
    assertEquals(result.errno, 0, `Parse error: ${result.name}`);
    assert(urlCalled, 'onUrl callback not called');
    console.log('✓ testBasicRequest passed');
});

// 测试2: 请求头解析
test(async () => {
    console.log('Running testRequestHeaders...');
    const parser = new Parser(REQUEST);
    initHandler(parser);

    const headers = {};
    let currentHeader = '';

    parser.onHeaderField = (ev, buf, off, len) => {
        currentHeader = new TextDecoder().decode(buf.slice(off, off + len)).toLowerCase();
    };

    parser.onHeaderValue = (ev, buf, off, len) => {
        headers[currentHeader] = new TextDecoder().decode(buf.slice(off, off + len));
    };

    const request =
        'POST /api/data HTTP/1.1\r\n' +
        'Host: api.example.com\r\n' +
        'Content-Type: application/json\r\n' +
        'Content-Length: 15\r\n' +
        '\r\n';

    parser.execute(encode(request));

    assertEquals(headers.host, 'api.example.com', 'Host header mismatch');
    assertEquals(headers['content-type'], 'application/json', 'Content-Type mismatch');
    assertEquals(headers['content-length'], '15', 'Content-Length mismatch');
    console.log('✓ testRequestHeaders passed');
});

// 测试3: 响应解析
test(async () => {
    console.log('Running testBasicResponse...');
    const parser = new Parser(RESPONSE);
    initHandler(parser);

    let statusCalled = false;
    parser.onStatus = (ev, buf, off, len) => {
        statusCalled = true;
        const status = new TextDecoder().decode(buf.slice(off, off + len));
        assertEquals(status, 'OK', 'Status text mismatch');
    };

    const response = 'HTTP/1.1 200 OK\r\nServer: test\r\n\r\n';
    const result = parser.execute(encode(response));

    assertEquals(result.errno, 0, `Parse error: ${result.name}`);
    assertEquals(parser.state.status, 200, 'Status code mismatch');
    assert(statusCalled, 'onStatus not called');
    console.log('✓ testBasicResponse passed');
});

// 测试4: Chunked响应解析
test(async () => {
    console.log('Running testChunkedResponse...');
    const parser = new Parser(RESPONSE);
    initHandler(parser);

    const chunks = [];
    let chunkHeaderCount = 0;
    let chunkCompleteCount = 0;

    parser.onChunkHeader = () => {
        chunkHeaderCount++;
    };

    parser.onBody = (ev, buf, off, len) => {
        chunks.push(new TextDecoder().decode(buf.slice(off, off + len)));
    };

    parser.onChunkComplete = () => {
        chunkCompleteCount++;
    };

    const response =
        'HTTP/1.1 200 OK\r\n' +
        'Transfer-Encoding: chunked\r\n' +
        '\r\n' +
        '5\r\n' +
        'Hello\r\n' +
        '6\r\n' +
        ' World\r\n' +
        '0\r\n' +
        '\r\n';

    parser.execute(encode(response));

    assertEquals(chunkHeaderCount, 3, 'Chunk header count mismatch'); // 2 data chunks + 1 final chunk
    assertEquals(chunkCompleteCount, 3, 'Chunk complete count mismatch');
    assertEquals(chunks.join(''), 'Hello World', 'Chunked body mismatch');
    console.log('✓ testChunkedResponse passed');
});

// 测试5: 请求体解析
test(async () => {
    console.log('Running testRequestBody...');
    const parser = new Parser(REQUEST);
    initHandler(parser);

    let body = '';
    let headersCompleteCalled = false;

    parser.onHeadersComplete = () => {
        headersCompleteCalled = true;
    };

    parser.onBody = (ev, buf, off, len) => {
        body += new TextDecoder().decode(buf.slice(off, off + len));
    };

    const request =
        'POST /submit HTTP/1.1\r\n' +
        'Host: form.com\r\n' +
        'Content-Length: 11\r\n' +
        '\r\n' +
        'hello=world';

    parser.execute(encode(request));

    assert(headersCompleteCalled, 'onHeadersComplete not called');
    assertEquals(body, 'hello=world', 'Request body mismatch');
    console.log('✓ testRequestBody passed');
});

// 测试6: 解析器重置
test(async () => {
    console.log('Running testParserReset...');
    const parser = new Parser(REQUEST);
    initHandler(parser);

    parser.execute(encode('GET /first HTTP/1.1\r\n\r\n'));
    assertEquals(parser.state.type, REQUEST, 'Type should be REQUEST');

    parser.reset(RESPONSE);
    parser.execute(encode('HTTP/1.1 200 OK\r\n\r\n'));
    assertEquals(parser.state.type, RESPONSE, 'Type should be RESPONSE after reset');

    console.log('✓ testParserReset passed');
});

// 测试7: 错误处理
test(async () => {
    console.log('Running testErrorHandling...');
    const parser = new Parser(REQUEST);
    initHandler(parser);

    const invalidRequest = 'INVALID HTTP FORMAT\r\n\r\n';
    const result = parser.execute(encode(invalidRequest));

    assert(result.errno !== 0, 'Should have parse error');
    console.log(`✓ Expected error: ${strerr(result.errno)}`);

    console.log('✓ testErrorHandler passed');
});

// 测试8: 暂停/恢复
test(async () => {
    console.log('Running testPauseResume...');
    const parser = new Parser(REQUEST);
    initHandler(parser);

    let callCount = 0;
    parser.onUrl = () => {
        callCount++;
        parser.pause();
    };

    const request = encode('GET /paused HTTP/1.1\r\n\r\n');
    parser.execute(request);

    assertEquals(callCount, 1, 'Callback should be called once before pause');

    // 恢复并继续
    parser.resume();
    parser.execute(request);

    assertEquals(callCount, 2, 'Callback should be called again after resume');
    console.log('✓ testPauseResume passed');
});

// ----------------------------- TCP 集成测试 -----------------------------

// 测试9: 通过TCP发送和接收HTTP消息
await test(async () => {
    console.log('Running testHttpOverTcp...');

    // 客户端发送请求
    const client = new TCP();
    const ip = (await resolve('captive.apple.com', { family: AF_INET }))[0];
    assert(ip, "No IP found for captive.apple.com");
    await client.connect({ ip: ip.ip, port: 80 });

    const request =
        'POST /api/test HTTP/1.1\r\n' +
        'Host: captive.apple.com\r\n' +
        'User-Agent: txiki-test\r\n' +
        'Content-Length: 7\r\n' +
        '\r\n' +
        'testing';

    await client.write(encode(request));

    // 解析响应
    const responseParser = new Parser(RESPONSE);
    const responseInfo = { status: null, body: '' };
    initHandler(responseParser);

    responseParser.onStatus = (ev, buf, off, len) => {
        responseInfo.status = new TextDecoder().decode(buf.slice(off, off + len));
    };

    responseParser.onBody = (ev, buf, off, len) => {
        responseInfo.body += new TextDecoder().decode(buf.slice(off, off + len));
    };

    const respBuf = new Uint8Array(4096);
    const respBytes = await client.read(respBuf);
    if (respBytes) {
        responseParser.execute(respBuf.slice(0, respBytes));
    }

    client.close();

    assertEquals(responseParser.state.status, 200, 'Response status mismatch');
    assert(responseInfo.body.includes('Success'), 'Response body mismatch');
    // assertEquals(responseParser.state.keepAlive, true, 'Keep-Alive mismatch');

    console.log(responseParser.state)

    console.log('✓ testHttpOverTcp passed');
});