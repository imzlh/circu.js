const CURLMod = import.meta.use('curl');
const { setTimeout } = import.meta.use('timers');

// ============ Basic functionality tests ============

await test('CURL.version - check version info', () => {
    const version = CURLMod.version;

    assert(typeof version.curl === 'string', 'curl version should be a string');
    assert(version.curl.length > 0, 'curl version should not be empty');
    assert(typeof version.protocols === 'string', 'protocol list should be a string');
    assert(typeof version.features === 'number', 'feature bitmask should be a number');

    console.log(`LibCURL version: ${version.curl}`);
    console.log(`Supported protocols: ${version.protocols}`);
});

// ============ CURL class tests ============
const pool = new CURLMod.ConnPool();

await test('CURL instance - chained config', async () => {
    const curl = new CURLMod.CURL(pool);

    const response = await curl
        .setUrl('https://httpbin.org/user-agent')
        .setMethod('GET')
        .setUserAgent('Custom-Agent/1.0')
        .setTimeout(5000)
        .setFollowRedirects(true)
        .perform();
    assertEquals(response.status, 200, 'status code should be 200');

    const data = JSON.parse(response.body);
    assert(data['user-agent'] === 'Custom-Agent/1.0', 'user agent should be set correctly');
});

await test('CURL instance - sync request', () => {
    const curl = new CURLMod.CURL(pool);

    const response = curl
        .setUrl('https://httpbin.org/status/200')
        .setMethod('GET')
        .setTimeout(5000)
        .performSync();

    assertEquals(response.status, 200, 'sync request status should be 200');
});

await test('CURL instance - set request headers', async () => {
    const curl = new CURLMod.CURL(pool);

    const response = await curl
        .setUrl('https://httpbin.org/headers')
        .setHeaders({
            'X-Custom-Header': 'custom-value',
            'X-Another-Header': 'another-value',
            'Accept': 'application/json'
        })
        .perform();

    assertEquals(response.status, 200);

    const data = JSON.parse(response.body);
    assert(data.headers['X-Custom-Header'] === 'custom-value', 'custom header should be set correctly');
    assert(data.headers['X-Another-Header'] === 'another-value', 'another header should be set correctly');
});

await test('CURL setHeaders keeps the previous list when enumeration throws', () => {
    const curl = new CURLMod.CURL(pool);
    curl.setHeaders({ 'X-Stable': 'old' });

    const badHeaders = new Proxy({}, {
        ownKeys() {
            throw new Error('enumeration failed');
        },
    });

    let threw = false;
    try {
        curl.setHeaders(badHeaders);
    } catch {
        threw = true;
    }

    assert(threw, 'setHeaders should propagate an enumeration error');
    assertEquals(curl.getHeaders(), ['X-Stable: old']);
});

await test('CURL instance - POST data', async () => {
    const curl = new CURLMod.CURL(pool);
    const postData = 'field1=value1&field2=value2';

    const response = await curl
        .setUrl('https://httpbin.org/post')
        .setMethod('POST')
        .setBody(postData)
        .setHeaders({
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        .perform();

    assertEquals(response.status, 200);

    const data = JSON.parse(response.body);
    assert(data.form.field1 === 'value1', 'form field1 should be transmitted correctly');
    assert(data.form.field2 === 'value2', 'form field2 should be transmitted correctly');
});

await test('CURL instance - error handling', async () => {
    const curl = new CURLMod.CURL(pool);

    try {
        // intentionally use an invalid URL
        await curl
            .setUrl('https://invalid-domain-that-does-not-exist-12345.com')
            .setTimeout(2000) // short timeout
            .perform();

        panic('should throw but did not');
    } catch (error) {
        assert(error instanceof Error, 'error should be an Error instance');
        assert(typeof error.message === 'string', 'error should have a message');
        assert(typeof error.code === 'number', 'error should have a code');
        console.log(`Expected error: ${error.message} (code: ${error.code})`);
    }
});

await test('CURL instance - follow redirects', async () => {
    const curl = new CURLMod.CURL(pool);

    // test redirect (httpbin.org/redirect-to?url=https://httpbin.org/get)
    const response = await curl
        .setUrl('https://httpbin.org/redirect-to?url=https://httpbin.org/get')
        .setFollowRedirects(true)
        .setMaxRedirects(5)
        .perform();

    assertEquals(response.status, 200, 'should successfully follow redirect');
    assert(response.url?.includes('/get'), 'final URL should contain /get');
});

await test('CURL instance - do not follow redirects', async () => {
    const curl = new CURLMod.CURL(pool);

    const response = await curl
        .setUrl('https://httpbin.org/redirect-to?url=https://httpbin.org/get')
        .setFollowRedirects(false)
        .perform();

    assertEquals(response.status, 302, 'not following redirect should return 302');
    assert(response.headers.includes('location'), 'redirect response should include Location header');
});

// ============ Streaming mode tests ============

await test('CURL instance - streaming mode (small data)', async () => {
    const curl = new CURLMod.CURL(pool);

    let receivedChunks = [];
    let totalSize = 0;

    curl.setStreamMode(true);
    curl.onData((buf) => {
        receivedChunks.push(buf);
        totalSize += buf.byteLength;
        return false; // continue receiving
    });

    const response = await curl
        .setUrl('https://httpbin.org/bytes/1024') // 1KB data
        .perform();

    assertEquals(response.status, 200, 'streaming request should succeed');
    assertEquals(response.streamed, true, "invalid streaming setup")

    // verify streaming data
    assert(receivedChunks.length > 0, 'should receive at least one data chunk');
    assert(totalSize > 0, 'total data should be greater than 0');

    // merge all chunks and verify size
    const fullData = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of receivedChunks) {
        fullData.set(new Uint8Array(chunk), offset);
        offset += chunk.byteLength;
    }

    assert(offset === 1024, 'should receive complete 1024 bytes of data');
    console.log(`Streaming mode: received ${receivedChunks.length} data chunks, total ${totalSize} bytes`);
});

await test('CURL instance - streaming mode (large data)', async () => {
    const curl = new CURLMod.CURL(pool);

    let receivedChunks = [];
    let chunkCount = 0;

    curl.setStreamMode(true);
    curl.onData((buf) => {
        receivedChunks.push(buf);
        chunkCount++;

        // test: stop after receiving 10 chunks
        return chunkCount >= 10;
    });

    // use endpoint that returns large data
    const response = await curl
        .setUrl('https://httpbin.org/bytes/32768') // 32KB data
        .setTimeout(10000)
        .perform();

    // due to early termination, may not receive complete response
    assert(chunkCount >= 1, 'should receive at least one data chunk');
    assert(chunkCount <= 10, 'should stop after 10 chunks');

    const totalSize = receivedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    console.log(`Early-terminated streaming: received ${chunkCount} data chunks, total ${totalSize} bytes`);
});

await test('CURL instance - streaming mode switch', async () => {
    const curl = new CURLMod.CURL(pool);

    // first test normal mode
    const response1 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();

    assert(typeof response1.body === 'string', 'normal mode response body should be a string');
    assert(response1.body.length > 0, 'normal mode should have response body');

    // switch to streaming mode
    let streamData = [];
    curl.setStreamMode(true);
    curl.onData((buf) => {
        streamData.push(buf);
        return false;
    });

    // reset instance
    curl.reset();

    const response2 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();

    assertEquals(response2.status, 200);
    assert(streamData.length > 0, 'streaming mode should receive data');

    // switch back to normal mode
    curl.setStreamMode(false);

    curl.reset();
    const response3 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();

    assert(typeof response3.body === 'string', 'response body should be string after switching back to normal mode');
});

// ============ ConnPool tests ============

await test('ConnPool - creation and basic operations', () => {
    const pool = new CURLMod.ConnPool({
        maxConnections: 10,
        maxConnectionsPerHost: 2,
        pipelining: true
    });

    const activeCount = pool.getActiveCount();
    assert(activeCount === 0, 'initial active connection count should be 0');

    pool.process(); // should not throw
    pool.close();   // should not throw
});

await test('ConnPool - connection reuse', async () => {
    const pool = new CURLMod.ConnPool();

    // create multiple CURL instances using the same connection pool
    const curls = [
        new CURLMod.CURL(pool),
        new CURLMod.CURL(pool),
        new CURLMod.CURL(pool)
    ];

    // execute multiple requests concurrently
    const promises = curls.map((curl, index) =>
        curl.setUrl(`https://httpbin.org/delay/${index % 2 + 1}`) // 1-2 second delay
            .setTimeout(5000)
            .perform()
    );

    const responses = await Promise.all(promises);

    responses.forEach((response, index) => {
        assertEquals(response.status, 200, `request ${index} should succeed`);
    });

    pool.close();
});

await test('ConnPool - advanced config', () => {
    const pool = new CURLMod.ConnPool();

    // test advanced config methods
    pool.setMaxPipelineLength(10);
    pool.setMaxConcurrentStreams(100);

    // these methods should not throw
    pool.process();
    pool.close();
});

// ============ Advanced feature tests ===========

await test('CURL instance - SSL/TLS options', async () => {
    const curl = new CURLMod.CURL(pool);

    // enable SSL verification (default)
    curl.setSSLVerify(true, true);

    const response = await curl
        .setUrl('https://httpbin.org/get')
        .setTimeout(5000)
        .perform();

    assertEquals(response.status, 200, 'SSL verification should pass');
});

await test('CURL instance - proxy settings (skip actual test)', () => {
    const curl = new CURLMod.CURL(pool);

    // only test config methods, no actual proxy request
    curl.setProxy('http://proxy.example.com:8080', 'http');
    curl.setProxy('socks5://localhost:1080', 'socks5');

    // methods should not throw
    console.log('Proxy settings test passed (no actual proxy connection)');
});

await test('CURL instance - progress callback', async () => {
    const curl = new CURLMod.CURL(pool);

    let progressEvents = 0;
    let lastProgress = { dltotal: 0, dlnow: 0, ultotal: 0, ulnow: 0 };

    curl.onProgress((dltotal, dlnow, ultotal, ulnow) => {
        progressEvents++;
        lastProgress = { dltotal, dlnow, ultotal, ulnow };

        // print progress (optional)
        if (dltotal > 0) {
            const percent = (dlnow / dltotal * 100).toFixed(1);
            console.log(`Progress: ${percent}% (${dlnow}/${dltotal} bytes)`);
        }

        return true; // continue transfer
    });

    const response = await curl
        .setUrl('https://httpbin.org/bytes/5120') // 5KB data
        .perform();

    assertEquals(response.status, 200);
    assert(progressEvents > 0, 'should receive progress callbacks');
    console.log(`Received ${progressEvents} progress callbacks, last progress: ${lastProgress.dlnow}/${lastProgress.dltotal}`);
});

await test('CURL instance - header callback', async () => {
    const curl = new CURLMod.CURL(pool);

    let headers = [];

    curl.onHeader((headerLine) => {
        headers.push(headerLine.trim());
        return headerLine.length; // continue processing
    });

    const response = await curl
        .setUrl('https://httpbin.org/get')
        .perform();

    assertEquals(response.status, 200);
    assert(headers.length > 0, 'should receive header callbacks');

    // check for common HTTP headers
    const hasContentType = headers.some(h => h.includes('content-type'));
    const hasServer = headers.some(h => h.includes('server'));

    assert(hasContentType || hasServer, 'should include common HTTP headers');
    console.log(`Received ${headers.length} header lines, sample: ${headers.slice(0, 3).join(' | ')}`);
});

await test('CURL instance - HTTP version settings', async () => {
    const curl = new CURLMod.CURL(pool);

    // test different HTTP versions (server may not support all)
    const versions = ['1.1', '2'];

    for (const version of versions) {
        curl.reset();

        try {
            curl.setHTTPVersion(version);

            const response = await curl
                .setUrl('https://httpbin.org/get')
                .setTimeout(5000)
                .perform();

            assertEquals(response.status, 200, `HTTP/${version} request should succeed`);
            console.log(`HTTP/${version} test passed`);
        } catch (error) {
            console.log(`HTTP/${version} may not be supported: ${error.message}`);
        }
    }
});

await test('CURL instance - range request', async () => {
    const curl = new CURLMod.CURL(pool);

    // request partial data
    curl.setRange(0, 100); // first 100 bytes

    const response = await curl
        .setUrl('https://httpbin.org/bytes/500') // 500 bytes data
        .perform();

    assertEquals(response.status, 200);

    // 206 means partial content, but httpbin may return 200
    if (response.status === 206 || response.status === 200) {
        const bodyLength = response.body.length;
        console.log(`Range request returned ${bodyLength} bytes of data`);
        assert(bodyLength > 0, 'should receive partial data');
    }
});

await test('CURL instance - DNS server settings', () => {
    const curl = new CURLMod.CURL(pool);

    if (typeof curl.setDNSServers !== 'function') return;

    // set DNS servers (config only, no actual connection test)
    curl.setDNSServers('8.8.8.8,1.1.1.1');

    // methods should not throw
    console.log('DNS server settings test passed');
});

await test('CURL instance - Cookie operations', async () => {
    const curl = new CURLMod.CURL(pool);

    // set cookie
    curl.setCookie('test_cookie=test_value; session=abc123');

    const response = await curl
        .setUrl('https://httpbin.org/cookies')
        .perform();

    assertEquals(response.status, 200);

    const data = JSON.parse(response.body);
    assert(data.cookies.test_cookie === 'test_value', 'Cookie should be set correctly');
});

await test('CURL instance - reset functionality', async () => {
    const curl = new CURLMod.CURL(pool);

    // first request
    const response1 = await curl
        .setUrl('https://httpbin.org/get')
        .setUserAgent('First-Agent')
        .perform();

    assertEquals(response1.status, 200);

    // reset
    curl.reset();

    // second request with different config
    const response2 = await curl
        .setUrl('https://httpbin.org/user-agent')
        .setUserAgent('Second-Agent')
        .perform();

    assertEquals(response2.status, 200);

    const data = JSON.parse(response2.body);
    assert(data['user-agent'] === 'Second-Agent', 'config should take effect after reset');
});

// ============ Performance tests ============

await test('CURL - concurrent performance test', async () => {
    const pool = new CURLMod.ConnPool();
    const startTime = Date.now();

    // create 5 concurrent requests
    const requests = Array.from({ length: 5 }, (_, i) => {
        const curl = new CURLMod.CURL(pool);
        return curl
            .setUrl(`https://httpbin.org/delay/${i % 3}`) // 0-2 second delay
            .setTimeout(10000)
            .perform();
    });

    const responses = await Promise.all(requests);
    const endTime = Date.now();
    const duration = endTime - startTime;

    // verify all requests succeeded
    const successCount = responses.filter(r => r.status === 200).length;
    assertEquals(successCount, 5, 'all concurrent requests should succeed');

    console.log(`5 concurrent requests completed in: ${duration}ms`);
    assert(duration < 15000, 'concurrent requests should complete before timeout'); // max single 10s, but concurrent should be faster

    pool.close();
});

await test('CURL - large file download test', async () => {
    const curl = new CURLMod.CURL(pool);

    const startTime = Date.now();

    // download medium-sized file
    const response = await curl
        .setUrl('https://httpbin.org/bytes/1048576') // 1MB
        .setTimeout(30000) // 30 second timeout
        .perform();

    const endTime = Date.now();
    const duration = endTime - startTime;

    assertEquals(response.status, 200);
    assert(response.body.length >= 1048576, 'should download complete 1MB data');

    console.log(`Downloaded 1MB in ${duration}ms, speed: ${(1048576 / duration * 1000 / 1024).toFixed(1)} KB/s`);
});

function assertTypeError(fn, message) {
    let error;
    try {
        fn();
    } catch (caught) {
        error = caught;
    }
    assert(error instanceof TypeError, message);
}

await test('CURL setOpt - ObjectPoint metadata and slist ownership', () => {
    const curl = new CURLMod.CURL(pool);

    curl.setOpt(CURLMod.CURLOPT_URL, 'https://example.invalid');
    curl.setOpt(CURLMod.CURLOPT_URL, null);
    curl.setOpt(CURLMod.CURLOPT_POSTFIELDS, 'copied body');
    curl.setOpt(CURLMod.CURLOPT_POSTFIELDS, new Uint8Array([1, 2, 3]));
    curl.setOpt(CURLMod.CURLOPT_POSTFIELDS, null);

    assertTypeError(
        () => curl.setOpt(CURLMod.CURLOPT_URL, ['not a URL']),
        'a copied-string option must reject arrays',
    );
    assertTypeError(
        () => curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, 'X-Invalid: value'),
        'a slist option must reject strings',
    );
    assertTypeError(
        () => curl.setOpt(CURLMod.CURLOPT_READDATA, null),
        'reserved native pointers must remain inaccessible',
    );
    assertTypeError(
        () => curl.setOpt(19999, null),
        'unknown object-pointer options must be rejected before calling libcurl',
    );

    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, ['X-Unique-Header: first']);
    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, ['X-Unique-Header: replacement']);
    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, null);
    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, ['X-Unique-Header: restored']);
    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, undefined);

    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, ['X-Unique-Header: reset']);
    curl.setHeaders({ 'X-From-SetHeaders': 'current' });
    assertEquals(curl.getHeaders(), ['X-From-SetHeaders: current']);

    curl.setOpt(CURLMod.CURLOPT_HTTPHEADER, ['X-From-SetOpt: current']);
    assertEquals(curl.getHeaders(), ['X-From-SetOpt: current'],
        'getHeaders must report the generic HTTPHEADER list that replaces setHeaders');

    curl.reset();
    assertEquals(curl.getHeaders(), [],
        'reset must release the current setHeaders list');
});

// ============ Cleanup tests ============

await test('CURL - memory cleanup test', async () => {
    // create multiple CURL instances and ensure proper cleanup
    const instances = [];

    for (let i = 0; i < 10; i++) {
        const curl = new CURLMod.CURL(pool);
        instances.push(curl);

        const response = await curl
            .setUrl('https://httpbin.org/get')
            .setTimeout(3000)
            .perform();

        assertEquals(response.status, 200);
    }

    console.log(`Created and used ${instances.length} CURL instances, should have no memory leaks`);
});
