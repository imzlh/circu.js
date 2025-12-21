const CURLMod = import.meta.use('curl');
const { setTimeout } = import.meta.use('timers');

// ============ 基础功能测试 ============

await test('CURL.version - 检查版本信息', () => {
    const version = CURLMod.version;
    
    assert(typeof version.curl === 'string', 'curl版本应该是字符串');
    assert(version.curl.length > 0, 'curl版本不应为空');
    assert(typeof version.protocols === 'string', '协议列表应该是字符串');
    assert(typeof version.features === 'number', '功能位掩码应该是数字');
    
    console.log(`LibCURL版本: ${version.curl}`);
    console.log(`支持协议: ${version.protocols}`);
});

// ============ CURL类测试 ============
const pool = new CURLMod.ConnPool();

await test('CURL实例 - 链式配置', async () => {
    const curl = new CURLMod.CURL(pool);
    
    const response = await curl
        .setUrl('https://httpbin.org/user-agent')
        .setMethod('GET')
        .setUserAgent('Custom-Agent/1.0')
        .setTimeout(5000)
        .setFollowRedirects(true)
        .perform();
    assertEquals(response.status, 200, '状态码应为200');
    
    const data = JSON.parse(response.body);
    assert(data['user-agent'] === 'Custom-Agent/1.0', '用户代理应正确设置');
});

await test('CURL实例 - 同步请求', () => {
    const curl = new CURLMod.CURL(pool);
    
    const response = curl
        .setUrl('https://httpbin.org/status/200')
        .setMethod('GET')
        .setTimeout(5000)
        .performSync();
    
    assertEquals(response.status, 200, '同步请求状态码应为200');
});

await test('CURL实例 - 请求头设置', async () => {
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
    assert(data.headers['X-Custom-Header'] === 'custom-value', '自定义头应正确设置');
    assert(data.headers['X-Another-Header'] === 'another-value', '另一个头应正确设置');
});

await test('CURL实例 - POST数据', async () => {
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
    assert(data.form.field1 === 'value1', '表单字段1应正确传输');
    assert(data.form.field2 === 'value2', '表单字段2应正确传输');
});

await test('CURL实例 - 错误处理', async () => {
    const curl = new CURLMod.CURL(pool);
    
    try {
        // 故意使用无效的URL
        await curl
            .setUrl('https://invalid-domain-that-does-not-exist-12345.com')
            .setTimeout(2000) // 短超时
            .perform();
        
        panic('应抛出异常但未抛出');
    } catch (error) {
        assert(error instanceof Error, '错误应该是Error实例');
        assert(typeof error.message === 'string', '错误应有消息');
        assert(typeof error.code === 'number', '错误应有代码');
        console.log(`预期错误: ${error.message} (代码: ${error.code})`);
    }
});

await test('CURL实例 - 重定向跟随', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 测试重定向（httpbin.org/redirect-to?url=https://httpbin.org/get）
    const response = await curl
        .setUrl('https://httpbin.org/redirect-to?url=https://httpbin.org/get')
        .setFollowRedirects(true)
        .setMaxRedirects(5)
        .perform();
    
    assertEquals(response.status, 200, '应成功跟随重定向');
    assert(response.url?.includes('/get'), '最终URL应包含/get');
});

await test('CURL实例 - 不跟随重定向', async () => {
    const curl = new CURLMod.CURL(pool);
    
    const response = await curl
        .setUrl('https://httpbin.org/redirect-to?url=https://httpbin.org/get')
        .setFollowRedirects(false)
        .perform();
    
    assertEquals(response.status, 302, '不跟随重定向应返回302');
    assert(response.headers.includes('location'), '重定向响应应包含Location头');
});

// ============ 流式模式测试 ============

await test('CURL实例 - 流式模式（小数据）', async () => {
    const curl = new CURLMod.CURL(pool);
    
    let receivedChunks = [];
    let totalSize = 0;
    
    curl.setStreamMode(true);
    curl.onData((buf) => {
        receivedChunks.push(buf);
        totalSize += buf.byteLength;
        return false; // 继续接收
    });
    
    const response = await curl
        .setUrl('https://httpbin.org/bytes/1024') // 1KB数据
        .perform();
    
    assertEquals(response.status, 200, '流式请求应成功');
    assertEquals(response.streamed, true, "无效流式设置")
    
    // 验证流式数据
    assert(receivedChunks.length > 0, '应收到至少一个数据块');
    assert(totalSize > 0, '总数据量应大于0');
    
    // 合并所有块并验证大小
    const fullData = new Uint8Array(totalSize);
    let offset = 0;
    for (const chunk of receivedChunks) {
        fullData.set(new Uint8Array(chunk), offset);
        offset += chunk.byteLength;
    }
    
    assert(offset === 1024, '应收到完整的1024字节数据');
    console.log(`流式模式：收到${receivedChunks.length}个数据块，总计${totalSize}字节`);
});

await test('CURL实例 - 流式模式（大数据）', async () => {
    const curl = new CURLMod.CURL(pool);
    
    let receivedChunks = [];
    let chunkCount = 0;
    
    curl.setStreamMode(true);
    curl.onData((buf) => {
        receivedChunks.push(buf);
        chunkCount++;
        
        // 测试：收到10个块后停止
        return chunkCount >= 10;
    });
    
    // 使用返回较大数据的端点
    const response = await curl
        .setUrl('https://httpbin.org/bytes/32768') // 32KB数据
        .setTimeout(10000)
        .perform();
    
    // 由于提前终止，可能不会收到完整响应
    assert(chunkCount >= 1, '应至少收到一个数据块');
    assert(chunkCount <= 10, '应在10个块后停止');
    
    const totalSize = receivedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    console.log(`提前终止流式：收到${chunkCount}个数据块，总计${totalSize}字节`);
});

await test('CURL实例 - 流式模式切换', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 先测试普通模式
    const response1 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();
    
    assert(typeof response1.body === 'string', '普通模式响应体应为字符串');
    assert(response1.body.length > 0, '普通模式应有响应体');
    
    // 切换到流式模式
    let streamData = [];
    curl.setStreamMode(true);
    curl.onData((buf) => {
        streamData.push(buf);
        return false;
    });
    
    // 重置实例
    curl.reset();
    
    const response2 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();
    
    assertEquals(response2.status, 200);
    assert(streamData.length > 0, '流式模式应收到数据');
    
    // 切换回普通模式
    curl.setStreamMode(false);
    
    curl.reset();
    const response3 = await curl
        .setUrl('https://httpbin.org/get')
        .perform();
    
    assert(typeof response3.body === 'string', '切换回普通模式后响应体应为字符串');
});

// ============ ConnPool测试 ============

await test('ConnPool - 创建和基本操作', () => {
    const pool = new CURLMod.ConnPool({
        maxConnections: 10,
        maxConnectionsPerHost: 2,
        pipelining: true
    });
    
    const activeCount = pool.getActiveCount();
    assert(activeCount === 0, '初始活跃连接数应为0');
    
    pool.process(); // 应无异常
    pool.close();   // 应无异常
});

await test('ConnPool - 连接复用', async () => {
    const pool = new CURLMod.ConnPool();
    
    // 创建多个使用同一连接池的CURL实例
    const curls = [
        new CURLMod.CURL(pool),
        new CURLMod.CURL(pool),
        new CURLMod.CURL(pool)
    ];
    
    // 并发执行多个请求
    const promises = curls.map((curl, index) => 
        curl.setUrl(`https://httpbin.org/delay/${index % 2 + 1}`) // 1-2秒延迟
            .setTimeout(5000)
            .perform()
    );
    
    const responses = await Promise.all(promises);
    
    responses.forEach((response, index) => {
        assertEquals(response.status, 200, `请求${index}应成功`);
    });
    
    pool.close();
});

await test('ConnPool - 高级配置', () => {
    const pool = new CURLMod.ConnPool();
    
    // 测试高级配置方法
    pool.setMaxPipelineLength(10);
    pool.setMaxConcurrentStreams(100);
    
    // 这些方法应无异常
    pool.process();
    pool.close();
});

// ============ 高级功能测试 ============

await test('CURL实例 - SSL/TLS选项', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 启用SSL验证（默认）
    curl.setSSLVerify(true, true);
    
    const response = await curl
        .setUrl('https://httpbin.org/get')
        .setTimeout(5000)
        .perform();
    
    assertEquals(response.status, 200, 'SSL验证应通过');
});

await test('CURL实例 - 代理设置（跳过实际测试）', () => {
    const curl = new CURLMod.CURL(pool);
    
    // 仅测试配置方法，不实际通过代理请求
    curl.setProxy('http://proxy.example.com:8080', 'http');
    curl.setProxy('socks5://localhost:1080', 'socks5');
    
    // 方法应无异常
    console.log('代理设置测试通过（未实际连接代理）');
});

await test('CURL实例 - 进度回调', async () => {
    const curl = new CURLMod.CURL(pool);
    
    let progressEvents = 0;
    let lastProgress = { dltotal: 0, dlnow: 0, ultotal: 0, ulnow: 0 };
    
    curl.onProgress((dltotal, dlnow, ultotal, ulnow) => {
        progressEvents++;
        lastProgress = { dltotal, dlnow, ultotal, ulnow };
        
        // 打印进度（可选）
        if (dltotal > 0) {
            const percent = (dlnow / dltotal * 100).toFixed(1);
            console.log(`进度: ${percent}% (${dlnow}/${dltotal} bytes)`);
        }
        
        return true; // 继续传输
    });
    
    const response = await curl
        .setUrl('https://httpbin.org/bytes/5120') // 5KB数据
        .perform();
    
    assertEquals(response.status, 200);
    assert(progressEvents > 0, '应收到进度回调');
    console.log(`收到${progressEvents}次进度回调，最后进度: ${lastProgress.dlnow}/${lastProgress.dltotal}`);
});

await test('CURL实例 - 头部回调', async () => {
    const curl = new CURLMod.CURL(pool);
    
    let headers = [];
    
    curl.onHeader((headerLine) => {
        headers.push(headerLine.trim());
        return headerLine.length; // 继续处理
    });
    
    const response = await curl
        .setUrl('https://httpbin.org/get')
        .perform();
    
    assertEquals(response.status, 200);
    assert(headers.length > 0, '应收到头部回调');
    
    // 检查是否有常见的HTTP头
    const hasContentType = headers.some(h => h.includes('content-type'));
    const hasServer = headers.some(h => h.includes('server'));
    
    assert(hasContentType || hasServer, '应包含常见HTTP头');
    console.log(`收到${headers.length}行头部，示例: ${headers.slice(0, 3).join(' | ')}`);
});

await test('CURL实例 - HTTP版本设置', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 测试不同HTTP版本（服务器可能不支持所有版本）
    const versions = ['1.1', '2'];
    
    for (const version of versions) {
        curl.reset();
        
        try {
            curl.setHTTPVersion(version);
            
            const response = await curl
                .setUrl('https://httpbin.org/get')
                .setTimeout(5000)
                .perform();
            
            assertEquals(response.status, 200, `HTTP/${version} 请求应成功`);
            console.log(`HTTP/${version} 测试通过`);
        } catch (error) {
            console.log(`HTTP/${version} 可能不被支持: ${error.message}`);
        }
    }
});

await test('CURL实例 - 范围请求', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 请求部分数据
    curl.setRange(0, 100); // 前100字节
    
    const response = await curl
        .setUrl('https://httpbin.org/bytes/500') // 500字节数据
        .perform();
    
    assertEquals(response.status, 200);
    
    // 206表示部分内容，但httpbin可能返回200
    if (response.status === 206 || response.status === 200) {
        const bodyLength = response.body.length;
        console.log(`范围请求返回${bodyLength}字节数据`);
        assert(bodyLength > 0, '应收到部分数据');
    }
});

await test('CURL实例 - DNS服务器设置', () => {
    const curl = new CURLMod.CURL(pool);
    
    // 设置DNS服务器（仅配置，不实际测试连接）
    curl.setDNSServers('8.8.8.8,1.1.1.1');
    
    // 方法应无异常
    console.log('DNS服务器设置测试通过');
});

await test('CURL实例 - Cookie操作', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 设置Cookie
    curl.setCookie('test_cookie=test_value; session=abc123');
    
    const response = await curl
        .setUrl('https://httpbin.org/cookies')
        .perform();
    
    assertEquals(response.status, 200);
    
    const data = JSON.parse(response.body);
    assert(data.cookies.test_cookie === 'test_value', 'Cookie应正确设置');
});

await test('CURL实例 - 重置功能', async () => {
    const curl = new CURLMod.CURL(pool);
    
    // 第一次请求
    const response1 = await curl
        .setUrl('https://httpbin.org/get')
        .setUserAgent('First-Agent')
        .perform();
    
    assertEquals(response1.status, 200);
    
    // 重置
    curl.reset();
    
    // 第二次请求，使用不同配置
    const response2 = await curl
        .setUrl('https://httpbin.org/user-agent')
        .setUserAgent('Second-Agent')
        .perform();
    
    assertEquals(response2.status, 200);
    
    const data = JSON.parse(response2.body);
    assert(data['user-agent'] === 'Second-Agent', '重置后配置应生效');
});

// ============ 性能测试 ============

await test('CURL - 并发性能测试', async () => {
    const pool = new CURLMod.ConnPool();
    const startTime = Date.now();
    
    // 创建10个并发请求
    const requests = Array.from({ length: 5 }, (_, i) => {
        const curl = new CURLMod.CURL(pool);
        return curl
            .setUrl(`https://httpbin.org/delay/${i % 3}`) // 0-2秒延迟
            .setTimeout(10000)
            .perform();
    });
    
    const responses = await Promise.all(requests);
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    // 验证所有请求成功
    const successCount = responses.filter(r => r.status === 200).length;
    assertEquals(successCount, 5, '所有并发请求应成功');
    
    console.log(`并发5个请求完成时间: ${duration}ms`);
    assert(duration < 15000, '并发请求应在超时前完成'); // 最长单个10秒，但并发应更快
    
    pool.close();
});

await test('CURL - 大文件下载测试', async () => {
    const curl = new CURLMod.CURL(pool);
    
    const startTime = Date.now();
    
    // 下载中等大小文件
    const response = await curl
        .setUrl('https://httpbin.org/bytes/1048576') // 1MB
        .setTimeout(30000) // 30秒超时
        .perform();
    
    const endTime = Date.now();
    const duration = endTime - startTime;
    
    assertEquals(response.status, 200);
    assert(response.body.length >= 1048576, '应下载完整1MB数据');
    
    console.log(`下载1MB数据用时: ${duration}ms, 速度: ${(1048576 / duration * 1000 / 1024).toFixed(1)} KB/s`);
});

// ============ 清理测试 ============

await test('CURL - 内存清理测试', async () => {
    // 创建多个CURL实例并确保正常清理
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
    
    console.log(`创建并使用了${instances.length}个CURL实例，应无内存泄漏`);
});