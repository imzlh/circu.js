// test-stream-sync.ts
const engine = import.meta.use('engine');
const stream = import.meta.use('streams');
const os = import.meta.use('os');
const dns = import.meta.use('dns');

// 测试同步读取流
await test('Stream.readSync - Basic functionality', () => {
    // 创建一个测试用的TCP连接
    const client = new stream.TCP();
    
    try {
        // 先解析域名获取IP地址
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // 使用第一个IPv4地址
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        console.log(addresses)
        
        // 尝试连接到一个公共服务器
        client.connectSync({ ip, port: 80 });
        console.log('Connect OK')
        
        // 尝试读取数据（可能会因为没有数据而返回null或空数组）
        client.writeSync(engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'))
        const buffer = new Uint8Array(1024);
        let bytesRead = client.readSync(buffer);
        console.log('read ok:', bytesRead, buffer.subarray(0, bytesRead), engine.decodeString(buffer.subarray(0, bytesRead)))
        
        // 验证返回值是预期的类型
        assert(typeof bytesRead === 'number' || bytesRead === null, 'Should return number of bytes read or null');
        
        if (bytesRead !== null) {
            assert(bytesRead <= 1024, 'Bytes read should not exceed buffer size');
            // 获取实际读取的数据
            const data = buffer.subarray(0, bytesRead);
            assert(data instanceof Uint8Array, 'Data should be a Uint8Array');
        }
    } finally {
        client.close();
    }
});

// 测试同步写入流
await test('Stream.writeSync - Basic functionality', () => {
    // 创建一个测试用的TCP连接
    const client = new stream.TCP();
    
    try {
        // 先解析域名获取IP地址
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // 使用第一个IPv4地址
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        
        // 尝试连接到一个公共服务器
        client.connectSync({ ip, port: 80 });
        
        // 创建一个简单的HTTP请求
        const requestData = engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
        
        // 尝试写入数据
        const bytesWritten = client.writeSync(requestData);
        
        // 验证写入的字节数
        assert(typeof bytesWritten === 'number', 'Should return number of bytes written');
        assert(bytesWritten > 0, 'Should write at least one byte');
        assert(bytesWritten <= requestData.length, 'Should not write more than requested');
    } finally {
        client.close();
    }
});

// 测试大文件同步操作
await test('Stream - Large file sync operations', () => {
    // 创建一个测试用的TCP连接
    const client = new stream.TCP();
    
    try {
        // 先解析域名获取IP地址
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // 使用第一个IPv4地址
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        
        // 尝试连接到一个公共服务器
        client.connectSync({ ip, port: 80 });
        
        // 发送一个简单的HTTP请求
        const requestData = engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');
        client.writeSync(requestData);
        
        // 尝试读取大量数据
        let totalBytesRead = 0;
        const maxReads = 10; // 限制读取次数以避免无限循环
        
        for (let i = 0; i < maxReads; i++) {
            const buffer = new Uint8Array(8192); // 8KB缓冲区
            const bytesRead = client.readSync(buffer);
            
            if (bytesRead === null || bytesRead === 0) {
                break; // 没有更多数据
            }
            
            totalBytesRead += bytesRead;
        }
        
        // 验证读取了一些数据
        assert(totalBytesRead >= 0, 'Should read non-negative bytes');
        
        console.log(`Read ${totalBytesRead} bytes from server`);
    } finally {
        client.close();
    }
});

// 测试错误处理
await test('Stream - Error handling', () => {
    // 创建一个测试用的TCP连接
    const client = new stream.TCP();
    
    try {
        // 尝试连接到一个不存在的服务器
        try {
            client.connectSync({ ip: 'this-domain-does-not-exist-12345.com', port: 80 });
            assert(false, 'Should throw an error for invalid domain');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
        
        // 尝试向未连接的流写入数据
        try {
            const textEncoder = new TextEncoder();
            const requestData = textEncoder.encode('test data');
            client.writeSync(requestData);
            assert(false, 'Should throw an error for writing to unconnected stream');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
        
        // 尝试从未连接的流读取数据
        try {
            const buffer = new Uint8Array(1024);
            client.readSync(buffer);
            assert(false, 'Should throw an error for reading from unconnected stream');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
    } finally {
        client.close();
    }
});

// 测试同步与异步结果一致性
await test('Stream - Result consistency', async () => {
    // 创建两个TCP连接
    const syncClient = new stream.TCP();
    const asyncClient = new stream.TCP();
    
    try {
        const ip = dns.resolveSync('www.gstatic.com', { family: os.AF_UNSPEC })[0].ip;
        // 连接到公共服务器
        syncClient.connectSync({ ip, port: 80 });
        
        await asyncClient.connect({ ip, port: 80 });
        
        // 准备测试数据
        const requestData = engine.encodeString('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n');
        
        // 异步写入
        await asyncClient.write(requestData);

        // 同步写入
        syncClient.writeSync(requestData);
        
        // 同步读取
        const syncData = new Uint8Array(1024);
        syncClient.readSync(syncData);
        
        // 异步读取
        const asyncData = new Uint8Array(1024);
        await asyncClient.read(asyncData);
        
        // 验证结果一致性
        if (syncData !== null && asyncData !== null) {
            assert(syncData.length === asyncData.length, 'Data length should be consistent');
            
            // 比较前几个字节（可能由于网络延迟，完整数据可能不同）
            let failed = false;
            const compareLength = Math.min(syncData.length, asyncData.length);
            for (let i = 0; i < compareLength; i++) {
                if (syncData[i] !== asyncData[i]) {
                    console.log(`Byte ${i} differs: sync=${syncData[i]}, async=${asyncData[i]}`);
                    failed = true;
                }
            }
            if (failed) {
                console.log('Data differs');
                console.log(engine.decodeString(syncData), '\n', engine.decodeString(asyncData));
            }
            assert(!failed, 'Data should be consistent');
            console.log('Data is consistent');
        }
    } finally {
        syncClient.close();
        asyncClient.close();
    }
});