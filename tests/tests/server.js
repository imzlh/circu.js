// @ts-check
/// <reference types="../type" />

import fetch from "../polyfill/fetch.js";

/**
 * Server 模块功能测试
 * 测试 HTTP 服务器的各项功能
 */

// 导入所需模块
const { createServer } = use('server');
const { Context, createSelfSignedCert } = use('ssl');
const { writeFile, unlink } = use('fs');
const { TCP } = use('streams');
const { setTimeout } = use('timers');
const { Decoder: TextDecoder, Encoder: TextEncoder } = use('text');

// 测试基础 HTTP 服务器功能
async function testBasicServer() {
    console.log('=== 测试基础 HTTP 服务器功能 ===');
    
    let requestCount = 0;
    
    const server = createServer({
        port: 8080,
        address: '127.0.0.1',
        
        onRequest: (req, res) => {
            requestCount++;
            console.log(`收到请求 #${requestCount}: ${req.method} ${req.url}`);
            
            // 测试不同的路由和响应方式
            if (req.url === '/') {
                // 测试 send 方法
                res.send(200, 'Hello World');
            } else if (req.url === '/json') {
                // 测试 writeHead + end
                res.writeHead(200, {
                    'Content-Type': 'application/json',
                    'X-Custom-Header': 'test'
                });
                res.end(JSON.stringify({ message: 'Hello JSON' }));
            } else if (req.url === '/chunked') {
                // 测试分块传输
                res.writeHead(200, {
                    'Content-Type': 'text/plain',
                    'Transfer-Encoding': 'chunked'
                });
                
                let chunkCount = 0;
                const sendChunk = () => {
                    if (chunkCount < 3) {
                        res.write(`Chunk ${chunkCount}\n`);
                        chunkCount++;
                        setTimeout(sendChunk, 100);
                    } else {
                        res.end();
                    }
                };
                sendChunk();
            } else if (req.url === '/not-found') {
                res.send(404, 'Not Found');
            } else {
                res.send(400, 'Bad Request');
            }
        },
        
        onError: (err, req, res) => {
            console.error('服务器错误:', err.message);
            res.send(500, 'Internal Server Error');
        }
    });
    
    // 等待服务器启动
    // @ts-ignore
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
        // 测试 GET 请求到根路径
        const response1 = await fetch('http://127.0.0.1:8080/');
        const text1 = await response1.text();
        assert(response1.status === 200, '根路径状态码应为 200');
        assert(text1 === 'Hello World', '根路径响应内容应为 Hello World');
        console.log('✓ 根路径测试通过');
        
        // 测试 JSON 响应
        const response2 = await fetch('http://127.0.0.1:8080/json');
        const json2 = await response2.json();
        assert(response2.status === 200, 'JSON 路径状态码应为 200');
        assert(json2.message === 'Hello JSON', 'JSON 响应内容正确');
        assert(response2.headers.get('content-type') === 'application/json', 'Content-Type 头正确');
        console.log('✓ JSON 响应测试通过');
        
        // 测试 404
        const response3 = await fetch('http://127.0.0.1:8080/not-found');
        assert(response3.status === 404, '未找到路径状态码应为 404');
        console.log('✓ 404 测试通过');
        
        // 测试分块传输
        const response4 = await fetch('http://127.0.0.1:8080/chunked');
        const text4 = await response4.text();
        assert(response4.status === 200, '分块传输状态码应为 200');
        assert(text4.includes('Chunk'), '分块传输内容正确');
        console.log('✓ 分块传输测试通过');
        
    } catch (error) {
        console.error('HTTP 请求测试失败:', error);
        throw error;
    } finally {
        // 关闭服务器
        server.close();
        console.log('服务器已关闭');
    }
}

// 测试 POST 请求和请求体处理
async function testPostRequests() {
    console.log('\n=== 测试 POST 请求和请求体处理 ===');
    
    const server = createServer({
        port: 8081,
        address: '127.0.0.1',
        
        onRequest: (req, res) => {
            if (req.method === 'POST') {
                if (req.body) {
                    const textDecoder = new TextDecoder();
                    const bodyText = textDecoder.decode(req.body);
                    
                    try {
                        const jsonData = JSON.parse(bodyText);
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ 
                            received: jsonData,
                            length: req.body.byteLength
                        }));
                    } catch (e) {
                        // 如果不是 JSON，返回原始文本
                        res.writeHead(200, { 'Content-Type': 'text/plain' });
                        res.end(`Received: ${bodyText}`);
                    }
                } else {
                    res.send(400, 'No body received');
                }
            } else {
                res.send(405, 'Method Not Allowed');
            }
        }
    });
    
    // @ts-ignore
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
        // 测试 JSON POST 请求
        const jsonData = { message: 'Hello Server', number: 42 };
        const response1 = await fetch('http://127.0.0.1:8081/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(jsonData)
        });
        
        const result1 = await response1.json();
        assert(response1.status === 200, 'POST 请求状态码应为 200');
        assert(result1.received.message === jsonData.message, 'JSON 数据正确接收');
        console.log('✓ JSON POST 测试通过');
        
        // 测试普通文本 POST 请求
        const response2 = await fetch('http://127.0.0.1:8081/', {
            method: 'POST',
            body: 'Hello Text'
        });
        
        const text2 = await response2.text();
        assert(text2.includes('Hello Text'), '文本数据正确接收');
        console.log('✓ 文本 POST 测试通过');
        
    } catch (error) {
        console.error('POST 请求测试失败:', error);
        throw error;
    } finally {
        server.close();
    }
}

// 测试服务器端事件 (Server-Sent Events)
async function testServerSentEvents() {
    console.log('\n=== 测试服务器端事件 (SSE) ===');
    
    const server = createServer({
        port: 8082,
        address: '127.0.0.1',
        
        onRequest: (req, res) => {
            if (req.url === '/events') {
                res.writeHead(200, {
                    'Content-Type': 'text/event-stream',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive'
                });
                
                let eventCount = 0;
                const sendEvent = () => {
                    if (eventCount < 3) {
                        res.write(`data: Event ${eventCount} at ${Date.now()}\n\n`);
                        eventCount++;
                        setTimeout(sendEvent, 50);
                    } else {
                        res.write('data: [DONE]\n\n');
                        res.end();
                    }
                };
                
                sendEvent();
            } else {
                res.send(404, 'Not Found');
            }
        }
    });
    
    // @ts-ignore
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
        const response = await fetch('http://127.0.0.1:8082/events');
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let receivedEvents = 0;
        
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const text = decoder.decode(value);
            if (text.includes('data: ')) {
                receivedEvents++;
            }
            if (text.includes('[DONE]')) {
                break;
            }
        }
        
        assert(receivedEvents >= 3, `应收到至少 3 个事件，实际收到: ${receivedEvents}`);
        console.log('✓ SSE 测试通过，收到事件:', receivedEvents);
        
    } catch (error) {
        console.error('SSE 测试失败:', error);
        throw error;
    } finally {
        server.close();
    }
}

// 测试连接升级功能 (WebSocket 模拟)
async function testUpgrade() {
    console.log('\n=== 测试连接升级功能 ===');
    
    const server = createServer({
        port: 8083,
        address: '127.0.0.1',
        
        onRequest: (req, res) => {
            // 检查升级头
            if (req.headers.upgrade === 'websocket') {
                console.log('收到 WebSocket 升级请求');
                
                // 升级连接
                const fd = res.upgrade();
                console.log(`连接已升级，文件描述符: ${fd}`);
                
                // 注意：在实际应用中，你需要使用 streams.Pipe 来处理原始连接
                // 这里只是演示升级过程
                res.send(101, 'Switching Protocols');
            } else {
                res.send(426, 'Upgrade Required');
            }
        }
    });
    
    // @ts-ignore
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
        // 注意：由于 fetch API 不支持 Upgrade 头，我们使用 TCP 连接进行测试
        const client = new TCP();
        await client.connect({
            ip: '127.0.0.1',
            port: 8083
        });
        
        // 发送 WebSocket 升级请求
        const upgradeRequest = `GET / HTTP/1.1\r\nHost: 127.0.0.1:8083\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`;
        await client.write(new Uint8Array(new TextEncoder().encode(upgradeRequest)));
        
        // 读取响应
        // @ts-ignore
        await new Promise(resolve => setTimeout(resolve, 500));
        const response = new Uint8Array(1024);
        const byteReaded = await client.read(response);
        const responseText = new TextDecoder().decode(response.subarray(0, byteReaded ?? 0));
        
        assert(responseText.includes('101'), '应返回 101 状态码');
        console.log('✓ 连接升级测试通过');
        
        client.close();
        
    } catch (error) {
        console.error('连接升级测试失败:', error);
        throw error;
    } finally {
        server.close();
    }
}

// 测试 SSL/TLS 功能
async function testSSL() {
    console.log('\n=== 测试 SSL/TLS 功能 ===');
    
    try {
        // 生成自签名证书
        const { cert, key } = createSelfSignedCert({
            commonName: 'localhost',
            days: 365
        });
        
        await writeFile('test-cert.pem', new TextEncoder().encode(cert));
        await writeFile('test-key.pem', new TextEncoder().encode(key));
        
        // 创建 SSL 上下文
        const Context = new Context({
            mode: "server",
            cert: 'test-cert.pem',
            key: 'test-key.pem',
            alpn: ["http/1.1"]
        });
        
        const server = createServer({
            port: 8443,
            address: '127.0.0.1',
            
            onAccept: (info) => {
                console.log('新连接接受:', info);
                return Context; // 使用 SSL
            },
            
            onRequest: (req, res) => {
                res.send(200, 'Hello HTTPS');
            }
        });
        
        console.log('✓ SSL 服务器创建成功');
        
        // 注意：由于需要处理 SSL 握手，这里只是演示服务器创建
        // 实际测试需要 SSL 客户端
        
    } catch (error) {
        console.error('SSL 测试失败:', error);
        throw error;
    } finally {
        // 清理临时文件
        try {
            await unlink('test-cert.pem');
            await unlink('test-key.pem');
        } catch (e) {
            // 忽略文件删除错误
        }
    }
}

// 测试错误处理
async function testErrorHandling() {
    console.log('\n=== 测试错误处理 ===');
    
    let errorHandled = false;
    
    const server = createServer({
        port: 8084,
        address: '127.0.0.1',
        
        onRequest: (req, res) => {
            // 模拟服务器端错误
            throw new Error('模拟服务器错误');
        },
        
        onError: (err, req, res) => {
            errorHandled = true;
            console.log('错误处理回调被调用:', err.message);
            res.send(500, 'Custom Error Message');
        }
    });
    
    // @ts-ignore
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
        const response = await fetch('http://127.0.0.1:8084/');
        const text = await response.text();
        
        assert(errorHandled, '错误处理回调应被调用');
        assert(response.status === 500, '应返回 500 状态码');
        assert(text === 'Custom Error Message', '应返回自定义错误消息');
        console.log('✓ 错误处理测试通过');
        
    } catch (error) {
        console.error('错误处理测试失败:', error);
        throw error;
    } finally {
        server.close();
    }
}

// 运行所有测试
async function runAllTests() {
    try {
        console.log('开始 Server 模块测试...\n');
        
        await testBasicServer();
        await testPostRequests();
        await testServerSentEvents();
        await testUpgrade();
        await testSSL();
        await testErrorHandling();
        
        console.log('\n🎉 所有测试通过！');
        
    } catch (error) {
        console.error('\n❌ 测试失败:', error);
        throw error;
    }
}

runAllTests();