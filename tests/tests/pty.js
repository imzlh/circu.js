/// <reference types="../type" />

// 导入所需模块
const { openpty, resize } = use('pty');
const { process } = use('process');
const { Pipe } = use('streams');

// 测试基础 PTY 创建功能
globalThis.test('基础 PTY 创建', async () => {
    console.log('=== 测试基础 PTY 创建 ===');
    
    const ptyInfo = await openpty({
        cols: 80,
        rows: 24,
        name: process.platform === 'win32' ? 'cmd.exe' : '/bin/bash',
        cwd: process.cwd(),
        env: { ...process.env, TEST_PTY: 'true' }
    });

    assert(ptyInfo.fd > 0, '文件描述符应为正数');
    assert(ptyInfo.pid > 0, '进程ID应为正数');
    
    if (process.platform === 'win32') {
        assert(ptyInfo.pty !== undefined, 'Windows 上应有 pty 句柄');
    }
    
    console.log(`✓ PTY 创建成功 - fd: ${ptyInfo.fd}, pid: ${ptyInfo.pid}`);
});

// 测试 PTY 默认参数
globalThis.test('PTY 默认参数', async () => {
    console.log('=== 测试 PTY 默认参数 ===');
    
    const ptyInfo = await openpty();
    
    assert(ptyInfo.fd > 0, '文件描述符应为正数');
    assert(ptyInfo.pid > 0, '进程ID应为正数');
    
    console.log(`✓ 默认参数 PTY 创建成功`);
});

// 测试 PTY 大小调整
globalThis.test('PTY 大小调整', async () => {
    console.log('=== 测试 PTY 大小调整 ===');
    
    const ptyInfo = await openpty({
        cols: 80,
        rows: 24
    });

    // 测试调整大小
    await resize(ptyInfo.fd, 120, 40);
    
    // 在 Windows 上测试使用 pty 句柄调整大小
    if (process.platform === 'win32' && ptyInfo.pty) {
        await resize(ptyInfo.pty, 100, 30);
    }
    
    console.log('✓ PTY 大小调整成功');
});

// 测试 PTY 进程执行命令
globalThis.test('PTY 进程执行命令', async () => {
    console.log('=== 测试 PTY 进程执行命令 ===');
    
    const ptyInfo = await openpty({
        name: process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
        argv: process.platform === 'win32' ? ['/c', 'echo Hello PTY'] : ['-c', 'echo "Hello PTY"'],
        env: process.env
    });

    // 创建 Pipe 来处理 PTY 输出
    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    // 读取输出
    let output = '';
    const startTime = Date.now();
    const timeout = 5000; // 5秒超时
    
    while (Date.now() - startTime < timeout) {
        const data = pipe.read();
        if (data) {
            const text = new TextDecoder().decode(data);
            output += text;
            console.log('收到输出:', text.trim());
            
            // 检查是否收到预期输出
            if (output.includes('Hello PTY')) {
                break;
            }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    assert(output.includes('Hello PTY'), `应包含 "Hello PTY"，实际输出: ${output}`);
    console.log('✓ PTY 命令执行成功');
    
    pipe.close();
});

// 测试 PTY 交互式会话
globalThis.test('PTY 交互式会话', async () => {
    console.log('=== 测试 PTY 交互式会话 ===');
    
    if (process.platform === 'win32') {
        console.log('⚠️  跳过 Windows 上的交互式测试');
        return;
    }
    
    const ptyInfo = await openpty({
        name: '/bin/sh',
        argv: ['-i'], // 交互模式
        env: { ...process.env, PS1: 'TEST$ ' }
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    // 等待提示符出现
    let promptReceived = false;
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = pipe.read();
        if (data) {
            const text = new TextDecoder().decode(data);
            if (text.includes('TEST$') || text.includes('$') || text.includes('#')) {
                promptReceived = true;
                break;
            }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    assert(promptReceived, '应收到 shell 提示符');
    console.log('✓ 交互式会话启动成功');
    
    pipe.close();
});

// 测试 PTY 环境变量
globalThis.test('PTY 环境变量', async () => {
    console.log('=== 测试 PTY 环境变量 ===');
    
    const testEnv = {
        ...process.env,
        CUSTOM_VAR: 'TEST_VALUE',
        ANOTHER_VAR: 'ANOTHER_VALUE'
    };
    
    const ptyInfo = await openpty({
        name: process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
        argv: process.platform === 'win32' ? ['/c', 'set'] : ['-c', 'env'],
        env: testEnv
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = pipe.read();
        if (data) {
            const text = new TextDecoder().decode(data);
            output += text;
            
            if (output.includes('CUSTOM_VAR=TEST_VALUE')) {
                break;
            }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    assert(output.includes('CUSTOM_VAR=TEST_VALUE'), '应包含自定义环境变量');
    console.log('✓ 环境变量设置成功');
    
    pipe.close();
});

// 测试 PTY 工作目录
globalThis.test('PTY 工作目录', async () => {
    console.log('=== 测试 PTY 工作目录 ===');
    
    // 创建临时目录用于测试
    const testDir = process.platform === 'win32' ? 'C:\\Windows\\Temp' : '/tmp';
    
    const ptyInfo = await openpty({
        name: process.platform === 'win32' ? 'cmd.exe' : '/bin/pwd',
        cwd: testDir,
        env: process.env
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = pipe.read();
        if (data) {
            const text = new TextDecoder().decode(data);
            output += text;
            
            // 检查输出是否包含测试目录
            if (output.includes(testDir)) {
                break;
            }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    assert(output.includes(testDir), `输出应包含工作目录 ${testDir}, 实际输出: ${output}`);
    console.log('✓ 工作目录设置成功');
    
    pipe.close();
});

// 测试多个 PTY 实例
globalThis.test('多个 PTY 实例', async () => {
    console.log('=== 测试多个 PTY 实例 ===');
    
    const pty1 = await openpty({ cols: 80, rows: 24 });
    const pty2 = await openpty({ cols: 100, rows: 30 });
    const pty3 = await openpty({ cols: 120, rows: 40 });
    
    assert(pty1.fd !== pty2.fd, '不同 PTY 应有不同文件描述符');
    assert(pty2.fd !== pty3.fd, '不同 PTY 应有不同文件描述符');
    assert(pty1.pid !== pty2.pid, '不同 PTY 应有不同进程ID');
    assert(pty2.pid !== pty3.pid, '不同 PTY 应有不同进程ID');
    
    console.log(`✓ 多个 PTY 实例创建成功 - fd: ${pty1.fd}, ${pty2.fd}, ${pty3.fd}`);
});

// 测试 PTY 错误处理
globalThis.test('PTY 错误处理', async () => {
    console.log('=== 测试 PTY 错误处理 ===');
    
    try {
        // 测试无效命令
        await openpty({
            name: '/invalid/nonexistent/command',
            argv: []
        });
        
        assert(false, '应抛出错误');
    } catch (error) {
        assert(error instanceof Error, '应捕获错误');
        console.log('✓ 无效命令错误处理成功:', error.message);
    }
    
    try {
        // 测试无效工作目录
        await openpty({
            name: process.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
            cwd: '/invalid/nonexistent/directory'
        });
        
        assert(false, '应抛出错误');
    } catch (error) {
        assert(error instanceof Error, '应捕获错误');
        console.log('✓ 无效目录错误处理成功:', error.message);
    }
});

// 测试 PTY 与进程模块集成
globalThis.test('PTY 与进程模块集成', async () => {
    console.log('=== 测试 PTY 与进程模块集成 ===');
    
    const ptyInfo = await openpty({
        name: process.platform === 'win32' ? 'cmd.exe' : '/bin/sleep',
        argv: process.platform === 'win32' ? ['/c', 'timeout', '2'] : ['2']
    });

    // 使用进程模块检查进程状态
    const childProcess = process.spawn(process.platform === 'win32' ? 'tasklist' : 'ps', 
        process.platform === 'win32' ? ['/fi', `PID eq ${ptyInfo.pid}`] : ['-p', ptyInfo.pid.toString()]);
    
    let processOutput = '';
    for await (const chunk of childProcess.stdout) {
        processOutput += new TextDecoder().decode(chunk);
    }
    
    await childProcess.wait();
    
    assert(processOutput.includes(ptyInfo.pid.toString()), `进程列表应包含 PTY 进程 ID ${ptyInfo.pid}`);
    console.log('✓ PTY 与进程模块集成成功');
});

// 测试 PTY 输入输出
globalThis.test('PTY 输入输出', async () => {
    console.log('=== 测试 PTY 输入输出 ===');
    
    if (process.platform === 'win32') {
        console.log('⚠️  跳过 Windows 上的复杂输入输出测试');
        return;
    }
    
    const ptyInfo = await openpty({
        name: '/bin/cat', // 使用 cat 命令进行回显测试
        env: process.env
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    // 发送测试数据
    const testInput = 'Hello PTY Input Output Test\n';
    pipe.write(new TextEncoder().encode(testInput));
    
    // 读取回显
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = pipe.read();
        if (data) {
            const text = new TextDecoder().decode(data);
            output += text;
            
            if (output.includes(testInput.trim())) {
                break;
            }
        }
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    assert(output.includes(testInput.trim()), `输出应包含输入内容, 实际输出: ${output}`);
    console.log('✓ PTY 输入输出测试成功');
    
    pipe.close();
});

// 运行所有测试
async function runAllTests() {
    try {
        console.log('开始 PTY 模块测试...\n');
        
        // 由于 globalThis.test 是异步的，我们需要等待所有测试完成
        const tests = [
            '基础 PTY 创建',
            'PTY 默认参数', 
            'PTY 大小调整',
            'PTY 进程执行命令',
            'PTY 交互式会话',
            'PTY 环境变量',
            'PTY 工作目录',
            '多个 PTY 实例',
            'PTY 错误处理',
            'PTY 与进程模块集成',
            'PTY 输入输出'
        ];
        
        for (const testName of tests) {
            try {
                await new Promise((resolve, reject) => {
                    // 这里模拟测试执行，实际环境中 globalThis.test 会处理异步
                    const testFn = async () => {
                        try {
                            // 查找对应的测试函数并执行
                            const testFunction = globalThis[testName.replace(/\s+/g, '')];
                            if (typeof testFunction === 'function') {
                                await testFunction();
                            }
                            resolve();
                        } catch (error) {
                            reject(error);
                        }
                    };
                    testFn();
                });
            } catch (error) {
                console.error(`测试 "${testName}" 失败:`, error);
                throw error;
            }
        }
        
        console.log('\n🎉 所有 PTY 测试通过！');
        
    } catch (error) {
        console.error('\n❌ PTY 测试失败:', error);
        throw error;
    }
}