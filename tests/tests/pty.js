// tests/tests/pty.js - PTY module tests

import { readOnce } from "../polyfill/stream.read.js";

const pty = import.meta.use('pty');
const sys = import.meta.use('sys');
const streams = import.meta.use('streams');
const proc = import.meta.use('process');
const os = import.meta.use('os');
const engine = import.meta.use('engine');
const timer = import.meta.use('timers');

const { openpty, resize } = pty;
const { Pipe } = streams;

// ========== Basic PTY Creation ==========
await test('pty.openpty - basic creation', async () => {
    const ptyInfo = await openpty({
        cols: 80,
        rows: 24,
        name: sys.platform === 'win32' ? 'cmd.exe' : '/bin/bash',
        cwd: os.cwd,
        env: {}
    });

    assert(ptyInfo.fd > 0, 'File descriptor should be positive');
    assert(ptyInfo.pid > 0, 'Process ID should be positive');
    
    if (sys.platform === 'win32') {
        assert(ptyInfo.pty !== undefined, 'Should have pty handle on Windows');
    }
});

await test('pty.openpty - default parameters', async () => {
    const ptyInfo = await openpty();
    
    assert(ptyInfo.fd > 0, 'File descriptor should be positive');
    assert(ptyInfo.pid > 0, 'Process ID should be positive');
});

// ========== PTY Resize ==========
await test('pty.resize - resize with fd', async () => {
    const ptyInfo = await openpty({
        cols: 80,
        rows: 24
    });

    await resize(ptyInfo.fd, 120, 40);
});

await test('pty.resize - resize with pty handle (Windows)', async () => {
    if (sys.platform !== 'win32') {
        return;
    }
    
    const ptyInfo = await openpty();
    
    if (ptyInfo.pty) {
        await resize(ptyInfo.pty, 100, 30);
    }
});

// ========== PTY Command Execution ==========
await test('pty.openpty - execute command', async () => {
    const ptyInfo = await openpty({
        name: sys.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
        argv: sys.platform === 'win32' ? ['/c', 'echo Hello PTY'] : ['-c', 'echo "Hello PTY"'],
        env: {}
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let output = '';
    const startTime = Date.now();
    const timeout = 5000;
    
    while (Date.now() - startTime < timeout) {
        const data = new Uint8Array(1024);
        const n = await readOnce(pipe, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            output += text;
            
            if (output.includes('Hello PTY')) {
                break;
            }
        }
        await new Promise(resolve => timer.setTimeout(resolve, 100));
    }
    
    assert(output.includes('Hello PTY'), `Should contain "Hello PTY", got: ${output}`);
    
    pipe.close();
});

// ========== PTY Interactive Session ==========
await test('pty.openpty - interactive session', async () => {
    if (sys.platform === 'win32') {
        return;
    }
    
    const ptyInfo = await openpty({
        name: '/bin/sh',
        argv: ['-i'],
        env: { PS1: 'TEST$ ' }
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let promptReceived = false;
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = new Uint8Array(1024);
        const n = await readOnce(pipe, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            if (text.includes('TEST$') || text.includes('$') || text.includes('#')) {
                promptReceived = true;
                break;
            }
        }
        await new Promise(resolve => timer.setTimeout(resolve, 100));
    }
    
    assert(promptReceived, 'Should receive shell prompt');
    
    pipe.close();
});

// ========== PTY Environment Variables ==========
await test('pty.openpty - environment variables', async () => {
    const testEnv = {
        CUSTOM_VAR: 'TEST_VALUE',
        ANOTHER_VAR: 'ANOTHER_VALUE'
    };
    
    const ptyInfo = await openpty({
        name: sys.platform === 'win32' ? 'cmd.exe' : '/usr/bin/env',
        argv: sys.platform === 'win32' ? ['/c', 'set'] : [],
        env: testEnv
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) try{
        const data = new Uint8Array(1024);
        const n = await readOnce(pipe, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            output += text;
            
            if (output.includes('CUSTOM_VAR=TEST_VALUE')) {
                break;
            }
        }
        await new Promise(resolve => timer.setTimeout(resolve, 100));
    }catch{ break; }
    
    console.log(output);
    assert(output.includes('CUSTOM_VAR=TEST_VALUE'), 'Should contain custom environment variable');
    
    pipe.close();
});

// ========== PTY Working Directory ==========
await test('pty.openpty - working directory', async () => {
    const testDir = sys.platform === 'win32' ? 'C:\\Windows\\Temp' : '/tmp';
    
    const ptyInfo = await openpty({
        name: sys.platform === 'win32' ? 'cmd.exe' : '/bin/pwd',
        cwd: testDir,
        env: {}
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = new Uint8Array(1024);
        const n = await readOnce(pipe, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            output += text;
            
            if (output.includes(testDir)) {
                break;
            }
        }
        await new Promise(resolve => timer.setTimeout(resolve, 100));
    }
    
    assert(output.includes(testDir), `Output should contain working directory ${testDir}, got: ${output}`);
    
    pipe.close();
});

// ========== Multiple PTY Instances ==========
await test('pty.openpty - multiple instances', async () => {
    const pty1 = await openpty({ cols: 80, rows: 24 });
    const pty2 = await openpty({ cols: 100, rows: 30 });
    const pty3 = await openpty({ cols: 120, rows: 40 });
    
    assert(pty1.fd !== pty2.fd, 'Different PTYs should have different file descriptors');
    assert(pty2.fd !== pty3.fd, 'Different PTYs should have different file descriptors');
    assert(pty1.pid !== pty2.pid, 'Different PTYs should have different process IDs');
    assert(pty2.pid !== pty3.pid, 'Different PTYs should have different process IDs');
});

// ========== PTY Error Handling ==========
await test('pty.openpty - invalid command error', async () => {
    try {
        await openpty({
            name: '/invalid/nonexistent/command',
            argv: []
        });
        
        assert(false, 'Should throw an error');
    } catch (error) {
        assert(error instanceof Error, 'Should catch error');
    }
});

await test('pty.openpty - invalid directory error', async () => {
    try {
        await openpty({
            name: sys.platform === 'win32' ? 'cmd.exe' : '/bin/sh',
            cwd: '/invalid/nonexistent/directory'
        });
        
        assert(false, 'Should throw an error');
    } catch (error) {
        assert(error instanceof Error, 'Should catch error');
    }
});

// ========== PTY Integration with Process Module ==========
await test('pty - integration with process module', async () => {
    const ptyInfo = await openpty({
        name: sys.platform === 'win32' ? 'cmd.exe' : '/bin/sleep',
        argv: sys.platform === 'win32' ? ['/c', 'timeout', '2'] : ['2']
    });

    const childProcess = proc.spawn(
        sys.platform === 'win32'
            ? ['tasklist', '/fi', `PID eq ${ptyInfo.pid}`]
            : ['ps', '-p', ptyInfo.pid.toString()],
        { stdout: 'pipe' }
    );
    
    let processOutput = '';
    const data = new Uint8Array(1024);
    while (true) {
        const n = await readOnce(childProcess.stdout, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            processOutput += text;
        } else {
            break;
        }
    }
    
    assert(processOutput.includes(ptyInfo.pid.toString()), `Process list should contain PTY process ID ${ptyInfo.pid}`);
});

// ========== PTY Input/Output ==========
await test('pty - input and output', async () => {
    if (sys.platform === 'win32') {
        return;
    }
    
    const ptyInfo = await openpty({
        name: '/bin/cat',
        env: {}
    });

    const pipe = new Pipe();
    pipe.open(ptyInfo.fd);
    
    const testInput = 'Hello PTY Input Output Test\n';
    pipe.write(engine.encodeString(testInput));
    
    let output = '';
    const startTime = Date.now();
    
    while (Date.now() - startTime < 3000) {
        const data = new Uint8Array(1024);
        const n = await readOnce(pipe, data);
        if (n) {
            const text = engine.decodeString(data.subarray(0, n));
            output += text;
            
            if (output.includes(testInput.trim())) {
                break;
            }
        }
        await new Promise(resolve => timer.setTimeout(resolve, 100));
    }
    
    assert(output.includes(testInput.trim()), `Output should contain input content, got: ${output}`);
    
    pipe.close();
});
