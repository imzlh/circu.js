// tests/tests/process.js - Process management module tests

const proc = import.meta.use('process');
const signals = import.meta.use('signals');
const engine = import.meta.use('engine');
const streams = import.meta.use('streams');
const os = import.meta.use('os');
const worker = import.meta.use('worker');
const { setTimeout, clearTimeout, setImmediate } = import.meta.use('timers');

if (worker.isWorker && worker.workerData?.type === 'processForkProbe') {
    assert(signals !== null, 'workers should be able to load signal numbers');
    assertEquals(typeof signals.signals.SIGTERM, 'number',
        'worker signal enum values should be numbers');
    try {
        signals.signal(signals.signals.SIGTERM, () => {});
        assert(false, 'workers should not register process-level signal handlers');
    } catch (cause) {
        assert(cause instanceof TypeError,
            'worker signal handler registration should throw TypeError');
    }

    let error = null;
    try {
        proc.fork();
    } catch (cause) {
        error = {
            name: cause?.name ?? 'Error',
            message: String(cause?.message ?? cause),
        };
    }
    worker.pipe.postMessage({ ok: error !== null, error });
    os.exit(0);
}

if (worker.isWorker && worker.workerData?.type === 'processForkHold') {
    worker.pipe.postMessage({ ready: true });
    await new Promise((resolve) => setTimeout(resolve, 10000));
    os.exit(0);
}

// ========== Process Fork (Linux/POSIX) ==========
if (os.platform === 'linux') {
    function drainProcessHandles() {
        engine.waitIO(new Promise((resolve) => setImmediate(resolve)));
    }

    function assertForkRequiresIdle() {
        let error = null;
        let unexpectedChild;
        try {
            unexpectedChild = proc.fork();
        } catch (cause) {
            error = cause;
        }
        if (unexpectedChild === null) {
            os.exit(99);
            return;
        }
        if (unexpectedChild) {
            unexpectedChild.kill(signals.signals.SIGKILL);
            unexpectedChild.waitSync();
        }
        assert(error instanceof TypeError, 'fork should reject pending work with TypeError');
        assert(String(error.message).includes('idle event loop'),
            'fork error should explain the idle event loop requirement');
    }

    await test('proc.fork - child continues with copied JS state', async () => {
        const shared = { value: 41 };
        const child = proc.fork();

        if (child === null) {
            assertEquals(shared.value, 41, 'child should see pre-fork state');
            shared.value = 42;
            os.exit(23);
            return;
        }

        assert(child, 'parent should receive a Process handle');
        assert(child.pid > 0, 'forked child should have a positive PID');
        assertEquals(typeof child.kill, 'function', 'parent should receive a Process handle');
        assertEquals(typeof child.wait, 'function', 'parent should receive a Process handle');
        shared.value = 43;
        const status = await child.wait();
        assertEquals(status.exit_status, 23, 'child exit status should be preserved');
        assertEquals(shared.value, 43, 'parent state should remain independent');
    });

    await test('proc.fork - parent can fork sequential children after handles close', () => {
        for (let index = 0; index < 2; index++) {
            drainProcessHandles();
            const child = proc.fork();
            if (child === null) {
                os.exit(30 + index);
                return;
            }
            const status = child.waitSync();
            assertEquals(status.exit_status, 30 + index, 'child exit status should be preserved');
            assertForkRequiresIdle();
        }
    });

    await test('proc.fork - rejects another fork while a child wait is pending', async () => {
        drainProcessHandles();
        const first = proc.fork();
        if (first === null) {
            await new Promise((resolve) => setTimeout(resolve, 10000));
            os.exit(40);
            return;
        }

        const pendingWait = first.wait();
        let firstStatus;
        try {
            assertEquals(first.wait(), pendingWait, 'live child should retain its wait promise');
            assertForkRequiresIdle();
        } finally {
            first.kill(signals.signals.SIGTERM);
            firstStatus = await pendingWait;
        }
        assertEquals(firstStatus.term_signal, signals.signals.SIGTERM,
            'parent should still own first child');
    });

    await test('proc.fork - rejects active and closing timers', () => {
        drainProcessHandles();
        const timer = setTimeout(() => panic('fork rejection timer should not run'), 10000);
        try {
            assertForkRequiresIdle();
        } finally {
            clearTimeout(timer);
        }
        assertForkRequiresIdle();
    });

    await test('proc.fork - rejects pending JS jobs', async () => {
        drainProcessHandles();
        let jobRan = false;
        const pendingJob = Promise.resolve().then(() => { jobRan = true; });
        assertForkRequiresIdle();
        assertEquals(jobRan, false, 'queued job should still be pending during fork');
        await pendingJob;
        assertEquals(jobRan, true, 'rejected fork should preserve the queued job');
    });

    await test('proc.fork - waitSync reaps the child', () => {
        drainProcessHandles();
        const child = proc.fork();
        if (child === null) {
            os.exit(24);
            return;
        }

        const status = child.waitSync();
        assertEquals(status.exit_status, 24, 'waitSync should preserve the child exit status');
    });

    await test('proc.fork - parent can terminate child', async () => {
        drainProcessHandles();
        const child = proc.fork();
        if (child === null) {
            await new Promise((resolve) => setTimeout(resolve, 10000));
            os.exit(0);
            return;
        }

        child.kill(signals.signals.SIGTERM);
        const status = await child.wait();
        assert(status.exit_status !== 0 || status.term_signal !== null,
            'forked child should be terminated by SIGTERM');
    });

    await test('proc.fork - worker runtime rejects fork', async () => {
        const child = new worker.Worker({ type: 'processForkProbe' });
        try {
            const result = await new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('worker fork probe timed out')), 3000);
                child.messagePipe.onmessage = (value) => {
                    clearTimeout(timer);
                    resolve(value);
                };
                child.messagePipe.onmessageerror = reject;
            });
            assert(result?.ok === true, 'worker fork should throw');
            assert(String(result.error?.message ?? '').includes('worker'),
                'worker fork error should explain the restriction');
        } finally {
            await child.terminate();
        }
    });

    await test('proc.fork - main runtime rejects fork while a worker exists', async () => {
        const runningWorker = new worker.Worker({ type: 'processForkHold' });
        try {
            await new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('worker ready probe timed out')), 3000);
                runningWorker.messagePipe.onmessage = (value) => {
                    if (!value?.ready) return;
                    clearTimeout(timer);
                    resolve();
                };
                runningWorker.messagePipe.onmessageerror = reject;
            });

            let error = null;
            try {
                proc.fork();
            } catch (cause) {
                error = cause;
            }
            assert(error, 'fork should throw while the main runtime owns a worker');
            assert(String(error.message ?? error).includes('worker'),
                'main-runtime fork error should explain the worker restriction');
        } finally {
            await runningWorker.terminate();
        }
    });

    await test('proc.fork - rejects active spawned process handles', async () => {
        const runningChild = proc.spawn(['sleep', '10']);
        try {
            let error = null;
            try {
                proc.fork();
            } catch (cause) {
                error = cause;
            }
            assert(error, 'fork should throw while a spawned process is active');
            assert(String(error.message ?? error).includes('process handle'),
                'fork error should explain the active process restriction');
        } finally {
            runningChild.kill(signals.signals.SIGKILL);
            await runningChild.wait();
        }
    });

    await test('proc.fork - rejects active PTY process handles', async () => {
        const runningChild = proc.spawn([], {
            pty: true,
            name: '/bin/sleep',
            argv: ['sleep', '10'],
        });
        try {
            let error = null;
            try {
                proc.fork();
            } catch (cause) {
                error = cause;
            }
            assert(error, 'fork should throw while a PTY process is active');
            assert(String(error.message ?? error).includes('process handle'),
                'fork error should explain the active PTY restriction');
        } finally {
            runningChild.kill(signals.signals.SIGKILL);
            await runningChild.wait();
        }
    });
}

// ========== Process Spawn ==========
await test('proc.spawn - basic spawn', async () => {
    const child = proc.spawn(['echo', 'hello world'], {
        stdout: 'pipe'
    });
    
    assert(child, 'Should create child process');
    assert(child.pid > 0, 'Should have positive PID');
    
    // Read output
    if (child.stdout) {
        const buf = new Uint8Array(1024);
        const r = await child.stdout.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assert(t.includes('hello world'), 'Should output correct text');
    }
    
    // Wait for process
    const status = await child.wait();
    assertEquals(status.exit_status, 0, 'Should exit with code 0');
});

await test('proc.spawn - spawn with executable string', async () => {
    const child = proc.spawn('echo', {
        stdout: 'pipe'
    });
    
    assert(child, 'Should create child process with string args');
    
    if (child.stdout) {
        const buf = new Uint8Array(1024);
        const r = await child.stdout.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assertEquals(t, '\n', 'Executable string should run without extra arguments');
    }
    
    await child.wait();
});

await test('proc.spawn and spawnSync - reject oversized argv lengths', () => {
    const spawnArgs = [];
    spawnArgs.length = 0x80000000;
    let spawnError = null;
    try {
        proc.spawn(spawnArgs);
    } catch (cause) {
        spawnError = cause;
    }
    assert(spawnError instanceof RangeError,
        'spawn should reject argv lengths that do not fit its native index type');

    const syncArgs = [];
    syncArgs.length = 0x7fffffff;
    let syncError = null;
    try {
        proc.spawnSync('echo', syncArgs);
    } catch (cause) {
        syncError = cause;
    }
    assert(syncError instanceof RangeError,
        'spawnSync should reject command-plus-args lengths that do not fit');
});

await test('proc.spawn - spawn with stdin', async () => {
    const child = proc.spawn(['cat'], {
        stdin: 'pipe',
        stdout: 'pipe'
    });
    
    if (child.stdin && child.stdout) {
        // Write to stdin
        await child.stdin.write(engine.encodeString('hello from stdin'));
        child.stdin.close();
        
        // Read from stdout
        const buf = new Uint8Array(1024);
        const r = await child.stdout.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assert(t.includes('hello from stdin'), 'Should echo input');
    }
    
    await child.wait();
});

await test('proc.spawn - spawn with stderr', async () => {
    const child = proc.spawn(['sh', '-c', 'echo error >&2'], {
        stderr: 'pipe'
    });
    
    if (child.stderr) {
        const buf = new Uint8Array(1024);
        const r = await child.stderr.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assert(t.includes('error'), 'Should capture stderr');
    }
    
    await child.wait();
});

await test('proc.spawn - spawn with cwd', async () => {
    const child = proc.spawn(['pwd'], {
        stdout: 'pipe',
        cwd: '/tmp'
    });
    
    if (child.stdout) {
        const buf = new Uint8Array(1024);
        const r = await child.stdout.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assert(t.includes('/tmp'), 'Should be in /tmp directory');
    }
    
    await child.wait();
});

await test('proc.spawn - spawn with env', async () => {
    const child = proc.spawn(['sh', '-c', 'echo $TEST_VAR'], {
        stdout: 'pipe',
        env: { TEST_VAR: 'test_value' }
    });
    
    if (child.stdout) {
        const buf = new Uint8Array(1024);
        const r = await child.stdout.read(buf);
        const t = engine.decodeString(buf.slice(0, r));
        assert(t.includes('test_value'), 'Should have env variable');
    }
    
    await child.wait();
});

await test('proc.spawn - spawn with ignored stdio', async () => {
    const child = proc.spawn(['echo', 'ignored'], {
        stdout: 'ignore'
    });
    
    assert(child.stdout === undefined || child.stdout === null, 'stdout should be ignored');
    await child.wait();
});

// ========== Process Wait ==========
await test('proc.wait - wait for process exit', async () => {
    const child = proc.spawn(['sleep', '0.1']);
    
    const status = await child.wait();
    assert(status, 'Should return status object');
    assertEquals(typeof status.exit_status, 'number', 'Should have exit_status');
});

await test('proc.wait - wait multiple times returns same result', async () => {
    const child = proc.spawn(['echo', 'test'], { stdout: 'pipe' });
    
    // Read output first
    if (child.stdout) {
        const buf = new Uint8Array(1024);
        await child.stdout.read(buf);
    }
    
    const status1 = await child.wait();
    const status2 = await child.wait();
    
    assertEquals(status1.exit_status, status2.exit_status, 'Should return same exit status');
});

await test('proc.waitSync - synchronous wait', () => {
    const child = proc.spawn(['echo', 'sync test']);
    
    const status = child.waitSync();
    assert(status, 'Should return status object');
    assertEquals(typeof status.exit_status, 'number', 'Should have exit_status');
    assertEquals(status.exit_status, 0, 'Should exit with 0');
});

await test('proc.spawnSync - capture stdout', () => {
    const result = proc.spawnSync(['echo', 'sync stdout']);
    const stdout = engine.decodeString(result.stdout);

    assertEquals(result.status, 0, 'Should exit with 0');
    assert(stdout.includes('sync stdout'), 'Should capture stdout');
});

await test('proc.spawnSync - capture stderr and status', () => {
    const result = proc.spawnSync(['sh', '-c', 'echo sync error >&2; exit 7']);
    const stderr = engine.decodeString(result.stderr);

    assertEquals(result.status, 7, 'Should report exit status');
    assert(stderr.includes('sync error'), 'Should capture stderr');
});

await test('proc.spawnSync - input', () => {
    const result = proc.spawnSync(['cat'], { input: engine.encodeString('sync input') });
    const stdout = engine.decodeString(result.stdout);

    assertEquals(result.status, 0, 'Should exit with 0');
    assertEquals(stdout, 'sync input', 'Should write input to stdin');
});

// ========== Process Kill ==========
await test('proc.kill - kill process with signal', async () => {
    const child = proc.spawn(['sleep', '10']);
    
    // Small delay to ensure process started
    await new Promise(r => setTimeout(r, 100));
    
    child.kill(signals.signals.SIGTERM);
    
    const status = await child.wait();
    // Exit code for SIGTERM is usually 128 + 15 = 143
    assert(status.exit_status !== 0 || status.term_signal !== null, 'Process should be terminated');
});

await test('proc.kill - kill with default signal', async () => {
    const child = proc.spawn(['sleep', '10']);
    
    await new Promise(r => setTimeout(r, 100));
    
    child.kill(); // Default SIGTERM
    
    const status = await child.wait();
    assert(status.exit_status !== 0 || status.term_signal !== null, 'Process should be terminated');
});

// ========== Process Properties ==========
await test('proc.pid - process ID', async () => {
    const child = proc.spawn(['echo', 'test']);
    
    assert(typeof child.pid === 'number', 'PID should be a number');
    assert(child.pid > 0, 'PID should be positive');
    
    await child.wait();
});

// ========== Global Kill ==========
await test('proc.kill - kill by PID', async () => {
    const child = proc.spawn(['sleep', '10']);
    
    await new Promise(r => setTimeout(r, 100));
    
    // Kill using global kill function
    proc.kill(child.pid, signals.signals.SIGTERM);
    
    const status = await child.wait();
    assert(status.exit_status !== 0 || status.term_signal !== null, 'Process should be terminated');
});

await test('proc.kill - kill by PID with default signal', async () => {
    const child = proc.spawn(['sleep', '10']);
    
    await new Promise(r => setTimeout(r, 100));
    
    proc.kill(child.pid); // Default SIGTERM
    
    const status = await child.wait();
    assert(status.exit_status !== 0 || status.term_signal !== null, 'Process should be terminated');
});

// ========== Exit Code Tests ==========
await test('proc - exit code 0', async () => {
    const child = proc.spawn(['true']);
    const status = await child.wait();
    assertEquals(status.exit_status, 0, 'Should exit with 0');
});

await test('proc - nonzero exit code', async () => {
    const child = proc.spawn(['false']);
    const status = await child.wait();
    assert(status.exit_status !== 0, 'Should exit with non-zero');
});

await test('proc - custom exit code', async () => {
    const child = proc.spawn(['sh', '-c', 'exit 42']);
    const status = await child.wait();
    assertEquals(status.exit_status, 42, 'Should exit with 42');
});

// ========== Process Exec ==========
await test('proc.exec - replace process', () => {
    // Note: exec replaces current process, so we can't really test it here
    // without killing the test runner. Just verify it exists.
    assertEquals(typeof proc.exec, 'function', 'exec should be a function');
});

// ========== Error Handling ==========
await test('proc.spawn - invalid command', () => {
    let error;
    try {
        proc.spawn(['/nonexistent/command']);
    } catch (cause) {
        error = cause;
    }
    assert(error, 'Should throw when the executable cannot be started');
    assert(String(error.message).includes('ENOENT'), 'Should report a missing executable');
});

await test('proc.kill - invalid PID', () => {
    let error;
    try {
        proc.kill(2147483647, signals.signals.SIGTERM);
    } catch (cause) {
        error = cause;
    }
    assert(error instanceof Error, 'Should throw for a nonexistent PID');
    assert(String(error.message).includes('ESRCH'), 'Should report a nonexistent process');
});

await test('proc.kill - rejects string signals', async () => {
    const child = proc.spawn(['echo', 'test']);
    
    try {
        child.kill('SIGTERM');
        assert(false, 'Should reject string signals');
    } catch (e) {
        assert(e instanceof TypeError, 'Should throw TypeError');
    }
    
    await child.wait();
});

await test('proc.spawn - detached process', async () => {
    const child = proc.spawn(['echo', 'detached'], {
        detached: true
    });
    
    assert(child, 'Should create detached process');
    await child.wait();
});

await test('proc.spawn - background process', async () => {
    const child = proc.spawn(['echo', 'background'], {
        background: true
    });
    
    assert(child, 'Should create background process');
    await child.wait();
});
