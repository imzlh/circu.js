/**
 * Worker Compatibility Tests
 */

const { use } = import.meta;
const { Worker, isWorker, pipe, workerData, close } = use('worker');
const console = use('console');
const os = use('os');
const { setTimeout, clearTimeout } = use('timers');

// If running inside Worker, handle worker logic
if (isWorker) {
    // Worker thread logic based on workerData
    const { type, testId } = workerData || {};
    assert(pipe, 'pipe should be available');
    console.log(`Worker started with type: ${type}`);
    
    switch (type) {
        case 'echo':
            // Echo worker - sends back any message received
            pipe.onmessage = (data) => {
                pipe.postMessage({ type: 'echo', original: data, testId });
            };
            pipe.postMessage({ type: 'ready', testId });
            break;
            
        case 'checkIsWorker':
            // Report worker status
            pipe.postMessage({ 
                type: 'check', 
                isWorker: isWorker,
                haspipe: !!pipe,
                hasWorkerData: !!workerData,
                workerDataKeys: workerData ? Object.keys(workerData) : [],
                testId 
            });
            break;
            
        case 'consoleTest':
            // Test console in worker (should be disabled/no-op)
            try {
                console.log('test log from worker');
                console.error('test error from worker');
                console.warn('test warn from worker');
                pipe.postMessage({ type: 'console', status: 'completed', testId });
            } catch (e) {
                pipe.postMessage({ type: 'console', status: 'error', error: e.message, testId });
            }
            break;
            
        case 'stress':
            // Heavy computation
            let result = 0;
            for (let i = 0; i < 1000000; i++) {
                result += Math.sqrt(i);
            }
            pipe.postMessage({ type: 'stress', result: Math.floor(result), testId });
            break;
            
        case 'moduleTest':
            // Test module availability in worker
            try {
                const available = [];
                const unavailable = [];
                
                // Try loading various modules
                const moduleList = ['algorithm', 'sys', 'os', 'fs', 'process'];
                for (const modName of moduleList) {
                    try {
                        use(modName);
                        available.push(modName);
                    } catch (e) {
                        unavailable.push(modName);
                    }
                }
                
                pipe.postMessage({ 
                    type: 'modules', 
                    available,
                    unavailable,
                    testId 
                });
            } catch (e) {
                pipe.postMessage({ type: 'modules', error: e.message, testId });
            }
            break;
            
        case 'multiMessage':
            // Send multiple messages
            const count = workerData.count || 5;
            for (let i = 0; i < count; i++) {
                pipe.postMessage({ type: 'multi', index: i, testId });
            }
            break;
            
        case 'waitForCommand':
            // Wait for commands from main thread
            pipe.postMessage({ type: 'waiting', testId });
            pipe.onmessage = (data) => {
                if (data.command === 'ping') {
                    pipe.postMessage({ type: 'pong', testId });
                } else if (data.command === 'exit') {
                    pipe.postMessage({ type: 'exiting', testId });
                }
            };
            break;

        case 'queueThenClose':
            pipe.postMessage({ type: 'pending-before-close' });
            close();
            break;

        case 'manyThenClose':
            for (let i = 0; i < workerData.count; i++)
                pipe.postMessage({ type: 'pending-before-close', index: i });
            close();
            break;

        case 'exitDuringImport': {
            const state = new Int32Array(workerData.state);
            Atomics.store(state, 0, 1);
            os.exit(37);
            Atomics.store(state, 0, 2);
            break;
        }
            
        default:
            // Unknown worker type
            if (pipe) {
                pipe.postMessage({ 
                    type: 'error', 
                    message: `Unknown worker type: ${type}`,
                    receivedData: workerData 
                });
            }
    }
    
    // Worker thread ends here - don't run tests
    // Just keep the event loop running
    await new Promise(() => {}); // Never resolve, keep worker alive
}

// ============================================
// Main Thread Tests
// ============================================

// Wait for message helper
function waitForMessage(pipe, timeout = 5000) {
    return waitForMessageType(pipe, undefined, timeout);
}

// Wait for specific message type
function waitForMessageType(pipe, expectedType, timeout = 5000, label = '') {
    return new Promise((resolve, reject) => {
        const originalHandler = pipe.onmessage;
        const originalError = pipe.onmessageerror;
        let settled = false;
        const finish = (error, data) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            if (pipe.onmessage === handler) pipe.onmessage = originalHandler;
            if (pipe.onmessageerror === onerror) pipe.onmessageerror = originalError;
            if (error) reject(error);
            else resolve(data);
        };
        const handler = (data) => {
            if (expectedType === undefined || data?.type === expectedType)
                finish(null, data);
        };
        const onerror = cause => finish(new Error(
            `Message error waiting for ${expectedType ?? 'message'} ${label}: ${cause}`,
        ));
        const timer = setTimeout(() => finish(new Error(
            `Timeout waiting for message type: ${expectedType ?? '*'} ${label}; ` +
            `pending=${JSON.stringify(pipe.pendingStats())}`,
        )), timeout);
        pipe.onmessageerror = onerror;
        pipe.onmessage = handler;
    });
}

await test('Worker basic creation and termination', async () => {
    const worker = new Worker({ type: 'checkIsWorker', testId: 'basic' });
    assert(worker, 'Worker should be created');
    assert(worker.messagePipe, 'Worker should have pipe');
    assert(typeof worker.terminate === 'function', 'Worker should have terminate method');

    let missingArgumentError;
    try {
        worker.messagePipe.postMessage();
    } catch (error) {
        missingArgumentError = error;
    }
    assert(missingArgumentError instanceof TypeError,
        'postMessage() must reject a missing value without reading argv[0]');
    
    // Clean up
    await worker.terminate();
});

await test('Worker termination is idempotent', async () => {
    const worker = new Worker({ type: 'checkIsWorker', testId: 'idempotent' });
    await waitForMessage(worker.messagePipe);
    await worker.terminate();
    await worker.terminate();
});

await test('Worker isWorker flag and workerData', async () => {
    const worker = new Worker({ type: 'checkIsWorker', testId: 'isworker' });
    
    const response = await waitForMessage(worker.messagePipe);
    assertEquals(response.type, 'check');
    assertEquals(response.isWorker, true, 'Worker should report isWorker=true');
    assertEquals(response.haspipe, true, 'Worker should have pipe');
    assertEquals(response.hasWorkerData, true, 'Worker should have workerData');
    assert(response.workerDataKeys.includes('type'), 'workerData should have type key');
    assert(response.workerDataKeys.includes('testId'), 'workerData should have testId key');
    
    await worker.terminate();
});

await test('Worker message passing', async () => {
    const worker = new Worker({ type: 'echo', testId: 'echo' });
    
    // Wait for ready signal
    const ready = await waitForMessageType(worker.messagePipe, 'ready');
    assertEquals(ready.testId, 'echo');
    
    // Send test messages
    const testData = [
        { str: 'hello' },
        { num: 42 },
        { arr: [1, 2, 3] },
        { obj: { nested: true } },
    ];
    
    for (const data of testData) {
        const promise = waitForMessage(worker.messagePipe, 1000);
        worker.messagePipe.postMessage(data);
        const response = await promise;
        
        assertEquals(response.type, 'echo');
        assert(response.original !== undefined, 'Response should contain original data');
    }

    const backing = new ArrayBuffer(16);
    const view = new Uint8Array(backing, 4, 3);
    view.set([17, 23, 41]);
    const shared = new SharedArrayBuffer(4);
    new Uint8Array(shared)[2] = 59;
    const transferred = waitForMessage(worker.messagePipe);
    worker.messagePipe.postMessage({ backing, view, shared }, [backing]);
    assertEquals(backing.byteLength, 0);
    const echoed = (await transferred).original;
    assertEquals(echoed.backing.byteLength, 16);
    assertEquals(echoed.view.buffer, echoed.backing);
    assertEquals(echoed.view.byteOffset, 4);
    assertEquals(echoed.view.join(','), '17,23,41');
    new Uint8Array(echoed.shared)[2] = 61;
    assertEquals(new Uint8Array(shared)[2], 61);

    const retained = new ArrayBuffer(8);
    let duplicateRejected = false;
    try {
        worker.messagePipe.postMessage(retained, [retained, retained]);
    } catch {
        duplicateRejected = true;
    }
    assert(duplicateRejected);
    assertEquals(retained.byteLength, 8);
    
    await worker.terminate();
});

await test('Worker console disabled', async () => {
    const worker = new Worker({ type: 'consoleTest', testId: 'console' });
    
    // Should complete without error
    const response = await waitForMessage(worker.messagePipe);
    assertEquals(response.type, 'console');
    assertEquals(response.status, 'completed', 'Console operations should complete without error');
    
    await worker.terminate();
});

await test('Worker stress test - concurrent workers', async () => {
    const WORKER_COUNT = 4;
    const workers = [];
    const promises = [];
    
    try {
        // Start all workers before arming the response deadline. Startup is
        // synchronous; early responses remain buffered by MessagePipe.
        for (let i = 0; i < WORKER_COUNT; i++)
            workers.push(new Worker({ type: 'stress', testId: `stress-${i}` }));
        for (let i = 0; i < WORKER_COUNT; i++)
            promises.push(waitForMessageType(
                workers[i].messagePipe, 'stress', 5000, `stress-${i}`,
            ));
        const results = await Promise.all(promises);
        for (let i = 0; i < WORKER_COUNT; i++) {
            assertEquals(results[i].type, 'stress');
            assertEquals(results[i].testId, `stress-${i}`);
            assert(typeof results[i].result === 'number', 'Result should be a number');
        }
    } finally {
        for (const worker of workers)
            await worker.terminate();
        // Let every helper release its timer/handlers even after one fails.
        await Promise.allSettled(promises);
    }
});

await test('Worker rapid create/terminate cycles', async () => {
    const CYCLES = 10;
    
    for (let i = 0; i < CYCLES; i++) {
        const worker = new Worker({ type: 'checkIsWorker', testId: `cycle-${i}` });
        const response = await waitForMessage(worker.messagePipe);
        assertEquals(response.type, 'check');
        assertEquals(response.isWorker, true);
        await worker.terminate();
    }
});

await test('Worker os.exit during module import tears down safely', async () => {
    const state = new Int32Array(new SharedArrayBuffer(4));
    const worker = new Worker({ type: 'exitDuringImport', state: state.buffer });

    try {
        await new Promise((resolve, reject) => {
            const timer = setTimeout(
                () => reject(new Error('Worker exit during import timed out')),
                3000,
            );
            worker.messagePipe.onmessageerror = cause => {
                clearTimeout(timer);
                reject(cause);
            };
            worker.messagePipe.onclose = () => {
                clearTimeout(timer);
                resolve();
            };
        });
        assertEquals(Atomics.load(state, 0), 1,
            'os.exit must unwind before later module code runs');
    } finally {
        await worker.terminate();
    }
});

await test('Worker module availability', async () => {
    const worker = new Worker({ type: 'moduleTest', testId: 'modules' });
    
    const response = await waitForMessageType(worker.messagePipe, 'modules');
    assertEquals(response.type, 'modules');
    assert(!response.error, `Module loading should not error: ${response.error}`);
    
    // Log available modules for debugging
    console.log('  Available modules in Worker:', response.available);
    console.log('  Unavailable modules in Worker:', response.unavailable);
    
    // Some modules should be available
    assert(response.available.length > 0, 'At least some modules should be available');
    
    await worker.terminate();
});

await test('Worker multiple messages', async () => {
    const MESSAGE_COUNT = 5;
    const worker = new Worker({ type: 'multiMessage', testId: 'multi', count: MESSAGE_COUNT });
    
    const messages = [];
    
    // Collect all messages
    const handler = (data) => {
        if (data.type === 'multi') {
            messages.push(data);
        }
    };
    worker.messagePipe.onmessage = handler;
    
    // Wait for all messages
    await new Promise(r => setTimeout(r, 500));
    
    assertEquals(messages.length, MESSAGE_COUNT, `Should receive ${MESSAGE_COUNT} messages`);
    for (let i = 0; i < MESSAGE_COUNT; i++) {
        assertEquals(messages[i].type, 'multi');
        assertEquals(messages[i].index, i);
    }
    
    await worker.terminate();
});

await test('MessagePipe preserves queued messages for a handler installed after close', async () => {
    const worker = new Worker({ type: 'queueThenClose' });
    let timeout;
    try {
        const deadline = Date.now() + 3000;
        while (worker.messagePipe.pendingStats().messages === 0) {
            if (Date.now() >= deadline) {
                throw new Error('Worker message did not become pending');
            }
            await new Promise(resolve => setTimeout(resolve, 1));
        }
        const closePromise = new Promise((resolve, reject) => {
            timeout = setTimeout(() => reject(new Error('Worker close timed out')), 3000);
            worker.messagePipe.onclose = () => {
                clearTimeout(timeout);
                resolve();
            };
        });
        await closePromise;
        assertEquals(worker.messagePipe.pendingStats().messages, 1,
            'EOF must preserve messages until a consumer is installed');
        const message = await waitForMessage(worker.messagePipe);
        assertEquals(message.type, 'pending-before-close');
        assertEquals(worker.messagePipe.pendingStats().messages, 0);
    } finally {
        clearTimeout(timeout);
        await worker.terminate();
    }
});

await test('MessagePipe delivers queued messages before close when handlers are installed', async () => {
    const worker = new Worker({ type: 'queueThenClose' });
    const events = [];
    let timeout;
    try {
        const closed = new Promise((resolve, reject) => {
            timeout = setTimeout(() => reject(new Error('Worker close timed out')), 3000);
            worker.messagePipe.onmessage = data => events.push(data.type);
            worker.messagePipe.onclose = () => {
                events.push('close');
                resolve();
            };
        });
        await closed;
        assertEquals(events.length, 2);
        assertEquals(events[0], 'pending-before-close');
        assertEquals(events[1], 'close');
        assertEquals(worker.messagePipe.pendingStats().messages, 0);
    } finally {
        clearTimeout(timeout);
        await worker.terminate();
    }
});

await test('MessagePipe close completes if onmessage is removed during a drain', async () => {
    const worker = new Worker({ type: 'manyThenClose', count: 5 });
    const events = [];
    let timeout;
    try {
        const closed = new Promise((resolve, reject) => {
            timeout = setTimeout(() => reject(new Error('Worker close timed out')), 3000);
            worker.messagePipe.onmessage = data => {
                events.push(data.index);
                worker.messagePipe.onmessage = null;
            };
            worker.messagePipe.onclose = () => {
                events.push('close');
                resolve();
            };
        });
        await closed;
        assertEquals(events[0], 0);
        assertEquals(events[events.length - 1], 'close');
        const remaining = worker.messagePipe.pendingStats().messages;
        const delivered = events.slice(0, -1);
        if (remaining > 0) {
            await new Promise((resolve, reject) => {
                clearTimeout(timeout);
                timeout = setTimeout(() => reject(new Error('Late drain timed out')), 3000);
                worker.messagePipe.onmessage = data => {
                    delivered.push(data.index);
                    if (delivered.length === 5) resolve();
                };
            });
        }
        assertEquals(delivered.join(','), '0,1,2,3,4',
            'removing a handler must not discard later frames');
        assertEquals(worker.messagePipe.pendingStats().messages, 0);
    } finally {
        clearTimeout(timeout);
        await worker.terminate();
    }
});

await test('Worker bidirectional communication', async () => {
    const worker = new Worker({ type: 'waitForCommand', testId: 'bidirectional' });
    
    // Wait for worker to be ready
    const waiting = await waitForMessageType(worker.messagePipe, 'waiting');
    assertEquals(waiting.testId, 'bidirectional');
    
    // Send ping command
    const pongPromise = waitForMessageType(worker.messagePipe, 'pong');
    worker.messagePipe.postMessage({ command: 'ping' });
    const pong = await pongPromise;
    assertEquals(pong.testId, 'bidirectional');
    
    // Send exit command
    const exitPromise = waitForMessageType(worker.messagePipe, 'exiting');
    worker.messagePipe.postMessage({ command: 'exit' });
    const exiting = await exitPromise;
    assertEquals(exiting.testId, 'bidirectional');
    
    await worker.terminate();
});

await test('Main thread isWorker=false', async () => {
    assertEquals(isWorker, false, 'Main thread should report isWorker=false');
});

await test('Main thread pipe undefined', async () => {
    assertEquals(pipe, undefined, 'Main thread should have undefined pipe');
});

await test('Main thread workerData undefined', async () => {
    assertEquals(workerData, undefined, 'Main thread should have undefined workerData');
});

console.log('\n✅ All Worker compatibility tests passed!');
