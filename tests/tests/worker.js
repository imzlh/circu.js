/**
 * Worker Compatibility Tests
 */

const { use } = import.meta;
const { Worker, isWorker, pipe, workerData } = use('worker');
const console = use('console');
const { setTimeout, clearTimeout, setInterval, clearInterval } = use('timers');

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
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            reject(new Error('Timeout waiting for message'));
        }, timeout);
        
        const originalHandler = pipe.onmessage;
        pipe.onmessage = (data) => {
            clearTimeout(timer);
            pipe.onmessage = originalHandler;
            resolve(data);
        };
    });
}

// Wait for specific message type
async function waitForMessageType(pipe, expectedType, timeout = 5000) {
    const startTime = Date.now();
    return new Promise((resolve, reject) => {
        const checkTimeout = () => {
            if (Date.now() - startTime > timeout) {
                reject(new Error(`Timeout waiting for message type: ${expectedType}`));
            }
        };
        
        const timer = setInterval(checkTimeout, 100);
        
        const handler = (data) => {
            if (data.type === expectedType) {
                clearInterval(timer);
                pipe.onmessage = null;
                resolve(data);
            }
        };
        pipe.onmessage = handler;
    });
}

await test('Worker basic creation and termination', async () => {
    const worker = new Worker({ type: 'checkIsWorker', testId: 'basic' });
    assert(worker, 'Worker should be created');
    assert(worker.messagePipe, 'Worker should have pipe');
    assert(typeof worker.terminate === 'function', 'Worker should have terminate method');
    
    // Clean up
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
    
    // Create multiple workers
    for (let i = 0; i < WORKER_COUNT; i++) {
        const worker = new Worker({ type: 'stress', testId: `stress-${i}` });
        workers.push(worker);
        promises.push(waitForMessageType(worker.messagePipe, 'stress'));
    }
    
    // Wait for all to complete
    const results = await Promise.all(promises);
    
    // Verify all workers completed successfully
    for (let i = 0; i < WORKER_COUNT; i++) {
        assertEquals(results[i].type, 'stress');
        assertEquals(results[i].testId, `stress-${i}`);
        assert(typeof results[i].result === 'number', 'Result should be a number');
    }
    
    // Clean up
    for (const worker of workers) {
        await worker.terminate();
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
