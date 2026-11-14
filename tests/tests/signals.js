const processModule = import.meta.use('process');
const signalsModule = import.meta.use('signals');
const os = import.meta.use('os');
const worker = import.meta.use('worker');
const { setTimeout, clearTimeout } = import.meta.use('timers');

if (worker.isWorker && worker.workerData?.type === 'signalEnumProbe') {
    let handlerRejected = false;
    try {
        signalsModule.signal(signalsModule.signals.SIGTERM, () => {});
    } catch (cause) {
        handlerRejected = cause instanceof TypeError;
    }
    worker.pipe.postMessage({
        signal: signalsModule.signals.SIGTERM,
        handlerRejected,
    });
} else {
    await test('signals - enum values and handlers use numbers', () => {
        const signalNumber = signalsModule.signals.SIGTERM;
        assertEquals(typeof signalNumber, 'number');

        const handler = signalsModule.signal(signalNumber, () => {});
        assertEquals(handler.signal, signalNumber);
        handler.close();
    });

    await test('signals - signal 0 cannot register a handler', () => {
        try {
            signalsModule.signal(0, () => {});
            assert(false, 'signal 0 must not register a handler');
        } catch (cause) {
            assert(cause instanceof RangeError, 'signal 0 should throw RangeError');
        }
    });

    await test('process - isAlive probes without exposing signal 0', () => {
        assertEquals(processModule.isAlive(os.pid), true,
            'current process should be alive');
        assertEquals(processModule.isAlive(2147483647), false,
            'unknown PID should not be alive');

        try {
            processModule.kill(os.pid, 0);
            assert(false, 'kill must not expose signal 0 as a signal token');
        } catch (cause) {
            assert(cause instanceof RangeError,
                'signal 0 should stay rejected by kill');
        }
    });

    await test('signals - workers can read enum values but cannot register handlers', async () => {
        const child = new worker.Worker({ type: 'signalEnumProbe' });
        try {
            const result = await new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('signal worker probe timed out')), 3000);
                child.messagePipe.onmessage = value => {
                    clearTimeout(timer);
                    resolve(value);
                };
                child.messagePipe.onmessageerror = reject;
            });
            assertEquals(result.signal, signalsModule.signals.SIGTERM);
            assertEquals(result.handlerRejected, true);
        } finally {
            await child.terminate();
        }
    });

    if (os.platform !== 'windows') {
        await test('process - signal input and results use signals.signals', async () => {
            const signalNumber = signalsModule.signals.SIGTERM;
            const child = processModule.spawn(['sleep', '10']);

            try {
                child.kill('SIGTERM');
                assert(false, 'string signals must be rejected');
            } catch (cause) {
                assert(cause instanceof TypeError, 'string signals should throw TypeError');
            }

            await new Promise(resolve => setTimeout(resolve, 25));
            child.kill(signalNumber);
            const status = await child.wait();
            assertEquals(status.term_signal, signalNumber);

            const syncStatus = processModule.spawnSync(['sh', '-c', 'kill -TERM $$']);
            assertEquals(syncStatus.signal, signalNumber);
        });
    }
}
