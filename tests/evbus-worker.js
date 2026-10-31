const evbus = import.meta.use('evbus');
const worker = import.meta.use('worker');

if (worker.isWorker) {
    const ns = worker.workerData.namespace;
    const hadParentValue = evbus.has(ns, 'key');
    const hadParentListener = evbus.emit(ns, 'event');
    evbus.set(ns, 'key', 'worker');
    evbus.on(ns, 'event', () => {});
    worker.pipe.postMessage({ hadParentValue, hadParentListener, value: evbus.get(ns, 'key') });
} else {
    await test('evbus - workers have an independent runtime bus', async () => {
        const ns = `circu.tests.evbus.worker.${Date.now()}`;
        const { setTimeout, clearTimeout } = import.meta.use('timers');
        evbus.set(ns, 'key', 'parent');
        let calls = 0;
        const off = evbus.on(ns, 'event', () => calls++);
        const child = new worker.Worker({ namespace: ns });

        try {
            const message = await new Promise((resolve, reject) => {
                const timer = setTimeout(() => reject(new Error('evbus worker timed out')), 5000);
                child.messagePipe.onmessage = value => {
                    clearTimeout(timer);
                    resolve(value);
                };
            });
            assertEquals(message.hadParentValue, false);
            assertEquals(message.hadParentListener, false);
            assertEquals(message.value, 'worker');
            assertEquals(evbus.get(ns, 'key'), 'parent');
            assertEquals(evbus.emit(ns, 'event'), true);
            assertEquals(calls, 1);
        } finally {
            await child.terminate();
            off();
            evbus.clear(ns);
        }
    });
}
