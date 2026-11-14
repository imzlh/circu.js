const wasm = import.meta.use('wasm');
const fs = import.meta.use('fs');
const ffi = import.meta.use('ffi');

function bytes() {
    const path = fs.exists('native/wasm.wasm') ? 'native/wasm.wasm' : 'tests/native/wasm.wasm';
    return fs.readFile(path);
}

test('wasm low-level API is object-oriented', () => {
    assert(wasm);
    for (const oldName of [
        'parseModule', 'moduleImports', 'moduleExports', 'buildInstance',
        'getMemoryBuffer', 'callFuncByIndex', 'getFuncIndex',
    ]) {
        assert(!(oldName in wasm), `${oldName} must not remain on the namespace`);
    }

    const module = wasm.load(bytes());
    assert(typeof module.imports === 'function');
    assert(typeof module.exports === 'function');
    assert(typeof module.instantiate === 'function');

    const imported = module.imports()[0];
    assert(imported.kind === 'function');
    assert(Array.isArray(imported.parameters));
    assert(imported.parameters[0] === 'i32' && imported.parameters[1] === 'i32');
    assert(Array.isArray(imported.results) && imported.results.length === 0);

    const memory = module.exports().find(entry => entry.kind === 'memory');
    assert(memory && memory.initial === 1);
    assert(typeof memory.maximum === 'number');
    assert(memory.shared === false);
});

test('wasm Module can create multiple owner-safe Instances', () => {
    const module = wasm.load(bytes());
    let calls = 0;
    module.resolveFunctions([{
        module: 'env',
        name: 'console_log',
        func(offset, length) {
            calls++;
            assert(offset === 0 && length === 35);
        },
    }]);

    const first = module.instantiate({ stackSize: 16 * 1024 });
    const second = module.instantiate();
    first.call('trigger');
    second.call('trigger');
    assert(calls === 2);
    assert(first.runningMode() === 'interpreter');
    assert(first.boundsChecks() === true);
});

test('wasm memory views use app offsets and detach after grow', () => {
    const module = wasm.load(bytes());
    module.resolveFunctions([{
        module: 'env',
        name: 'console_log',
        func() {},
    }]);
    const instance = module.instantiate({ hostManagedHeapSize: 64 * 1024 });

    const offset = instance.dupData(new Uint8Array([1, 2, 3, 4]));
    assert(instance.validateAddress(offset, 4));
    const range = instance.addressRange(offset);
    assert(range && range.start <= offset && range.end >= offset + 3);
    const view = instance.memoryView(offset, 4);
    assert(view[0] === 1 && view[3] === 4);

    let pointerError;
    try {
        ffi.unsafe.pointerOf(view);
    } catch (error) {
        pointerError = error;
    }
    assert(pointerError && String(pointerError).includes('does not support pinning'),
        'FFI must reject a long-lived pointer into movable WASM memory');

    const libc = ffi.open(ffi.libraries.c);
    try {
        const strlen = libc.bind([ffi.types.usize, 'strlen', ffi.types.buffer]);
        let callError;
        try {
            strlen(view);
        } catch (error) {
            callError = error;
        }
        assert(callError && String(callError).includes('does not support pinning'),
            'FFI buffer calls must reject movable WASM memory before entering native code');
    } finally {
        libc.close();
    }

    const before = instance.memoryInfo().currentPages;
    assert(instance.growMemory(1) === before);
    assert(view.buffer.byteLength === 0, 'memory growth must detach stale views');
    instance.free(offset);
});
