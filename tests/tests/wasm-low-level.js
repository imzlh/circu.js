const wasm = import.meta.use('wasm');
const fs = import.meta.use('fs');
const ffi = import.meta.use('ffi');
const engine = import.meta.use('engine');

function bytes() {
    const path = fs.exists('native/wasm.wasm') ? 'native/wasm.wasm' : 'tests/native/wasm.wasm';
    return fs.readFile(path);
}

// Precompiled from tests/native/wasm-provider-chain.wat. Keep this fixture
// inline so the test suite does not require wat2wasm at runtime.
const PROVIDER_CHAIN_BYTES = Uint8Array.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x09, 0x02, 0x60, 0x00, 0x01, 0x7f, 0x60,
    0x00, 0x01, 0x7e, 0x02, 0x26, 0x02, 0x08, 0x70,
    0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x08,
    0x74, 0x68, 0x72, 0x6f, 0x77, 0x69, 0x6e, 0x67,
    0x00, 0x00, 0x08, 0x70, 0x72, 0x6f, 0x76, 0x69,
    0x64, 0x65, 0x72, 0x05, 0x77, 0x72, 0x6f, 0x6e,
    0x67, 0x00, 0x01, 0x03, 0x04, 0x03, 0x00, 0x01,
    0x00, 0x06, 0x0b, 0x02, 0x7f, 0x01, 0x41, 0x00,
    0x0b, 0x7f, 0x01, 0x41, 0x00, 0x0b, 0x07, 0x36,
    0x05, 0x08, 0x74, 0x68, 0x72, 0x6f, 0x77, 0x69,
    0x6e, 0x67, 0x00, 0x02, 0x05, 0x77, 0x72, 0x6f,
    0x6e, 0x67, 0x00, 0x03, 0x05, 0x70, 0x72, 0x6f,
    0x62, 0x65, 0x00, 0x04, 0x0a, 0x61, 0x66, 0x74,
    0x65, 0x72, 0x54, 0x68, 0x72, 0x6f, 0x77, 0x03,
    0x00, 0x0a, 0x61, 0x66, 0x74, 0x65, 0x72, 0x57,
    0x72, 0x6f, 0x6e, 0x67, 0x03, 0x01, 0x0a, 0x18,
    0x03, 0x08, 0x00, 0x10, 0x00, 0x41, 0x01, 0x24,
    0x00, 0x0b, 0x08, 0x00, 0x10, 0x01, 0x41, 0x01,
    0x24, 0x01, 0x0b, 0x04, 0x00, 0x41, 0x2a, 0x0b,
]);

function providerDescriptor(name, func, provider) {
    const descriptor = { module: 'provider', name, func };
    if (provider) {
        descriptor.provider = provider;
        descriptor.sourceIndex = provider.functionIndex(name);
    }
    return descriptor;
}

function providerChain(leafFunctions) {
    const leafModule = wasm.load(PROVIDER_CHAIN_BYTES);
    const leaf = leafModule.instantiate({
        functions: [
            providerDescriptor('throwing', leafFunctions.throwing),
            providerDescriptor('wrong', leafFunctions.wrong),
        ],
    });

    const middleModule = wasm.load(PROVIDER_CHAIN_BYTES);
    const middle = middleModule.instantiate({
        functions: [
            providerDescriptor('throwing', () => 0, leaf),
            providerDescriptor('wrong', () => 0n, leaf),
        ],
    });

    const outerModule = wasm.load(PROVIDER_CHAIN_BYTES);
    const outer = outerModule.instantiate({
        functions: [
            providerDescriptor('throwing', () => 0, middle),
            providerDescriptor('wrong', () => 0n, middle),
        ],
    });

    return { outer, middle, leaf };
}

function assertProviderCanReenter(instance, failureKind, instanceName) {
    let result;
    let thrown;
    try {
        result = instance.call('probe');
    } catch (error) {
        thrown = error;
    }
    assert(thrown === undefined,
        `${failureKind} must not leave a stale exception on ${instanceName}: ${thrown}`);
    assert(result === 42, `${instanceName} must run after the caught chain failure`);
}

function assertProviderChainRecovered(chain, failureKind) {
    for (const [name, instance] of Object.entries(chain)) {
        assert(instance.exception() === null,
            `${failureKind} must clear the propagated trap from ${name}`);
        assertProviderCanReenter(instance, failureKind, name);
    }
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

test('wasm Instance finalization detaches memory without retaining its realm', () => {
    const source = `
        const module = wasm.load(bytes);
        module.resolveFunctions([{ module: 'env', name: 'console_log', func() {} }]);
        const instance = module.instantiate();
        globalThis.buffer = instance.memoryBuffer();
    `;
    let sandbox = new engine.Sandbox();
    sandbox.global.wasm = wasm;
    sandbox.global.bytes = bytes();
    sandbox.call(source);
    const buffer = sandbox.global.buffer;
    assert(buffer.byteLength > 0);

    sandbox = null;
    engine.gc.run();
    assert(buffer.byteLength === 0,
        'collecting an Instance realm must detach its externally held memory buffer');
});

test('wasm provider chains propagate an imported JS exception through every consumer', () => {
    const sentinel = new Error('provider-chain sentinel');
    const { outer, middle, leaf } = providerChain({
        throwing() { throw sentinel; },
        wrong() { return 0n; },
    });

    let thrown;
    try {
        outer.call('throwing');
    } catch (error) {
        thrown = error;
    }

    assert(thrown === sentinel, 'the outer call must rethrow the original JS exception');
    assertProviderChainRecovered({ outer, middle, leaf }, 'the caught JS exception');
    assert(leaf.getGlobal('afterThrow') === 0,
        'the leaf must stop immediately after its JS import throws');
    assert(middle.getGlobal('afterThrow') === 0,
        'the middle provider must not consume an undefined import result');
    assert(outer.getGlobal('afterThrow') === 0,
        'the outer consumer must stop when its provider traps');
});

test('wasm provider chains propagate JS import result conversion failures', () => {
    const { outer, middle, leaf } = providerChain({
        throwing() { return 0; },
        // A Number is invalid for a WebAssembly i64 result; it must be a BigInt.
        wrong() { return 7; },
    });

    let thrown;
    try {
        outer.call('wrong');
    } catch (error) {
        thrown = error;
    }

    assert(thrown instanceof TypeError,
        'the outer call must receive the JS i64 conversion TypeError');
    assertProviderChainRecovered({ outer, middle, leaf }, 'the caught conversion failure');
    assert(leaf.getGlobal('afterWrong') === 0,
        'the leaf must stop after its JS result conversion fails');
    assert(middle.getGlobal('afterWrong') === 0,
        'the middle provider must not consume the invalid import result');
    assert(outer.getGlobal('afterWrong') === 0,
        'the outer consumer must stop when its provider conversion traps');
});
