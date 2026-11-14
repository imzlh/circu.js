// Tests for the high-level native FFI API. The companion ffi_fixture shared
// library is built next to the cjs executable by CMake.

const ffi = import.meta.use('ffi');
const engine = import.meta.use('engine');
const os = import.meta.use('os');
const text = import.meta.use('text');
const worker = import.meta.use('worker');
const types = ffi.types;

function fixturePath() {
    const slash = Math.max(os.exePath.lastIndexOf('/'), os.exePath.lastIndexOf('\\'));
    const directory = slash < 0 ? '.' : os.exePath.slice(0, slash);
    const filename = os.platform === 'windows'
        ? 'ffi_fixture.dll'
        : os.platform === 'darwin'
            ? 'libffi_fixture.dylib'
            : 'libffi_fixture.so';
    return directory + (os.platform === 'windows' ? '\\' : '/') + filename;
}

function assertArrayEquals(actual, expected, message) {
    assertEquals(actual.length, expected.length, message ?? 'array lengths differ');
    for (let i = 0; i < expected.length; i++) {
        assertEquals(actual[i], expected[i], message ?? `array element ${i} differs`);
    }
}

function assertThrows(fn, messagePart) {
    let error;
    try {
        fn();
    } catch (caught) {
        error = caught;
    }
    assert(error !== undefined, `expected an exception containing ${messagePart ?? 'any message'}`);
    if (messagePart !== undefined) {
        assert(String(error).toLowerCase().includes(messagePart.toLowerCase()),
            `exception ${String(error)} does not contain ${messagePart}`);
    }
    return error;
}

async function collectUnreachableFfiOwners() {
    // Run more than one collection and drain jobs between passes. This keeps
    // pointer-finalizer tests independent of temporary roots in the creating
    // frame and of cleanup work queued by a finalizer.
    for (let i = 0; i < 3; i++) {
        engine.gc.run();
        await Promise.resolve();
    }
}

function alignUp(value, alignment) {
    return Math.ceil(value / alignment) * alignment;
}

await test('ffi exposes immutable ABI type descriptors', () => {
    assert(Object.isFrozen(types), 'ffi.types must be frozen');
    assert(Object.isFrozen(ffi.libraries), 'ffi.libraries must be frozen');
    for (const name of [
        'void', 'bool', 'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64',
        'f32', 'f64', 'pointer', 'buffer', 'function', 'int', 'uint', 'long',
        'ulong', 'longLong', 'ulongLong', 'usize', 'isize', 'longDouble',
    ]) {
        assert(types[name], `missing ffi.types.${name}`);
        assert(typeof types[name].name === 'string', `${name}.name must be a string`);
        assert(typeof types[name].size === 'number', `${name}.size must be a number`);
        assert(typeof types[name].alignment === 'number', `${name}.alignment must be a number`);
        assert(Object.isFrozen(types[name]), `${name} descriptor must be frozen`);
    }

    const originalSize = types.i32.size;
    assertThrows(() => { types.i32.size = 99; });
    assertEquals(types.i32.size, originalSize);

    assertEquals(types.void.size, 0);
    assertEquals(types.i8.size, 1);
    assertEquals(types.u32.size, 4);
    assert(types.pointer.size === types.usize.size, 'pointer and usize must have the same size');
});

await test('ffi struct and array descriptors pack ABI-shaped bytes', () => {
    const record = types.struct([types.u8, types.u32, types.f64]);
    const expectedAlignment = Math.max(types.u8.alignment, types.u32.alignment, types.f64.alignment);
    const expectedOffsets = [
        0,
        alignUp(types.u8.size, types.u32.alignment),
        alignUp(alignUp(types.u8.size, types.u32.alignment) + types.u32.size, types.f64.alignment),
    ];
    const expectedSize = alignUp(expectedOffsets[2] + types.f64.size, expectedAlignment);
    assertEquals(record.size, expectedSize);
    assertEquals(record.alignment, expectedAlignment);
    assertArrayEquals(record.offsets, expectedOffsets);

    const packed = record.pack([5, 35, 1.5]);
    assert(packed instanceof Uint8Array, 'struct.pack must return Uint8Array');
    assertEquals(packed.length, record.size);
    const unpacked = record.unpack(packed);
    assertArrayEquals(unpacked, [5, 35, 1.5]);

    const words = types.array(types.u16, 3);
    assertEquals(words.size, 6);
    assertEquals(words.alignment, 2);
    const packedWords = words.pack([0x102, 0x304, 0x506]);
    assertEquals(packedWords.length, 6);
    assertArrayEquals(words.unpack(packedWords), [0x102, 0x304, 0x506]);

    assertThrows(() => record.pack([1, 2]), '3');
    assertThrows(() => record.unpack(new Uint8Array(record.size - 1)), 'size');
    assertThrows(() => types.array(types.u8, 0), 'positive');
});

await test('ffi validates aggregate counts as strict positive integers', () => {
    for (const count of [-1, 1.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
        assertThrows(() => types.array(types.u8, count));
    }
});

await test('ffi opens libc and binds scalar and zero-copy buffer calls', () => {
    const libc = ffi.open(ffi.libraries.c);
    try {
        const abs = libc.bind([types.int, 'abs', types.int]);
        const strlen = libc.bind([types.usize, 'strlen', types.buffer]);
        assertEquals(abs(-123), 123);

        const bytes = new text.Encoder().encode('hello ffi\0ignored');
        assertEquals(strlen(bytes), 9n);
        assert(strlen.pointer !== null, 'a bound function must expose its pointer');
        assert(ffi.unsafe.address(strlen.pointer) > 0n, 'function address must be non-zero');
    } finally {
        libc.close();
    }
});

await test('ffi bound functions retain a temporary library wrapper through GC', () => {
    const add = ffi.open(fixturePath()).bind([
        types.i32,
        'ffi_fixture_add_i32',
        types.i32,
        types.i32,
    ]);
    engine.gc.run();
    assertEquals(add(20, 22), 42,
        'a live binding must keep its otherwise unreachable library loaded');
});

await test('ffi fixture covers scalar, bigint, buffer, symbol, and errno calls', () => {
    const library = ffi.open(fixturePath());
    try {
        const add = library.bind([types.i32, 'ffi_fixture_add_i32', types.i32, types.i32]);
        const roundtrip = library.bind([types.u64, 'ffi_fixture_roundtrip_u64', types.u64]);
        const weighted = library.bind([types.f64, 'ffi_fixture_weighted_sum', types.f64, types.f64, types.i32]);
        const xor = library.bind([types.void, 'ffi_fixture_xor_bytes', types.buffer, types.usize, types.u8]);
        const setErrno = library.bind([types.i32, 'ffi_fixture_set_errno', types.i32]);

        assertEquals(add(20, 22), 42);
        assertThrows(() => add(1), 'argument');
        assertThrows(() => add('1', 2), 'number');
        assertEquals(roundtrip(0xfedcba9876543210n), 0xfedcba9876543210n);
        assertEquals(weighted(1.25, 2.25, 4), 14);

        const storage = new Uint8Array([1, 2, 3, 4, 5, 6]);
        const slice = storage.subarray(1, 5);
        xor(slice, BigInt(slice.length), 0xff);
        assertArrayEquals(storage, [1, 253, 252, 251, 250, 6]);

        assertEquals(library.read([types.i32, 'ffi_fixture_global']), 0x12345678);
        assert(ffi.unsafe.address(library.symbol('ffi_fixture_global')) > 0n);
        assertThrows(() => library.symbol('ffi_fixture_missing_symbol'), 'symbol');

        assertEquals(setErrno(22), -1);
        assertEquals(ffi.errno(), 22);
        assert(ffi.strerror(ffi.errno()).length > 0, 'strerror must return a message');
    } finally {
        library.close();
    }
});

await test('ffi preserves every fixed-width integer boundary', () => {
    const library = ffi.open(fixturePath());
    try {
        const cases = [
            [types.i8, 'ffi_fixture_roundtrip_i8', -128, 127],
            [types.u8, 'ffi_fixture_roundtrip_u8', 0, 255],
            [types.i16, 'ffi_fixture_roundtrip_i16', -32768, 32767],
            [types.u16, 'ffi_fixture_roundtrip_u16', 0, 65535],
            [types.i32, 'ffi_fixture_roundtrip_i32', -2147483648, 2147483647],
            [types.u32, 'ffi_fixture_roundtrip_u32', 0, 4294967295],
            [types.i64, 'ffi_fixture_roundtrip_i64', -9223372036854775808n, 9223372036854775807n],
            [types.u64, 'ffi_fixture_roundtrip_u64', 0n, 18446744073709551615n],
        ];
        for (const [type, symbol, minimum, maximum] of cases) {
            const roundtrip = library.bind([type, symbol, type]);
            assertEquals(roundtrip(minimum), minimum, `${symbol} minimum changed`);
            assertEquals(roundtrip(maximum), maximum, `${symbol} maximum changed`);
        }

        const roundtripBool = library.bind([
            types.bool,
            'ffi_fixture_roundtrip_bool',
            types.bool,
        ]);
        assertEquals(roundtripBool(false), false);
        assertEquals(roundtripBool(true), true);
        assertThrows(() => roundtripBool(1), 'boolean');

        const invalidCases = [
            [types.i8, 'ffi_fixture_roundtrip_i8', [-129, 128, 1.5, NaN, Infinity]],
            [types.u8, 'ffi_fixture_roundtrip_u8', [-1, 256, 1.5, NaN, Infinity]],
            [types.i16, 'ffi_fixture_roundtrip_i16', [-32769, 32768, 1.5, NaN, Infinity]],
            [types.u16, 'ffi_fixture_roundtrip_u16', [-1, 65536, 1.5, NaN, Infinity]],
            [types.i32, 'ffi_fixture_roundtrip_i32', [-2147483649, 2147483648, 1.5, NaN, Infinity]],
            [types.u32, 'ffi_fixture_roundtrip_u32', [-1, 4294967296, 1.5, NaN, Infinity]],
            [types.i64, 'ffi_fixture_roundtrip_i64', [
                -9223372036854775809n,
                9223372036854775808n,
            ]],
            [types.u64, 'ffi_fixture_roundtrip_u64', [-1n, 18446744073709551616n]],
        ];
        for (const [type, symbol, invalidValues] of invalidCases) {
            const roundtrip = library.bind([type, symbol, type]);
            for (const value of invalidValues) assertThrows(() => roundtrip(value));
        }
    } finally {
        library.close();
    }
});

await test('ffi bind cache keys include signature token identity and normalized options', () => {
    const library = ffi.open(fixturePath());
    try {
        const signature = [types.i32, 'ffi_fixture_add_i32', types.i32, types.i32];
        const first = library.bind(signature);
        const same = library.bind([
            types.i32,
            'ffi_fixture_add_i32',
            types.i32,
            types.i32,
        ]);
        const sameWithEmptyOptions = library.bind(signature, {});
        assert(first === same, 'identical binds must reuse the bound function object');
        assert(first === sameWithEmptyOptions,
            'omitted and empty options must have the same normalized cache key');

        const differentSignature = library.bind([
            types.u32,
            'ffi_fixture_add_i32',
            types.i32,
            types.i32,
        ]);
        assert(first !== differentSignature, 'a different result token must not hit the cache');
        assertEquals(differentSignature(20, 22), 42);
        const differentParameter = library.bind([
            types.i32,
            'ffi_fixture_add_i32',
            types.u32,
            types.i32,
        ]);
        assert(first !== differentParameter, 'a different parameter token must not hit the cache');
        assert(differentSignature !== differentParameter,
            'distinct signatures for one symbol must have distinct cache entries');

        const variadicSignature = [
            types.i32,
            'ffi_fixture_sum_varargs',
            types.i32,
            types.i32,
            types.i32,
            types.i32,
        ];
        const fixedOne = library.bind(variadicSignature, { fixed: 1 });
        const sameFixedOne = library.bind(variadicSignature, { fixed: 1 });
        const fixedTwo = library.bind(variadicSignature, { fixed: 2 });
        assert(fixedOne === sameFixedOne, 'equivalent fixed options must hit the cache');
        assert(fixedOne !== fixedTwo, 'different fixed counts must not hit the cache');
        assertEquals(fixedOne(3, 10, 20, 12), 42);
    } finally {
        library.close();
    }
});

await test('ffi binding keeps its library loaded after a temporary Library wrapper is collected', () => {
    const add = ffi.open(fixturePath()).bind([
        types.i32,
        'ffi_fixture_add_i32',
        types.i32,
        types.i32,
    ]);

    engine.gc.run();
    assertEquals(add(20, 22), 42,
        'collecting the Library wrapper must not implicitly close surviving bindings');
});

await test('ffi keeps zero-length BufferSource distinct from null', () => {
    const library = ffi.open(fixturePath());
    try {
        const isNull = library.bind([
            types.i32,
            'ffi_fixture_pointer_is_null',
            types.buffer,
        ]);
        assertEquals(isNull(null), 1);
        const empty = new Uint8Array(0);
        assert(ffi.unsafe.pointerOf(empty) !== null,
            'unsafe.pointerOf must preserve a zero-length backing store');
        assertEquals(isNull(empty), 0,
            'an empty backing store must still be passed as a non-null buffer');

        const storage = new Uint8Array(4);
        assertEquals(isNull(storage.subarray(storage.length)), 0,
            'a zero-length view at the end of a backing store must not become null');

        const detached = new ArrayBuffer(4);
        const detachedView = new Uint8Array(detached);
        engine.detachArrayBuffer(detached);
        assertThrows(() => isNull(detached));
        assertThrows(() => isNull(detachedView));
        assertThrows(() => ffi.unsafe.pointerOf(detached));
        assertThrows(() => ffi.unsafe.pointerOf(detachedView));
    } finally {
        library.close();
    }
});

await test('ffi accepts SharedArrayBuffer views and honors their byteOffset', () => {
    const library = ffi.open(fixturePath());
    try {
        const xor = library.bind([
            types.void,
            'ffi_fixture_xor_bytes',
            types.buffer,
            types.usize,
            types.u8,
        ]);
        const shared = engine.toSharedBytes(new Uint8Array([1, 2, 3, 4, 5]));
        const slice = shared.subarray(1, 4);
        xor(slice, 3n, 0xff);
        assertArrayEquals(shared, [1, 253, 252, 251, 5]);
    } finally {
        library.close();
    }
});

await test('ffi pointerOf pins a shared backing through derived pointers and views', async () => {
    const backing = new ArrayBuffer(32);
    const bytes = new Uint8Array(backing);
    let first;
    let second;
    [first, second] = (() => {
        const firstView = new Uint8Array(backing, 1, 8);
        const secondView = new DataView(backing, 8, 8);
        return [ffi.unsafe.pointerOf(firstView), ffi.unsafe.pointerOf(secondView)];
    })();

    assertEquals(ffi.unsafe.address(second) - ffi.unsafe.address(first), 7n,
        'pointerOf must include each BufferSource byteOffset');
    assertEquals(backing.immutable, false,
        'pinning an address must not make the buffer contents immutable');
    bytes[1] = 41;
    assertEquals(bytes[1], 41, 'ordinary typed-array writes must remain enabled');

    // The public immutable toggle is not the FFI address pin. Clearing it is
    // allowed, but must not permit detachment while any Pointer still exists.
    engine.setImmutableArrayBuffer(backing, false);
    assertEquals(backing.immutable, false);
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');

    let derived = ffi.unsafe.offset(second, 1);
    let borrowedView = ffi.unsafe.view(derived, 2);
    borrowedView[0] = 99;
    assertEquals(bytes[9], 99, 'unsafe.view must remain writable and zero-copy');

    first = null;
    await collectUnreachableFfiOwners();
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');

    second = null;
    await collectUnreachableFfiOwners();
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');

    derived = null;
    await collectUnreachableFfiOwners();
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');
    assertEquals(borrowedView[0], 99,
        'an unsafe view must retain its hidden Pointer owner');

    borrowedView = null;
    await collectUnreachableFfiOwners();
    engine.detachArrayBuffer(backing);
    assertEquals(backing.detached, true,
        'the backing must become detachable after the final owner is collected');
});

await test('ffi pointerOf pins zero-length backing stores until Pointer GC', async () => {
    const backing = new ArrayBuffer(0);
    let pointer = (() => ffi.unsafe.pointerOf(new Uint8Array(backing)))();
    assert(pointer !== null, 'a zero-length backing store still has pointer identity');
    assertEquals(ffi.unsafe.view(pointer, 0).length, 0);
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');

    pointer = null;
    await collectUnreachableFfiOwners();
    engine.detachArrayBuffer(backing);
    assertEquals(backing.detached, true);
});

await test('ffi pins make structured-clone transfer rejection atomic', () => {
    const first = new ArrayBuffer(8);
    const pinned = new ArrayBuffer(8);
    const pointer = ffi.unsafe.pointerOf(pinned);
    assertThrows(
        () => new worker.Worker({ first, pinned }, [first, pinned]),
        'pinned',
    );
    assertEquals(first.detached, false,
        'an earlier transfer-list entry must remain attached after rejection');
    assertEquals(pinned.detached, false,
        'the pinned transfer-list entry must remain attached after rejection');
    assertEquals(ffi.unsafe.view(pointer, 1).length, 1,
        'failed transfer must leave the borrowed address valid');
});

await test('ffi temporary call pins and pointerOf lifetime pins have independent counts', async () => {
    const library = ffi.open(fixturePath());
    const mutateAroundCallback = library.bind([
        types.i32,
        'ffi_fixture_mutate_around_callback',
        types.buffer,
        types.function,
    ]);
    const backing = new ArrayBuffer(8);
    const bytes = new Uint8Array(backing);
    let lifetimePointer;
    let createPointer;
    let releasePointer;
    try {
        createPointer = ffi.callback([types.i32, types.i32, types.i32], (left, right) => {
            lifetimePointer = ffi.unsafe.pointerOf(bytes);
            return left * 10 + right;
        });
        assertEquals(mutateAroundCallback(bytes, createPointer.pointer), 43);
        assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');
        assertEquals(ffi.unsafe.view(lifetimePointer, 2)[1], 42,
            'the lifetime pin created in a callback must survive native return');

        releasePointer = ffi.callback([types.i32, types.i32, types.i32], (left, right) => {
            lifetimePointer = null;
            engine.gc.run();
            assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');
            return left * 10 + right;
        });
        assertEquals(mutateAroundCallback(bytes, releasePointer.pointer), 43);
        await collectUnreachableFfiOwners();
        engine.detachArrayBuffer(backing);
        assertEquals(backing.detached, true,
            'the transient call pin must release after the native call returns');
    } finally {
        createPointer?.close();
        releasePointer?.close();
        library.close();
    }
});

await test('ffi pointerOf prevents resizable backing relocation until Pointer GC', async () => {
    const backing = new ArrayBuffer(8, { maxByteLength: 32 });
    const fixedBacking = new ArrayBuffer(8, { maxByteLength: 16 });
    const immutableBacking = new ArrayBuffer(8, { maxByteLength: 16 });
    const bytes = new Uint8Array(backing);
    bytes[2] = 42;
    let pointer = (() => {
        const slice = new Uint8Array(backing, 2, 4);
        return ffi.unsafe.pointerOf(slice);
    })();
    let fixedPointer = ffi.unsafe.pointerOf(fixedBacking);
    let immutablePointer = ffi.unsafe.pointerOf(immutableBacking);

    engine.setImmutableArrayBuffer(backing, false);
    assertThrows(() => backing.resize(16), 'pinned');
    assertThrows(() => backing.transfer(), 'pinned');
    assertThrows(() => fixedBacking.transferToFixedLength(), 'pinned');
    assertThrows(() => immutableBacking.transferToImmutable(), 'pinned');
    assertThrows(() => engine.detachArrayBuffer(backing), 'pinned');
    assertEquals(ffi.unsafe.view(pointer, 1)[0], 42,
        'failed relocation attempts must leave the borrowed address intact');

    pointer = null;
    fixedPointer = null;
    immutablePointer = null;
    await collectUnreachableFfiOwners();
    backing.resize(16);
    assertEquals(backing.byteLength, 16,
        'resize must recover after the final Pointer releases its pin');
    const transferred = backing.transfer(12);
    assertEquals(backing.detached, true,
        'transfer must recover after the final Pointer releases its pin');
    assertEquals(transferred.byteLength, 12);
    assertEquals(new Uint8Array(transferred)[2], 42);

    const fixed = fixedBacking.transferToFixedLength(6);
    assertEquals(fixedBacking.detached, true);
    assertEquals(fixed.byteLength, 6);
    assertEquals(fixed.resizable, false);

    const immutable = immutableBacking.transferToImmutable(6);
    assertEquals(immutableBacking.detached, true);
    assertEquals(immutable.byteLength, 6);
    assertEquals(immutable.immutable, true);
});

await test('ffi pointerOf pins growable SharedArrayBuffer views without copying', async () => {
    const backing = new SharedArrayBuffer(8, { maxByteLength: 16 });
    const bytes = new Uint8Array(backing);
    let first;
    let second;
    [first, second] = (() => [
        ffi.unsafe.pointerOf(new Uint8Array(backing, 0, 4)),
        ffi.unsafe.pointerOf(new DataView(backing, 2, 4)),
    ])();

    assertEquals(ffi.unsafe.address(second) - ffi.unsafe.address(first), 2n,
        'SharedArrayBuffer views must honor byteOffset');
    bytes[2] = 31;
    assertEquals(ffi.unsafe.view(second, 1)[0], 31);
    let borrowedView = ffi.unsafe.view(ffi.unsafe.offset(second, 1), 1);
    borrowedView[0] = 77;
    assertEquals(bytes[3], 77,
        'unsafe views over SharedArrayBuffer must stay writable and zero-copy');
    assertThrows(() => backing.grow(12), 'pinned');

    first = null;
    second = null;
    await collectUnreachableFfiOwners();
    assertThrows(() => backing.grow(12), 'pinned');
    assertEquals(borrowedView[0], 77,
        'a derived unsafe view must retain the SharedArrayBuffer pin chain');

    borrowedView = null;
    await collectUnreachableFfiOwners();
    backing.grow(12);
    assertEquals(backing.byteLength, 12,
        'grow must recover after the final SharedArrayBuffer owner is collected');
});

await test('ffi calls arbitrary function pointers', () => {
    const library = ffi.open(fixturePath());
    try {
        const getAddPointer = library.bind([types.function, 'ffi_fixture_add_pointer']);
        const pointer = getAddPointer();
        const add = ffi.function(pointer, [types.i32, types.i32, types.i32]);
        assertEquals(add(19, 23), 42);
        assert(ffi.unsafe.address(add.pointer) === ffi.unsafe.address(pointer),
            'ffi.function must retain the supplied address');
    } finally {
        library.close();
    }
});

await test('ffi bind validates variadic signatures eagerly', () => {
    const library = ffi.open(fixturePath());
    try {
        const sum = library.bind([
            types.i32,
            'ffi_fixture_sum_varargs',
            types.i32,
            types.i32,
            types.i32,
            types.i32,
        ], { fixed: 1 });
        assertEquals(sum(3, 10, 20, 12), 42);

        assertThrows(() => library.bind(
            [types.i32, 'ffi_fixture_sum_varargs', types.i32],
            { fixed: 2 },
        ), 'fixed');
        assertThrows(() => library.bind(
            [types.i32, 'ffi_fixture_sum_varargs', types.i32],
            { fixed: -1 },
        ), 'fixed');
        assertThrows(() => library.bind(
            [types.i32, 'ffi_fixture_sum_varargs', types.i32, types.i32],
            { fixed: 0 },
        ), 'fixed');
        assertThrows(() => library.bind(
            [types.i32, 'ffi_fixture_sum_varargs', types.i32, types.i32],
            { fixed: 2 },
        ), 'fixed');
        for (const fixed of [0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
            assertThrows(() => library.bind(
                [types.i32, 'ffi_fixture_sum_varargs', types.i32],
                { fixed },
            ));
        }
    } finally {
        library.close();
    }
});

await test('ffi rejects array tokens as top-level call types', () => {
    const library = ffi.open(fixturePath());
    const array = types.array(types.i32, 2);
    try {
        assertThrows(() => library.bind([
            array,
            'ffi_fixture_add_i32',
            types.i32,
            types.i32,
        ]), 'array');
        assertThrows(() => library.bind([
            types.i32,
            'ffi_fixture_add_i32',
            array,
            types.i32,
        ]), 'array');

        const pointer = library.symbol('ffi_fixture_add_i32');
        assertThrows(() => ffi.function(pointer, [array, types.i32, types.i32]), 'array');
        assertThrows(() => ffi.function(pointer, [types.i32, array, types.i32]), 'array');

        assertThrows(() => ffi.callback([array, types.i32], () => new Uint8Array(array.size)),
            'array');
        assertThrows(() => ffi.callback([types.i32, array], () => 0), 'array');
    } finally {
        library.close();
    }
});

await test('ffi callbacks receive and return direct JS values', () => {
    const library = ffi.open(fixturePath());
    const callback = ffi.callback(
        [types.i32, types.i32, types.i32],
        (left, right) => left * 10 + right,
    );
    const throwingCallback = ffi.callback(
        [types.i32, types.i32, types.i32],
        () => { throw new Error('ffi callback sentinel'); },
    );
    try {
        const call = library.bind([
            types.i32,
            'ffi_fixture_call_callback',
            types.function,
            types.i32,
            types.i32,
        ]);
        assertEquals(call(callback.pointer, 4, 2), 42);
        assertThrows(() => call(throwingCallback.pointer, 1, 2), 'ffi callback sentinel');
    } finally {
        callback.close();
        callback.close();
        throwingCallback.close();
        library.close();
    }
});

await test('ffi callbacks support reentry and logical self-close', () => {
    const library = ffi.open(fixturePath());
    const call = library.bind([
        types.i32,
        'ffi_fixture_call_callback',
        types.function,
        types.i32,
        types.i32,
    ]);
    const callTwice = library.bind([
        types.i32,
        'ffi_fixture_call_callback_twice',
        types.function,
        types.i32,
        types.i32,
    ]);

    let reentrant;
    let selfClosing;
    try {
        reentrant = ffi.callback(
            [types.i32, types.i32, types.i32],
            (depth, base) => depth === 0
                ? base
                : call(reentrant.pointer, depth - 1, base) + 1,
        );
        assertEquals(call(reentrant.pointer, 4, 38), 42,
            'nested native calls must be able to reenter a callback');

        let calls = 0;
        selfClosing = ffi.callback(
            [types.i32, types.i32, types.i32],
            (left, right) => {
                calls++;
                selfClosing.close();
                return left * 10 + right;
            },
        );
        const pointer = selfClosing.pointer;
        assertEquals(callTwice(pointer, 4, 2), 42000,
            'self-close must preserve the active return and zero later native entries');
        assertEquals(calls, 1, 'a closed callback must not reenter JavaScript');
        assertThrows(() => selfClosing.pointer, 'closed');
        assertThrows(() => call(pointer, 4, 2), 'closed');
    } finally {
        if (reentrant !== undefined) reentrant.close();
        if (selfClosing !== undefined) selfClosing.close();
        library.close();
    }
});

await test('ffi callbacks reject calls from a foreign native thread safely', () => {
    const library = ffi.open(fixturePath());
    let entered = false;
    const callback = ffi.callback(
        [types.i32, types.i32, types.i32],
        () => {
            entered = true;
            return 42;
        },
    );
    try {
        const callOnThread = library.bind([
            types.i32,
            'ffi_fixture_call_callback_on_thread',
            types.function,
            types.i32,
            types.i32,
        ]);
        assertThrows(() => callOnThread(callback.pointer, 4, 2), 'thread');
        assertThrows(() => callOnThread(callback.pointer, 4, 2), 'thread');
        assertEquals(entered, false, 'a foreign native thread must never enter QuickJS');
    } finally {
        callback.close();
        library.close();
    }
});

await test('ffi detects foreign-thread callbacks passed as generic pointers', () => {
    const library = ffi.open(fixturePath());
    let entered = false;
    const callback = ffi.callback(
        [types.i32, types.i32, types.i32],
        () => {
            entered = true;
            return 42;
        },
    );
    try {
        const callOnThread = library.bind([
            types.i32,
            'ffi_fixture_call_callback_on_thread',
            types.pointer,
            types.i32,
            types.i32,
        ]);
        assertThrows(() => callOnThread(callback.pointer, 4, 2), 'thread');
        assertEquals(entered, false,
            'using pointer instead of function must not bypass callback thread checks');
    } finally {
        callback.close();
        library.close();
    }
});

await test('ffi delays library unload when a callback closes an active call', () => {
    const library = ffi.open(fixturePath());
    const call = library.bind([
        types.i32,
        'ffi_fixture_call_callback_then_add',
        types.function,
        types.i32,
        types.i32,
        types.i32,
    ]);
    const callback = ffi.callback(
        [types.i32, types.i32, types.i32],
        (left, right) => {
            library.close();
            return left * 10 + right;
        },
    );
    try {
        assertEquals(call(callback.pointer, 4, 0, 2), 42,
            'the active shared-library frame must finish before physical unload');
        assertThrows(() => call(callback.pointer, 4, 0, 2), 'closed');
        assertThrows(() => library.bind([
            types.i32,
            'ffi_fixture_add_i32',
            types.i32,
            types.i32,
        ]), 'closed');
    } finally {
        callback.close();
        library.close();
    }
});

await test('ffi pins buffer backing stores across callback reentry', () => {
    const library = ffi.open(fixturePath());
    const storage = new Uint8Array(2);
    let detachRejected = false;
    const callback = ffi.callback(
        [types.i32, types.i32, types.i32],
        (left, right) => {
            assertThrows(() => engine.detachArrayBuffer(storage.buffer));
            detachRejected = true;
            return left * 10 + right;
        },
    );
    try {
        const mutate = library.bind([
            types.i32,
            'ffi_fixture_mutate_around_callback',
            types.buffer,
            types.function,
        ]);
        assertEquals(mutate(storage, callback.pointer), 43);
        assertEquals(detachRejected, true);
        assertArrayEquals(storage, [1, 42]);
    } finally {
        callback.close();
        library.close();
    }
});

await test('ffi passes and returns structs by value', () => {
    const library = ffi.open(fixturePath());
    try {
        const record = types.struct([types.u8, types.u32, types.f64]);
        const transform = library.bind([
            record,
            'ffi_fixture_transform_record',
            record,
        ]);
        const score = library.bind([types.i32, 'ffi_fixture_record_score', record]);

        const input = record.pack([5, 35, 1.5]);
        assertEquals(score(input), 41);
        const output = transform(input);
        assert(output instanceof Uint8Array, 'struct return value must be raw ABI bytes');
        assertEquals(output.length, record.size);
        assertArrayEquals(record.unpack(output), [6, 42, 3]);
    } finally {
        library.close();
    }
});

await test('ffi arrays retain their ABI layout when nested in structs', () => {
    const library = ffi.open(fixturePath());
    try {
        const values = types.array(types.u16, 3);
        const record = types.struct([types.u8, values, types.u32]);
        const transform = library.bind([
            record,
            'ffi_fixture_transform_array_record',
            record,
        ]);

        const packed = record.pack([5, [10, 20, 30], 60]);
        const output = record.unpack(transform(packed));
        assertEquals(output[0], 6);
        assertArrayEquals(output[1], [11, 21, 31]);
        assertEquals(output[2], 63);
    } finally {
        library.close();
    }
});

await test('ffi unsafe pointers expose offsets, views, dereference, and strings', () => {
    const bytes = new Uint8Array([10, 20, 30, 40, 50]);
    const pointer = ffi.unsafe.pointerOf(bytes.subarray(1, 4));
    const view = ffi.unsafe.view(pointer, 3);
    assertArrayEquals(view, [20, 30, 40]);
    view[1] = 99;
    assertEquals(bytes[2], 99, 'unsafe.view must not copy memory');

    const offset = ffi.unsafe.offset(pointer, 2);
    assertEquals(ffi.unsafe.address(offset) - ffi.unsafe.address(pointer), 2n);
    assertEquals(ffi.unsafe.view(offset, 1)[0], 40);
    assertEquals(ffi.unsafe.fromAddress(0n), null);
    assert(ffi.unsafe.currentEventLoop() !== null, 'event loop pointer must be non-null');

    const library = ffi.open(fixturePath());
    try {
        const getString = library.bind([types.pointer, 'ffi_fixture_string']);
        const getSlot = library.bind([types.pointer, 'ffi_fixture_pointer_slot']);
        assertEquals(ffi.unsafe.readCString(getString()), 'circu ffi fixture');
        assertEquals(ffi.unsafe.readCString(ffi.unsafe.deref(getSlot(), 1)), 'circu ffi fixture');
    } finally {
        library.close();
    }
});

await test('ffi unsafe pointer controls require strict safe integers', () => {
    const bytes = new Uint8Array([10, 20, 30, 40]);
    const middle = ffi.unsafe.pointerOf(bytes.subarray(2));
    const previous = ffi.unsafe.offset(middle, -1);
    assertEquals(ffi.unsafe.view(previous, 1)[0], 20,
        'negative integral pointer offsets must remain supported');

    for (const offset of [0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
        assertThrows(() => ffi.unsafe.offset(middle, offset));
    }
    for (const length of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
        assertThrows(() => ffi.unsafe.view(middle, length));
    }
    assertEquals(ffi.unsafe.view(middle, 0).length, 0);

    const library = ffi.open(fixturePath());
    try {
        const getString = library.bind([types.pointer, 'ffi_fixture_string']);
        const getSlot = library.bind([types.pointer, 'ffi_fixture_pointer_slot']);
        const string = getString();
        const slot = getSlot();

        for (const count of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
            assertThrows(() => ffi.unsafe.deref(slot, count));
        }
        assertEquals(ffi.unsafe.address(ffi.unsafe.deref(slot, 0)), ffi.unsafe.address(slot));

        for (const maximum of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1]) {
            assertThrows(() => ffi.unsafe.readCString(string, maximum));
        }
        assertEquals(ffi.unsafe.readCString(string, 0), '');
    } finally {
        library.close();
    }
});

await test('ffi OwnedPointer releases memory exactly once', () => {
    const library = ffi.open(fixturePath());
    const allocate = library.bind([types.pointer, 'ffi_fixture_alloc', types.usize]);
    const free = library.bind([types.void, 'ffi_fixture_free', types.pointer]);
    const owned = ffi.unsafe.adopt(allocate(8n), free);
    const view = ffi.unsafe.view(owned, 8);
    const derived = ffi.unsafe.offset(owned, 0);
    view[7] = 42;
    assertEquals(view[7], 42);
    owned.close();
    assertThrows(() => ffi.unsafe.address(derived), 'closed');
    owned.close();
    library.close();
});

await test('ffi OwnedPointer retains its disposer across logical library close', () => {
    const library = ffi.open(fixturePath());
    const observer = ffi.open(fixturePath());
    const allocate = library.bind([types.pointer, 'ffi_fixture_alloc', types.usize]);
    const countDisposed = library.bind([
        types.void,
        'ffi_fixture_count_disposed_and_free',
        types.pointer,
    ]);
    const resetCount = observer.bind([types.void, 'ffi_fixture_reset_disposed_count']);
    const getCount = observer.bind([types.u32, 'ffi_fixture_get_disposed_count']);
    resetCount();
    const owned = ffi.unsafe.adopt(allocate(8n), countDisposed);

    library.close();
    assertEquals(getCount(), 0, 'the disposer must not run before OwnedPointer.close');
    owned.close();
    assertEquals(getCount(), 1,
        'the library must remain loaded until its last OwnedPointer disposer runs');
    owned.close();
    assertEquals(getCount(), 1, 'repeated close must not run the disposer twice');
    observer.close();
});

await test('ffi OwnedPointer release transfers the live pointer without disposal', async () => {
    const library = ffi.open(fixturePath());
    const allocate = library.bind([types.pointer, 'ffi_fixture_alloc', types.usize]);
    const free = library.bind([types.void, 'ffi_fixture_free', types.pointer]);
    const countDisposed = library.bind([
        types.void,
        'ffi_fixture_count_disposed_and_free',
        types.pointer,
    ]);
    const resetCount = library.bind([types.void, 'ffi_fixture_reset_disposed_count']);
    const getCount = library.bind([types.u32, 'ffi_fixture_get_disposed_count']);
    resetCount();
    let owned = ffi.unsafe.adopt(allocate(8n), countDisposed);
    const address = ffi.unsafe.address(owned);
    const derived = ffi.unsafe.offset(owned, 0);
    const released = owned.release();

    assertEquals(ffi.unsafe.address(released), address);
    assertEquals(getCount(), 0, 'release must disarm rather than call the disposer');
    assertThrows(() => ffi.unsafe.address(owned), 'released');
    assertThrows(() => ffi.unsafe.address(derived), 'released');
    assertThrows(() => owned.release(), 'released');
    owned.close();

    owned = null;
    engine.gc.run();
    await Promise.resolve();
    assertEquals(getCount(), 0, 'GC must not dispose a released pointer');
    assertEquals(ffi.unsafe.address(released), address,
        'the transferred pointer must remain valid after its former owner is collected');
    free(released);
    library.close();
});

await test('ffi OwnedPointer cycle GC runs its disposer exactly once after library close', async () => {
    let library = ffi.open(fixturePath());
    const observer = ffi.open(fixturePath());
    const allocate = library.bind([types.pointer, 'ffi_fixture_alloc', types.usize]);
    let countDisposed = library.bind([
        types.void,
        'ffi_fixture_count_disposed_and_free',
        types.pointer,
    ]);
    const resetCount = observer.bind([types.void, 'ffi_fixture_reset_disposed_count']);
    const getCount = observer.bind([types.u32, 'ffi_fixture_get_disposed_count']);
    resetCount();
    let owned = ffi.unsafe.adopt(allocate(8n), countDisposed);
    owned.library = library;
    library.owned = owned;

    library.close();
    owned = null;
    countDisposed = null;
    library = null;
    assertEquals(getCount(), 0,
        'the library/OwnedPointer cycle must remain intact until cycle collection');

    engine.gc.run();
    // Yield through the job queue as well so both immediate and queued cleanup
    // implementations can satisfy the observable eventual-disposal contract.
    await Promise.resolve();
    engine.gc.run();
    await Promise.resolve();
    assertEquals(getCount(), 1,
        'cycle GC must run the disposer while its logically closed library is retained');

    engine.gc.run();
    await Promise.resolve();
    assertEquals(getCount(), 1, 'later GC runs must not repeat the disposer');
    observer.close();
});

await test('ffi OwnedPointer rejects borrowed JS buffer and callback addresses', () => {
    const library = ffi.open(fixturePath());
    const free = library.bind([types.void, 'ffi_fixture_free', types.pointer]);
    const callback = ffi.callback([types.void, types.pointer], () => {});
    try {
        assertThrows(
            () => ffi.unsafe.adopt(ffi.unsafe.pointerOf(new Uint8Array(8)), free),
            'borrowed',
        );
        assertThrows(() => ffi.unsafe.adopt(callback.pointer, free), 'callback');
    } finally {
        callback.close();
        library.close();
    }
});

await test('ffi library close invalidates bindings and derived pointers', () => {
    const library = ffi.open(fixturePath());
    const add = library.bind([types.i32, 'ffi_fixture_add_i32', types.i32, types.i32]);
    const symbol = library.symbol('ffi_fixture_add_i32');
    const indirect = ffi.function(symbol, [types.i32, types.i32, types.i32]);
    assertEquals(add(1, 2), 3);
    assertEquals(indirect(2, 3), 5);

    library.close();
    library.close();
    assertThrows(() => add(1, 2), 'closed');
    assertThrows(() => indirect(1, 2), 'closed');
    assertThrows(() => ffi.unsafe.address(symbol), 'closed');
    assertThrows(() => library.bind([types.i32, 'ffi_fixture_add_i32', types.i32, types.i32]), 'closed');
});
