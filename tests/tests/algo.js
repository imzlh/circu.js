// tests/tests/algo.js - Algorithm module tests

const algo = import.meta.use('algorithm');
const text = import.meta.use('text');

function encode(str) {
    return new text.Encoder().encode(str);
}

// ========== WebSocket Mask Unpack ==========
await test('algo.ws_unpack - basic unmasking', () => {
    const masked = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const key = new Uint8Array([0xFF, 0x00, 0xFF, 0x00]);
    const result = algo.ws_unpack(masked, key);
    
    assert(result instanceof Uint8Array, 'Result should be Uint8Array');
    assertEquals(result.length, masked.length, 'Length should match input');
    assertEquals(result[0], 0xFE, 'First byte should be XORed correctly');
    assertEquals(result[1], 0x02, 'Second byte should be XORed correctly');
});

await test('algo.ws_unpack - key must be 4 bytes', () => {
    try {
        algo.ws_unpack(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]));
        assert(false, 'Should throw for invalid key length');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

// ========== FNV-1a Hash ==========
await test('algo.fnv1a32 - basic hashing', () => {
    const data = encode('hello');
    const hash = algo.fnv1a32(data);
    
    assertEquals(typeof hash, 'number', 'Should return a number');
    const hash2 = algo.fnv1a32(data);
    assertEquals(hash, hash2, 'Same input should produce same hash');
});

await test('algo.fnv1a32 - different inputs', () => {
    const hash1 = algo.fnv1a32(encode('hello'));
    const hash2 = algo.fnv1a32(encode('world'));
    assert(hash1 !== hash2, 'Different inputs should produce different hashes');
});

await test('algo.fnv1a64 - basic hashing', () => {
    const data = encode('hello world');
    const hash = algo.fnv1a64(data);
    
    assert(typeof hash === 'bigint', 'Should return a bigint');
    const hash2 = algo.fnv1a64(data);
    assertEquals(hash, hash2, 'Same input should produce same hash');
});

// ========== MurmurHash3 ==========
await test('algo.murmur3 - basic hashing', () => {
    const data = encode('test');
    const hash = algo.murmur3(data);
    
    assertEquals(typeof hash, 'number', 'Should return a number');
    const hash2 = algo.murmur3(data);
    assertEquals(hash, hash2, 'Same input should produce same hash');
});

await test('algo.murmur3 - with seed', () => {
    const data = encode('test');
    const hash1 = algo.murmur3(data, 0);
    const hash2 = algo.murmur3(data, 12345);
    assert(hash1 !== hash2, 'Different seeds should produce different hashes');
});

// ========== xxHash32 ==========
await test('algo.xxhash32 - basic hashing', () => {
    const data = encode('xxhash test');
    const hash = algo.xxhash32(data);
    
    assertEquals(typeof hash, 'number', 'Should return a number');
    const hash2 = algo.xxhash32(data);
    assertEquals(hash, hash2, 'Same input should produce same hash');
});

await test('algo.xxhash32 - with seed', () => {
    const data = encode('test');
    const hash1 = algo.xxhash32(data, 0);
    const hash2 = algo.xxhash32(data, 999);
    assert(hash1 !== hash2, 'Different seeds should produce different hashes');
});

// ========== XoshiroRNG ==========
await test('algo.XoshiroRNG - basic construction', () => {
    const rng = new algo.XoshiroRNG();
    assert(rng instanceof algo.XoshiroRNG, 'Should create instance');
});

await test('algo.XoshiroRNG - with number seed', () => {
    const rng = new algo.XoshiroRNG(12345);
    assert(rng instanceof algo.XoshiroRNG, 'Should create instance with seed');
});

await test('algo.XoshiroRNG - with array seed', () => {
    const rng = new algo.XoshiroRNG([1, 2, 3, 4]);
    assert(rng instanceof algo.XoshiroRNG, 'Should create instance with array seed');
});

await test('algo.XoshiroRNG - next() returns values', () => {
    const rng = new algo.XoshiroRNG(42);
    const val1 = rng.next();
    const val2 = rng.next();
    
    assert(val1 !== undefined && val1 !== null, 'Should return value');
    assert(val1 !== val2, 'Consecutive calls should return different values');
});

await test('algo.XoshiroRNG - nextDouble() returns [0,1)', () => {
    const rng = new algo.XoshiroRNG(42);
    
    for (let i = 0; i < 10; i++) {
        const val = rng.nextDouble();
        assert(typeof val === 'number', 'Should return a number');
        assert(val >= 0 && val < 1, 'Should be in range [0, 1)');
    }
});

await test('algo.XoshiroRNG - same seed produces same sequence', () => {
    const rng1 = new algo.XoshiroRNG(12345);
    const rng2 = new algo.XoshiroRNG(12345);
    
    const seq1 = [rng1.next(), rng1.next(), rng1.next()];
    const seq2 = [rng2.next(), rng2.next(), rng2.next()];
    
    assertEquals(seq1[0], seq2[0], 'Same seed should produce same sequence');
    assertEquals(seq1[1], seq2[1], 'Same seed should produce same sequence');
    assertEquals(seq1[2], seq2[2], 'Same seed should produce same sequence');
});

await test('algo.XoshiroRNG - jump changes sequence', () => {
    const rng = new algo.XoshiroRNG(12345);
    const val1 = rng.next();
    rng.jump();
    const val2 = rng.next();
    
    assert(val1 !== val2, 'Jump should change sequence');
});

await test('algo.XoshiroRNG - longJump changes sequence', () => {
    const rng = new algo.XoshiroRNG(12345);
    const val1 = rng.next();
    rng.longJump();
    const val2 = rng.next();
    
    assert(val1 !== val2, 'Long jump should change sequence');
});

await test('algo.XoshiroRNG - clone produces same sequence', () => {
    const rng1 = new algo.XoshiroRNG(12345);
    rng1.next();
    rng1.next();
    
    const rng2 = rng1.clone();
    const val1 = rng1.next();
    const val2 = rng2.next();
    
    assertEquals(val1, val2, 'Clone should produce same sequence');
});

// ========== Error handling ==========
await test('algo - invalid input handling', () => {
    try {
        algo.fnv1a32('not a buffer');
        assert(false, 'Should throw for non-buffer input');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
    
    try {
        algo.murmur3('not a buffer');
        assert(false, 'Should throw for non-buffer input');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});
