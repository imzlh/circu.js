// tests/tests/algo.js - Algorithm module tests

const algo = import.meta.use('algorithm');
const text = import.meta.use('text');

function encode(str) {
    return new text.Encoder().encode(str);
}

// ========== WebSocket Mask ==========
await test('algo.wsMask - basic masking', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    const key = new Uint8Array([0xFF, 0x00, 0xFF, 0x00]);
    const result = algo.wsMask(data, key);
    
    assert(result instanceof Uint8Array, 'Result should be Uint8Array');
    assertEquals(result.length, data.length, 'Length should match input');
    assertEquals(result[0], 0xFE, 'First byte should be XORed correctly');
    assertEquals(result[1], 0x02, 'Second byte should be XORed correctly');
});

await test('algo.wsMask - symmetric (mask then mask restores original)', () => {
    const original = new Uint8Array([0x48, 0x65, 0x6C, 0x6C, 0x6F]);
    const key = new Uint8Array([0x37, 0xFA, 0x21, 0x3D]);
    const masked = algo.wsMask(original, key);
    const restored = algo.wsMask(masked, key);
    
    for (let i = 0; i < original.length; i++) {
        assertEquals(restored[i], original[i], 'Double mask should restore original');
    }
});

await test('algo.wsMaskInto - writes into target with offset', () => {
    const data = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]);
    const key = new Uint8Array([0xFF, 0x00, 0xFF, 0x00]);
    const expected = algo.wsMask(data, key);
    const target = new Uint8Array([0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]);
    const result = algo.wsMaskInto(data, key, target, 2);

    assert(result === target, 'Should return target buffer');
    assertEquals(target[0], 0xAA, 'Prefix should remain untouched');
    assertEquals(target[1], 0xAA, 'Prefix should remain untouched');
    for (let i = 0; i < expected.length; i++) {
        assertEquals(target[i + 2], expected[i], 'Masked byte should match wsMask');
    }
    assertEquals(target[7], 0xAA, 'Suffix should remain untouched');
});

await test('algo.wsMask - key must be 4 bytes', () => {
    try {
        algo.wsMask(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]));
        assert(false, 'Should throw for invalid key length');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('algo.bytesCompare - lexicographic byte comparison', () => {
    assertEquals(algo.bytesCompare(new Uint8Array([1, 2]), new Uint8Array([1, 2])), 0);
    assertEquals(algo.bytesCompare(new Uint8Array([1, 2]), new Uint8Array([1, 3])), -1);
    assertEquals(algo.bytesCompare(new Uint8Array([1, 4]), new Uint8Array([1, 3])), 1);
    assertEquals(algo.bytesCompare(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0])), -1);
    assertEquals(algo.bytesCompare(new Uint8Array([1, 2, 0]), new Uint8Array([1, 2])), 1);
});

await test('algo.bytesEqual - checks byte equality', () => {
    assertEquals(algo.bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
    assertEquals(algo.bytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
    assertEquals(algo.bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0])), false);
});

await test('algo.bytesIsAscii - checks 7-bit ASCII bytes', () => {
    assertEquals(algo.bytesIsAscii(new Uint8Array([0x00, 0x41, 0x7f])), true);
    assertEquals(algo.bytesIsAscii(new Uint8Array([0x80])), false);
});

await test('algo.bytesIsUtf8 - validates UTF-8 bytes', () => {
    assertEquals(algo.bytesIsUtf8(encode('hello 世界')), true);
    assertEquals(algo.bytesIsUtf8(new Uint8Array([0xc0, 0x80])), false);
    assertEquals(algo.bytesIsUtf8(new Uint8Array([0xe2, 0x82])), false);
    assertEquals(algo.bytesIsUtf8(new Uint8Array([0xed, 0xa0, 0x80])), false);
    assertEquals(algo.bytesIsUtf8(new Uint8Array([0xf4, 0x90, 0x80, 0x80])), false);
});

await test('algo.bytesInvert - inverts bytes in place', () => {
    const data = new Uint8Array([0x00, 0x55, 0xaa, 0xff]);
    const result = algo.bytesInvert(data);

    assert(result === data, 'Should return input buffer');
    assertEquals(Array.from(data).join(','), '255,170,85,0');
    algo.bytesInvert(data);
    assertEquals(Array.from(data).join(','), '0,85,170,255');
});

await test('algo.bytesReverse - reverses bytes in place', () => {
    const data = new Uint8Array([1, 2, 3, 4, 5]);
    const result = algo.bytesReverse(data);

    assert(result === data, 'Should return input buffer');
    assertEquals(Array.from(data).join(','), '5,4,3,2,1');
});

await test('algo.base64DecodeLoose - decodes Node Buffer-compatible base64', () => {
    assertEquals(Array.from(algo.base64DecodeLoose('SGVsbG8=')).join(','), '72,101,108,108,111');
    assertEquals(Array.from(algo.base64DecodeLoose('SGV sbG8=')).join(','), '72,101,108,108,111');
    assertEquals(Array.from(algo.base64DecodeLoose('SGVsbG8!!!!')).join(','), '72,101,108,108,111');
    assertEquals(Array.from(algo.base64DecodeLoose('-_8=')).join(','), '251,255');
    assertEquals(Array.from(algo.base64DecodeLoose('䄫䄫䄫䄫')).join(','), '251,239,190');
    assertEquals(algo.base64DecodeLoose('A===').length, 0);
});

await test('algo.hexDecodeLoose - decodes Node Buffer-compatible hex', () => {
    assertEquals(Array.from(algo.hexDecodeLoose('48656c6c6f')).join(','), '72,101,108,108,111');
    assertEquals(Array.from(algo.hexDecodeLoose('1ag123')).join(','), '26');
    assertEquals(Array.from(algo.hexDecodeLoose('1a7')).join(','), '26');
    assertEquals(algo.hexDecodeLoose('zz').length, 0);
    assertEquals(algo.hexDecodeLoose('１a').length, 0);
});

await test('algo.asciiEncodeLoose / latin1EncodeLoose - encodes code units', () => {
    assertEquals(Array.from(algo.asciiEncodeLoose('AéĀ')).join(','), '65,105,0');
    assertEquals(Array.from(algo.latin1EncodeLoose('AéĀ')).join(','), '65,233,0');
});

await test('algo.bytesConcat - concatenates chunks', () => {
    const out = algo.bytesConcat([
        new Uint8Array([1, 2]),
        new Uint8Array(0),
        new Uint8Array([3, 4, 5]),
    ]);

    assert(out instanceof Uint8Array, 'Result should be Uint8Array');
    assertEquals(Array.from(out).join(','), '1,2,3,4,5');
});

await test('algo.bytesConcat - empty input returns empty bytes', () => {
    assertEquals(algo.bytesConcat([]).length, 0);
});

await test('algo.bytesRepeatInto - repeats pattern into target range', () => {
    const target = new Uint8Array([9, 9, 9, 9, 9, 9, 9, 9]);
    const result = algo.bytesRepeatInto(target, new Uint8Array([1, 2, 3]), 2, 7);

    assert(result === target, 'Should return target buffer');
    assertEquals(Array.from(target).join(','), '9,9,1,2,3,1,2,9');
});

await test('algo.bytesSwap - swaps byte lanes in place', () => {
    const s16 = new Uint8Array([1, 2, 3, 4]);
    assert(algo.bytesSwap16(s16) === s16, 'swap16 should return input');
    assertEquals(Array.from(s16).join(','), '2,1,4,3');

    const s32 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    assert(algo.bytesSwap32(s32) === s32, 'swap32 should return input');
    assertEquals(Array.from(s32).join(','), '4,3,2,1,8,7,6,5');

    const s64 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    assert(algo.bytesSwap64(s64) === s64, 'swap64 should return input');
    assertEquals(Array.from(s64).join(','), '8,7,6,5,4,3,2,1');
});

await test('algo.bytesIndexOf - finds byte sequences', () => {
    const data = new Uint8Array([1, 2, 3, 2, 3, 4, 3]);

    assertEquals(algo.bytesIndexOf(data, new Uint8Array([2, 3])), 1);
    assertEquals(algo.bytesIndexOf(data, new Uint8Array([2, 3]), 2), 3);
    assertEquals(algo.bytesIndexOf(data, new Uint8Array([4]), 0), 5);
    assertEquals(algo.bytesIndexOf(data, 4, 0), 5);
    assertEquals(algo.bytesIndexOf(data, new Uint8Array([3, 5])), -1);
    assertEquals(algo.bytesIndexOf(data, new Uint8Array([1, 2, 3]), 0), 0);
    assertEquals(algo.bytesIndexOf(data, new Uint8Array([4, 3]), 0), 5);
});

await test('algo.bytesIndexOf - finds single bytes', () => {
    const data = new Uint8Array([1, 2, 3, 2, 3, 4, 3]);

    assertEquals(algo.bytesIndexOf(data, 2), 1);
    assertEquals(algo.bytesIndexOf(data, 2, 2), 3);
    assertEquals(algo.bytesIndexOf(data, 0x104), 5);
    assertEquals(algo.bytesIndexOf(data, 9), -1);
});

await test('algo.bytesLastIndexOf - finds byte sequences backward', () => {
    const data = new Uint8Array([1, 2, 3, 2, 3, 4, 3]);

    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([2, 3])), 3);
    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([2, 3]), 2), 1);
    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([4]), data.length), 5);
    assertEquals(algo.bytesLastIndexOf(data, 3, data.length), 6);
    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([3, 5])), -1);
    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([1, 2, 3]), data.length), 0);
    assertEquals(algo.bytesLastIndexOf(data, new Uint8Array([4, 3]), data.length), 5);
});

await test('algo.bytesLastIndexOf - finds single bytes backward', () => {
    const data = new Uint8Array([1, 2, 3, 2, 3, 4, 3]);

    assertEquals(algo.bytesLastIndexOf(data, 3), 6);
    assertEquals(algo.bytesLastIndexOf(data, 3, 5), 4);
    assertEquals(algo.bytesLastIndexOf(data, 0x104), 5);
    assertEquals(algo.bytesLastIndexOf(data, 9), -1);
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
await test('algo.xxHash32 - basic hashing', () => {
    const data = encode('xxhash test');
    const hash = algo.xxHash32(data);
    
    assertEquals(typeof hash, 'number', 'Should return a number');
    const hash2 = algo.xxHash32(data);
    assertEquals(hash, hash2, 'Same input should produce same hash');
});

await test('algo.xxHash32 - with seed', () => {
    const data = encode('test');
    const hash1 = algo.xxHash32(data, 0);
    const hash2 = algo.xxHash32(data, 999);
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
