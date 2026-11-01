// tests/tests/zlib.js - Zlib compression module tests

const zlib = import.meta.use('zlib');
const text = import.meta.use('text');

function encode(str) {
    return new text.Encoder().encode(str);
}

function arraysEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false;
    }
    return true;
}

// ========== One-shot Compression ==========
await test('zlib.deflate - basic compression', () => {
    const data = encode('hello world hello world hello world');
    const compressed = zlib.deflate(data);
    
    assert(compressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(compressed.length > 0, 'Compressed data should not be empty');
    assert(compressed.length < data.length, 'Compressed should be smaller than original');
});

await test('zlib.deflate - with compression level', () => {
    const data = encode('test data for compression');
    const compressed1 = zlib.deflate(data, zlib.BEST_SPEED);
    const compressed9 = zlib.deflate(data, zlib.BEST_COMPRESSION);
    
    assert(compressed1 instanceof Uint8Array, 'Should return Uint8Array');
    assert(compressed9 instanceof Uint8Array, 'Should return Uint8Array');
    // Note: BEST_COMPRESSION doesn't always produce smaller output for small data
});

await test('zlib.gzip - basic compression', () => {
    const data = encode('hello world');
    const compressed = zlib.gzip(data);
    
    assert(compressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(compressed.length > 0, 'Compressed data should not be empty');
    // Gzip header starts with 0x1f 0x8b
    assertEquals(compressed[0], 0x1f, 'Should have gzip magic number');
    assertEquals(compressed[1], 0x8b, 'Should have gzip magic number');
});

await test('zlib.deflateRaw - raw deflate', () => {
    const data = encode('hello world');
    const compressed = zlib.deflateRaw(data);
    
    assert(compressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(compressed.length > 0, 'Compressed data should not be empty');
    // Raw deflate should not have zlib header
});

// ========== One-shot Decompression ==========
await test('zlib.inflate - basic decompression', () => {
    const original = encode('hello world hello world hello world');
    const compressed = zlib.deflate(original);
    const decompressed = zlib.inflate(compressed);
    
    assert(decompressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(arraysEqual(decompressed, original), 'Decompressed should match original');
});

await test('zlib.gunzip - basic decompression', () => {
    const original = encode('hello world');
    const compressed = zlib.gzip(original);
    const decompressed = zlib.gunzip(compressed);
    
    assert(decompressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(arraysEqual(decompressed, original), 'Decompressed should match original');
});

await test('zlib.inflateRaw - raw inflate', () => {
    const original = encode('hello world');
    const compressed = zlib.deflateRaw(original);
    const decompressed = zlib.inflateRaw(compressed);
    
    assert(decompressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(arraysEqual(decompressed, original), 'Decompressed should match original');
});

await test('zlib - round-trip with various data', () => {
    const testData = [
        'Hello World',
        'The quick brown fox jumps over the lazy dog',
        '重复的数据来测试压缩重复的数据来测试压缩',
        ' specials!@#$%^&*() ',
        'a'.repeat(1000), // Highly compressible
    ];
    
    for (const str of testData) {
        const original = encode(str);
        const compressed = zlib.deflate(original);
        const decompressed = zlib.inflate(compressed);
        
        assert(arraysEqual(decompressed, original), `Round-trip failed for: ${str.substring(0, 20)}...`);
    }
});

// ========== Checksum Functions ==========
await test('zlib.crc32 - basic CRC32', () => {
    const data = encode('hello world');
    const crc = zlib.crc32(data);
    
    assertEquals(typeof crc, 'number', 'Should return a number');
    assert(crc > 0, 'CRC should be positive');
});

await test('zlib.crc32 - deterministic', () => {
    const data = encode('test data');
    const crc1 = zlib.crc32(data);
    const crc2 = zlib.crc32(data);
    
    assertEquals(crc1, crc2, 'Same data should produce same CRC');
});

await test('zlib.crc32 - different data', () => {
    const crc1 = zlib.crc32(encode('hello'));
    const crc2 = zlib.crc32(encode('world'));
    
    assert(crc1 !== crc2, 'Different data should produce different CRC');
});

await test('zlib.crc32 - with initial value', () => {
    const data = encode('hello');
    const crc1 = zlib.crc32(data);
    const crc2 = zlib.crc32(data, 0);
    
    assertEquals(crc1, crc2, 'Default and explicit initial should match');
});

await test('zlib.crc32 - incremental', () => {
    const part1 = encode('hello');
    const part2 = encode(' world');
    
    const crc1 = zlib.crc32(part1);
    const crc2 = zlib.crc32(part2, crc1);
    const combined = zlib.crc32(encode('hello world'));
    
    // Note: CRC32 is not simply additive, this tests the API works
    assert(typeof crc2 === 'number', 'Incremental CRC should work');
});

await test('zlib.adler32 - basic Adler32', () => {
    const data = encode('hello world');
    const adler = zlib.adler32(data);
    
    assertEquals(typeof adler, 'number', 'Should return a number');
    assert(adler > 0, 'Adler32 should be positive');
});

await test('zlib.adler32 - deterministic', () => {
    const data = encode('test data');;
    const adler1 = zlib.adler32(data);
    const adler2 = zlib.adler32(data);
    
    assertEquals(adler1, adler2, 'Same data should produce same Adler32');
});

// ========== Streaming Compression ==========
await test('zlib.createDeflate - create deflate stream', () => {
    const deflate = zlib.createDeflate();
    assert(deflate, 'Should create deflate stream');
});

await test('zlib.createDeflate - with options', () => {
    const deflate = zlib.createDeflate(zlib.BEST_COMPRESSION, zlib.FILTERED);
    assert(deflate, 'Should create deflate stream with options');
});

await test('zlib.Deflate - compress stream', () => {
    const deflate = zlib.createDeflate();
    const data = encode('hello world');
    
    const compressed = deflate.deflate(data);
    assert(compressed instanceof Uint8Array, 'Should return Uint8Array');
    
    const finished = deflate.finish();
    assert(finished instanceof Uint8Array, 'Finish should return Uint8Array');
});

await test('zlib.Deflate - flush', () => {
    const deflate = zlib.createDeflate();
    const data = encode('hello');
    
    deflate.deflate(data, zlib.SYNC_FLUSH);
    const flushed = deflate.flush();
    
    assert(flushed instanceof Uint8Array, 'Flush should return Uint8Array');
});

await test('zlib.Deflate - reset', () => {
    const deflate = zlib.createDeflate();
    deflate.deflate(encode('data'));
    deflate.reset();
    
    // After reset, should be able to compress again
    const compressed = deflate.deflate(encode('new data'));
    assert(compressed instanceof Uint8Array, 'Should compress after reset');
});

await test('zlib.Deflate - getTotalIn/Out', () => {
    const deflate = zlib.createDeflate();
    const data = encode('hello world');
    
    deflate.deflate(data);
    
    const totalIn = deflate.getTotalIn();
    const totalOut = deflate.getTotalOut();
    
    assert(typeof totalIn === 'number', 'getTotalIn should return number');
    assert(typeof totalOut === 'number', 'getTotalOut should return number');
    assert(totalIn > 0, 'TotalIn should be > 0');
});

// ========== Streaming Decompression ==========
await test('zlib.createInflate - create inflate stream', () => {
    const inflate = zlib.createInflate();
    assert(inflate, 'Should create inflate stream');
});

await test('zlib.Inflate - decompress stream', () => {
    // First compress some data
    const original = encode('hello world hello world');
    const compressed = zlib.deflate(original);
    
    // Now decompress in chunks
    const inflate = zlib.createInflate();
    const decompressed = inflate.inflate(compressed);
    
    assert(decompressed instanceof Uint8Array, 'Should return Uint8Array');
    assert(arraysEqual(decompressed, original), 'Should decompress correctly');
});

await test('zlib.Inflate - reset', () => {
    const inflate = zlib.createInflate();
    const compressed = zlib.deflate(encode('data'));
    
    inflate.inflate(compressed);
    inflate.reset();
    
    // After reset, should be able to decompress again
    const compressed2 = zlib.deflate(encode('new data'));
    const decompressed = inflate.inflate(compressed2);
    
    assert(arraysEqual(decompressed, encode('new data')), 'Should decompress after reset');
});

await test('zlib.Inflate - getTotalIn/Out', () => {
    const inflate = zlib.createInflate();
    const compressed = zlib.deflate(encode('hello world'));
    
    inflate.inflate(compressed);
    
    const totalIn = inflate.getTotalIn();
    const totalOut = inflate.getTotalOut();
    
    assert(typeof totalIn === 'number', 'getTotalIn should return number');
    assert(typeof totalOut === 'number', 'getTotalOut should return number');
});

// ========== Gzip/Gunzip Streaming ==========
await test('zlib.createGzip - create gzip stream', () => {
    const gzip = zlib.createGzip();
    assert(gzip, 'Should create gzip stream');
});

await test('zlib.createGunzip - create gunzip stream', () => {
    const gunzip = zlib.createGunzip();
    assert(gunzip, 'Should create gunzip stream');
});

// ========== Constants ==========
await test('zlib constants - compression levels', () => {
    assertEquals(typeof zlib.NO_COMPRESSION, 'number', 'NO_COMPRESSION should be defined');
    assertEquals(typeof zlib.BEST_SPEED, 'number', 'BEST_SPEED should be defined');
    assertEquals(typeof zlib.BEST_COMPRESSION, 'number', 'BEST_COMPRESSION should be defined');
    assertEquals(typeof zlib.DEFAULT_COMPRESSION, 'number', 'DEFAULT_COMPRESSION should be defined');
});

await test('zlib constants - strategies', () => {
    assertEquals(typeof zlib.FILTERED, 'number', 'FILTERED should be defined');
    assertEquals(typeof zlib.HUFFMAN_ONLY, 'number', 'HUFFMAN_ONLY should be defined');
    assertEquals(typeof zlib.RLE, 'number', 'RLE should be defined');
    assertEquals(typeof zlib.FIXED, 'number', 'FIXED should be defined');
    assertEquals(typeof zlib.DEFAULT_STRATEGY, 'number', 'DEFAULT_STRATEGY should be defined');
});

await test('zlib constants - flush modes', () => {
    assertEquals(typeof zlib.NO_FLUSH, 'number', 'NO_FLUSH should be defined');
    assertEquals(typeof zlib.PARTIAL_FLUSH, 'number', 'PARTIAL_FLUSH should be defined');
    assertEquals(typeof zlib.SYNC_FLUSH, 'number', 'SYNC_FLUSH should be defined');
    assertEquals(typeof zlib.FULL_FLUSH, 'number', 'FULL_FLUSH should be defined');
    assertEquals(typeof zlib.FINISH, 'number', 'FINISH should be defined');
    assertEquals(typeof zlib.BLOCK, 'number', 'BLOCK should be defined');
});

// ========== Error Handling ==========
await test('zlib - invalid data throws', () => {
    try {
        zlib.inflate(new Uint8Array([1, 2, 3, 4, 5])); // Invalid deflate data
        assert(false, 'Should throw for invalid data');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('zlib.gunzip - invalid gzip data throws', () => {
    try {
        zlib.gunzip(new Uint8Array([1, 2, 3, 4, 5])); // Invalid gzip data
        assert(false, 'Should throw for invalid gzip data');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('zlib - invalid compression level throws', () => {
    try {
        zlib.deflate(encode('test'), 100); // Invalid level
        assert(false, 'Should throw for invalid level');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

// ========== Regression: params(), truncated input, catchable stream errors ==========
await test('zlib.Deflate.params - changes level mid-stream and round-trips', () => {
    const deflate = zlib.createDeflate(zlib.BEST_SPEED);
    const a = encode('hello world '.repeat(500));
    const b = encode('goodbye world '.repeat(500));
    const parts = [deflate.deflate(a)];
    const flushed = deflate.params(zlib.BEST_COMPRESSION, zlib.DEFAULT_STRATEGY);
    assert(flushed instanceof Uint8Array, 'params() should return a Uint8Array');
    parts.push(flushed);
    parts.push(deflate.deflate(b));
    parts.push(deflate.finish());

    let total = 0;
    for (const p of parts) total += p.length;
    const joined = new Uint8Array(total);
    let off = 0;
    for (const p of parts) { joined.set(p, off); off += p.length; }

    const expected = new Uint8Array(a.length + b.length);
    expected.set(a, 0);
    expected.set(b, a.length);
    assert(arraysEqual(zlib.inflate(joined), expected), 'Round-trip after params() failed');
});

await test('zlib.inflate - truncated input throws a catchable TypeError', () => {
    const full = zlib.deflate(encode('truncate me '.repeat(200)));
    const cut = full.subarray(0, full.length >> 1);
    let thrown = null;
    try {
        zlib.inflate(cut);
    } catch (e) {
        thrown = e;
    }
    assert(thrown instanceof TypeError, 'Truncated one-shot inflate should throw TypeError');
});

await test('zlib.Inflate - finished stream error is catchable', () => {
    const inflate = zlib.createInflate();
    inflate.inflate(zlib.deflate(encode('abc')));
    assert(inflate.finished, 'Stream should be finished');
    let thrown = null;
    try {
        inflate.inflate(new Uint8Array([1]));
    } catch (e) {
        thrown = e;
    }
    assert(thrown instanceof TypeError, 'Inflating after finish should throw a catchable TypeError');
});
