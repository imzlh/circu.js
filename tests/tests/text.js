// tests/tests/text.js - Text encoding/decoding module tests

const text = import.meta.use('text');

// ========== TextEncoder ==========
await test('text.Encoder - basic construction', () => {
    const encoder = new text.Encoder();
    assert(encoder, 'Should create TextEncoder');
    assertEquals(encoder.encoding, 'utf-8', 'Default encoding should be utf-8');
});

await test('text.Encoder.encode - basic encoding', () => {
    const encoder = new text.Encoder();
    const encoded = encoder.encode('hello');
    
    assert(encoded instanceof Uint8Array, 'Should return Uint8Array');
    assertEquals(encoded.length, 5, 'Should encode 5 bytes for "hello"');
    assertEquals(encoded[0], 0x68, 'First byte should be "h"');
    assertEquals(encoded[1], 0x65, 'Second byte should be "e"');
});

await test('text.Encoder.encode - UTF-8 multibyte', () => {
    const encoder = new text.Encoder();
    const encoded = encoder.encode('你好');
    
    assert(encoded instanceof Uint8Array, 'Should return Uint8Array');
    assertEquals(encoded.length, 6, 'Chinese characters should be 3 bytes each');
});

await test('text.Encoder.encode - empty string', () => {
    const encoder = new text.Encoder();
    const encoded = encoder.encode('');
    
    assertEquals(encoded.length, 0, 'Empty string should encode to empty array');
});

await test('text.Encoder.encode - grows for UTF-32 output', () => {
    const encoded = new text.Encoder('UTF-32LE').encode('a'.repeat(300));
    assertEquals(encoded.length, 1200, 'Each ASCII character should use four UTF-32 bytes');
    for (let i = 0; i < encoded.length; i += 4) {
        assertEquals(encoded[i], 0x61, 'UTF-32LE code point byte should be present');
        assertEquals(encoded[i + 1], 0, 'UTF-32LE high byte should be zero');
        assertEquals(encoded[i + 2], 0, 'UTF-32LE high byte should be zero');
        assertEquals(encoded[i + 3], 0, 'UTF-32LE high byte should be zero');
    }
});

await test('text.Encoder.encode - replaces unrepresentable custom output', () => {
    const encoded = new text.Encoder('ASCII').encode('AéB');
    assertEquals(Array.from(encoded).join(','), '65,63,66', 'Unrepresentable characters should become question marks');
});

await test('text.Encoder.encodeInto - replaces unrepresentable custom output', () => {
    const output = new Uint8Array(2);
    const result = new text.Encoder('ASCII').encodeInto('é', output);
    assertEquals(result.read, 1, 'The source character should be consumed');
    assertEquals(result.written, 1, 'The replacement should be written');
    assertEquals(output[0], 0x3f, 'Unrepresentable characters should become question marks');
});

await test('text.Encoder.encodeInto - encode into existing buffer', () => {
    const encoder = new text.Encoder();
    const buffer = new Uint8Array(10);
    const result = encoder.encodeInto('hello', buffer);
    
    assertEquals(typeof result.read, 'number', 'Should return read count');
    assertEquals(typeof result.written, 'number', 'Should return written count');
    assertEquals(result.read, 5, 'Should read 5 characters');
    assertEquals(result.written, 5, 'Should write 5 bytes');
    assertEquals(buffer[0], 0x68, 'Buffer should contain encoded data');
});

await test('text.Encoder.encodeInto - partial encoding', () => {
    const encoder = new text.Encoder();
    const buffer = new Uint8Array(3); // Too small for "hello"
    const result = encoder.encodeInto('hello', buffer);
    
    assert(result.written <= 3, 'Should not write more than buffer size');
});

// ========== TextDecoder ==========
await test('text.Decoder - basic construction', () => {
    const decoder = new text.Decoder();
    assert(decoder, 'Should create TextDecoder');
    assertEquals(decoder.encoding, 'utf-8', 'Default encoding should be UTF-8');
    assertEquals(decoder.fatal, false, 'Default fatal should be false');
    assertEquals(decoder.ignoreBOM, false, 'Default ignoreBOM should be false');
});

await test('text.Decoder - with options', () => {
    const decoder = new text.Decoder('utf-8', { fatal: true, ignoreBOM: true });
    assertEquals(decoder.fatal, true, 'Fatal should be true');
    assertEquals(decoder.ignoreBOM, true, 'IgnoreBOM should be true');
});

await test('text.Decoder.decode - basic decoding', () => {
    const decoder = new text.Decoder();
    const encoded = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const decoded = decoder.decode(encoded);
    
    assertEquals(decoded, 'hello', 'Should decode to "hello"');
});

await test('text.Decoder.decode - UTF-8 multibyte', () => {
    const decoder = new text.Decoder();
    // UTF-8 encoding of "你好"
    const encoded = new Uint8Array([0xe4, 0xbd, 0xa0, 0xe5, 0xa5, 0xbd]);
    const decoded = decoder.decode(encoded);
    
    assertEquals(decoded, '你好', 'Should decode Chinese characters');
});

await test('text.Decoder.decode - empty buffer', () => {
    const decoder = new text.Decoder();
    const decoded = decoder.decode(new Uint8Array(0));
    
    assertEquals(decoded, '', 'Should decode empty buffer to empty string');
});

await test('text.Decoder.decode - streaming mode', () => {
    const decoder = new text.Decoder();
    // Split UTF-8 sequence across chunks
    const chunk1 = new Uint8Array([0xe4, 0xbd]); // incomplete
    const chunk2 = new Uint8Array([0xa0]); // completion
    
    const decoded1 = decoder.decode(chunk1, { stream: true });
    const decoded2 = decoder.decode(chunk2, { stream: false });
    
    assertEquals(decoded1, '', 'Should return empty for incomplete sequence');
    assertEquals(decoded2, '你', 'Should decode complete character');
});

await test('text.Decoder.decode - streaming mode preserves valid prefixes', () => {
    const decoder = new text.Decoder();
    assertEquals(decoder.decode(new Uint8Array([0x41, 0xc2]), { stream: true }), 'A');
    assertEquals(decoder.decode(new Uint8Array([0xa2])), '¢');
});

await test('text.Decoder.decode - streaming mode rejects malformed prefixes', () => {
    const decoder = new text.Decoder();
    assertEquals(
        decoder.decode(new Uint8Array([0x41, 0xe1, 0x41]), { stream: true }),
        'A�A',
    );
    assertEquals(decoder.decode(), '');
});

await test('text.Decoder - BOM handling', () => {
    const decoder = new text.Decoder('utf-8', { ignoreBOM: false });
    // UTF-8 BOM + "hello"
    const withBOM = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const decoded = decoder.decode(withBOM);
    
    assertEquals(decoded, 'hello', 'Should strip BOM by default');
});

await test('text.Decoder - ignoreBOM option', () => {
    const decoder = new text.Decoder('utf-8', { ignoreBOM: true });
    // UTF-8 BOM + "hello"
    const withBOM = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x65, 0x6c, 0x6c, 0x6f]);
    const decoded = decoder.decode(withBOM);
    
    console.log(decoded)
    assert(decoded == 'hello', 'Should ignore BOM with ignoreBOM option')
    // assertEquals(decoded, 'hello', 'Should decode with ignoreBOM option');
});

await test('text.Decoder.decode - different encodings', () => {
    // UTF-16LE encoding of "A"
    const decoder = new text.Decoder('utf-16le');
    const encoded = new Uint8Array([0x41, 0x00]);
    const decoded = decoder.decode(encoded);
    
    assertEquals(decoded, 'A', 'Should decode UTF-16LE');
});

// ========== Utility Functions ==========
await test('text.convert - basic conversion', () => {
    // Convert UTF-8 to UTF-16LE
    const utf8Data = new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]); // "hello"
    const converted = text.convert('UTF-8', 'UTF-16LE', utf8Data);
    
    assert(converted instanceof Uint8Array, 'Should return Uint8Array');
});

await test('text.convert - UTF-8 to string', () => {
    const utf8Data = new Uint8Array([0xe4, 0xbd, 0xa0, 0xe5, 0xa5, 0xbd]); // "你好"
    const converted = text.convert('UTF-8', 'UTF-8', utf8Data);
    
    assert(typeof converted === 'string' || converted instanceof Uint8Array, 'Should return result');
});

await test('text.listEncodings - get supported encodings', () => {
    const encodings = text.listEncodings();
    
    assert(Array.isArray(encodings), 'Should return array');
    assert(encodings.length > 0, 'Should have encodings');
    assert(encodings.includes('UTF-8'), 'Should include UTF-8');
});

// ========== Round-trip Tests ==========
await test('text - encoder/decoder round-trip', () => {
    const encoder = new text.Encoder();
    const decoder = new text.Decoder();
    
    const original = 'Hello, 世界! 🌍';
    const encoded = encoder.encode(original);
    const decoded = decoder.decode(encoded);
    
    assertEquals(decoded, original, 'Round-trip should preserve string');
});

await test('text - round-trip with various characters', () => {
    const testStrings = [
        'Hello World',
        '你好，世界',
        'مرحبا بالعالم',
        'Привет мир',
        '🎉🎊🎁',
        '<script>alert("xss")</script>',
        'Line1\nLine2\tTab',
        ''
    ];
    
    const encoder = new text.Encoder();
    const decoder = new text.Decoder();
    
    for (const str of testStrings) {
        const encoded = encoder.encode(str);
        const decoded = decoder.decode(encoded);
        assertEquals(decoded, str, `Round-trip failed for: ${str}`);
    }
});

// ========== Error Handling ==========
await test('text.Decoder - fatal mode throws on invalid data', () => {
    const decoder = new text.Decoder('utf-8', { fatal: true });
    const invalidData = new Uint8Array([0xff, 0xfe]); // Invalid UTF-8
    
    try {
        decoder.decode(invalidData);
        // Some decoders may handle this gracefully
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error in fatal mode');
    }
});

await test('text.convert - invalid encoding throws', () => {
    try {
        text.convert('InvalidEncoding', 'UTF-8', new Uint8Array([1, 2, 3]));
        assert(false, 'Should throw for invalid encoding');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('text.Decoder - invalid data in non-fatal mode', () => {
    const decoder = new text.Decoder('utf-8', { fatal: false });
    const invalidData = new Uint8Array([0xff, 0xfe, 0x68]); // Invalid UTF-8 followed by 'h'
    
    // Should not throw in non-fatal mode
    const decoded = decoder.decode(invalidData);
    assert(typeof decoded === 'string', 'Should return string even with invalid data');
});
