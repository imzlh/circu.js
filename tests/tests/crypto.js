// tests/tests/crypto.js - Crypto module tests

const crypto = import.meta.use('crypto');
const text = import.meta.use('text');

function encode(str) {
    return new text.Encoder().encode(str);
}

function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ========== Hash Functions ==========
await test('crypto.md5 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.md5(data);
    
    assertEquals(hash.byteLength, 16, 'MD5 should be 16 bytes');
});

await test('crypto.sha1 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha1(data);
    
    assertEquals(hash.byteLength, 20, 'SHA1 should be 20 bytes');
});

await test('crypto.sha256 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha256(data);
    
    assertEquals(hash.byteLength, 32, 'SHA256 should be 32 bytes');
});

await test('crypto.sha384 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha384(data);
    
    assertEquals(hash.byteLength, 48, 'SHA384 should be 48 bytes');
});

await test('crypto.sha512 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha512(data);
    
    assertEquals(hash.byteLength, 64, 'SHA512 should be 64 bytes');
});

await test('crypto.sha3_256 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha3_256(data);
    
    assertEquals(hash.byteLength, 32, 'SHA3-256 should be 32 bytes');
});

await test('crypto.sha3_512 - basic hash', () => {
    const data = encode('hello');
    const hash = crypto.sha3_512(data);
    
    assertEquals(hash.byteLength, 64, 'SHA3-512 should be 64 bytes');
});

await test('crypto hashes - deterministic', () => {
    const data = encode('deterministic test');
    const hash1 = crypto.sha256(data);
    const hash2 = crypto.sha256(data);
    
    assertEquals(bufToHex(hash1), bufToHex(hash2), 'Same input should produce same hash');
});

// ========== HMAC ==========
await test('crypto.hmacSha256 - basic HMAC', () => {
    const key = encode('secret key');
    const data = encode('message');
    const hmac = crypto.hmacSha256(key, data);
    
    assertEquals(hmac.byteLength, 32, 'HMAC-SHA256 should be 32 bytes');
});

await test('crypto.hmacSha512 - basic HMAC', () => {
    const key = encode('secret key');
    const data = encode('message');
    const hmac = crypto.hmacSha512(key, data);
    
    assertEquals(hmac.byteLength, 64, 'HMAC-SHA512 should be 64 bytes');
});

await test('crypto.hmac - different keys produce different results', () => {
    const data = encode('message');
    const hmac1 = crypto.hmacSha256(encode('key1'), data);
    const hmac2 = crypto.hmacSha256(encode('key2'), data);
    
    assert(bufToHex(hmac1) !== bufToHex(hmac2), 'Different keys should produce different HMACs');
});

// ========== HKDF ==========
await test('crypto.hkdfSha256 - basic key derivation', () => {
    const ikm = encode('input key material');
    const keylen = 32;
    const derived = crypto.hkdfSha256(ikm, keylen);
    
    assertEquals(derived.byteLength, keylen, 'Derived key byteLength should match requested');
});

await test('crypto.hkdfSha256 - with salt and info', () => {
    const ikm = encode('input key material');
    const salt = encode('salt');
    const info = encode('context info');
    const keylen = 32;
    
    const derived = crypto.hkdfSha256(ikm, keylen, salt, info);
    
    assertEquals(derived.byteLength, keylen, 'Derived key byteLength should match requested');
});

await test('crypto.hkdfSha256 - different salts produce different keys', () => {
    const ikm = encode('input key material');
    const key1 = crypto.hkdfSha256(ikm, 32, encode('salt1'));
    const key2 = crypto.hkdfSha256(ikm, 32, encode('salt2'));
    
    assert(bufToHex(key1) !== bufToHex(key2), 'Different salts should produce different keys');
});

// ========== ECC (P-256) ==========
await test('crypto.generateEcKeyP256 - key generation', () => {
    const keypair = crypto.generateEcKeyP256();
    
    assert(keypair.publicKey instanceof ArrayBuffer, 'Should have publicKey');
    assert(keypair.privateKey instanceof ArrayBuffer, 'Should have privateKey');
    assert(keypair.publicKey.byteLength > 0, 'Public key should not be empty');
    assert(keypair.privateKey.byteLength > 0, 'Private key should not be empty');
});

await test('crypto.ecdsaSignP256 - signing and verification', () => {
    const keypair = crypto.generateEcKeyP256();
    const data = encode('message to sign');
    
    const signature = crypto.ecdsaSignP256(keypair.privateKey, data);
    assert(signature instanceof ArrayBuffer, 'Signature should be ArrayBuffer');
    assert(signature.byteLength > 0, 'Signature should not be empty');
    
    const valid = crypto.ecdsaVerifyP256(keypair.publicKey, data, signature);
    assertEquals(valid, true, 'Signature should be valid');
});

await test('crypto.ecdsaVerifyP256 - invalid signature', () => {
    const keypair = crypto.generateEcKeyP256();
    const data = encode('message to sign');
    const wrongData = encode('wrong message');
    
    const signature = crypto.ecdsaSignP256(keypair.privateKey, data);
    const valid = crypto.ecdsaVerifyP256(keypair.publicKey, wrongData, signature);
    
    assertEquals(valid, false, 'Signature should be invalid for wrong data');
});

await test('crypto.ecdhDeriveP256 - key agreement', () => {
    const alice = crypto.generateEcKeyP256();
    const bob = crypto.generateEcKeyP256();
    
    const secret1 = crypto.ecdhDeriveP256(alice.privateKey, bob.publicKey);
    const secret2 = crypto.ecdhDeriveP256(bob.privateKey, alice.publicKey);
    
    assert(secret1 instanceof ArrayBuffer, 'Secret should be ArrayBuffer');
    assert(secret2 instanceof ArrayBuffer, 'Secret should be ArrayBuffer');
    assertEquals(bufToHex(secret1), bufToHex(secret2), 'Both parties should derive same secret');
});

// ========== ECC (P-384) ==========
await test('crypto.generateEcKeyP384 - key generation', () => {
    const keypair = crypto.generateEcKeyP384();
    
    assert(keypair.publicKey instanceof ArrayBuffer, 'Should have publicKey');
    assert(keypair.privateKey instanceof ArrayBuffer, 'Should have privateKey');
});

await test('crypto.ecdsaSignP384 - signing and verification', () => {
    const keypair = crypto.generateEcKeyP384();
    const data = encode('message to sign');
    
    const signature = crypto.ecdsaSignP384(keypair.privateKey, data);
    const valid = crypto.ecdsaVerifyP384(keypair.publicKey, data, signature);
    
    assertEquals(valid, true, 'Signature should be valid');
});

// ========== ECC (P-521) ==========
await test('crypto.generateEcKeyP521 - key generation', () => {
    const keypair = crypto.generateEcKeyP521();
    
    assert(keypair.publicKey instanceof ArrayBuffer, 'Should have publicKey');
    assert(keypair.privateKey instanceof ArrayBuffer, 'Should have privateKey');
});

await test('crypto.ecdsaSignP521 - signing and verification', () => {
    const keypair = crypto.generateEcKeyP521();
    const data = encode('message to sign');
    
    const signature = crypto.ecdsaSignP521(keypair.privateKey, data);
    const valid = crypto.ecdsaVerifyP521(keypair.publicKey, data, signature);
    
    assertEquals(valid, true, 'Signature should be valid');
});

// ========== Error handling ==========
await test('crypto - invalid input handling', () => {
    try {
        crypto.sha256('not a buffer');
        assert(false, 'Should throw for non-buffer input');
    } catch (e) {
        console.log(e);
        assert(e instanceof Error, 'Should throw Error for invalid input');
    }
});

await test('crypto.hmacSha256 - invalid input handling', () => {
    try {
        crypto.hmacSha256('not a buffer', encode('data'));
        assert(false, 'Should throw for non-buffer key');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});
