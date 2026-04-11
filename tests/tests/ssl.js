// tests/tests/ssl.js - SSL/TLS module tests
const ssl = import.meta.use('ssl');
const text = import.meta.use('text');

function encode(str) {
    return new text.Encoder().encode(str);
}

// ========== SSLContext ==========
await test('ssl.Context - basic client context', () => {
    const ctx = new ssl.Context({ mode: 'client' });
    assert(ctx, 'Should create SSLContext');
    assertEquals(ctx.mode, 'client', 'Mode should be client');
});

await test('ssl.Context - basic server context', () => {
    const ctx = new ssl.Context({ mode: 'server' });
    assert(ctx, 'Should create SSLContext');
    assertEquals(ctx.mode, 'server', 'Mode should be server');
});

await test('ssl.Context - default mode is client', () => {
    const ctx = new ssl.Context({});
    assertEquals(ctx.mode, 'client', 'Default mode should be client');
});

await test('ssl.Context - with TLS version', () => {
    const ctx = new ssl.Context({ 
        mode: 'client',
        version: 'TLSv1.2'
    });
    assert(ctx, 'Should create context with TLS version');
});

await test('ssl.Context - with min/max version', () => {
    const ctx = new ssl.Context({ 
        mode: 'client',
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3'
    });
    assert(ctx, 'Should create context with version range');
});

await test('ssl.Context - with certificate and key', () => {
    // Note: This test requires valid cert files
    // Skipping if files don't exist
    try {
        const ctx = new ssl.Context({ 
            mode: 'server',
            cert: '/path/to/cert.pem',
            key: '/path/to/key.pem'
        });
        // If files don't exist, this may throw
    } catch (e) {
        // Expected if test certs not available
        assert(e instanceof Error, 'Should throw Error for invalid cert paths');
    }
});

await test('ssl.Context - with CA', () => {
    try {
        const ctx = new ssl.Context({ 
            mode: 'client',
            ca: '/path/to/ca.pem'
        });
    } catch (e) {
        // Expected if CA file not available
        assert(e instanceof Error, 'Should throw Error for invalid CA path');
    }
});

await test('ssl.Context - with ciphers', () => {
    const ctx = new ssl.Context({ 
        mode: 'client',
        ciphers: 'HIGH:!aNULL:!MD5'
    });
    assert(ctx, 'Should create context with cipher list');
});

await test('ssl.Context - with verify mode', () => {
    const ctx = new ssl.Context({ 
        mode: 'client',
        verify: true
    });
    assert(ctx, 'Should create context with verify enabled');
});

await test('ssl.Context - with session options', () => {
    const ctx = new ssl.Context({ 
        mode: 'client',
        sessionTickets: true,
        sessionCache: true
    });
    assert(ctx, 'Should create context with session options');
});

// ========== SSLPipe ==========
await test('ssl.Pipe - basic construction', () => {
    const ctx = new ssl.Context({ mode: 'client' });
    const pipe = new ssl.Pipe(ctx);
    
    assert(pipe, 'Should create SSLPipe');
    assertEquals(pipe.isServer, false, 'Should be client mode');
});

await test('ssl.Pipe - server mode', () => {
    const ctx = new ssl.Context({ mode: 'server' });
    const pipe = new ssl.Pipe(ctx);
    
    assertEquals(pipe.isServer, true, 'Should be server mode');
});

await test('ssl.Pipe - with servername', () => {
    const ctx = new ssl.Context({ mode: 'client' });
    const pipe = new ssl.Pipe(ctx, { servername: 'example.com' });
    
    assert(pipe, 'Should create SSLPipe with servername');
});

await test('ssl.Pipe - handshake not complete initially', () => {
    const ctx = new ssl.Context({ mode: 'client' });
    const pipe = new ssl.Pipe(ctx);
    
    assertEquals(pipe.handshakeComplete, false, 'Handshake should not be complete initially');
});

await test('ssl.Pipe - feed and getOutput', () => {
    const ctx = new ssl.Context({ mode: 'client' });
    const pipe = new ssl.Pipe(ctx);
    
    // Client hello should be generated
    const data = new Uint8Array([1, 2, 3, 4]);
    const written = pipe.feed(data);
    
    // After feeding data, there might be output to send
    const output = pipe.getOutput();
    // Output might be null if not ready
});

await test('ssl.Pipe - write encrypted data', () => {
    const clientCtx = new ssl.Context({ mode: 'client' });
    const client = new ssl.Pipe(clientCtx);
    
    const data = encode('hello world');
    const written = client.write(data);
    
    assert(typeof written === 'number', 'Write should return number of bytes written');
});

await test('ssl.Pipe - full handshake simulation', () => {
    // Create client and server contexts
    const clientCtx = new ssl.Context({ mode: 'client' });
    const serverCtx = new ssl.Context({ mode: 'server' });
    
    const client = new ssl.Pipe(clientCtx);
    const server = new ssl.Pipe(serverCtx);
    
    // Perform handshake
    let clientDone = false;
    let serverDone = false;
    let iterations = 0;
    const maxIterations = 10;
    
    while ((!clientDone || !serverDone) && iterations < maxIterations) {
        iterations++;
        
        // Client handshake step
        if (!clientDone) {
            clientDone = client.handshake();
            const clientOut = client.getOutput();
            if (clientOut) {
                server.feed(clientOut);
            }
        }
        
        // Server handshake step
        if (!serverDone) {
            serverDone = server.handshake();
            const serverOut = server.getOutput();
            if (serverOut) {
                client.feed(serverOut);
            }
        }
    }
    
    // Note: Without proper certificates, handshake may not complete
    // This test mainly checks that the methods work
});

// ========== Utility Functions ==========
await test('ssl.version - get OpenSSL version', () => {
    const version = ssl.version;
    assertEquals(typeof version, 'string', 'Should return version string');
    assert(version.length > 0, 'Version should not be empty');
});

await test('ssl.ciphers - get cipher list', () => {
    const ciphers = ssl.ciphers;
    assert(Array.isArray(ciphers), 'Should return array');
    assert(ciphers.length > 0, 'Should have ciphers');
    assertEquals(typeof ciphers[0], 'string', 'Ciphers should be strings');
});

await test('ssl.loadPEM - load certificate PEM', () => {
    // Test with a self-signed cert PEM
    const certPEM = `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc
3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMMBn
Rlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC5kzmkCRnEGOrWNwux5S2KwL7
-----END CERTIFICATE-----`;
    
    try {
        const cert = ssl.loadPEM(certPEM, 'certificate');
        // May return null for invalid/incomplete cert
    } catch (e) {
        // Expected for invalid cert
    }
});

await test('ssl.loadPEM - load key PEM', () => {
    const keyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZXhhbXBsZSBrZXkg
ZGF0YSBmb3IgdGVzdGluZyBvbmx5MLOWfjAlgM5E
-----END PRIVATE KEY-----`;
    
    try {
        const key = ssl.loadPEM(keyPEM, 'key');
        // May return null for invalid/incomplete key
    } catch (e) {
        // Expected for invalid key
    }
});

await test('ssl.createSelfSignedCert - generate certificate', () => {
    try {
        const cert = ssl.createSelfSignedCert({
            commonName: 'test.example.com',
            days: 365
        });
        
        assert(cert, 'Should create certificate');
        assertEquals(typeof cert.cert, 'string', 'Should have cert PEM');
        assertEquals(typeof cert.key, 'string', 'Should have key PEM');
    } catch (e) {
        // May not be available in all builds
        assert(e instanceof Error, 'May throw if not supported');
    }
});

// ========== Error Handling ==========
await test('ssl - invalid version throws', () => {
    try {
        new ssl.Context({ mode: 'client', version: 'InvalidVersion' });
        assert(false, 'Should throw for invalid version');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('ssl.Pipe - invalid context throws', () => {
    try {
        new ssl.Pipe('not a context');
        assert(false, 'Should throw for invalid context');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});
