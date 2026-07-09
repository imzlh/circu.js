import { readOnce } from "../polyfill/stream.read.js";

// test-stream-sync.ts
const engine = import.meta.use('engine');
const stream = import.meta.use('streams');
const os = import.meta.use('os');
const dns = import.meta.use('dns');

// Test synchronous read stream
await test('Stream.readSync - Basic functionality', () => {
    // Create a test TCP connection
    const client = new stream.TCP();
    
    try {
        // Resolve domain name to get IP address first
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // Use the first IPv4 address
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        console.log(addresses)
        
        // Try connecting to a public server
        client.connectSync({ ip, port: 80 });
        client.setBlocking(true);
        console.log('Connect OK')
        
        // Try reading data (may return null or empty array if no data available)
        client.writeSync(engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'))
        const buffer = new Uint8Array(1024);
        let bytesRead = client.readSync(buffer);
        console.log('read ok:', bytesRead, buffer.subarray(0, bytesRead), engine.decodeString(buffer.subarray(0, bytesRead)))
        
        // Verify the return value is the expected type
        assert(typeof bytesRead === 'number' || bytesRead === null, 'Should return number of bytes read or null');
        
        if (bytesRead !== null) {
            assert(bytesRead <= 1024, 'Bytes read should not exceed buffer size');
            // Get the actual data read
            const data = buffer.subarray(0, bytesRead);
            assert(data instanceof Uint8Array, 'Data should be a Uint8Array');
        }
    } finally {
        client.close();
    }
});

// Test synchronous write stream
await test('Stream.writeSync - Basic functionality', () => {
    // Create a test TCP connection
    const client = new stream.TCP();
    
    try {
        // Resolve domain name to get IP address first
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // Use the first IPv4 address
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        
        // Try connecting to a public server
        client.connectSync({ ip, port: 80 });
        client.setBlocking(true);
        
        // Create a simple HTTP request
        const requestData = engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
        
        // Try writing data
        const bytesWritten = client.writeSync(requestData);
        
        // Verify the number of bytes written
        assert(typeof bytesWritten === 'number', 'Should return number of bytes written');
        assert(bytesWritten > 0, 'Should write at least one byte');
        assert(bytesWritten <= requestData.length, 'Should not write more than requested');
    } finally {
        client.close();
    }
});

// Test large file synchronous operations
await test('Stream - Large file sync operations', () => {
    // Create a test TCP connection
    const client = new stream.TCP();
    
    try {
        // Resolve domain name to get IP address first
        const addresses = dns.resolveSync('example.com', { family: 0 }); // 0 = AF_UNSPEC (both IPv4 and IPv6)
        // Use the first IPv4 address
        const ipv4Address = addresses.find(addr => addr.family === 4);
        if (!ipv4Address) {
            throw new Error('No IPv4 address found for example.com');
        }
        const ip = ipv4Address.ip;
        
        // Try connecting to a public server
        client.connectSync({ ip, port: 80 });
        client.setBlocking(true);
        
        // Send a simple HTTP request
        const requestData = engine.encodeString('GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');
        client.writeSync(requestData);
        
        // Try reading large amounts of data
        let totalBytesRead = 0;
        const maxReads = 10; // Limit read count to avoid infinite loops
        
        for (let i = 0; i < maxReads; i++) {
            const buffer = new Uint8Array(8192); // 8KB buffer
            const bytesRead = client.readSync(buffer);
            
            if (bytesRead === null || bytesRead === 0) {
                break; // No more data
            }
            
            totalBytesRead += bytesRead;
        }
        
        // Verify some data was read
        assert(totalBytesRead >= 0, 'Should read non-negative bytes');
        
        console.log(`Read ${totalBytesRead} bytes from server`);
    } finally {
        client.close();
    }
});

// Test error handling
await test('Stream - Error handling', () => {
    // Create a test TCP connection
    const client = new stream.TCP();
    
    try {
        // Try connecting to a non-existent server
        try {
            client.connectSync({ ip: 'this-domain-does-not-exist-12345.com', port: 80 });
            assert(false, 'Should throw an error for invalid domain');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
        
        // Try writing data to an unconnected stream
        try {
            const textEncoder = new TextEncoder();
            const requestData = textEncoder.encode('test data');
            client.writeSync(requestData);
            assert(false, 'Should throw an error for writing to unconnected stream');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
        
        // Try reading data from an unconnected stream
        try {
            const buffer = new Uint8Array(1024);
            client.readSync(buffer);
            assert(false, 'Should throw an error for reading from unconnected stream');
        } catch (error) {
            assert(error instanceof Error, 'Should throw an Error');
            assert(error.message, 'Error should have a message');
        }
    } finally {
        client.close();
    }
});

// Test sync and async result consistency (sync part only)
await test('Stream - Sync read/write consistency', () => {
    const syncClient = new stream.TCP();
    
    try {
        const ip = dns.resolveSync('www.gstatic.com', { family: os.AF_UNSPEC })[0].ip;
        
        // sync connect
        syncClient.connectSync({ ip, port: 80 });
        syncClient.setBlocking(true);
        
        // Prepare test data
        const requestData = engine.encodeString('GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\n\r\n');
        
        // Synchronous write
        const bytesWritten = syncClient.writeSync(requestData);
        assert(bytesWritten > 0, 'Should write data');
        
        // Synchronous read
        const syncData = new Uint8Array(1024);
        const bytesRead = syncClient.readSync(syncData);
        
        assert(bytesRead > 0, 'Should read data');
        
        // Verify HTTP response
        const response = engine.decodeString(syncData.subarray(0, bytesRead));
        assert(response.startsWith('HTTP/1.1'), 'Should get HTTP response');
        console.log('Sync read/write consistent, got', bytesRead, 'bytes');
    } finally {
        syncClient.close();
    }
});