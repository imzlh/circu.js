// test-dns.ts
const dns = import.meta.use('dns');
const os = import.meta.use('os');

// Test DNS resolution functionality
await test('DNS.resolve - IPv4 resolution', async () => {
    const addresses = await dns.resolve('example.com', {
        family: os.AF_INET, // IPv4
    });

    assert(Array.isArray(addresses), 'Should return an array');
    assert(addresses.length > 0, 'Should have at least one address');

    const addr = addresses[0];
    assertEquals(typeof addr.ip, 'string', 'Address should have ip property');
    assert(addr.ip.includes('.'), 'IPv4 address should contain dots');
});

await test('DNS.resolve - IPv6 resolution', async () => {
    const addresses = await dns.resolve('example.com', {
        family: os.AF_INET6 // IPv6
    });

    assert(Array.isArray(addresses), 'Should return an array');

    if (addresses.length > 0) {
        const addr = addresses[0];
        assert(addr.ip.includes(':'), 'IPv6 address should contain colons');
    }
});

// Test DNS query functionality
await test('DNS.query - A record query', async () => {
    const answers = await dns.query('example.com', dns.A);

    assert(Array.isArray(answers), 'Should return an array');

    if (answers.length > 0) {
        const answer = answers[0];
        assertEquals(answer.type, dns.A, 'Should be A record');
        assertEquals(answer.name, 'example.com', 'Should match query name');
        assert(typeof answer.ttl === 'number', 'Should have TTL');

        if ('address' in answer) {
            assert(answer.address.includes('.'), 'IPv4 address should contain dots');
        }
    }
});

await test('DNS.query - CNAME record query', async () => {
    // Test a domain that may have CNAME
    const answers = await dns.query('www.github.com', dns.CNAME, '114.114.114.114', 3000);

    assert(Array.isArray(answers), 'Should return an array');

    // If there are CNAME records
    const cnameAnswers = answers.filter(a => a.type === dns.CNAME);

    if (cnameAnswers.length > 0) {
        const answer = cnameAnswers[0];
        assert(typeof answer.cname === 'string', 'Should have cname property');
        assert(answer.cname.length > 0, 'CNAME should not be empty');
    }
});

await test('DNS.query - MX record query', async () => {
    const answers = await dns.query('gmail.com', dns.MX);

    assert(Array.isArray(answers), 'Should return an array');

    const mxAnswers = answers.filter(a => a.type === dns.MX);
    assert(mxAnswers.length > 0, 'Should have at least one MX record');

    const answer = mxAnswers[0];
    assertEquals(answer.type, dns.MX, 'Should be MX record');
    assert(typeof answer.priority === 'number', 'Should have priority');
    assert(typeof answer.exchange === 'string', 'Should have exchange');
    assert(answer.exchange.length > 0, 'Exchange should not be empty');
});

await test('DNS.query - TXT record query', async () => {
    const answers = await dns.query('google.com', dns.TXT);

    assert(Array.isArray(answers), 'Should return an array');

    const txtAnswers = answers.filter(a => a.type === dns.TXT);

    if (txtAnswers.length > 0) {
        const answer = txtAnswers[0];
        assertEquals(answer.type, dns.TXT, 'Should be TXT record');
        assert(typeof answer.txt === 'string', 'Should have txt property');
    }
});

await test('DNS.query - AAAA record query', async () => {
    const answers = await dns.query('example.com', dns.AAAA, '114.114.114.114', 5000);

    assert(Array.isArray(answers), 'Should return an array');

    const aaaaAnswers = answers.filter(a => a.type === dns.AAAA);

    if (aaaaAnswers.length > 0) {
        const answer = aaaaAnswers[0];
        assert(answer.address.includes(':'), 'IPv6 address should contain colons');
    }
});

await test('DNS.query - NS record query', async () => {
    const answers = await dns.query('example.com', dns.NS);

    assert(Array.isArray(answers), 'Should return an array');

    const nsAnswers = answers.filter(a => a.type === dns.NS);

    if (nsAnswers.length > 0) {
        const answer = nsAnswers[0];
        assert(typeof answer.ns === 'string', 'Should have ns property');
        assert(answer.ns.includes('.'), 'NS record should be a domain');
    }
});

await test('DNS.query - SOA record query', async () => {
    const answers = await dns.query('example.com', dns.SOA);

    assert(Array.isArray(answers), 'Should return an array');

    const soaAnswers = answers.filter(a => a.type === dns.SOA);

    if (soaAnswers.length > 0) {
        const answer = soaAnswers[0];
        assert(typeof answer.primary === 'string', 'Should have primary');
        assert(typeof answer.admin === 'string', 'Should have admin');
        assert(answer.admin.includes('@'), 'Admin should be email format');
        assert(typeof answer.serial === 'number', 'Should have serial');
        assert(typeof answer.refresh === 'number', 'Should have refresh');
        assert(typeof answer.retry === 'number', 'Should have retry');
        assert(typeof answer.expire === 'number', 'Should have expire');
        assert(typeof answer.minimum === 'number', 'Should have minimum');
    }
});

// Test error cases
await test('DNS.query - Invalid domain should handle gracefully', async () => {
    try {
        const answers = await dns.query('this-domain-probably-does-not-exist-12345.com', dns.A);

        // May return an empty array or records with error information
        assert(Array.isArray(answers), 'Should still return an array');
        // Don't expect to find records, so it may be empty
    } catch (error) {
        // Throwing an error is also acceptable
        assert(error instanceof Error, 'Should throw Error');
    }
});

await test('DNS.query - Invalid server timeout', async () => {
    try {
        // Use an address that may not respond and a timeout value
        await dns.query('example.com', dns.A, '192.0.2.1', 100);
        // If timeout occurs, it may throw an error
    } catch (error) {
        // Timeout error is expected
        assert(error instanceof Error, 'Should throw Error on timeout');
    }
});

// Test constants
await test('DNS constants', () => {
    assertEquals(dns.A, 1, 'A record type should be 1');
    assertEquals(dns.NS, 2, 'NS record type should be 2');
    assertEquals(dns.CNAME, 5, 'CNAME record type should be 5');
    assertEquals(dns.SOA, 6, 'SOA record type should be 6');
    assertEquals(dns.PTR, 12, 'PTR record type should be 12');
    assertEquals(dns.MX, 15, 'MX record type should be 15');
    assertEquals(dns.TXT, 16, 'TXT record type should be 16');
    assertEquals(dns.AAAA, 28, 'AAAA record type should be 28');
    assertEquals(dns.SRV, 33, 'SRV record type should be 33');
    assertEquals(dns.NAPTR, 35, 'NAPTR record type should be 35');
    assertEquals(dns.CAA, 257, 'CAA record type should be 257');
});

// Test union type functionality
await test('DNSAnswer type discrimination', async () => {
    const answers = await dns.query('example.com', dns.A);

    if (answers.length > 0) {
        const answer = answers[0];

        // Type guard check based on type
        if (answer.type === dns.A || answer.type === dns.AAAA) {
            // TypeScript should now know this is an AddressAnswer
            const addrAnswer = answer;
            assert('address' in addrAnswer, 'AddressAnswer should have address');
        } else if (answer.type === dns.CNAME) {
            const cnameAnswer = answer;
            assert('cname' in cnameAnswer, 'CNameAnswer should have cname');
        } else if (answer.type === dns.MX) {
            const mxAnswer = answer;
            assert('priority' in mxAnswer, 'MxAnswer should have priority');
            assert('exchange' in mxAnswer, 'MxAnswer should have exchange');
        } else if (answer.type === dns.TXT) {
            const txtAnswer = answer;
            assert('txt' in txtAnswer, 'TxtAnswer should have txt');
        }
        // ... other types are similar
    }
});