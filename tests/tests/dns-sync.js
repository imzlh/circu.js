// test-dns-sync.ts
const dns = import.meta.use('dns');
const os = import.meta.use('os');

// Test DNS synchronous resolution functionality
await test('DNS.resolveSync - IPv4 resolution', () => {
    const addresses = dns.resolveSync('example.com', {
        family: os.AF_INET, // IPv4
    });

    assert(Array.isArray(addresses), 'Should return an array');
    assert(addresses.length > 0, 'Should have at least one address');

    const addr = addresses[0];
    assertEquals(typeof addr.ip, 'string', 'Address should have ip property');
    assert(addr.ip.includes('.'), 'IPv4 address should contain dots');
});

await test('DNS.resolveSync - IPv6 resolution', () => {
    const addresses = dns.resolveSync('example.com', {
        family: os.AF_INET6 // IPv6
    });

    assert(Array.isArray(addresses), 'Should return an array');

    if (addresses.length > 0) {
        const addr = addresses[0];
        assert(addr.ip.includes(':'), 'IPv6 address should contain colons');
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
        assert(typeof answer.name === 'string', 'Should have cname property');
        assert(answer.name.length > 0, 'CNAME should not be empty');
    }
});