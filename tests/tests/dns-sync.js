// test-dns-sync.ts
const dns = import.meta.use('dns');
const os = import.meta.use('os');

// 测试 DNS 同步解析功能
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

// 测试 DNS 同步查询功能
await test('DNS.querySync - A record query', () => {
    const answers = dns.querySync('example.com', dns.A);

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

await test('DNS.querySync - CNAME record query', () => {
    // 测试一个可能有CNAME的域名
    const answers = dns.querySync('www.github.com', dns.CNAME, '114.114.114.114', 3000);

    assert(Array.isArray(answers), 'Should return an array');

    // 如果有CNAME记录
    const cnameAnswers = answers.filter(a => a.type === dns.CNAME);

    if (cnameAnswers.length > 0) {
        const answer = cnameAnswers[0];
        assert(typeof answer.cname === 'string', 'Should have cname property');
        assert(answer.cname.length > 0, 'CNAME should not be empty');
    }
});

await test('DNS.querySync - MX record query', () => {
    const answers = dns.querySync('gmail.com', dns.MX);

    assert(Array.isArray(answers), 'Should return an array');

    const mxAnswers = answers.filter(a => a.type === dns.MX);
    assert(mxAnswers.length > 0, 'Should have at least one MX record');

    const answer = mxAnswers[0];
    assertEquals(answer.type, dns.MX, 'Should be MX record');
    assert(typeof answer.priority === 'number', 'Should have priority');
    assert(typeof answer.exchange === 'string', 'Should have exchange');
    assert(answer.exchange.length > 0, 'Exchange should not be empty');
});

await test('DNS.querySync - TXT record query', () => {
    const answers = dns.querySync('google.com', dns.TXT);

    assert(Array.isArray(answers), 'Should return an array');

    const txtAnswers = answers.filter(a => a.type === dns.TXT);

    if (txtAnswers.length > 0) {
        const answer = txtAnswers[0];
        assertEquals(answer.type, dns.TXT, 'Should be TXT record');
        assert(typeof answer.txt === 'string', 'Should have txt property');
    }
});

await test('DNS.querySync - AAAA record query', () => {
    const answers = dns.querySync('example.com', dns.AAAA, '114.114.114.114', 5000);

    assert(Array.isArray(answers), 'Should return an array');

    const aaaaAnswers = answers.filter(a => a.type === dns.AAAA);

    if (aaaaAnswers.length > 0) {
        const answer = aaaaAnswers[0];
        assert(answer.address.includes(':'), 'IPv6 address should contain colons');
    }
});

await test('DNS.querySync - NS record query', () => {
    const answers = dns.querySync('example.com', dns.NS);

    assert(Array.isArray(answers), 'Should return an array');

    const nsAnswers = answers.filter(a => a.type === dns.NS);

    if (nsAnswers.length > 0) {
        const answer = nsAnswers[0];
        assert(typeof answer.ns === 'string', 'Should have ns property');
        assert(answer.ns.includes('.'), 'NS record should be a domain');
    }
});

await test('DNS.querySync - SOA record query', () => {
    const answers = dns.querySync('example.com', dns.SOA);

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

// 测试错误情况
await test('DNS.querySync - Invalid domain should handle gracefully', () => {
    try {
        const answers = dns.querySync('this-domain-probably-does-not-exist-12345.com', dns.A);

        // 可能返回空数组或包含错误信息的记录
        assert(Array.isArray(answers), 'Should still return an array');
        // 不期望找到记录，所以可能为空
    } catch (error) {
        // 如果抛出错误也是可以接受的
        assert(error instanceof Error, 'Should throw Error');
    }
});

// 性能比较测试
await test('DNS performance comparison', async () => {
    const domain = 'example.com';
    const iterations = 5;
    
    // 同步版本测试
    const syncStart = Date.now();
    for (let i = 0; i < iterations; i++) {
        dns.querySync(domain, dns.A);
    }
    const syncTime = Date.now() - syncStart;
    
    // 异步版本测试
    const asyncStart = Date.now();
    for (let i = 0; i < iterations; i++) {
        await dns.query(domain, dns.A);
    }
    const asyncTime = Date.now() - asyncStart;
    
    console.log(`Sync DNS queries took ${syncTime}ms for ${iterations} iterations`);
    console.log(`Async DNS queries took ${asyncTime}ms for ${iterations} iterations`);
    
    // 同步版本可能更快，因为没有回调开销
    assert(syncTime <= asyncTime * 2, 'Sync version should not be significantly slower');
});

// 测试结果一致性
await test('DNS result consistency', async () => {
    const domain = 'example.com';
    
    // 获取异步结果
    const asyncResults = await dns.query(domain, dns.A);
    
    // 获取同步结果
    const syncResults = dns.querySync(domain, dns.A);
    
    // 验证结果类型一致
    assert(Array.isArray(asyncResults), 'Async should return array');
    assert(Array.isArray(syncResults), 'Sync should return array');
    
    // 如果都有结果，验证第一个结果的类型一致
    if (asyncResults.length > 0 && syncResults.length > 0) {
        assertEquals(asyncResults[0].type, syncResults[0].type, 'Result types should match');
        assertEquals(asyncResults[0].name, syncResults[0].name, 'Result names should match');
    }
});