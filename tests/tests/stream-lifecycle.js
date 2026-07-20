const streams = import.meta.use('streams');
const engine = import.meta.use('engine');

await test('streams: repeated listen/read controls and close are idempotent', async () => {
    const server = new streams.TCP();
    let acceptedResolve;
    const accepted = new Promise(resolve => { acceptedResolve = resolve; });
    server.onconnection = (error, client) => {
        assert(!error, `accept failed: ${error}`);
        acceptedResolve(client);
    };

    server.bind({ ip: '127.0.0.1', port: 0 });
    server.listen(8);
    server.listen(16);

    const client = new streams.TCP();
    await client.connect(server.sockname);
    const peer = await accepted;

    client.onread = () => {};
    client.startRead();
    let repeatedReadThrew = false;
    try {
        client.startRead();
    } catch {
        repeatedReadThrew = true;
    }
    assert(repeatedReadThrew, 'a second startRead must not acquire another pin');
    client.stopRead();
    client.stopRead();

    const canceledBuffer = new Uint8Array([0xaa, 0xaa, 0xaa, 0xaa]);
    const canceledRead = client.read(canceledBuffer).then(
        () => null,
        error => error,
    );
    client.cancelRead();
    client.cancelRead();
    assert(await canceledRead instanceof Error, 'cancelRead must reject the pending read');
    assert(canceledBuffer.every(value => value === 0xaa), 'cancelled reads must not mutate the caller buffer');

    await peer.write(engine.encodeString('ok'));
    const received = new Uint8Array(8);
    const bytesRead = await client.read(received);
    assertEquals(bytesRead, 2);
    assertEquals(engine.decodeString(received.subarray(0, bytesRead)), 'ok');

    let closeCount = 0;
    let closeResolve;
    const closed = new Promise(resolve => { closeResolve = resolve; });
    client.onclose = () => {
        closeCount++;
        closeResolve();
    };
    client.close();
    client.close();
    await closed;
    client.close();
    assertEquals(closeCount, 1, 'close callback must run once');

    peer.close();
    peer.close();
    server.close();
    server.close();
});
