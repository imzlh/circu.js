const socket = import.meta.use('socket');
const engine = import.meta.use('engine');
const os = import.meta.use('os');
const udp = import.meta.use('udp');

const loopback = { ip: '127.0.0.1', port: 0 };

await test('socket TCP methods accept address objects', () => {
    const server = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);
    let client;
    let accepted;
    try {
        server.bind(loopback);
        server.listen();

        const serverAddress = server.sockname;
        assertEquals(serverAddress.ip, loopback.ip);
        assert(serverAddress.port > 0, 'bind({ port: 0 }) should select a port');
        assertEquals(server.info.type, socket.SOCK_STREAM);
        assert(server.getopt(socket.SOL_SOCKET, socket.SO_TYPE, 4) instanceof Uint8Array);

        client = new socket.Socket(socket.AF_INET, socket.SOCK_STREAM);
        client.connect({ ip: serverAddress.ip, port: serverAddress.port });
        accepted = server.accept();

        assertEquals(accepted.peername.ip, loopback.ip);
        assertEquals(client.peername.port, serverAddress.port);

        const payload = new Uint8Array([1, 2, 3, 4]);
        assertEquals(client.send(payload), payload.length);
        const received = accepted.recv(payload.length);
        assert(received instanceof Uint8Array);
        assertEquals(received.length, payload.length);
        for (let i = 0; i < payload.length; i++) {
            assertEquals(received[i], payload[i]);
        }
    } finally {
        accepted?.close();
        client?.close();
        server.close();
    }
});

await test('socket sendmsg and recvmsg use address objects', () => {
    if (typeof socket.Socket.prototype.sendmsg !== 'function') return;

    const receiver = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);
    const sender = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);
    try {
        receiver.bind(loopback);
        sender.bind(loopback);

        const target = receiver.sockname;
        const payload = new Uint8Array([9, 8, 7]);
        assertEquals(sender.sendmsg(target, null, 0, payload), payload.length);

        const message = receiver.recvmsg(64);
        assert(message.address, 'recvmsg should decode the sender address');
        assertEquals(message.address.ip, loopback.ip);
        assertEquals(message.address.port, sender.sockname.port);
        assertEquals(message.data.length, payload.length);
        for (let i = 0; i < payload.length; i++) {
            assertEquals(message.data[i], payload[i]);
        }
    } finally {
        sender.close();
        receiver.close();
    }
});

await test('socket createFrom borrows descriptors by default', () => {
    const original = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);
    try {
        const wrapper = socket.createFrom(original.fileno);
        assertEquals(wrapper.fileno, original.fileno);
        wrapper.close();

        // Windows exposes pointer-width socket handles as bigint. Exercise the
        // bigint input path on every platform so it cannot silently regress.
        const bigintWrapper = socket.createFrom(BigInt(original.fileno));
        assertEquals(bigintWrapper.fileno, original.fileno);
        bigintWrapper.close();

        // Closing a borrowed wrapper must not invalidate the original socket.
        original.bind(loopback);
        assert(original.sockname.port > 0);

        // This mirrors dgram's short-lived option wrappers: collection must
        // release the wrappers without closing libuv's descriptor.
        for (let i = 0; i < 128; i++) {
            socket.createFrom(original.fileno).getopt(
                socket.SOL_SOCKET,
                socket.SO_TYPE,
                4,
            );
        }
        engine.gc.run();
        assertEquals(original.info.type, socket.SOCK_DGRAM);
    } finally {
        original.close();
    }
});

await test('socket createFrom pins across an options getter', () => {
    const original = new socket.Socket(socket.AF_INET, socket.SOCK_DGRAM);
    const fd = original.fileno;
    const wrapper = socket.createFrom(fd, {
        get closeOnClose() {
            original.close();
            return false;
        },
    });
    try {
        wrapper.bind(loopback);
        assert(wrapper.sockname.port > 0);
    } finally {
        wrapper.close();
    }
});

await test('UDP fileno round-trips through socket.createFrom without narrowing', () => {
    const handle = new udp.UDP();
    let wrapper;
    try {
        handle.bind(loopback);
        const fd = handle.fileno();
        assertEquals(typeof fd, os.platform === 'windows' ? 'bigint' : 'number');

        wrapper = socket.createFrom(fd);
        assertEquals(wrapper.fileno, fd);
        assertEquals(wrapper.info.type, socket.SOCK_DGRAM);
    } finally {
        wrapper?.close();
        handle.close();
    }
});
