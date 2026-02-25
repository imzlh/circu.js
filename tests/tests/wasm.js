const wasm = import.meta.use('wasm');
const fs = import.meta.use('fs');
const engine = import.meta.use('engine');
assert(wasm);

test('wasm', () => {
    const buffer = fs.exists('wasm.wasm') ? fs.readFile('wasm.wasm') : fs.readFile('tests/wasm.wasm');
    const { module, instance } = wasm.instantiate(buffer, {
        env: {
            console_log: (offset, len) => {
                const memory = new Uint8Array(instance.exports.memory.buffer);
                const bytes = memory.subarray(offset, offset + len);
                const text = engine.decodeString(bytes);
                console.log("[From WASM]", text);
            }
        }
    });
    instance.exports.trigger();
});

test('wasm:memory', () => {
    const mem = new wasm.Memory({
        initial: 1,
        maximum: 2,
        shared: false
    });
    assert(mem.buffer.byteLength == 65536);
    mem.grow(1);
    console.log(mem.buffer.byteLength);
    assert(mem.buffer.byteLength == 2 * 65536);
})