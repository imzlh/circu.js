const fs = import.meta.use('fs');
const os = import.meta.use('os');
const engine = import.meta.use('engine');

fs.setBlocking(os.STDOUT_FILENO, true)
test('fs.write', async () => {
    fs.write(os.STDOUT_FILENO, engine.encodeString('Hello, world!\n'))
})