const process = import.meta.use('process');
const engine = import.meta.use('engine');
const console = import.meta.use('console');
const os = import.meta.use('os');

// PTY mode: creates a child process with a PTY
const p = process.spawn('cmd.exe', {
    pty: true,
    cols: 80,
    rows: 24,
});

console.log('PID:', p.pid);

// Write to PTY (child stdin)
const writer = p.writable.getWriter();
await writer.write(engine.encodeString('echo hello world\r\n'));

// Give the command time to execute
await os.sleep(500);

// Read from PTY (child stdout)
const reader = p.readable.getReader();
const result = await reader.read();
if (!result.done && result.value) {
    console.log('Output:', engine.decodeString(result.value));
}

// Resize
p.resize(120, 30);
const size = p.getwinsize();
console.log('Size:', size.cols, 'x', size.rows);

// Cleanup
p.kill('SIGTERM');
const exitInfo = await p.wait();
console.log('Exit:', exitInfo);
