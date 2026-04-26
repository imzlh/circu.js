// tests/tests/fs.js - Filesystem module tests (syncfs)

const fs = import.meta.use('fs');
const os = import.meta.use('os');
const text = import.meta.use('text');

const encoder = new text.Encoder();
const decoder = new text.Decoder();

function encode(str) {
    return encoder.encode(str);
}

const TEST_DIR = '/tmp/test_fs_' + Date.now();
const TEST_FILE = TEST_DIR + '/test.txt';

// ========== File Operations ==========
await test('fs.write - write to stdout', () => {
    fs.setBlocking(os.STDOUT_FILENO, true);
    fs.write(os.STDOUT_FILENO, encode('Hello, world!\n'));
});

await test('fs.open - open file for writing', () => {
    fs.mkdir(TEST_DIR, 0o755);
    const fd = fs.open(TEST_FILE, 'w', 0o644);
    assert(typeof fd === 'number', 'Should return file descriptor');
    assert(fd >= 0, 'File descriptor should be non-negative');
    fs.close(fd);
});

await test('fs.write - write to file', () => {
    const fd = fs.open(TEST_FILE, 'w', 0o644);
    const data = encode('Hello, World!');
    const written = fs.write(fd, data);
    assertEquals(written, data.length, 'Should write all bytes');
    fs.close(fd);
});

await test('fs.read - read from file', () => {
    // First write some data
    const fd = fs.open(TEST_FILE, 'w', 0o644);
    fs.write(fd, encode('Test data'));
    fs.close(fd);
    
    // Now read it back
    const fd2 = fs.open(TEST_FILE, 'r');
    const buffer = new Uint8Array(100);
    const bytesRead = fs.read(fd2, buffer);
    fs.close(fd2);
    
    assert(bytesRead > 0, 'Should read some bytes');
    const content = decoder.decode(buffer.slice(0, bytesRead));
    assertEquals(content, 'Test data', 'Content should match');
});

await test('fs.pwrite/pread - positional write/read', () => {
    const fd = fs.open(TEST_FILE, 'w+', 0o644);
    
    // Write at offset
    fs.pwrite(fd, encode('World'), 6);
    fs.pwrite(fd, encode('Hello'), 0);
    
    // Read back
    const buffer = new Uint8Array(100);
    const bytesRead = fs.pread(fd, buffer, 0);
    fs.close(fd);
    
    const content = decoder.decode(buffer.slice(0, bytesRead));
    assert(content.includes('Hello') && content.includes('World'), 'Should have written both parts');
});

// ========== File Status ==========
await test('fs.stat - get file status', () => {
    fs.writeFile(TEST_FILE, encode('test'));
    const stats = fs.stat(TEST_FILE);
    
    assert(stats, 'Should return stats object');
    assertEquals(typeof stats.size, 'number', 'Should have size');
    assertEquals(typeof stats.mode, 'number', 'Should have mode');
    assert(stats.size > 0, 'File should have content');
});

await test('fs.stat - file type checks', () => {
    fs.mkdir(TEST_DIR + '/subdir', 0o755);
    fs.writeFile(TEST_FILE, encode('test'));
    
    const fileStats = fs.stat(TEST_FILE);
    const dirStats = fs.stat(TEST_DIR);
    
    // isFile/isDirectory are boolean properties (not methods) in circu.js
    assert(fileStats.isFile === true, 'Should be file');
    assert(dirStats.isDirectory === true, 'Should be directory');
    assert(fileStats.isDirectory === false, 'File should not be directory');
    assert(dirStats.isFile === false, 'Directory should not be file');
});

await test('fs.lstat - symlink stats', () => {
    fs.writeFile(TEST_FILE, encode('test'));
    fs.symlink(TEST_FILE, TEST_DIR + '/link');
    
    const stats = fs.lstat(TEST_DIR + '/link');
    assert(stats, 'Should return stats');
    // Note: lstat follows symlinks on some platforms
});

await test('fs.exists - check file existence', () => {
    fs.writeFile(TEST_FILE, encode('test'));
    
    assertEquals(fs.exists(TEST_FILE), true, 'Should exist');
    assertEquals(fs.exists('/nonexistent/file'), false, 'Should not exist');
});

// ========== File Read/Write Helpers ==========
await test('fs.readFile - read entire file', () => {
    const content = 'Hello, World!';
    fs.writeFile(TEST_FILE, encode(content));
    
    const data = fs.readFile(TEST_FILE);
    // readFile returns ArrayBuffer in circu.js, wrap in Uint8Array for decoding
    const view = data instanceof Uint8Array ? data : new Uint8Array(data);
    assert(data instanceof ArrayBuffer || data instanceof Uint8Array, 'Should return ArrayBuffer or Uint8Array');
    assertEquals(decoder.decode(view), content, 'Content should match');
});

await test('fs.writeFile - write entire file', () => {
    const content = 'Write file test content';
    fs.writeFile(TEST_FILE, encode(content));
    
    const read = fs.readFile(TEST_FILE);
    assertEquals(decoder.decode(read), content, 'Written content should match');
});

await test('fs.writeFile - overwrite existing', () => {
    fs.writeFile(TEST_FILE, encode('first'));
    fs.writeFile(TEST_FILE, encode('second'));
    
    const read = fs.readFile(TEST_FILE);
    assertEquals(decoder.decode(read), 'second', 'Should be overwritten');
});

// ========== Directory Operations ==========
await test('fs.mkdir - create directory', () => {
    const newDir = TEST_DIR + '/newdir';
    fs.mkdir(newDir, 0o755);
    
    assert(fs.exists(newDir), 'Directory should exist');
    const stats = fs.stat(newDir);
    assert(stats.isDirectory === true, 'Should be directory');
});

await test('fs.rmdir - remove directory', () => {
    const emptyDir = TEST_DIR + '/emptydir';
    fs.mkdir(emptyDir, 0o755);
    assert(fs.exists(emptyDir), 'Directory should exist');
    
    fs.rmdir(emptyDir);
    assertEquals(fs.exists(emptyDir), false, 'Directory should be removed');
});

// ========== Link Operations ==========
await test('fs.symlink - create symbolic link', () => {
    fs.writeFile(TEST_FILE, encode('target'));
    const linkPath = TEST_DIR + '/symlink';
    
    fs.symlink(TEST_FILE, linkPath);
    assert(fs.exists(linkPath), 'Symlink should exist');
});

await test('fs.link - create hard link', () => {
    fs.writeFile(TEST_FILE, encode('target'));
    const hardLinkPath = TEST_DIR + '/hardlink';
    
    fs.link(TEST_FILE, hardLinkPath);
    assert(fs.exists(hardLinkPath), 'Hard link should exist');
    
    // Both should point to same content
    const origContent = decoder.decode(fs.readFile(TEST_FILE));
    const linkContent = decoder.decode(fs.readFile(hardLinkPath));
    assertEquals(origContent, linkContent, 'Content should be same');
});

await test('fs.unlink - remove file', () => {
    const fileToRemove = TEST_DIR + '/toremove.txt';
    fs.writeFile(fileToRemove, encode('delete me'));
    assert(fs.exists(fileToRemove), 'File should exist');
    
    fs.unlink(fileToRemove);
    assertEquals(fs.exists(fileToRemove), false, 'File should be removed');
});

// ========== File Descriptor Management ==========
await test('fs.close - close file descriptor', () => {
    const fd = fs.open(TEST_FILE, 'w+', 0o644);
    fs.write(fd, encode('test'));
    fs.close(fd);
    
    // Closing again should throw or be handled gracefully
    try {
        fs.close(fd);
    } catch (e) {
        // Expected - fd already closed
        assert(e instanceof Error, 'Should throw for invalid fd');
    }
});

await test('fs.setBlocking - set blocking mode', () => {
    // Test on stdout
    fs.setBlocking(os.STDOUT_FILENO, true);
    fs.setBlocking(os.STDOUT_FILENO, false);
    fs.setBlocking(os.STDOUT_FILENO, true);
    
    // Should not throw
});

// ========== Open Flags ==========
await test('fs.open - different open modes', () => {
    const testFile = TEST_DIR + '/modes.txt';
    
    // Write mode
    const fd1 = fs.open(testFile, 'w', 0o644);
    fs.write(fd1, encode('test'));
    fs.close(fd1);
    
    // Read mode
    const fd2 = fs.open(testFile, 'r');
    const buf = new Uint8Array(10);
    fs.read(fd2, buf);
    fs.close(fd2);
    
    // Append mode
    const fd3 = fs.open(testFile, 'a');
    fs.write(fd3, encode(' appended'));
    fs.close(fd3);
    
    const content = decoder.decode(fs.readFile(testFile));
    assert(content.includes('test'), 'Should have original content');
});

// ========== Error Handling ==========
await test('fs - error on nonexistent file', () => {
    try {
        fs.open('/nonexistent/path/to/file', 'r');
        assert(false, 'Should throw for nonexistent file');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('fs - error on invalid flags', () => {
    try {
        fs.open(TEST_FILE, 'invalid_mode');
        assert(false, 'Should throw for invalid mode');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('fs.rmdir - error on nonempty directory', () => {
    const dirWithFile = TEST_DIR + '/nonempty';
    fs.mkdir(dirWithFile, 0o755);
    fs.writeFile(dirWithFile + '/file.txt', encode('content'));
    
    try {
        fs.rmdir(dirWithFile);
        assert(false, 'Should throw for nonempty directory');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
        // Cleanup
        fs.unlink(dirWithFile + '/file.txt');
        fs.rmdir(dirWithFile);
    }
});

// Cleanup
await test('fs - cleanup test files', () => {
    try {
        // Remove all test files
        const files = [TEST_FILE, TEST_DIR + '/link', TEST_DIR + '/symlink', TEST_DIR + '/hardlink'];
        for (const f of files) {
            try { fs.unlink(f); } catch (e) {}
        }
        
        // Remove test directories
        const dirs = [TEST_DIR + '/subdir', TEST_DIR + '/newdir', TEST_DIR];
        for (const d of dirs) {
            try { fs.rmdir(d); } catch (e) {}
        }
    } catch (e) {
        // Ignore cleanup errors
    }
});
