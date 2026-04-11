// tests/tests/sqlite3.js - SQLite3 module tests

const sqlite3 = import.meta.use('sqlite3');

// ========== Database Open/Close ==========
await test('sqlite3.open - create in-memory database', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    assert(db, 'Should create database handle');
    db.close();
});

await test('sqlite3.open - with flags', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    assert(db, 'Should create database handle');
    db.close();
});

await test('sqlite3 constants', () => {
    assertEquals(typeof sqlite3.O_CREATE, 'number', 'O_CREATE should be defined');
    assertEquals(typeof sqlite3.O_READONLY, 'number', 'O_READONLY should be defined');
    assertEquals(typeof sqlite3.O_READWRITE, 'number', 'O_READWRITE should be defined');
    assertEquals(typeof sqlite3.O_MEMORY, 'number', 'O_MEMORY should be defined');
});

// ========== SQL Execution ==========
await test('sqlite3.exec - basic SQL execution', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)');
    db.exec('INSERT INTO test (name) VALUES ("hello")');
    
    db.close();
});

await test('sqlite3.exec - multiple statements', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    
    db.exec(`
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
        INSERT INTO users (name) VALUES ('Alice');
        INSERT INTO users (name) VALUES ('Bob');
    `);
    
    db.close();
});

// ========== Prepared Statements ==========
await test('sqlite3.prepare - create statement', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)');
    
    const stmt = db.prepare('INSERT INTO test (name) VALUES (?)');
    assert(stmt, 'Should create statement');
    
    stmt.finalize();
    db.close();
});

await test('sqlite3.Statement.run - execute with params', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)');
    
    const stmt = db.prepare('INSERT INTO test (name, age) VALUES (?, ?)');
    stmt.run(['Alice', 30]);
    stmt.run(['Bob', 25]);
    stmt.finalize();
    
    db.close();
});

await test('sqlite3.Statement.run - with object params', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)');
    
    const stmt = db.prepare('INSERT INTO test (name) VALUES (:name)');
    stmt.run({ ':name': 'Charlie' });
    stmt.finalize();
    
    db.close();
});

await test('sqlite3.Statement.all - fetch results', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)');
    db.exec('INSERT INTO test (name) VALUES ("Alice")');
    db.exec('INSERT INTO test (name) VALUES ("Bob")');
    
    const stmt = db.prepare('SELECT * FROM test ORDER BY id');
    const rows = stmt.all();
    
    assert(Array.isArray(rows), 'Should return array');
    assertEquals(rows.length, 2, 'Should have 2 rows');
    assertEquals(rows[0].name, 'Alice', 'First row should be Alice');
    assertEquals(rows[1].name, 'Bob', 'Second row should be Bob');
    
    stmt.finalize();
    db.close();
});

await test('sqlite3.Statement.all - with params', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, age INTEGER)');
    db.exec('INSERT INTO test (name, age) VALUES ("Alice", 30)');
    db.exec('INSERT INTO test (name, age) VALUES ("Bob", 25)');
    
    const stmt = db.prepare('SELECT * FROM test WHERE age > ?');
    const rows = stmt.all([27]);
    
    assertEquals(rows.length, 1, 'Should have 1 row matching condition');
    assertEquals(rows[0].name, 'Alice', 'Should be Alice');
    
    stmt.finalize();
    db.close();
});

// ========== Data Types ==========
await test('sqlite3 - various data types', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE types (int_val INTEGER, real_val REAL, text_val TEXT, blob_val BLOB, null_val)');
    
    const blob = new Uint8Array([1, 2, 3, 4, 5]);
    const stmt = db.prepare('INSERT INTO types VALUES (?, ?, ?, ?, ?)');
    stmt.run([42, 3.14, 'hello', blob, null]);
    stmt.finalize();
    
    const select = db.prepare('SELECT * FROM types');
    const rows = select.all();
    
    assertEquals(rows[0].int_val, 42, 'Integer should match');
    assertEquals(rows[0].real_val, 3.14, 'Real should match');
    assertEquals(rows[0].text_val, 'hello', 'Text should match');
    assert(rows[0].blob_val instanceof Uint8Array, 'Blob should be Uint8Array');
    assertEquals(rows[0].null_val, null, 'Null should be null');
    
    select.finalize();
    db.close();
});

// ========== Transaction Support ==========
await test('sqlite3 - transaction support', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, value INTEGER)');
    
    // Test inTransaction
    assertEquals(db.inTransaction(), false, 'Should not be in transaction initially');
    
    db.exec('BEGIN');
    assertEquals(db.inTransaction(), true, 'Should be in transaction after BEGIN');
    
    db.exec('INSERT INTO test (value) VALUES (1)');
    db.exec('COMMIT');
    assertEquals(db.inTransaction(), false, 'Should not be in transaction after COMMIT');
    
    db.close();
});

// ========== Statement Finalize ==========
await test('sqlite3.Statement.finalize - cleanup', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY)');
    
    const stmt = db.prepare('INSERT INTO test (id) VALUES (?)');
    stmt.run([1]);
    stmt.finalize();
    
    // Should be able to create new statement after finalizing
    const stmt2 = db.prepare('SELECT * FROM test');
    const rows = stmt2.all();
    assertEquals(rows.length, 1, 'Should have 1 row');
    stmt2.finalize();
    
    db.close();
});

// ========== Error Handling ==========
await test('sqlite3 - error on invalid SQL', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    
    try {
        db.exec('INVALID SQL SYNTAX');
        assert(false, 'Should throw for invalid SQL');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
    
    db.close();
});

await test('sqlite3 - error on constraint violation', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY)');
    db.exec('INSERT INTO test (id) VALUES (1)');
    
    try {
        db.exec('INSERT INTO test (id) VALUES (1)');
        assert(false, 'Should throw for duplicate primary key');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
    
    db.close();
});

await test('sqlite3 - error on missing table', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    
    try {
        db.exec('SELECT * FROM nonexistent_table');
        assert(false, 'Should throw for missing table');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
    
    db.close();
});

// ========== Statement.expand ==========
await test('sqlite3.Statement.expand - get expanded SQL', () => {
    const db = sqlite3.open(':memory:', sqlite3.O_CREATE | sqlite3.O_READWRITE);
    db.exec('CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)');
    
    const stmt = db.prepare('INSERT INTO test (id, name) VALUES (?, ?)');
    stmt.run([1, 'test']);
    
    const expanded = stmt.expand();
    assertEquals(typeof expanded, 'string', 'Should return string');
    
    stmt.finalize();
    db.close();
});
