const console = import.meta.use('console');
const { setTimeout, setInterval, clearTimeout, clearInterval } = import.meta.use('timers');
Reflect.set(globalThis, 'console', console);
Reflect.set(globalThis, 'setTimeout', setTimeout);
Reflect.set(globalThis, 'clearTimeout', clearTimeout);
Reflect.set(globalThis, 'clearInterval', clearInterval);
Reflect.set(globalThis, 'setInterval', setInterval);
test("console.log basic types", () => {
    console.log("=== Basic types test ===");
    console.log("String:", "hello world");
    console.log("Number:", 42, 3.14, -100, 0, Infinity, -Infinity, NaN);
    console.log("Boolean:", true, false);
    console.log("null:", null);
    console.log("undefined:", undefined);
    console.log("symbol:", Symbol("test"), Symbol.for("global"));
    console.log("bigint:", 123n);
});

test("console.log complex types", () => {
    console.log("=== Complex types test ===");
    console.log("Array:", [1, 2, 3, 4, 5]);
    console.log("Nested array:", [[1, 2], [3, 4], [5, 6]]);
    console.log("Sparse array:", [1, , , 4]);
    console.log("Object:", { name: "test", value: 123 });
    console.log("Nested object:", { user: { name: "alice", age: 25 }, active: true });
    console.log("Date:", new Date("2024-01-01"));
    console.log("RegExp:", /test[0-9]+/gi);
});

test("console.log special objects", () => {
    console.log("=== Special objects test ===");
    console.log("Map:", new Map([["key1", "value1"], ["key2", "value2"]]));
    console.log("Set:", new Set([1, 2, 3, 3, 4]));
    console.log("WeakMap:", new WeakMap());
    console.log("WeakSet:", new WeakSet());

    const ab = new ArrayBuffer(16);
    console.log("ArrayBuffer:", ab);
    console.log("Uint8Array:", new Uint8Array([1, 2, 3, 4]));
    console.log("Int32Array:", new Int32Array([100, 200, 300]));
    console.log("Float64Array:", new Float64Array([1.1, 2.2, 3.3]));
});

test("console.log functions and classes", () => {
    console.log("=== Functions and classes test ===");
    function testFunc() { return "hello"; }
    console.log("Regular function:", testFunc);

    class TestClass {
        constructor() { this.value = 42; }
        method() { return "method"; }
    }
    console.log("Class constructor:", TestClass);
    console.log("Class instance:", new TestClass());

    const arrow = () => "arrow";
    console.log("Arrow function:", arrow);

    const objWithMethods = {
        method1() { return 1; },
        method2: function () { return 2; },
        arrow: () => 3
    };
    console.log("Object with methods:", objWithMethods);
});

test("console.log errors and Promise", () => {
    console.log("=== Errors and Promise test ===");
    console.log("Error:", new Error("test error"));
    console.log("TypeError:", new TypeError("type error"));
    console.log("Custom error:", (() => {
        const err = new Error("custom");
        err.code = "CUSTOM_ERROR";
        err.details = { foo: "bar" };
        return err;
    })());

    console.log("Pending Promise:", new Promise(() => { }));
    console.log("Resolved Promise:", Promise.resolve("resolved"));
    console.log("Rejected Promise:", Promise.reject("rejected"));
});

test("console.log circular references", () => {
    console.log("=== Circular references test ===");
    const obj1 = { name: "obj1" };
    const obj2 = { name: "obj2" };
    obj1.ref = obj2;
    obj2.ref = obj1;
    console.log("Circular reference object:", obj1);

    const arr = [1, 2, 3];
    arr.push(arr);
    console.log("Circular reference array:", arr);

    const complex = { a: { b: { c: {} } } };
    complex.a.b.c.ref = complex;
    console.log("Deep circular reference:", complex);
});

test("console.log large objects/arrays", () => {
    console.log("=== Large objects/arrays test ===");
    const bigArray = Array.from({ length: 150 }, (_, i) => i);
    console.log("Large array (150 items):", bigArray);

    const bigObject = {};
    for (let i = 0; i < 50; i++) {
        bigObject[`prop${i}`] = `value${i}`;
    }
    console.log("Large object (50 props):", bigObject);

    const deepNested = {};
    let current = deepNested;
    for (let i = 0; i < 20; i++) {
        current.level = { index: i };
        current = current.level;
    }
    console.log("Deeply nested:", deepNested);
});

test("console.error", () => {
    console.log("=== console.error test ===");
    console.error("Error message");
    console.error("Error object:", { error: "something went wrong" });
    console.error("Multiple args:", "Error:", 500, "Internal Server Error");
});

test("console.warn", () => {
    console.log("=== console.warn test ===");
    console.warn("Warning message");
    console.warn("Warning object:", { warning: "deprecated API" });
    console.warn("Multiple args:", "Warning:", "low memory");
});

test("console.info", () => {
    console.log("=== console.info test ===");
    console.info("Info message");
    console.info("Info object:", { info: "system ready" });
});

test("console.debug", () => {
    console.log("=== console.debug test (DEBUG env var) ===");
    console.debug("Debug message (not shown)");
    console.debug("Debug object:", { debug: "verbose info" });
});

test("console.assert", () => {
    console.log("=== console.assert test ===");
    console.assert(true, "this will not display");
    console.assert(false, "assertion failed: this should display as error");
    console.assert(1 === 2, "math error", { expected: 1, actual: 2 });
});

test("console.dir", () => {
    console.log("=== console.dir test ===");
    const testObj = {
        string: "test",
        number: 42,
        nested: { deep: { value: "hidden" } },
        array: [1, 2, 3],
        method() { return "test"; }
    };
    console.dir(testObj);
});

test("console.table", () => {
    console.log("=== console.table test ===");

    console.log("Array of objects:");
    const users = [
        { name: "Alice", age: 25, city: "New York" },
        { name: "Bob", age: 30, city: "San Francisco" },
        { name: "Charlie", age: 35, city: "London" }
    ];
    console.table(users);

    console.log("Simple object:");
    const stats = {
        cpu: 45,
        memory: 78,
        disk: 23,
        network: 56
    };
    console.table(stats);

    console.log("Large table:");
    const bigTable = Array.from({ length: 20 }, (_, i) => ({
        id: i,
        value: Math.random(),
        status: i % 2 === 0 ? "active" : "dormant",
        timestamp: new Date().toISOString()
    }));
    console.table(bigTable);
});

test("console.trace", () => {
    console.log("=== console.trace test ===");
    function deep1() { deep2(); }
    function deep2() { deep3(); }
    function deep3() { console.trace("trace here"); }
    deep1();
});

test("console.count", () => {
    console.log("=== console.count test ===");
    console.count("default");
    console.count("default");
    console.count("default");

    console.count("custom");
    console.count("custom");

    console.count("default"); // should display 4
    console.count("custom");  // should display 3
});

test("console.countReset", () => {
    console.log("=== console.countReset test ===");
    console.count("reset_test");
    console.count("reset_test");
    console.count("reset_test");
    console.countReset("reset_test");
    console.count("reset_test"); // should reset to 1
});

test("console.time/timeEnd/timeLog", () => {
    console.log("=== console.time test ===");

    console.time("timer1");
    // simulate some work
    for (let i = 0; i < 1000000; i++) { Math.random(); }
    console.timeEnd("timer1");

    console.time("timer2");
    setTimeout(() => {
        console.timeLog("timer2", "mid check point");
        setTimeout(() => {
            console.timeEnd("timer2");
        }, 100);
    }, 100);
});

test("console.timeStamp", () => {
    console.log("=== console.timeStamp test ===");
    console.timeStamp("start");
    console.timeStamp("middle");
    console.timeStamp("end");
});

test("console.clear", () => {
    console.log("=== console.clear test ===");
    console.log("before clear");
    // console.clear(); // uncomment during actual testing
    console.log("after clear");
});

test("console.inspect (non-standard)", () => {
    console.log("=== console.inspect test ===");
    const result = console.inspect({ test: "value", nested: { data: 123 } });
    console.log("inspect result:", result);
});

test("mixed output test", () => {
    console.log("=== Mixed output test ===");
    const mixed = {
        string: "test",
        number: 42,
        bool: true,
        null: null,
        undefined: undefined,
        array: [1, 2, 3],
        object: { nested: "value" },
        date: new Date(),
        regex: /test/gi,
        func: function test() { },
        symbol: Symbol("test"),
        bigint: 123n,
        map: new Map([["key", "value"]]),
        set: new Set([1, 2, 3]),
        buffer: new ArrayBuffer(8),
        uint8: new Uint8Array([1, 2, 3]),
        error: new Error("test"),
        promise: Promise.resolve("done")
    };
    console.log("mixed object:", mixed);
});

// run all tests
console.log("\n🧪 Starting console full feature test...\n");