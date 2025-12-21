const console = import.meta.use('console');
const { setTimeout, setInterval, clearTimeout, clearInterval } = import.meta.use('timers');
Reflect.set(globalThis, 'console', console);
Reflect.set(globalThis, 'setTimeout', setTimeout);
Reflect.set(globalThis, 'clearTimeout', clearTimeout);
Reflect.set(globalThis, 'clearInterval', clearInterval);
Reflect.set(globalThis, 'setInterval', setInterval);

test("console.log 基础类型", () => {
    console.log("=== 基础类型测试 ===");
    console.log("字符串:", "hello world");
    console.log("数字:", 42, 3.14, -100, 0, Infinity, -Infinity, NaN);
    console.log("布尔:", true, false);
    console.log("null:", null);
    console.log("undefined:", undefined);
    console.log("symbol:", Symbol("test"), Symbol.for("global"));
    console.log("bigint:", 123n);
});

test("console.log 复杂类型", () => {
    console.log("=== 复杂类型测试 ===");
    console.log("数组:", [1, 2, 3, 4, 5]);
    console.log("嵌套数组:", [[1, 2], [3, 4], [5, 6]]);
    console.log("稀疏数组:", [1, , , 4]);
    console.log("对象:", { name: "test", value: 123 });
    console.log("嵌套对象:", { user: { name: "alice", age: 25 }, active: true });
    console.log("日期:", new Date("2024-01-01"));
    console.log("正则:", /test[0-9]+/gi);
});

test("console.log 特殊对象", () => {
    console.log("=== 特殊对象测试 ===");
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

test("console.log 函数和类", () => {
    console.log("=== 函数和类测试 ===");
    function testFunc() { return "hello"; }
    console.log("普通函数:", testFunc);

    class TestClass {
        constructor() { this.value = 42; }
        method() { return "method"; }
    }
    console.log("类构造函数:", TestClass);
    console.log("类实例:", new TestClass());

    const arrow = () => "arrow";
    console.log("箭头函数:", arrow);

    const objWithMethods = {
        method1() { return 1; },
        method2: function () { return 2; },
        arrow: () => 3
    };
    console.log("带方法的对象:", objWithMethods);
});

test("console.log 错误和Promise", () => {
    console.log("=== 错误和Promise测试 ===");
    console.log("Error:", new Error("test error"));
    console.log("TypeError:", new TypeError("type error"));
    console.log("自定义错误:", (() => {
        const err = new Error("custom");
        err.code = "CUSTOM_ERROR";
        err.details = { foo: "bar" };
        return err;
    })());

    console.log("Pending Promise:", new Promise(() => { }));
    console.log("Resolved Promise:", Promise.resolve("resolved"));
    console.log("Rejected Promise:", Promise.reject("rejected"));
});

test("console.log 循环引用", () => {
    console.log("=== 循环引用测试 ===");
    const obj1 = { name: "obj1" };
    const obj2 = { name: "obj2" };
    obj1.ref = obj2;
    obj2.ref = obj1;
    console.log("循环引用对象:", obj1);

    const arr = [1, 2, 3];
    arr.push(arr);
    console.log("循环引用数组:", arr);

    const complex = { a: { b: { c: {} } } };
    complex.a.b.c.ref = complex;
    console.log("深层循环引用:", complex);
});

test("console.log 大对象/数组", () => {
    console.log("=== 大对象/数组测试 ===");
    const bigArray = Array.from({ length: 150 }, (_, i) => i);
    console.log("大数组(150项):", bigArray);

    const bigObject = {};
    for (let i = 0; i < 50; i++) {
        bigObject[`prop${i}`] = `value${i}`;
    }
    console.log("大对象(50属性):", bigObject);

    const deepNested = {};
    let current = deepNested;
    for (let i = 0; i < 20; i++) {
        current.level = { index: i };
        current = current.level;
    }
    console.log("深层嵌套:", deepNested);
});

test("console.error", () => {
    console.log("=== console.error 测试 ===");
    console.error("错误信息");
    console.error("错误对象:", { error: "something went wrong" });
    console.error("多个参数:", "Error:", 500, "Internal Server Error");
});

test("console.warn", () => {
    console.log("=== console.warn 测试 ===");
    console.warn("警告信息");
    console.warn("警告对象:", { warning: "deprecated API" });
    console.warn("多个参数:", "Warning:", "low memory");
});

test("console.info", () => {
    console.log("=== console.info 测试 ===");
    console.info("信息消息");
    console.info("信息对象:", { info: "system ready" });
});

test("console.debug", () => {
    console.log("=== console.debug 测试 (DEBUG环境变量) ===");
    console.debug("调试消息(不显示)");
    console.debug("调试对象:", { debug: "verbose info" });
});

test("console.assert", () => {
    console.log("=== console.assert 测试 ===");
    console.assert(true, "这个不会显示");
    console.assert(false, "断言失败: 这应该显示为错误");
    console.assert(1 === 2, "数学错误", { expected: 1, actual: 2 });
});

test("console.dir", () => {
    console.log("=== console.dir 测试 ===");
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
    console.log("=== console.table 测试 ===");

    console.log("数组对象:");
    const users = [
        { name: "Alice", age: 25, city: "New York" },
        { name: "Bob", age: 30, city: "San Francisco" },
        { name: "Charlie", age: 35, city: "London" }
    ];
    console.table(users);

    console.log("简单对象:");
    const stats = {
        cpu: 45,
        memory: 78,
        disk: 23,
        network: 56
    };
    console.table(stats);

    console.log("大表格:");
    const bigTable = Array.from({ length: 20 }, (_, i) => ({
        id: i,
        value: Math.random(),
        status: i % 2 === 0 ? "活动" : "休眠",
        timestamp: new Date().toISOString()
    }));
    console.table(bigTable);
});

test("console.trace", () => {
    console.log("=== console.trace 测试 ===");
    function deep1() { deep2(); }
    function deep2() { deep3(); }
    function deep3() { console.trace("跟踪到这里"); }
    deep1();
});

test("console.count", () => {
    console.log("=== console.count 测试 ===");
    console.count("default");
    console.count("default");
    console.count("default");

    console.count("custom");
    console.count("custom");

    console.count("default"); // 应该显示4
    console.count("custom");  // 应该显示3
});

test("console.countReset", () => {
    console.log("=== console.countReset 测试 ===");
    console.count("reset_test");
    console.count("reset_test");
    console.count("reset_test");
    console.countReset("reset_test");
    console.count("reset_test"); // 应该重置为1
});

test("console.time/timeEnd/timeLog", () => {
    console.log("=== console.time 测试 ===");

    console.time("timer1");
    // 模拟一些工作
    for (let i = 0; i < 1000000; i++) { Math.random(); }
    console.timeEnd("timer1");

    console.time("timer2");
    setTimeout(() => {
        console.timeLog("timer2", "中间检查点");
        setTimeout(() => {
            console.timeEnd("timer2");
        }, 100);
    }, 100);
});

test("console.timeStamp", () => {
    console.log("=== console.timeStamp 测试 ===");
    console.timeStamp("start");
    console.timeStamp("middle");
    console.timeStamp("end");
});

test("console.clear", () => {
    console.log("=== console.clear 测试 ===");
    console.log("清除前");
    // console.clear(); // 实际测试时取消注释
    console.log("清除后");
});

test("console.inspect (非标准)", () => {
    console.log("=== console.inspect 测试 ===");
    const result = console.inspect({ test: "value", nested: { data: 123 } });
    console.log("inspect结果:", result);
});

test("混合输出测试", () => {
    console.log("=== 混合输出测试 ===");
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
    console.log("混合对象:", mixed);
});

// 运行所有测试
console.log("\n🧪 开始console全功能测试...\n");