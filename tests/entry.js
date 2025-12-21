/**
 * circu.js test suite entry point.
 */

const { use } = import.meta;
const console = use('console');
const { onEvent, onModule } = use('engine');
const { args, version, platform, exePath, loadModule } = use('sys');
const { exit } = use('os');
const { realpath } = use('fs');
globalThis.console = console;
/**
 * @type {ImportMeta['use']}
 */
globalThis.use = (name) => use(name);

// override promise reject event handler
const currentExceptions = [];
onEvent((name, data) => {
    if (name == 'unhandledrejection') {
        if (currentExceptions.some(e => e[0] === data[0])) {
            return true;    // prevent duplicate error messages
        }

        if (in_test) return;    // no log
        const [promise, error] = data;
        if (error instanceof Error && promise.stack?.trim()) {
            error.stack += `\n    ---- eventloop ---- \n    ${promise.stack}`;
        }
        console.error('Uncaught Error(in promise):', error);
        currentExceptions.push(data[0]);
        new Promise(() => void 0).then(() => currentExceptions.length = 0);
    }
});

onModule({
    init(name, meta) {
        Object.assign(meta, import.meta);
    }
})

if (args.length < 2) {
    console.log(`Usage: ${exePath} <script.js>
Run a circu.js test suite script.`);
    exit(1);
}

// simple polyfill
let in_test = false;
globalThis.assert = (value, message) => {
    if (!value) {
        throw new Error(message ?? "Assertion failed");
    }
};
globalThis.test = async (name, fn) => {
    if (typeof name == 'function') fn = name, name = fn.name;
    if(name) console.log(`Running test: ${name}`);
    in_test = true;
    try {
        await fn();
        console.log(`✓ Test ${name} passed`);
    } catch (error) {
        console.error(`❌ Test ${name} failed:`, error);
        exit(1);
    } finally {
        in_test = false;
    }
};
globalThis.panic = (message) => {
    console.error('Panic:', message);
    exit(1);
};
globalThis.assertEquals = (actual, expected, message) => {
    if (actual !== expected) {
        console.error('assertEquals failed:', expected, actual);
        throw new Error(message ?? `Expected ${expected}, got ${actual}`);
    }
};

const [, script] = args;
if (!script || !script.endsWith(".js")) {
    throw new Error("Script must be a .js file");
}

console.log("Test suite, tjs", version, "on", platform);
console.log("Loading script:", realpath(script));
await loadModule(script);
console.log("🎉 " + script.split('/').at(-1).split('.').at(0) + ": All tests passed!")