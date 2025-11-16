/**
 * circu.js test suite entry point.
 */

const { use } = import.meta;
globalThis.use = use;
const console = use('console');

// override promise reject event handler
const currentExceptions = [];
use('engine').onEvent((name, data) => {
    if (name == 'unhandledrejection') {
        if (currentExceptions.some(e => e[0] === data[0])) {
            return true;    // prevent duplicate error messages
        }

        const [promise, error] = data;
        if (error instanceof Error && promise.stack?.trim()) {
            error.stack += `\n    ---- eventloop ---- \n    ${promise.stack}`;
        }
        console.error('Uncaught Error(in promise):', error);
        currentExceptions.push(data);
        new Promise(() => void 0).then(() => currentExceptions.length = 0);
    }
})
use('engine').onModule({
    init(name, meta){
        meta.use = use;
    }
})
const self = use("sys");
const os = use("os");
if (self.args.length < 2) {
    console.log(`Usage: ${self.exePath} <script.js>
Run a circu.js test suite script.`);
    os.exit(1);
}

const [, script] = self.args
if (!script || !script.endsWith(".js")) {
    throw new Error("Script must be a .js file");
}

console.log("Test suite, tjs", self.version, "on", self.platform);
console.log("Loading script:", await use('fs').realPath(script));
await self.evalFile(script);