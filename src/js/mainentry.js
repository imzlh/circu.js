/**
 * txiki.js test suite entry point.
 */

const { use } = import.meta;
globalThis.use = use;

// override promise reject event handler
const currentExceptions = [];
use('sys').setOptions({
    eventReceiver(name, data){
        if(name == 'unhandledrejection'){
            if(currentExceptions.some(e => e[0] === data[0])){
                return true;    // prevent duplicate error messages
            }

            const [ promise, error, tickID ] = data;
            if (tickID != promise.index && error instanceof Error){
                error.stack += `\n    ---- eventloop ---- \n    ${promise.stack}`;
            }
            print('Uncaught Error(in promise):', error);
            currentExceptions.push(data);
            new Promise(() => void 0).then(() => currentExceptions.length = 0);
        }
    }
})

const self = use("sys");
const os = use("os");
if(self.args.length < 2){
    print(`Usage: ${self.exepath()} <script.js>
Run a txiki.js test suite script.`);
    os.exit(1);
}

const [, script] = self.args
if(!script || !script.endsWith(".js")){
    throw new Error("Script must be a .js file");
}

print("Test suite, tjs", self.version, "on", self.platform);
await self.evalFile(script);