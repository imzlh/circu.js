/**
 * txiki.js test suite entry point.
 */

const { use } = import.meta;
globalThis.use = use;

const self = use("sys");
const os = use("os");
if(self.args.length < 2){
    print(`Usage: tjs <script.js>
Run a txiki.js test suite script.`);
    os.exit(1);
}

const [, script] = self.args
if(!script || !script.endsWith(".js")){
    throw new Error("Script must be a .js file");
}

print("Test suite, tjs", self.version, "on", self.platform);
await self.evalFile(script);