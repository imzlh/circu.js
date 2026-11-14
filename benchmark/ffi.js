// FFI call-path microbenchmarks for the high-level open()/bind() API.
//
// The benchmark intentionally binds each symbol once, before timing. This keeps
// symbol lookup and ffi_cif preparation out of the hot-path measurement.

const ffi = import.meta.use('ffi');
const console = import.meta.use('console');
const engine = import.meta.use('engine');
const os = import.meta.use('os');

const DEFAULT_ITERATIONS = 1_000_000;
const DEFAULT_WARMUP = 100_000;
const DEFAULT_SAMPLES = 7;

function usage() {
    console.log(`Usage: ${os.exePath} [options]

Options:
  --iterations=N  Calls per measured sample (default: ${DEFAULT_ITERATIONS})
  --warmup=N      Calls per warmup (default: ${DEFAULT_WARMUP})
  --samples=N     Number of measured samples (default: ${DEFAULT_SAMPLES})
  --json          Print only the machine-readable JSON result
  --help          Show this help`);
}

function parseIntegerOption(name, value, allowZero) {
    if (!/^\d+$/.test(value)) {
        throw new TypeError(`--${name} must be an integer`);
    }

    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < (allowZero ? 0 : 1)) {
        throw new RangeError(`--${name} must be ${allowZero ? 'non-negative' : 'positive'}`);
    }
    return number;
}

function parseOptions(argv) {
    const options = {
        iterations: DEFAULT_ITERATIONS,
        warmup: DEFAULT_WARMUP,
        samples: DEFAULT_SAMPLES,
        json: false,
        help: false,
    };

    for (const argument of argv) {
        if (argument === '--json') {
            options.json = true;
        } else if (argument === '--help') {
            options.help = true;
        } else {
            const match = /^--(iterations|warmup|samples)=(.*)$/.exec(argument);
            if (!match) throw new TypeError(`unknown option: ${argument}`);
            options[match[1]] = parseIntegerOption(match[1], match[2], match[1] === 'warmup');
        }
    }
    return options;
}

function fixturePath() {
    const slash = Math.max(os.exePath.lastIndexOf('/'), os.exePath.lastIndexOf('\\'));
    const directory = slash < 0 ? '.' : os.exePath.slice(0, slash);
    const filename = os.platform === 'windows'
        ? 'ffi_fixture.dll'
        : os.platform === 'darwin'
            ? 'libffi_fixture.dylib'
            : 'libffi_fixture.so';
    return directory + (os.platform === 'windows' ? '\\' : '/') + filename;
}

function median(sortedValues) {
    const middle = Math.floor(sortedValues.length / 2);
    return sortedValues.length % 2 === 0
        ? (sortedValues[middle - 1] + sortedValues[middle]) / 2
        : sortedValues[middle];
}

// Store the last result outside each loop so the calls remain observable while
// adding only one JavaScript assignment per native invocation.
let blackhole;

function measure(name, signature, loop, options) {
    if (options.warmup !== 0) blackhole = loop(options.warmup);

    const samplesNsPerOp = [];
    const elapsedMs = [];
    for (let sample = 0; sample < options.samples; sample++) {
        const start = performance.now();
        blackhole = loop(options.iterations);
        const elapsed = performance.now() - start;
        elapsedMs.push(elapsed);
        samplesNsPerOp.push(elapsed * 1_000_000 / options.iterations);
    }

    const sorted = [...samplesNsPerOp].sort((left, right) => left - right);
    const medianNsPerOp = median(sorted);
    const meanNsPerOp = samplesNsPerOp.reduce((sum, value) => sum + value, 0)
        / samplesNsPerOp.length;

    return {
        name,
        signature,
        iterationsPerSample: options.iterations,
        samples: options.samples,
        medianNsPerOp,
        meanNsPerOp,
        minNsPerOp: sorted[0],
        maxNsPerOp: sorted[sorted.length - 1],
        opsPerSecond: 1_000_000_000 / medianNsPerOp,
        sampleElapsedMs: elapsedMs,
        sampleNsPerOp: samplesNsPerOp,
    };
}

function checksum(value) {
    return typeof value === 'bigint' ? `${value}n` : String(value);
}

function printHuman(report) {
    console.log('circu.js FFI benchmark (bind once, synchronous calls)');
    console.log(`runtime=${report.runtime} platform=${report.platform} arch=${report.arch}`);
    console.log(`iterations=${report.config.iterations} warmup=${report.config.warmup} samples=${report.config.samples}`);
    for (const result of report.results) {
        console.log(
            `${result.name.padEnd(25)} ${result.medianNsPerOp.toFixed(2).padStart(12)} ns/op  `
            + `${Math.round(result.opsPerSecond).toString().padStart(12)} ops/s`,
        );
    }
    console.log(`checksum=${report.checksum}`);
    console.log(`FFI_BENCHMARK_JSON ${JSON.stringify(report)}`);
}

function main() {
    const options = parseOptions(os.args.slice(1));
    if (options.help) {
        usage();
        return;
    }

    const types = ffi.types;
    const libc = ffi.open(ffi.libraries.c);
    let fixture;
    try {
        fixture = ffi.open(fixturePath());
        const abs = libc.bind([types.int, 'abs', types.int]);
        const strlen = libc.bind([types.usize, 'strlen', types.buffer]);
        const weightedSum = fixture.bind([
            types.f64,
            'ffi_fixture_weighted_sum',
            types.f64,
            types.f64,
            types.i32,
        ]);
        const string = new Uint8Array([
            99, 105, 114, 99, 117, 46, 106, 115, 32, 102, 102, 105, 0,
        ]);

        // Fail before measuring if a symbol, signature, or conversion is wrong.
        if (abs(-123) !== 123) throw new Error('abs preflight failed');
        if (strlen(string) !== 12n) throw new Error('strlen preflight failed');
        if (weightedSum(1.25, 2.25, 4) !== 14) throw new Error('weighted sum preflight failed');

        const results = [
            measure('ffi.abs', 'int(int)', iterations => {
                let result = 0;
                for (let index = 0; index < iterations; index++) result = abs(-123);
                return result;
            }, options),
            measure('ffi.strlen', 'usize(buffer)', iterations => {
                let result = 0n;
                for (let index = 0; index < iterations; index++) result = strlen(string);
                return result;
            }, options),
            measure('ffi.weighted_sum', 'f64(f64,f64,i32)', iterations => {
                let result = 0;
                for (let index = 0; index < iterations; index++) {
                    result = weightedSum(1.25, 2.25, 4);
                }
                return result;
            }, options),
        ];

        const uname = os.uname();
        const report = {
            schema: 'circu.ffi-benchmark.v1',
            api: 'open/bind',
            runtime: engine.versions.core,
            platform: os.platform,
            arch: uname.machine,
            config: {
                iterations: options.iterations,
                warmup: options.warmup,
                samples: options.samples,
            },
            results,
            checksum: checksum(blackhole),
        };

        if (options.json) {
            console.log(JSON.stringify(report));
        } else {
            printHuman(report);
        }
    } finally {
        fixture?.close();
        libc.close();
    }
}

main();
