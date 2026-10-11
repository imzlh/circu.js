import { spawnSync } from 'node:child_process';
import {
    appendFileSync, chmodSync, copyFileSync, cpSync, existsSync, mkdirSync,
    readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { endianness } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// This script belongs to the standalone circu.js repository. It needs neither
// the parent cno-cli checkout nor its Node dependencies or bundled CLI.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const platform = process.env.CJS_PLATFORM ?? ({ win32: 'windows', darwin: 'macos' }[process.platform] ?? process.platform);
const arch = process.env.CJS_ARCH ?? ({ x64: 'x86_64', ia32: 'x86' }[process.arch] ?? process.arch);
const asan = process.env.CJS_ASAN === '1';
const windows = platform === 'windows';
const macos = platform === 'macos';
const expectedHost = { windows: 'win32', macos: 'darwin', linux: 'linux' }[platform];
if (expectedHost !== process.platform) throw new Error(`Cannot build ${platform} on ${process.platform}`);
if (!['x86_64', 'x86', 'arm64'].includes(arch)) throw new Error(`Unsupported native architecture: ${arch}`);
if (asan && (platform !== 'linux' || arch !== 'x86_64')) throw new Error('ASan is supported by the Linux x86_64 CI job');

const target = `${platform}-${arch}${asan ? '-asan' : ''}`;
const buildDir = join(root, `build-native-${target}`);
const stage = join(buildDir, 'stage');
const extension = windows ? '.exe' : '';
const tripletArch = { x86_64: 'x64', x86: 'x86', arm64: 'arm64' }[arch];
const triplet = `${tripletArch}-windows`;
const installed = join(buildDir, 'vcpkg_installed');
const fixture = join(root, 'scripts/ci/fixtures/smoke.mjs');

function run(command, args, options = {}) {
    const { capture = false, quiet = false, timeout = 60 * 60 * 1000, ...spawnOptions } = options;
    if (!quiet) console.log(command, ...args);
    const result = spawnSync(command, args, {
        cwd: root, stdio: capture ? 'pipe' : 'inherit', encoding: 'utf8',
        windowsHide: true, timeout, ...spawnOptions,
    });
    if (capture && (!quiet || result.error || result.signal || result.status !== 0)) {
        if (result.stdout) process.stdout.write(result.stdout);
        if (result.stderr) process.stderr.write(result.stderr);
    }
    if (result.error) throw result.error;
    if (result.signal || result.status !== 0) {
        throw new Error(`${command} failed (${result.signal ?? result.status})`);
    }
    return result.stdout ?? '';
}

function requiredFile(path) {
    if (!existsSync(path) || !statSync(path).isFile() || statSync(path).size === 0) {
        throw new Error(`Missing or empty file: ${path}`);
    }
    return path;
}

function resetDirectory(path) {
    const inside = relative(buildDir, resolve(path));
    if (!inside || inside.startsWith(`..${sep}`) || inside === '..' || isAbsolute(inside)) {
        throw new Error(`Refusing to clear a directory outside ${buildDir}: ${path}`);
    }
    rmSync(path, { recursive: true, force: true });
    mkdirSync(path, { recursive: true });
}

function configure(blob = '') {
    const args = [
        '-S', root, '-B', buildDir, '-G', 'Ninja',
        `-DCMAKE_BUILD_TYPE=${asan ? 'Debug' : 'Release'}`,
        `-DENABLE_ASAN=${asan ? 'ON' : 'OFF'}`,
        '-DBUILD_WITH_WASM=ON', '-DBUILD_WITH_MIMALLOC=OFF', '-DCJS_USE_SYMBOL_INTERNAL=OFF',
        `-DWAMR_BUILD_TARGET=${{ x86_64: 'X86_64', x86: 'X86_32', arm64: 'AARCH64' }[arch]}`,
        `-DCJS_BLOB_C=${blob}`,
    ];
    if (windows) {
        const vcpkgRoot = process.env.VCPKG_ROOT;
        if (!vcpkgRoot) throw new Error('VCPKG_ROOT is required; initialize vcpkg first');
        args.push('-DCMAKE_C_COMPILER=cl', '-DCMAKE_CXX_COMPILER=cl',
            `-DCMAKE_TOOLCHAIN_FILE=${requiredFile(join(vcpkgRoot, 'scripts/buildsystems/vcpkg.cmake'))}`,
            `-DVCPKG_TARGET_TRIPLET=${triplet}`,
            `-DVCPKG_HOST_TRIPLET=${process.arch === 'arm64' ? 'arm64' : 'x64'}-windows`,
            `-DVCPKG_INSTALLED_DIR=${installed}`);
    }
    if (macos) {
        if (!process.env.CJS_CMAKE_PREFIX_PATH) throw new Error('CJS_CMAKE_PREFIX_PATH must include the Homebrew dependency prefixes');
        args.push(`-DCMAKE_OSX_ARCHITECTURES=${arch}`,
            `-DCMAKE_PREFIX_PATH=${process.env.CJS_CMAKE_PREFIX_PATH}`,
            '-DCMAKE_EXE_LINKER_FLAGS=-Wl,-headerpad_max_install_names');
    }
    run('cmake', args);
}

function copyDlls(directory) {
    if (!existsSync(directory)) throw new Error(`Missing DLL directory: ${directory}`);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const source = join(directory, entry.name);
        if (entry.isDirectory()) {
            copyDlls(source);
        } else if (/\.dll$/i.test(entry.name)) {
            const destination = join(stage, entry.name);
            if (existsSync(destination) && !readFileSync(destination).equals(readFileSync(source))) {
                throw new Error(`Different DLLs share the name ${entry.name}: ${source}`);
            }
            copyFileSync(source, destination);
        }
    }
}

function stageWindowsDependencies() {
    // qjs is a shared target on Windows; every vcpkg runtime dependency,
    // including libiconv and libcharset, must accompany both executables.
    copyFileSync(requiredFile(join(buildDir, 'qjs.dll')), join(stage, 'qjs.dll'));
    copyDlls(join(installed, triplet, 'bin'));
    const redistRoot = process.env.VCToolsRedistDir;
    if (!redistRoot) throw new Error('VCToolsRedistDir is required to package the MSVC runtime');
    const archRedist = join(redistRoot, tripletArch);
    const crtDirectories = readdirSync(archRedist, { withFileTypes: true })
        .filter(entry => entry.isDirectory() && /^Microsoft\.VC\d+\.CRT$/i.test(entry.name));
    if (crtDirectories.length === 0) throw new Error(`Cannot find the ${arch} MSVC CRT in ${archRedist}`);
    for (const entry of crtDirectories) copyDlls(join(archRedist, entry.name));

    const share = join(installed, triplet, 'share');
    for (const port of readdirSync(share, { withFileTypes: true })) {
        const copyright = join(share, port.name, 'copyright');
        if (!port.isDirectory() || !existsSync(copyright)) continue;
        const destination = join(stage, 'licenses', port.name);
        mkdirSync(destination, { recursive: true });
        copyFileSync(copyright, join(destination, 'copyright'));
    }
}

function bundleMacDependencies(executables, destinationRoot) {
    const libraries = new Map();
    const pending = executables.map(path => ({ source: path, destination: path, library: false }));
    const systemLibrary = path => path.startsWith('/usr/lib/') || path.startsWith('/System/Library/');
    const expand = (path, loader) => path
        .replace(/^@loader_path(?=\/|$)/, dirname(loader))
        .replace(/^@executable_path(?=\/|$)/, dirname(executables[0]));
    const rpaths = path => [...run('otool', ['-l', path], { capture: true, quiet: true })
        .matchAll(/cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset \d+\)/g)]
        .map(match => expand(match[1], path));
    const executableRpaths = rpaths(executables[0]);

    for (let index = 0; index < pending.length; index++) {
        const item = pending[index];
        const dependencies = run('otool', ['-L', item.source], { capture: true, quiet: true })
            .split('\n').slice(1).map(line => line.trim().replace(/ \(compatibility version .*$/, '')).filter(Boolean);
        const installId = item.library
            ? run('otool', ['-D', item.source], { capture: true, quiet: true }).split('\n')[1]?.trim()
            : undefined;
        const searchPaths = [...rpaths(item.source), ...executableRpaths];
        for (const dependency of dependencies) {
            if (dependency === installId || systemLibrary(dependency)) continue;
            const candidates = dependency.startsWith('@rpath/')
                ? searchPaths.map(path => join(path, dependency.slice('@rpath/'.length)))
                : [expand(dependency, item.source)];
            const resolved = candidates.find(path => isAbsolute(path) && existsSync(path));
            if (!resolved) throw new Error(`Cannot resolve ${dependency} required by ${item.source}`);
            const source = realpathSync(resolved);
            if (systemLibrary(source) || source === realpathSync(item.source)) continue;
            const name = basename(source);
            const existing = libraries.get(name);
            if (existing && existing !== source) throw new Error(`Conflicting macOS libraries: ${existing} and ${source}`);
            if (!existing) {
                libraries.set(name, source);
                const destination = join(destinationRoot, 'lib', name);
                mkdirSync(dirname(destination), { recursive: true });
                copyFileSync(source, destination);
                chmodSync(destination, 0o755);
                pending.push({ source, destination, library: true });
            }
            const replacement = `@loader_path/${item.library ? '' : 'lib/'}${name}`;
            run('install_name_tool', ['-change', dependency, replacement, item.destination]);
        }
        if (item.library) run('install_name_tool', ['-id', `@rpath/${basename(item.destination)}`, item.destination]);
    }
    // Re-sign only after every load command has been updated.
    for (const item of pending.reverse()) run('codesign', ['--force', '--sign', '-', item.destination]);
}

function build() {
    configure();
    // cjsc is EXCLUDE_FROM_ALL, so a plain `cmake --build` would omit it.
    run('cmake', ['--build', buildDir, '--target', 'cjs-cli', 'cjsc']);
    resetDirectory(stage);
    for (const name of ['cjs', 'cjsc']) {
        const destination = join(stage, name + extension);
        copyFileSync(requiredFile(join(buildDir, name + extension)), destination);
        if (!windows) chmodSync(destination, 0o755);
    }
    cpSync(join(root, 'types'), join(stage, 'types'), { recursive: true });
    copyFileSync(join(root, 'LICENSE'), join(stage, 'LICENSE'));
    if (windows) stageWindowsDependencies();
    if (macos) bundleMacDependencies(['cjs', 'cjsc'].map(name => join(stage, name)), stage);
    writeFileSync(join(stage, 'RUNTIME.txt'), [
        'cjs is the native circu.js runtime template; cjsc compiles JavaScript modules.',
        'The runtime executes embedded bytecode, and has no standalone --version or script-file CLI.',
        'Linux/Windows: copy cjs, then use cjsc -m -o <copied-runtime> script.mjs.',
        'Use a bare output filename without dots on Unix, and an .exe filename on Windows.',
        macos
            ? 'macOS: compiled bytecode must be embedded through CMake CJS_BLOB_C before code signing. Runtime dylibs are bundled in lib/.'
            : windows
                ? 'Keep all bundled DLLs beside both executables.'
                : 'Linux binaries use the Ubuntu 24.04 system libraries (curl, OpenSSL, SQLite, ffi, zlib, expat and brotli).',
        asan ? 'This Debug build also requires the AddressSanitizer runtime.' : '',
        '',
    ].filter((line, index, lines) => line || index === lines.length - 1).join('\n'));
}

function smoke() {
    const scratch = join(buildDir, 'smoke');
    resetDirectory(scratch);
    cpSync(stage, scratch, { recursive: true });
    const compiler = requiredFile(join(scratch, 'cjsc' + extension));
    const bytecodeFile = join(scratch, 'smoke.jsc');
    const options = { cwd: scratch, capture: true, timeout: 60_000 };
    // No cjs --version/script.jsc CLI exists: vm.c loads only embedded bytecode.
    run(compiler, ['-m', '-o', 'smoke.jsc', fixture], options);
    const bytecode = readFileSync(requiredFile(bytecodeFile));

    const assertOutput = executable => {
        const output = run(executable, [], options);
        if (!/^CJS_SMOKE_OK \S+ QuickJS \S+/m.test(output)) throw new Error('Native smoke did not report success');
    };
    if (macos) {
        // Appending to a signed Mach-O invalidates its signature; signing again
        // would replace the trailer that binary.c reads. Embed the actual cjsc
        // output before linking the smoke executable, as CJS_BLOB_C supports.
        // The original runtime template was already copied to stage above.
        const blob = join(buildDir, 'smoke-blob.c');
        writeFileSync(blob, `#include <stdint.h>\nconst uint32_t cjs_blob_size = ${bytecode.length};\nconst uint8_t cjs_blob[] = {${[...bytecode].join(',')}};\n`);
        configure(blob);
        run('cmake', ['--build', buildDir, '--target', 'cjs-cli']);
        const executable = join(scratch, 'cjs-smoke');
        copyFileSync(requiredFile(join(buildDir, 'cjs')), executable);
        chmodSync(executable, 0o755);
        bundleMacDependencies([executable], scratch);
        assertOutput(executable);
    } else {
        const attachedName = `cjs-smoke${extension}`;
        const attached = join(scratch, attachedName);
        copyFileSync(join(stage, 'cjs' + extension), attached);
        if (!windows) chmodSync(attached, 0o755);
        // A basename is significant: cjsc chooses Unix attach mode only when
        // the complete output argument contains no dot (circu.js has one).
        run(compiler, ['-m', '-o', attachedName, fixture], options);
        assertOutput(attached);

        const raw = join(scratch, `cjs-raw${extension}`);
        copyFileSync(join(stage, 'cjs' + extension), raw);
        const length = Buffer.alloc(4);
        if (endianness() === 'LE') length.writeUInt32LE(bytecode.length);
        else length.writeUInt32BE(bytecode.length);
        appendFileSync(raw, Buffer.concat([bytecode, length]));
        if (!windows) chmodSync(raw, 0o755);
        assertOutput(raw);
    }
}

function packageArtifacts() {
    for (const name of ['cjs', 'cjsc']) requiredFile(join(stage, name + extension));
    requiredFile(join(stage, 'types/index.d.ts'));
    const artifacts = join(root, 'artifacts');
    mkdirSync(artifacts, { recursive: true });
    const archive = join(artifacts, `cjs-${target}${windows ? '.zip' : '.tar.gz'}`);
    if (windows) run('cmake', ['-E', 'tar', 'cf', archive, '--format=zip', '.'], { cwd: stage });
    else run('tar', ['-czf', archive, '-C', stage, '.']);
    requiredFile(archive);
    console.log(`Packaged ${archive}`);
}

const command = process.argv[2] ?? 'all';
if (!['all', 'build', 'smoke', 'package'].includes(command)) throw new Error('Usage: node scripts/ci/native.mjs [build|smoke|package|all]');
if (command === 'all' || command === 'build') build();
if (command === 'all' || command === 'smoke') smoke();
if (command === 'all' || command === 'package') packageArtifacts();
