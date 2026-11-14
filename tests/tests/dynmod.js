// test-engine-export-global.js
/*  global test  */

/* 1. grab the engine via import.meta.use */
const engine = import.meta.use('engine');

function assertThrowsTypeError(fn, message) {
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert(error instanceof TypeError, message ?? 'expected TypeError');
}

function assertThrowsError(fn, message) {
  let error;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert(error instanceof Error, message ?? 'expected Error');
}

/* --------- test case 1 --------- */
await test('Module#create + export() should be importable immediately', async () => {
  /* create the C-module and export stuff */
  const m = engine.Module.create('mod1');
  console.log(m)
  m.export('answer', 42);
  m.export('greet',  name => `Hello, ${name}!`);

  /* module is already registered – just import it */
  const mod = await import('mod1');
  console.log(mod);

  /* assertions */
  if (mod.answer !== 42)              throw new Error('answer !== 42');
  if (mod.greet('Q') !== 'Hello, Q!') throw new Error('greet broken');
});


/* --------- test case 2 --------- */
await test('over-writing export with same name', async () => {
  const m = engine.Module.create('mod3');
  m.export('val', 1);
  m.export('val', 2);                // later call wins

  const mod = await import('mod3');
  console.log(mod);

  if (mod.val !== 2)                 throw new Error('val not overwritten');
});

await test('dynamic exports remain live and can be re-added after unref', async () => {
  const m = engine.Module.create('mod-live-export');
  const namespace = m.namespace;

  m.export('value', 1);
  assertEquals(namespace.value, 1);
  m.export('value', 2);
  assertEquals(namespace.value, 2);

  m.unref('value');
  m.export('value', 3);
  assertEquals(namespace.value, 3);
  assertEquals((await import('mod-live-export')).value, 3);
});

await test('compiled ES modules expose live runtime-defined exports', async () => {
  const providerName = 'mod-compiled-runtime-provider';
  const provider = new engine.Module('export const fixed = 1;', providerName);
  provider.export('extra', 10);

  const consumer = new engine.Module(`
    import { fixed, extra } from '${providerName}';
    export function read() { return [fixed, extra]; }
  `, 'mod-compiled-runtime-consumer');
  await consumer.eval();

  assertEquals(JSON.stringify(consumer.namespace.read()), '[1,10]');
  provider.export('extra', 20);
  assertEquals(JSON.stringify(consumer.namespace.read()), '[1,20]');
  assertEquals(provider.namespace.extra, 20);
  assertEquals(Object.keys(provider.namespace).sort().join(','), 'extra,fixed');
});

await test('compiled runtime exports support CJS binding names', async () => {
  const providerName = 'mod-compiled-cjs-bindings';
  const provider = new engine.Module('', providerName);
  const initialModule = { exports: { answer: 1 } };
  const initialRequire = specifier => `initial:${specifier}`;
  provider.export('default', initialModule.exports);
  provider.export('module.exports', initialModule.exports);
  provider.export('exports', initialModule.exports);
  provider.export('module', initialModule);
  provider.export('require', initialRequire);
  provider.export('*', initialModule.exports);

  const consumer = new engine.Module(`
    import def, {
      exports,
      module,
      require,
      "module.exports" as whole
    } from '${providerName}';
    export function read() { return [def, exports, module, require, whole]; }
  `, 'mod-compiled-cjs-consumer');
  await consumer.eval();
  let values = consumer.namespace.read();
  assert(values[0] === initialModule.exports);
  assert(values[1] === initialModule.exports);
  assert(values[2] === initialModule);
  assert(values[3] === initialRequire);
  assert(values[4] === initialModule.exports);
  assert(provider.namespace['*'] === initialModule.exports);

  const replacement = { answer: 2 };
  const replacementModule = { exports: replacement };
  const replacementRequire = specifier => `replacement:${specifier}`;
  provider.export('default', replacement);
  provider.export('module.exports', replacement);
  provider.export('exports', replacement);
  provider.export('module', replacementModule);
  provider.export('require', replacementRequire);
  provider.export('*', replacement);
  values = consumer.namespace.read();
  assert(values[0] === replacement);
  assert(values[1] === replacement);
  assert(values[2] === replacementModule);
  assert(values[3] === replacementRequire);
  assert(values[4] === replacement);
  assert(provider.namespace['*'] === replacement);
});

await test('compiled modules reject unsafe export collisions and late names', async () => {
  const m = new engine.Module('export const value = 1;', 'mod-static-export');
  assertThrowsTypeError(() => m.export('value', 2));
  m.export('early', 3);
  assertThrowsError(() => m.namespace,
    'a compiled namespace with unlinked static bindings must fail safely');
  m.export('early', 4);
  await m.eval();
  const namespace = m.namespace;
  assertEquals(namespace.value, 1);
  assertEquals(namespace.early, 4);
  m.export('early', 5);
  assertEquals(namespace.early, 5);
  assertThrowsTypeError(() => m.export('late', 6));
  assert(!Reflect.has(namespace, 'late'));
  assertThrowsTypeError(() => m.export('afterEval', 6));

  let missingError;
  const missingConsumer = new engine.Module(`
    import { late } from 'mod-static-export';
  `, 'mod-static-export-missing-consumer');
  try {
    await missingConsumer.eval();
  } catch (caught) {
    missingError = caught;
  }
  assert(missingError instanceof Error,
    'a rejected late export must not leave a resolvable half-entry');
});

await test('compiled modules reject indirect export collisions safely', async () => {
  new engine.Module(
    'export const value = 1;',
    'mod-indirect-collision-dependency',
  );
  const facade = new engine.Module(`
    export { value } from 'mod-indirect-collision-dependency';
  `, 'mod-indirect-collision-facade');
  assertThrowsTypeError(() => facade.export('value', 2));
  await facade.eval();
  assertEquals(facade.namespace.value, 1);
});

await test('export-star namespaces cannot freeze an unlinked export set', async () => {
  const providerName = 'mod-runtime-star-provider';
  const provider = new engine.Module('', providerName);
  provider.export('first', 1);
  const facade = new engine.Module(
    `export * from '${providerName}';`,
    'mod-runtime-star-facade',
  );
  assertThrowsError(() => facade.namespace);
  provider.export('second', 2);
  await facade.eval();
  assertEquals(facade.namespace.first, 1);
  assertEquals(facade.namespace.second, 2);
});

await test('compiled modules can add runtime exports after resolve but before link', async () => {
  const providerName = 'mod-runtime-after-resolve';
  const provider = new engine.Module('', providerName);
  provider.export('beforeResolve', 1);
  provider.resolve();
  provider.export('afterResolve', 2);

  const consumer = new engine.Module(`
    import { beforeResolve, afterResolve } from '${providerName}';
    export const read = () => [beforeResolve, afterResolve];
  `, 'mod-runtime-after-resolve-consumer');
  await consumer.eval();
  assertEquals(JSON.stringify(consumer.namespace.read()), '[1,2]');
});

await test('compiled runtime exports survive repeated updates and GC', async () => {
  const providerName = 'mod-runtime-export-gc-provider';
  const provider = new engine.Module('', providerName);
  provider.export('value', { iteration: -1 });
  const consumer = new engine.Module(`
    import { value } from '${providerName}';
    export const read = () => value;
  `, 'mod-runtime-export-gc-consumer');
  await consumer.eval();
  for (let iteration = 0; iteration < 128; iteration++) {
    provider.export('value', { iteration });
    engine.gc.run();
    assertEquals(consumer.namespace.read().iteration, iteration);
  }
  assertEquals(provider.namespace.value.iteration, 127);
});

await test('dump rejects compiled modules with runtime-defined exports', () => {
  const m = new engine.Module('', 'mod-runtime-export-dump');
  m.export('value', 1);
  assertThrowsTypeError(() => m.dump());
  assertThrowsTypeError(() => engine.Module.create('mod-create-dump').dump());
  assertThrowsTypeError(() => engine.Module.from('mod-from-dump', { value: 1 }).dump());
});

await test('Module.from updates existing linked exports safely', async () => {
  const m = engine.Module.from('mod-from-live-export', { value: 1 });
  const namespace = await import('mod-from-live-export');
  assertEquals(namespace.value, 1);

  m.export('value', 2);
  assertEquals(namespace.value, 2);

  let error;
  try {
    m.export('lateExport', 3);
  } catch (caught) {
    error = caught;
  }
  assert(error instanceof TypeError, 'linked C modules must reject new export names');
});

await test('free not-imported module', async () => {
  const m = engine.Module.create('mod4');
  m.export('val', 1);

  // the var_ref should be automately GCed
  engine.gc.run()
})

await test('re-evaluating both members of an ES module cycle is idempotent', async () => {
  const aName = 'dynmod-cycle-a';
  const bName = 'dynmod-cycle-b';
  const bSource = `
    import { valueA } from '${aName}';
    globalThis.__dynmodCycleB = (globalThis.__dynmodCycleB || 0) + 1;
    export function valueB() { return valueA() + 1; }
  `;
  let b;

  engine.onModule({
    load(name) {
      if (name !== bName) throw new Error(`unexpected module: ${name}`);
      b = new engine.Module(bSource, bName);
      return b;
    },
  });

  globalThis.__dynmodCycleA = 0;
  globalThis.__dynmodCycleB = 0;
  const a = new engine.Module(`
    import { valueB } from '${bName}';
    globalThis.__dynmodCycleA++;
    export function valueA() { return 1; }
    export function result() { return valueB(); }
  `, aName);

  await a.eval();
  assert(b, 'cycle dependency wrapper was not returned by the loader');
  assertEquals(a.namespace.result(), 2);

  for (let i = 0; i < 32; i++) {
    await a.eval();
    await b.eval();
    engine.gc.run();
  }

  assertEquals(globalThis.__dynmodCycleA, 1, 'cycle root executed more than once');
  assertEquals(globalThis.__dynmodCycleB, 1, 'cycle dependency executed more than once');
  delete globalThis.__dynmodCycleA;
  delete globalThis.__dynmodCycleB;
});

await test('a loader may evaluate a circular module before returning it', async () => {
  const aName = 'dynmod-reentrant-a';
  const bName = 'dynmod-reentrant-b';
  const sources = {
    [aName]: `
      import { valueB } from '${bName}';
      export function valueA() { return 1; }
      export function result() { return valueB(); }
    `,
    [bName]: `
      import { valueA } from '${aName}';
      export function valueB() { return valueA() + 1; }
    `,
  };
  const modules = new Map();
  const evaluations = [];

  engine.onModule({
    load(name) {
      const source = sources[name];
      if (source === undefined) throw new Error(`unexpected module: ${name}`);
      const module = new engine.Module(source, name);
      modules.set(name, module);
      evaluations.push(module.eval());
      return module;
    },
  });

  const a = await import(aName);
  await Promise.all(evaluations);
  assertEquals(a.result(), 2);
  assertEquals(modules.size, 2, 'each module should be loaded exactly once');

  await modules.get(aName).eval();
  await modules.get(bName).eval();
  assertEquals(a.result(), 2);
});
