// test-engine-export-global.js
/*  global test  */

/* 1. grab the engine via import.meta.use */
const engine = import.meta.use('engine');

/* --------- test case 1 --------- */
await test('Module#create + export() should be importable immediately', async () => {
  /* create the C-module and export stuff */
  const m = engine.Module.create('mod1');
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

await test('free not-imported module', async () => {
  const m = engine.Module.create('mod4');
  m.export('val', 1);

  // the var_ref should be automately GCed
  engine.gc.run()
})