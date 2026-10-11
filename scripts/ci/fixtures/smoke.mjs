const console = import.meta.use('console');
const { versions } = import.meta.use('engine');

const values = await Array.fromAsync(
    [Promise.resolve(20), Promise.resolve(21)],
    async value => value + 1,
);
if (values.join(',') !== '21,22') throw new Error('Array.fromAsync returned incorrect values');
if (!versions.core || !versions.quickjs) throw new Error('Missing runtime version information');

console.log(`CJS_SMOKE_OK ${versions.core} QuickJS ${versions.quickjs}`);
