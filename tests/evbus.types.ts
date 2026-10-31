// From circu.js: ../node_modules/.bin/tsc -p tests/tsconfig.evbus.json
export {};

type Equal<A, B> =
    (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2)
        ? true : false;
type Assert<T extends true> = T;

const evbus = import.meta.use('evbus');
type BuiltinExport = Assert<Equal<typeof evbus, typeof CModuleEvBus>>;
type ListedModule = Assert<Equal<TjsModules['evbus'], typeof CModuleEvBus>>;
type PublicMethods = Assert<Equal<
    keyof typeof evbus,
    'set' | 'get' | 'has' | 'delete' | 'clear' | 'on' | 'emit'
>>;

const setResult = evbus.set('app', 'counter', 1);
const clearResult = evbus.clear('app');
const missingOrUnknown = evbus.get('app', 'counter');
const counter = evbus.get<number>('app', 'counter');
const hasCounter = evbus.has('app', 'counter');
const deleted = evbus.delete('app', 'counter');
const delivered = evbus.emit('app', 'changed', { count: 1 });
const deliveredWithoutPayload = evbus.emit('app', 'changed');
type SetResult = Assert<Equal<typeof setResult, void>>;
type ClearResult = Assert<Equal<typeof clearResult, void>>;
type DefaultGet = Assert<Equal<typeof missingOrUnknown, unknown>>;
type TypedGet = Assert<Equal<typeof counter, number | undefined>>;
type HasResult = Assert<Equal<typeof hasCounter, boolean>>;
type DeleteResult = Assert<Equal<typeof deleted, boolean>>;
type EmitResult = Assert<Equal<typeof delivered, boolean>>;
type EmitWithoutPayloadResult = Assert<Equal<typeof deliveredWithoutPayload, boolean>>;

const unsubscribe: CModuleEvBus.Unsubscribe = evbus.on<{ count: number }>(
    'app', 'changed', value => {
        const count: number = value.count;
        // @ts-expect-error Payload fields retain their declared types.
        const text: string = value.count;
        void [count, text];
    },
);
unsubscribe();
type UnsubscribeResult = Assert<Equal<ReturnType<typeof unsubscribe>, void>>;

evbus.on('app', 'unknown', payload => {
    // @ts-expect-error Untyped payloads must be narrowed before use.
    payload.toFixed();
});

// The generic payload and get types are caller assertions, not a shared schema.
evbus.on<number>('app', 'changed', value => value.toFixed());
evbus.emit('app', 'changed');
evbus.emit<number>('app', 'changed');
const oldRuntimeBus = evbus as typeof CModuleEvBus | null;
if (oldRuntimeBus) oldRuntimeBus.clear('app');

function receiverRequired(this: { name: string }, _value: unknown): void {
    void this.name;
}
// @ts-expect-error Callbacks cannot require a receiver from emit.
evbus.on('app', 'changed', receiverRequired);
// @ts-expect-error A value argument is required, even when it is undefined.
evbus.set('app', 'counter');
// @ts-expect-error Namespace must be a string.
evbus.get(1, 'counter');
// @ts-expect-error Keys must be strings.
evbus.has('app', Symbol());
// @ts-expect-error clear requires a namespace.
evbus.clear();
// @ts-expect-error A listener must be callable.
evbus.on('app', 'changed', 42);
// @ts-expect-error Event names must be strings.
evbus.emit('app', 1);
// @ts-expect-error An explicitly typed payload must match its type.
evbus.emit<number>('app', 'changed', 'not a number');
// @ts-expect-error The unsubscribe handle is a function, not a numeric token.
const token: number = unsubscribe;
// @ts-expect-error Native evbus does not export off.
evbus.off('app', 'changed', unsubscribe);
// @ts-expect-error Native evbus does not export once.
evbus.once('app', 'changed', () => {});
// @ts-expect-error The local declaration alias is not a native export.
evbus.deleteValue('app', 'counter');

void [setResult, clearResult, missingOrUnknown, counter, hasCounter, deleted,
    delivered, deliveredWithoutPayload, token];
