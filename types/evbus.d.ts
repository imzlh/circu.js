/**
 * Runtime-local event bus and shared value registry, loaded with
 * `import.meta.use('evbus')` in bootstrap code.
 *
 * Values and listeners are strongly retained, not cloned. Contexts in the same
 * QuickJS runtime can share them by identity; each worker has its own runtime
 * and bus. This is not an isolation or security boundary.
 *
 * A value belongs to the context of its most recent `set`, and a listener to
 * the context of its `on` call. Owned entries are removed when a sandbox is
 * finalized, and all entries are removed at runtime shutdown.
 */
declare namespace CModuleEvBus {
    /** Native runtime events are published under this namespace and event. */
    export const RUNTIME_NAMESPACE: "circu.runtime";
    export const RUNTIME_EVENT: "event";

    export interface RuntimeEventContext {
        handled: boolean;
        dispatched: boolean;
        rejectionEmitted: boolean;
    }

    export interface RuntimeEvent<T = unknown> {
        name: number;
        data: T;
        context: RuntimeEventContext;
    }

    /**
     * A listener called synchronously with one payload and an undefined
     * `this` argument. `T` is a caller-supplied convention, not runtime validation;
     * an emit with no payload supplies `undefined`. Return values are ignored,
     * including promises, which are not awaited.
     */
    export type Listener<T = unknown, R = void> = (this: void, payload: T) => R;

    /**
     * An idempotent function that removes one registration. Dropping the
     * function without calling it does not unsubscribe the listener.
     */
    export type Unsubscribe = () => void;

    /**
     * Store or replace a value under a string namespace and string key.
     * Replacing a value transfers ownership to the calling context.
     * @throws {TypeError} If a name is not a string or the value is omitted.
     */
    export function set<T>(namespace: string, key: string, value: T): void;

    /**
     * Return the stored value by identity, or `undefined` when the key is
     * absent. `T` is a caller-supplied assertion; it is not checked at runtime.
     * @throws {TypeError} If a name is not a string.
     */
    export function get<T = unknown>(namespace: string, key: string): T | undefined;

    /**
     * Test whether a key exists, including keys whose value is `undefined`.
     * @throws {TypeError} If a name is not a string.
     */
    export function has(namespace: string, key: string): boolean;

    /**
     * Remove a key and report whether it existed.
     * @throws {TypeError} If a name is not a string.
     */
    function deleteValue(namespace: string, key: string): boolean;
    export { deleteValue as delete };

    /**
     * Remove every stored value in a namespace. Listeners are unaffected.
     * @throws {TypeError} If the namespace is not a string.
     */
    export function clear(namespace: string): void;

    /**
     * Register a listener and return its unsubscribe function. Each call is a
     * separate registration, including repeated calls with the same callback.
     * Priority affects only the native runtime-event channel; higher values run
     * first and equal values retain registration order. Other events always use
     * registration order.
     * @throws {TypeError} If a name is not a string or listener is not callable.
     */
    export function on<T = unknown, R = void>(
        namespace: string,
        event: string,
        listener: Listener<T, R>,
        priority?: number,
    ): Unsubscribe;

    /**
     * Synchronously call a registration-order snapshot of matching listeners.
     * Registrations added or removed during dispatch affect later emits, not
     * this snapshot. The first synchronously thrown value, even `undefined`,
     * propagates and stops dispatch. If no payload is provided, listeners
     * receive `undefined`. Returns `true` if the snapshot was nonempty,
     * otherwise `false`.
     * @throws {TypeError} If a name is not a string.
     */
    export function emit<T = unknown>(namespace: string, event: string, payload?: T): boolean;

    /**
     * Dispatch a runtime event through the same native path used by the core.
     * Intended for lifecycle bridges and tests; ordinary publishers use emit().
     */
    export function dispatchRuntimeEvent<T = unknown>(eventName: number, data?: T): boolean;
}
