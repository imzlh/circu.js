const evbus = import.meta.use('evbus');
const engine = import.meta.use('engine');

const namespacePrefix = `circu.tests.evbus.${Date.now()}`;

await test('evbus - runtime nested snapshots preserve sticky cancellation', () => {
    let nested = false;
    let calls = 0;
    const offFirst = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, () => {
        if (!nested) {
            nested = true;
            assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.BEFORE_UNLOAD), true);
        }
        return true;
    }, 100);
    const offLast = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, () => {
        calls++;
        offFirst();
        engine.gc.run();
        return false;
    }, -100);
    try {
        assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.BEFORE_UNLOAD), true);
        assertEquals(calls, 2, 'both nested snapshots must finish');
    } finally {
        offFirst();
        offLast();
    }
});

await test('evbus - same-realm runtime lifecycle exceptions retain identity', () => {
    for (const name of ['BEFORE_EXIT', 'BEFORE_UNLOAD']) {
        const marker = new Error(name);
        let off = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, () => {
            off();
            engine.gc.run();
            throw marker;
        });
        let caught;
        try {
            evbus.dispatchRuntimeEvent(engine.EventType[name]);
        } catch (error) {
            caught = error;
        } finally {
            off();
        }
        assert(caught === marker, 'lifecycle dispatch must preserve the pending exception');
    }
});

await test('evbus - detached runtime snapshot consumes exceptions before releasing realms', () => {
    for (const name of ['BEFORE_EXIT', 'BEFORE_UNLOAD', 'JOB_EXCEPTION']) {
        let sandbox = new engine.Sandbox();
        sandbox.global.evbus = evbus;
        const marker = new Error(name);
        sandbox.global.marker = marker;
        const off = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, () => {
            sandbox = null;
            engine.gc.run();
        }, 100);
        sandbox.call(`evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, () => {
            throw marker;
        })`);
        let caught;
        try {
            evbus.dispatchRuntimeEvent(engine.EventType[name]);
        } catch (error) {
            caught = error;
        } finally {
            off();
        }
        assert(caught === (name === 'JOB_EXCEPTION' ? undefined : marker),
            'only lifecycle listener exceptions propagate');
        engine.gc.run();
    }
});

function assertTypeError(fn, message) {
    let thrown;
    try {
        fn();
    } catch (error) {
        thrown = error;
    }
    assert(thrown instanceof TypeError, message);
}

await test('evbus - module registration and argument validation', () => {
    assert(evbus !== null, 'evbus must load in the main context');
    if (import.meta.module !== undefined) {
        assert(import.meta.module.includes('evbus'), 'evbus must be listed as a built-in module');
    }

    assertTypeError(() => evbus.set('namespace', 'key'), 'set requires a value');
    assertTypeError(() => evbus.get(1, 'key'), 'get requires a string namespace');
    assertTypeError(() => evbus.clear(), 'clear requires a namespace');
    assertTypeError(() => evbus.on('namespace', 'event', null), 'on requires a listener');
    assertTypeError(() => evbus.emit('namespace'), 'emit requires an event name');
});

await test('evbus - namespaced value lifecycle preserves identity', () => {
    const namespace = `${namespacePrefix}.values`;
    const otherNamespace = `${namespacePrefix}.other-values`;
    evbus.clear(namespace);
    evbus.clear(otherNamespace);

    assertEquals(evbus.get(namespace, 'missing'), undefined);
    assertEquals(evbus.has(namespace, 'missing'), false);
    assertEquals(evbus.delete(namespace, 'missing'), false);

    const first = { version: 1 };
    const second = { version: 2 };
    evbus.set(namespace, 'object', first);
    assert(evbus.get(namespace, 'object') === first, 'stored objects must retain identity');
    evbus.set(namespace, 'object', second);
    assert(evbus.get(namespace, 'object') === second, 'set must replace an existing value');

    evbus.set(namespace, 'undefined', undefined);
    assertEquals(evbus.has(namespace, 'undefined'), true, 'has must distinguish undefined from absence');
    assertEquals(evbus.get(namespace, 'undefined'), undefined);

    evbus.set(otherNamespace, 'kept', 42);
    evbus.clear(namespace);
    assertEquals(evbus.has(namespace, 'object'), false);
    assertEquals(evbus.has(namespace, 'undefined'), false);
    assertEquals(evbus.get(otherNamespace, 'kept'), 42, 'clear must not affect another namespace');

    assertEquals(evbus.delete(otherNamespace, 'kept'), true);
    assertEquals(evbus.delete(otherNamespace, 'kept'), false, 'delete must report an absent key');
});

await test('evbus - listeners are synchronous, ordered, and isolated', () => {
    const namespace = `${namespacePrefix}.listeners`;
    const calls = [];
    const payload = { message: 'hello' };

    const offFirst = evbus.on(namespace, 'message', function (value) {
        assert(this === undefined, 'listeners must be called without a receiver');
        calls.push(['first', value]);
    });
    const offSecond = evbus.on(namespace, 'message', value => {
        calls.push(['second', value]);
    });

    assertEquals(evbus.emit(namespace, 'other', payload), false);
    assertEquals(evbus.emit(`${namespace}.other`, 'message', payload), false);
    assertEquals(evbus.emit(namespace, 'message', payload), true);
    assertEquals(calls.length, 2);
    assertEquals(calls[0][0], 'first');
    assertEquals(calls[1][0], 'second');
    assert(calls[0][1] === payload && calls[1][1] === payload, 'payload identity must be preserved');

    offFirst();
    offFirst();
    offSecond();
    offSecond();
    assertEquals(evbus.emit(namespace, 'message', payload), false, 'unsubscribe must be idempotent');
});

await test('evbus - application events ignore runtime listener priority', () => {
    const namespace = `${namespacePrefix}.application-priority`;
    const calls = [];
    const offFirst = evbus.on(namespace, 'event', () => calls.push('first'), -100);
    const offSecond = evbus.on(namespace, 'event', () => calls.push('second'), 100);
    evbus.emit(namespace, 'event');
    assertEquals(calls.join(','), 'first,second');
    offFirst();
    offSecond();
});

await test('evbus - dispatch uses a stable listener snapshot', () => {
    const namespace = `${namespacePrefix}.snapshot`;
    const calls = [];
    let offLate;
    let offSecond = () => {};

    const offFirst = evbus.on(namespace, 'event', () => {
        calls.push('first');
        offSecond();
        if (!offLate) {
            offLate = evbus.on(namespace, 'event', () => calls.push('late'));
        }
    });
    offSecond = evbus.on(namespace, 'event', () => calls.push('second'));

    evbus.emit(namespace, 'event');
    assertEquals(calls.join(','), 'first,second', 'removal must not alter the active snapshot');

    calls.length = 0;
    evbus.emit(namespace, 'event');
    assertEquals(calls.join(','), 'first,late', 'new listeners must wait for the next dispatch');

    offFirst();
    offSecond();
    offLate();
});

await test('evbus - listener failures propagate and stop dispatch', () => {
    const namespace = `${namespacePrefix}.errors`;
    const marker = { marker: true };
    let laterCalls = 0;

    const offThrowing = evbus.on(namespace, 'event', () => {
        throw marker;
    });
    const offLater = evbus.on(namespace, 'event', () => {
        laterCalls++;
    });

    let caught;
    try {
        evbus.emit(namespace, 'event');
    } catch (error) {
        caught = error;
    }
    assert(caught === marker, 'emit must preserve the listener exception');
    assertEquals(laterCalls, 0, 'dispatch must stop after a listener throws');

    offThrowing();
    assertEquals(evbus.emit(namespace, 'event'), true);
    assertEquals(laterCalls, 1, 'remaining listeners must stay registered after an error');
    offLater();
});

await test('evbus - runtime events are prioritized and independently removable', () => {
    const calls = [];
    let sharedContext;
    const offLow = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, frame => {
        calls.push('low');
        assert(frame.context === sharedContext, 'runtime listeners must share one context');
        return false;
    }, -10);
    const offHigh = evbus.on(evbus.RUNTIME_NAMESPACE, evbus.RUNTIME_EVENT, frame => {
        calls.push('high');
        sharedContext = frame.context;
        frame.context.handled = true;
        return true;
    }, 10);

    assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.JOB_EXCEPTION, new Error('test')), false);
    assertEquals(calls.join(','), 'high,low', 'higher priority listeners run first');

    calls.length = 0;
    sharedContext = undefined;
    offLow();
    assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.JOB_EXCEPTION, new Error('test')), true);
    assertEquals(calls.join(','), 'high', 'unsubscribing one listener leaves the other installed');
    offHigh();

    assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.UNHANDLED_REJECTION, []), false,
        'an event with no listeners uses its native default');
    assertEquals(evbus.dispatchRuntimeEvent(engine.EventType.JOB_EXCEPTION, new Error('test')), true,
        'job exceptions default to non-fatal without listeners');
});

await test('evbus - sandboxes share the runtime bus and release owned entries', () => {
    const namespace = `${namespacePrefix}.sandbox`;
    evbus.clear(namespace);
    evbus.set(namespace, 'main', 'kept');

    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    let sandboxValue = sandbox.call(`(() => {
        const value = { owner: 'sandbox' };
        evbus.set(${JSON.stringify(namespace)}, 'owned', value);
        evbus.on(${JSON.stringify(namespace)}, 'message', payload => {
            evbus.set(${JSON.stringify(namespace)}, 'seen', payload);
        });
        return value;
    })()`);

    assert(evbus.get(namespace, 'owned') === sandboxValue, 'sandboxes must share values by identity');
    const payload = { source: 'main' };
    assertEquals(evbus.emit(namespace, 'message', payload), true);
    assert(evbus.get(namespace, 'seen') === payload, 'sandbox listeners must receive main-context values');

    sandboxValue = null;
    sandbox = null;
    engine.gc.run();

    assertEquals(evbus.has(namespace, 'owned'), false, 'sandbox-owned values must be cleaned up');
    assertEquals(evbus.has(namespace, 'seen'), false, 'values written by sandbox listeners must be cleaned up');
    assertEquals(evbus.get(namespace, 'main'), 'kept', 'main-context values must survive sandbox cleanup');
    assertEquals(evbus.emit(namespace, 'message', payload), false, 'sandbox listeners must be cleaned up');
    evbus.clear(namespace);
});

await test('evbus - sandbox cleanup during dispatch keeps the snapshot realm alive', () => {
    const namespace = `${namespacePrefix}.sandbox-dispatch-cleanup`;
    const calls = [];
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    sandbox.global.calls = calls;

    const offDrop = evbus.on(namespace, 'event', () => {
        calls.push('main');
        sandbox = null;
        engine.gc.run();
    });

    /* Register main first so its callback can finalize the Sandbox wrapper
     * while the sandbox listener is still retained by this dispatch snapshot. */
    sandbox.call(`(() => {
        evbus.on(${JSON.stringify(namespace)}, 'event', () => calls.push('sandbox'));
    })()`);

    assertEquals(evbus.emit(namespace, 'event'), true);
    assertEquals(calls.join(','), 'main,sandbox', 'owner cleanup must not invalidate a snapshotted realm');

    offDrop();
    engine.gc.run();
    assertEquals(evbus.emit(namespace, 'event'), false, 'the sandbox listener must stay removed after dispatch');
    evbus.clear(namespace);
});

// ── Extended tests ──────────────────────────────────────────────────────

await test('evbus - extended argument validation', () => {
    // empty strings are valid namespace/key values
    evbus.set('', '', 42);
    assertEquals(evbus.get('', ''), 42);
    assertEquals(evbus.has('', ''), true);
    assertEquals(evbus.delete('', ''), true);
    assertEquals(evbus.has('', ''), false);

    // numeric namespace must throw TypeError
    assertTypeError(() => evbus.set(0, 'k', 1), 'set: numeric namespace');
    assertTypeError(() => evbus.get(0, 'k'), 'get: numeric namespace');
    assertTypeError(() => evbus.has(0, 'k'), 'has: numeric namespace');
    assertTypeError(() => evbus.delete(0, 'k'), 'delete: numeric namespace');
    assertTypeError(() => evbus.clear(0), 'clear: numeric namespace');
    assertTypeError(() => evbus.on(0, 'e', () => {}), 'on: numeric namespace');
    assertTypeError(() => evbus.emit(0, 'e'), 'emit: numeric namespace');

    // numeric key/event must throw TypeError
    assertTypeError(() => evbus.set('ns', 0, 1), 'set: numeric key');
    assertTypeError(() => evbus.get('ns', 0), 'get: numeric key');
    assertTypeError(() => evbus.has('ns', 0), 'has: numeric key');
    assertTypeError(() => evbus.delete('ns', 0), 'delete: numeric key');
    assertTypeError(() => evbus.on('ns', 0, () => {}), 'on: numeric event');
    assertTypeError(() => evbus.emit('ns', 0), 'emit: numeric event');

    // null and undefined arguments
    assertTypeError(() => evbus.set(null, 'k', 1), 'set: null namespace');
    assertTypeError(() => evbus.get(undefined, 'k'), 'get: undefined namespace');
    assertTypeError(() => evbus.on('ns', 'e', 'not a function'), 'on: non-function listener');
    assertTypeError(() => evbus.on('ns', 'e', {}), 'on: object as listener');

    // zero args
    assertTypeError(() => evbus.set(), 'set: zero args');
    assertTypeError(() => evbus.get(), 'get: zero args');
    assertTypeError(() => evbus.has(), 'has: zero args');
    assertTypeError(() => evbus.delete(), 'delete: zero args');
    assertTypeError(() => evbus.on(), 'on: zero args');
    assertTypeError(() => evbus.emit(), 'emit: zero args');
});

await test('evbus - falsy and special values stored correctly', () => {
    const ns = `${namespacePrefix}.special`;
    evbus.clear(ns);

    evbus.set(ns, 'null', null);
    evbus.set(ns, 'zero', 0);
    evbus.set(ns, 'false', false);
    evbus.set(ns, 'emptystr', '');
    evbus.set(ns, 'nan', NaN);

    assertEquals(evbus.get(ns, 'null'), null);
    assertEquals(evbus.get(ns, 'zero'), 0);
    assertEquals(evbus.get(ns, 'false'), false);
    assertEquals(evbus.get(ns, 'emptystr'), '');
    assert(Number.isNaN(evbus.get(ns, 'nan')), 'NaN must be preserved');

    assertEquals(evbus.has(ns, 'null'), true);
    assertEquals(evbus.has(ns, 'zero'), true);
    assertEquals(evbus.has(ns, 'false'), true);
    assertEquals(evbus.has(ns, 'emptystr'), true);
    assertEquals(evbus.has(ns, 'nan'), true);

    evbus.clear(ns);
});

await test('evbus - throw undefined from listener', () => {
    const ns = `${namespacePrefix}.throw-undef`;
    let secondCalled = false;

    const off1 = evbus.on(ns, 'e', () => { throw undefined; });
    const off2 = evbus.on(ns, 'e', () => { secondCalled = true; });

    let caught;
    let didThrow = false;
    try {
        evbus.emit(ns, 'e');
    } catch (error) {
        caught = error;
        didThrow = true;
    }
    assert(didThrow, 'emit must propagate even when the thrown value is undefined');
    assertEquals(caught, undefined, 'the thrown value must be undefined itself');
    assertEquals(secondCalled, false, 'dispatch must stop after throw undefined');

    off1();
    off2();
});

await test('evbus - throw null from listener', () => {
    const ns = `${namespacePrefix}.throw-null`;
    const off = evbus.on(ns, 'e', () => { throw null; });

    let caught;
    let didThrow = false;
    try {
        evbus.emit(ns, 'e');
    } catch (error) {
        caught = error;
        didThrow = true;
    }
    assert(didThrow, 'emit must propagate when throwing null');
    assertEquals(caught, null, 'the thrown value must be null');

    off();
});

await test('evbus - recursive dispatch from listener', () => {
    const ns = `${namespacePrefix}.recursive`;
    const log = [];

    const off = evbus.on(ns, 'ping', payload => {
        log.push(`ping:${payload}`);
        if (payload < 3) {
            evbus.emit(ns, 'ping', payload + 1);
        }
    });

    evbus.emit(ns, 'ping', 1);
    assertEquals(log.join(','), 'ping:1,ping:2,ping:3', 'recursive dispatch must work');

    off();
});

await test('evbus - recursive emit across events', () => {
    const ns = `${namespacePrefix}.cross-recursive`;
    const log = [];

    const offA = evbus.on(ns, 'a', () => {
        log.push('a');
        evbus.emit(ns, 'b');
    });
    const offB = evbus.on(ns, 'b', () => {
        log.push('b');
    });

    evbus.emit(ns, 'a');
    assertEquals(log.join(','), 'a,b', 'cross-event recursive emit must work');

    offA();
    offB();
});

await test('evbus - unsubscribe during recursive dispatch', () => {
    const ns = `${namespacePrefix}.unsub-recurse`;
    const log = [];
    let offSelf;

    offSelf = evbus.on(ns, 'e', () => {
        log.push('before-unsub');
        offSelf();
        evbus.emit(ns, 'e');
        log.push('after-recurse');
    });

    evbus.emit(ns, 'e');
    assertEquals(log.join(','), 'before-unsub,after-recurse',
        'unsubscribing inside a listener prevents it from firing in the recursive emit');
});

await test('evbus - clear does not remove listeners', () => {
    const ns = `${namespacePrefix}.clear-listeners`;
    let called = false;

    evbus.set(ns, 'data', 99);
    const off = evbus.on(ns, 'e', () => { called = true; });

    evbus.clear(ns);
    assertEquals(evbus.has(ns, 'data'), false, 'clear removes values');
    assertEquals(evbus.emit(ns, 'e'), true, 'listeners must survive clear');
    assert(called, 'listener must fire after namespace clear');

    off();
});

await test('evbus - emit with no payload passes undefined', () => {
    const ns = `${namespacePrefix}.no-payload`;
    let received = 'sentinel';

    const off = evbus.on(ns, 'e', payload => {
        received = payload;
    });

    evbus.emit(ns, 'e');
    assertEquals(received, undefined, 'missing payload must arrive as undefined');
    off();
});

await test('evbus - many rapid subscribe and unsubscribe cycles', () => {
    const ns = `${namespacePrefix}.rapid`;
    const offs = [];

    for (let i = 0; i < 100; i++) {
        offs.push(evbus.on(ns, 'e', () => {}));
    }
    for (const off of offs) {
        off();
    }
    assertEquals(evbus.emit(ns, 'e'), false, 'all 100 listeners must be removed');

    // subscribe again to ensure no list corruption
    let count = 0;
    const off = evbus.on(ns, 'e', () => { count++; });
    evbus.emit(ns, 'e');
    assertEquals(count, 1, 'listener registered after mass-unsub must work');
    off();
});

await test('evbus - set from within a listener triggered by emit', () => {
    const ns = `${namespacePrefix}.set-in-listener`;
    evbus.clear(ns);

    const off = evbus.on(ns, 'write', payload => {
        evbus.set(ns, 'written', payload);
    });

    evbus.emit(ns, 'write', 'hello');
    assertEquals(evbus.get(ns, 'written'), 'hello', 'set inside listener must succeed');

    off();
    evbus.clear(ns);
});

await test('evbus - delete from within a listener', () => {
    const ns = `${namespacePrefix}.delete-in-listener`;
    evbus.set(ns, 'target', 'exists');

    const off = evbus.on(ns, 'clean', () => {
        evbus.delete(ns, 'target');
    });

    evbus.emit(ns, 'clean');
    assertEquals(evbus.has(ns, 'target'), false, 'delete inside listener must take effect');

    off();
    evbus.clear(ns);
});

await test('evbus - set replaces value and returns undefined', () => {
    const ns = `${namespacePrefix}.set-return`;
    const result = evbus.set(ns, 'k', 1);
    assertEquals(result, undefined, 'set must return undefined');
    const result2 = evbus.set(ns, 'k', 2);
    assertEquals(result2, undefined, 'set replacing value must return undefined');
    evbus.clear(ns);
});

await test('evbus - on returns a function', () => {
    const ns = `${namespacePrefix}.on-return`;
    const off = evbus.on(ns, 'e', () => {});
    assertEquals(typeof off, 'function', 'on must return a function');
    off();
});

await test('evbus - multiple namespaces with same key are independent', () => {
    const nsA = `${namespacePrefix}.multi-ns-a`;
    const nsB = `${namespacePrefix}.multi-ns-b`;

    evbus.set(nsA, 'shared', 'A');
    evbus.set(nsB, 'shared', 'B');

    assertEquals(evbus.get(nsA, 'shared'), 'A');
    assertEquals(evbus.get(nsB, 'shared'), 'B');

    evbus.delete(nsA, 'shared');
    assertEquals(evbus.has(nsA, 'shared'), false);
    assertEquals(evbus.get(nsB, 'shared'), 'B', 'delete in one namespace must not affect another');

    evbus.clear(nsB);
});

await test('evbus - multiple namespaces with same event are independent', () => {
    const nsA = `${namespacePrefix}.multi-evt-a`;
    const nsB = `${namespacePrefix}.multi-evt-b`;
    const log = [];

    const offA = evbus.on(nsA, 'e', () => log.push('A'));
    const offB = evbus.on(nsB, 'e', () => log.push('B'));

    evbus.emit(nsA, 'e');
    assertEquals(log.join(','), 'A', 'emit on nsA must not fire nsB listener');
    log.length = 0;

    evbus.emit(nsB, 'e');
    assertEquals(log.join(','), 'B');

    offA();
    offB();
});

await test('evbus - rooted values and callbacks survive garbage collection', () => {
    const ns = `${namespacePrefix}.gc-roots`;
    let value = { count: 0 };
    value.self = value;
    evbus.set(ns, 'value', value);
    const off = ((captured) => evbus.on(ns, 'event', () => captured.count++))(value);
    value = null;

    engine.gc.run();
    assertEquals(evbus.emit(ns, 'event'), true);
    const retained = evbus.get(ns, 'value');
    assert(retained.self === retained, 'the stored cycle must retain its identity');
    assertEquals(retained.count, 1, 'the listener closure must remain rooted');
    off();
    evbus.clear(ns);
    engine.gc.run();
});

await test('evbus - collecting an unsubscribe function keeps its listener', () => {
    const ns = `${namespacePrefix}.collected-unsubscribe`;
    const state = { calls: 0 };
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    sandbox.global.state = state;
    sandbox.call(`void evbus.on(${JSON.stringify(ns)}, 'event', () => state.calls++)`);

    engine.gc.run();
    assertEquals(evbus.emit(ns, 'event'), true);
    assertEquals(state.calls, 1);
    sandbox = null;
    engine.gc.run();
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - subscription churn remains safe under frequent GC', () => {
    const ns = `${namespacePrefix}.gc-subscriptions`;
    const threshold = engine.gc.getThreshold();
    try {
        for (let i = 0; i < 50; i++) {
            engine.gc.setThreshold(0);
            let sandbox = new engine.Sandbox();
            sandbox.global.evbus = evbus;
            const off = sandbox.call(`evbus.on(${JSON.stringify(ns)}, 'event', () => {})`);
            assertEquals(evbus.emit(ns, 'event'), true);
            off();
            sandbox = null;
            engine.gc.run();
            assertEquals(evbus.emit(ns, 'event'), false);
        }
    } finally {
        engine.gc.setThreshold(threshold);
    }
});

await test('evbus - recursive once and removal preserve each dispatch snapshot', () => {
    const ns = `${namespacePrefix}.recursive-snapshots`;
    const calls = [];
    let offOnce;
    let offSecond;
    offOnce = evbus.on(ns, 'event', depth => {
        calls.push(`once:${depth}`);
        offOnce();
        offSecond();
        if (depth === 0) evbus.emit(ns, 'event', 1);
    });
    offSecond = evbus.on(ns, 'event', depth => calls.push(`second:${depth}`));
    const offThird = evbus.on(ns, 'event', depth => calls.push(`third:${depth}`));

    assertEquals(evbus.emit(ns, 'event', 0), true);
    assertEquals(calls.join(','), 'once:0,third:1,second:0,third:0');
    offOnce();
    offSecond();
    offThird();
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - clear tolerates sandbox finalizer reentry', () => {
    const ns = `${namespacePrefix}.clear-reentry`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    evbus.set(ns, 'wrapper', sandbox);
    sandbox.call(`evbus.set(${JSON.stringify(ns)}, 'sandbox-value', { alive: true })`);
    evbus.set(ns, 'tail', 'main');
    sandbox = null;

    evbus.clear(ns);
    assertEquals(evbus.has(ns, 'wrapper'), false);
    assertEquals(evbus.has(ns, 'sandbox-value'), false);
    assertEquals(evbus.has(ns, 'tail'), false);
});

await test('evbus - clear tolerates cascading sandbox finalizers', () => {
    const ns = `${namespacePrefix}.clear-cascade`;
    let first = new engine.Sandbox();
    let second = new engine.Sandbox();
    first.global.evbus = evbus;
    second.global.evbus = evbus;
    first.global.other = second;
    evbus.set(ns, 'first-wrapper', first);
    first.call(`evbus.set(${JSON.stringify(ns)}, 'second-wrapper', other)`);
    second.call(`evbus.set(${JSON.stringify(ns)}, 'owned', { alive: true })`);
    second.call(`evbus.on(${JSON.stringify(ns)}, 'event', () => {})`);
    first.global.other = null;
    first = null;
    second = null;

    evbus.clear(ns);
    assertEquals(evbus.has(ns, 'first-wrapper'), false);
    assertEquals(evbus.has(ns, 'second-wrapper'), false);
    assertEquals(evbus.has(ns, 'owned'), false);
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - replacement transfers ownership before finalizer reentry', () => {
    const ns = `${namespacePrefix}.set-reentry`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    sandbox.global.wrapper = sandbox;
    sandbox.call(`evbus.set(${JSON.stringify(ns)}, 'key', wrapper)`);
    sandbox.call(`evbus.set(${JSON.stringify(ns)}, 'owned', { alive: true })`);
    sandbox.global.wrapper = null;
    sandbox = null;

    const replacement = { owner: 'main' };
    evbus.set(ns, 'key', replacement);
    assert(evbus.get(ns, 'key') === replacement, 'the new owner must survive sandbox cleanup');
    assertEquals(evbus.has(ns, 'owned'), false);
    evbus.clear(ns);
});

await test('evbus - unsubscribe tolerates sandbox finalizer reentry', () => {
    const ns = `${namespacePrefix}.off-reentry`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    sandbox.global.wrapper = sandbox;
    const off = sandbox.call(`((owner) => evbus.on(${JSON.stringify(ns)}, 'event', () => owner))(wrapper)`);
    sandbox.call(`evbus.on(${JSON.stringify(ns)}, 'event', () => {})`);
    sandbox.call(`evbus.set(${JSON.stringify(ns)}, 'owned', { alive: true })`);
    sandbox.global.wrapper = null;
    sandbox = null;

    off();
    off();
    assertEquals(evbus.has(ns, 'owned'), false);
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - detached snapshot callbacks cannot leave owned entries', () => {
    const ns = `${namespacePrefix}.detached-snapshot`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    const offMain = evbus.on(ns, 'event', () => {
        sandbox = null;
        engine.gc.run();
    });
    sandbox.call(`evbus.on(${JSON.stringify(ns)}, 'event', () => {
        evbus.set(${JSON.stringify(ns)}, 'late', 1);
        evbus.on(${JSON.stringify(ns)}, 'late-event', () => {});
    })`);

    assertEquals(evbus.emit(ns, 'event'), true);
    offMain();
    assertEquals(evbus.has(ns, 'late'), false);
    assertEquals(evbus.emit(ns, 'late-event'), false);
});

await test('evbus - detached snapshot cleanup also runs after throw undefined', () => {
    const ns = `${namespacePrefix}.detached-snapshot-error`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    const offMain = evbus.on(ns, 'event', () => {
        sandbox = null;
        engine.gc.run();
    });
    sandbox.call(`evbus.on(${JSON.stringify(ns)}, 'event', () => {
        evbus.set(${JSON.stringify(ns)}, 'late', 1);
        evbus.on(${JSON.stringify(ns)}, 'late-event', () => {});
        throw undefined;
    })`);

    let threw = false;
    try {
        evbus.emit(ns, 'event');
    } catch (error) {
        threw = true;
        assertEquals(error, undefined);
    }
    assert(threw, 'throw undefined must survive detached-context cleanup');
    offMain();
    assertEquals(evbus.has(ns, 'late'), false);
    assertEquals(evbus.emit(ns, 'late-event'), false);
});

await test('evbus - escaped callbacks cannot create released sandbox entries', () => {
    const ns = `${namespacePrefix}.detached-function`;
    let sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    const set = sandbox.call(`() => evbus.set(${JSON.stringify(ns)}, 'key', 1)`);
    const on = sandbox.call(`() => evbus.on(${JSON.stringify(ns)}, 'event', () => {})`);
    sandbox = null;
    engine.gc.run();

    for (const fn of [set, on]) {
        let error;
        try {
            fn();
        } catch (caught) {
            error = caught;
        }
        assertEquals(error?.name, 'TypeError', 'released sandboxes must reject new entries');
    }
    assertEquals(evbus.has(ns, 'key'), false);
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - throwing during nested dispatch releases all snapshot references', () => {
    const ns = `${namespacePrefix}.nested-error`;
    const calls = [];
    let offLater;
    const offFirst = evbus.on(ns, 'event', depth => {
        calls.push(`first:${depth}`);
        if (depth === 0) {
            offLater();
            evbus.emit(ns, 'event', 1);
        } else {
            throw undefined;
        }
    });
    offLater = evbus.on(ns, 'event', depth => calls.push(`later:${depth}`));

    let threw = false;
    try {
        evbus.emit(ns, 'event', 0);
    } catch (error) {
        threw = true;
        assertEquals(error, undefined);
    }
    assert(threw, 'nested throw undefined must propagate');
    assertEquals(calls.join(','), 'first:0,first:1');
    offFirst();
    offLater();
    engine.gc.run();
    assertEquals(evbus.emit(ns, 'event'), false);
});

await test('evbus - runtime shutdown releases live sandbox-owned entries', () => {
    const ns = `${namespacePrefix}.shutdown`;
    const sandbox = new engine.Sandbox();
    sandbox.global.evbus = evbus;
    sandbox.call(`(() => {
        const value = { realm: 'sandbox' };
        value.self = value;
        evbus.set(${JSON.stringify(ns)}, ${JSON.stringify(`value-${Date.now()}`)}, value);
        evbus.on(${JSON.stringify(ns)}, ${JSON.stringify(`event-${Date.now()}`)}, () => value);
    })()`);
    // Keep the wrapper and entries alive until TJS_FreeRuntime exercises cleanup.
    globalThis.evbusShutdownSandbox = sandbox;
});
