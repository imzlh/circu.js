/**
 * Native `debug` module — QuickJS debugger primitives + cross-thread DebugChannel.
 *
 * Reviewed final definitions. Notes vs. the previous draft:
 *  - `getFrameInfo` is now declared (was missing).
 *  - Frame info uses the key `column` (not `col`).
 *  - `STEP_*` constants are actually exported by the native module now.
 *  - `EV_PAUSED` / `EV_RESUMED` event-type constants added for `notify()`.
 *  - `DebugChannelMain.waitRequest()` returns a discriminated union
 *    (`inspect` | `resume`), never raw control messages.
 *  - `waitRequest()` throws InternalError (EAGAIN) when `stop()` is called.
 */

declare namespace CModuleDebug {
	/** Break reason passed to the onBreak callback. */
	export const BREAKPOINT: number; // 0
	export const EXCEPTION: number; // 1
	export const DEBUGGER: number; // 2 (debugger; statement)
	export const STEP: number; // 3 (step-mode pause)
	export const INTERRUPT: number; // 4 (explicit pause via dc.interrupt())
	export const DEBUGGER_STMT: number; // trace flag bit

	/** Exception breakpoint modes accepted by setExceptionBreakpoint(). */
	export const EXCEPTION_NONE: number; // 0
	export const EXCEPTION_CAUGHT: number; // 1
	export const EXCEPTION_UNCAUGHT: number; // 2
	export const EXCEPTION_ALL: number; // 3

	/** Step modes (also accepted by DebugChannelWorker.setStep / resume). */
	export const STEP_NONE: number; // 0
	export const STEP_INTO: number; // 1
	export const STEP_OVER: number; // 2
	export const STEP_OUT: number; // 3

	/** DebugControlBlock.state values. */
	export const STATE_IDLE: number; // 0
	export const STATE_RUNNING: number; // 1
	export const STATE_PAUSED: number; // 2

	/** Event-type constants for DebugChannelMain.notify(evType, json). */
	export const EV_PAUSED: number; // 21
	export const EV_RESUMED: number; // 22

	/** Requests/Response OP */
	export const REQ_INSPECT: number;
	export const REQ_RESUME: number;
	export const RES_EVENT: number;
	export const RES_REPLY: number;

	/**
	 * onBreak callback. Return value:
	 *   - undefined / 0 -> continue
	 *   - negative -> abort execution (exception)
	 * Called synchronously on the executing (main) thread at a safepoint.
	 */
	type BreakCallback = (
		reason: number,
		file: string | undefined,
		func: string | undefined,
		line: number,
		column: number,
		thrown?: unknown,
	) => number | void;

	export function start(onBreak: BreakCallback): void;
	export function stop(): void;

	export function addBreakpoint(file: string, line: number, column?: number): void;
	export function removeBreakpoint(file: string, line: number): void;
	export function clearBreakpoints(): void;

	export function getStackDepth(): number;

	/** Stack frame info for `level` (0 = top). Returns null if out of range. */
	export function getFrameInfo(level: number): {
		line: number;
		column: number;
		/** The Function object for the frame. */
		func: Function;
		/** Source path / URL of the frame's function. */
		file: string;
	};

	export function getLocalVariables(level: number): Array<{
		name: string;
		value: unknown;
		isArg: boolean;
		isClosure: boolean;
		scopeLevel: number;
	}>;

	export function setVariable(level: number, name: string, value: unknown, scopeNumber?: number): void;
	export function evalInFrame(level: number, expr: string): unknown;

	export function setExceptionBreakpoint(mode: boolean | number): void;
	/** Must be called from within an onBreak callback. */
	export function step(mode: number): void;

	/* ---- Cross-thread DebugChannel ------------------------------------- */

	/** Return type of createDebugChannel(). */
	export interface DebugChannelPair {
		handle: ArrayBuffer;
		dc: DebugChannelMain;
	}

	/** Main-thread channel handle. Owns one ref; call stop() before dropping. */
	export interface DebugChannelMain {
		/** Send an event (e.g. EV_PAUSED/EV_RESUMED) to the worker. */
		notify(evType: number, payload: any): boolean;
		/**
		 * Block until the worker sends an inspect request or a resume signal.
		 * Control messages (breakpoints/step) are applied in C and never returned.
		 * Throws InternalError (EAGAIN) when stop() is called (channel torn down).
		 */
		waitRequest():
			| { kind: typeof REQ_INSPECT; id: number; method: string; params: unknown }
			| { kind: typeof REQ_RESUME; step: number };
		/** Reply to an inspect request previously returned by waitRequest(). */
		reply(id: number, result: any): boolean;
		/** Detach the weak trace pointer (if ours) and release this ref. */
		stop(): void;
	}

	/** Worker-thread channel handle (reconstructed from the transferred handle). */
	export interface DebugChannelWorker {
		/** Request the main thread to pause at the next safepoint. */
		interrupt(): void;
		/** Read the current DebugControlBlock.state (STATE_*). */
		state(): number;

		/* Control-class methods — applied in C, never enter JS on main. */
		addBreakpoint(file: string, line: number, column?: number): void;
		removeBreakpoint(file: string, line: number): void;
		clearBreakpoints(): void;
		setBreakpointsActive(active: boolean): void;
		setExceptionBreakpoint(mode: boolean | number): void;
		setStep(mode: number): void;

		/** Send an inspect request; the reply arrives via recv() with the same id. */
		send(id: number, method: string, params: any): boolean;
		/** Non-blocking pop from the main->worker queue. */
		recv():
			| { kind: typeof RES_EVENT | typeof RES_REPLY; type: number; id: number; payload?: any }
			| null;
		/** Timed-wait until a main->worker message arrives (default 1ms). */
		waitRecv(timeoutMs?: number): boolean;
		/** Resume a paused main thread, optionally with a step mode (STEP_*). */
		resume(step?: number): boolean;
		/** Release this ref. */
		stop(): void;
	}

	/**
	 * Allocate a DebugControlBlock and return the main-thread handle plus an
	 * 8-byte ArrayBuffer carrying the raw pointer. Transfer `handle` to the
	 * worker (one-shot) and rebuild it there with getDebugChannel().
	 */
	export function createDebugChannel(): DebugChannelPair;

	/** Rebuild the worker-side handle from a transferred handle ArrayBuffer. */
	export function getDebugChannel(handle: ArrayBuffer): DebugChannelWorker;
}
