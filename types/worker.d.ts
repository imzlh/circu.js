/**
 * Worker module - Multi-threading support
 * 
 * @example
 * const { Worker, isWorker, pipe } = import.meta.use('worker');
 * 
 * if (!isWorker) {
 *   const worker = new Worker({ task: 'heavy-computation' });
 *   worker.messagePipe.onmessage = (data) => console.log(data);
 *   await worker.messagePipe.postMessage({ start: true });
 * }
 */
declare namespace CModuleWorker {
    /**
     * MessagePipe object
     */
    export interface MessagePipe {
        /**
         * Send message
         * @param data Data to send
         */
        postMessage(data: unknown): void;

        /**
         * Keep this pipe's underlying libuv handle referenced.
         */
        ref(): void;

        /**
         * Allow the runtime to exit even if this pipe is the only active handle.
         */
        unref(): void;

        /**
         * Message event handler
         */
        onmessage: ((data: unknown) => void) | undefined;

        /**
         * Message error event handler
         */
        onmessageerror: ((error: Error) => void) | undefined;

        readonly [Symbol.toStringTag]: 'MessagePipe';
    }

    /**
     * Worker object
     */
    export class Worker {
        /**
         * Create a Worker
         * @param user_data Any object (including functions, but dangerous!)
         */
        constructor(user_data: unknown);

        /**
         * Terminate Worker
         */
        terminate(): void;

        /**
         * Get MessagePipe object
         */
        readonly messagePipe: MessagePipe;

        readonly [Symbol.toStringTag]: 'Worker';
    }

    /** Whether running in Worker thread */
    export const isWorker: boolean;

    /** Get current Worker's MessagePipe */
    export const pipe: MessagePipe | undefined;

    /** Get current Worker's user data (passed in constructor) */
    export const workerData: unknown;

    /** Stop the current worker runtime. Only available inside Worker. */
    export function close(): void;
}
