declare namespace CModuleError {
    export class Error extends globalThis.Error {
        /**
         * ERRNO code, mostly for syscall results.
         */
        code: number;
    }
}