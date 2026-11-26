/**
 * Error module - System error codes and error handling.
 *
 * `errno.*` numeric values are libuv UV_* codes: on Unix they are typically
 * `-(platform errno)` (e.g. Linux ESRCH is often -3), not fixed cross-platform
 * constants. Prefer `error.errno.NAME` at runtime over hard-coded numbers.
 */
declare namespace CModuleError {
    /** Names exported by libuv's UV_ERRNO_MAP; values come from the host platform. */
    export type ErrnoName =
        | 'E2BIG' | 'EACCES' | 'EADDRINUSE' | 'EADDRNOTAVAIL' | 'EAFNOSUPPORT' | 'EAGAIN'
        | 'EAI_ADDRFAMILY' | 'EAI_AGAIN' | 'EAI_BADFLAGS' | 'EAI_BADHINTS' | 'EAI_CANCELED'
        | 'EAI_FAIL' | 'EAI_FAMILY' | 'EAI_MEMORY' | 'EAI_NODATA' | 'EAI_NONAME'
        | 'EAI_OVERFLOW' | 'EAI_PROTOCOL' | 'EAI_SERVICE' | 'EAI_SOCKTYPE'
        | 'EALREADY' | 'EBADF' | 'EBUSY' | 'ECANCELED' | 'ECHARSET' | 'ECONNABORTED'
        | 'ECONNREFUSED' | 'ECONNRESET' | 'EDESTADDRREQ' | 'EEXIST' | 'EFAULT' | 'EFBIG'
        | 'EHOSTUNREACH' | 'EINTR' | 'EINVAL' | 'EIO' | 'EISCONN' | 'EISDIR' | 'ELOOP'
        | 'EMFILE' | 'EMSGSIZE' | 'ENAMETOOLONG' | 'ENETDOWN' | 'ENETUNREACH' | 'ENFILE'
        | 'ENOBUFS' | 'ENODEV' | 'ENOENT' | 'ENOMEM' | 'ENONET' | 'ENOPROTOOPT' | 'ENOSPC'
        | 'ENOSYS' | 'ENOTCONN' | 'ENOTDIR' | 'ENOTEMPTY' | 'ENOTSOCK' | 'ENOTSUP'
        | 'EOVERFLOW' | 'EPERM' | 'EPIPE' | 'EPROTO' | 'EPROTONOSUPPORT' | 'EPROTOTYPE'
        | 'ERANGE' | 'EROFS' | 'ESHUTDOWN' | 'ESPIPE' | 'ESRCH' | 'ETIMEDOUT' | 'ETXTBSY'
        | 'EXDEV' | 'UNKNOWN' | 'EOF' | 'ENXIO' | 'EMLINK' | 'EHOSTDOWN' | 'EREMOTEIO'
        | 'ENOTTY' | 'EFTYPE' | 'EILSEQ' | 'ESOCKTNOSUPPORT' | 'ENODATA' | 'EUNATCH' | 'ENOEXEC';

    export const errno: Readonly<Record<ErrnoName, number>>;

    /**
     * Structured I/O error from the native layer.
     * `name` is always `"IOError"`; `code` is a UV errno (e.g. `errno.EOF`).
     * Callable both as `Error(code)` and `new Error(code)`.
     */
    export interface Error extends globalThis.Error {
        name: 'IOError';
        /** UV errno (negative int), e.g. `errno.EPIPE`. */
        code: number;
    }

    export interface ErrorConstructor {
        (code: number): Error;
        new (code: number): Error;
        prototype: Error;
    }

    export const Error: ErrorConstructor;

    /**
     * Returns a string describing a uv errno code.
     *
     * With no argument, or when the argument cannot be converted to an int32,
     * the native implementation falls back to the current C `errno`.
     *
     * @param errno The error code to describe.
     * @throws {TypeError} if the given error code is not a system error code.
     */
    export function strerror(errno?: number): string;

    /** Return libuv's description directly, without an error-name prefix. */
    export function getErrorMessage(errno: number): string;

    /** Return libuv's canonical name or its unknown-error fallback. */
    export function getErrorName(errno: number): string;

}
