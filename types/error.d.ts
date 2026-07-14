/**
 * Error module - System error codes and error handling.
 *
 * `errno.*` numeric values are libuv UV_* codes: on Unix they are typically
 * `-(platform errno)` (e.g. Linux ESRCH is often -3), not fixed cross-platform
 * constants. Prefer `error.errno.NAME` at runtime over hard-coded numbers.
 * Literals below match libuv's portable fallback table for documentation only.
 */
declare namespace CModuleError {
    export const errno: {
        OK: 0;
        
        EOF: -4095;
        E2BIG: -4093;
        EACCES: -4092;
        EADDRINUSE: -4091;
        EADDRNOTAVAIL: -4090;
        EAFNOSUPPORT: -4089;
        EAGAIN: -4088;
        EALREADY: -4087;
        EBADF: -4086;
        EBUSY: -4085;
        ECANCELED: -4084;
        ECONNABORTED: -4083;
        ECONNREFUSED: -4082;
        EDESTADDRREQ: -4080;
        EEXIST: -4079;
        EFAULT: -4078;
        EHOSTUNREACH: -4077;
        EINTR: -4076;
        EINVAL: -4075;
        EIO: -4074;
        EISCONN: -4073;
        EISDIR: -4072;
        ELOOP: -4071;
        EMFILE: -4070;
        EMSGSIZE: -4069;
        ENAMETOOLONG: -4068;
        ENETDOWN: -4067;
        ENETRESET: -4066;
        ENETUNREACH: -4065;
        ENFILE: -4064;
        ENOBUFS: -4063;
        ENODEV: -4062;
        ENOENT: -4061;
        ENOMEM: -4060;
        ENONET: -4059;
        ENOPROTOOPT: -4058;
        ENOSPC: -4057;
        ENOSYS: -4056;
        ENOTCONN: -4055;
        ENOTDIR: -4054;
        ENOTEMPTY: -4053;
        ENOTSOCK: -4052;
        ENOTSUP: -4051;
        EOPNOTSUPP: -4051;
        EPROTONOSUPPORT: -4049;
        EPROTOTYPE: -4048;
        EPIPE: -4047;
        EROFS: -4046;
        ESHUTDOWN: -4045;
        ESPIPE: -4044;
        ESRCH: -4043;
        ETIMEDOUT: -4042;
        ETXTBSY: -4041;
        EXDEV: -4040;
        EUNATCH: -4039;
        EBADMSG: -4038;
        EIDRM: -4037;
        EMULTIHOP: -4036;
        ENODATA: -4035;
        ENOLINK: -4034;
        ENOMSG: -4033;
        ENOSR: -4032;
        ENOSTR: -4031;
        EOVERFLOW: -4030;
        EPROTO: -4029;
        ETIME: -4028;
        ECONNRESET: -4027;
        EILSEQ: -4026;
        ERANGE: -4025;
        
        UNKNOWN: -1;
        EFBIG: -4010;
        EHOSTDOWN: -4009;
        EREMOTEIO: -4008;
        ENOKEY: -4007;
        EKEYEXPIRED: -4006;
        EKEYREVOKED: -4005;
        EKEYREJECTED: -4004;
        EOWNERDEAD: -4003;
        ENOTRECOVERABLE: -4002;
        ERFKILL: -4001;
        EHWPOISON: -4000;
    };

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
}
