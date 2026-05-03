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

    export class Error extends globalThis.Error {
        /**
         * ERRNO code, mostly for syscall results.
         */
        code: number;
    }

    /**
     * Returns a string describing the given error code (uv errno)
     * @param errno The error code to describe.
     * @throws {TypeError} if the given error code is not a system error code.
     */
    export function strerror(errno: number): string;
}