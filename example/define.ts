export const STATUS: Record<number, string> = {
    100: "Continue",
    101: "Switching Protocols",
    102: "Processing",  // WebDAV; RFC 2518
    103: "Early Hints",  // RFC 8297

    200: "OK",
    201: "Created",
    202: "Accepted",
    203: "Non-Authoritative Information",  // since HTTP/1.1
    204: "No Content",
    205: "Reset Content",
    206: "Partial Content",  // RFC 7233
    207: "Multi-Status",  // WebDAV; RFC 4918
    208: "Already Reported",  // WebDAV; RFC 5842
    226: "IM Used",  // RFC 3229

    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Found",  // Previously "Moved temporarily"
    303: "See Other",  // since HTTP/1.1
    304: "Not Modified",  // RFC 7232
    305: "Use Proxy",  // since HTTP/1.1
    306: "Switch Proxy",
    307: "Temporary Redirect",  // since HTTP/1.1
    308: "Permanent Redirect",  // RFC 7538

    400: "Bad Request",
    401: "Unauthorized",  // RFC 7235
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",  // RFC 7235
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",  // RFC 7232
    413: "Payload Too Large",  // RFC 7231
    414: "URI Too Long",  // RFC 7231
    415: "Unsupported Media Type",  // RFC 7231
    416: "Range Not Satisfiable",  // RFC 7233
    417: "Expectation Failed",
    418: "I'm a teapot",  // RFC 2324, RFC 7168
    421: "Misdirected Request",  // RFC 7540
    422: "Unprocessable Entity",  // WebDAV; RFC 4918
    423: "Locked",  // WebDAV; RFC 4918
    424: "Failed Dependency",  // WebDAV; RFC 4918
    425: "Too Early",  // RFC 8470
    426: "Upgrade Required",
    428: "Precondition Required",  // RFC 6585
    429: "Too Many Requests",  // RFC 6585
    431: "Request Header Fields Too Large",  // RFC 6585
    451: "Unavailable For Legal Reasons",  // RFC 7725

    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    506: "Variant Also Negotiates",  // RFC 2295
    507: "Insufficient Storage",  // WebDAV; RFC 4918
    508: "Loop Detected",  // WebDAV; RFC 5842
    510: "Not Extended",  // RFC 2774
    511: "Network Authentication Required",  // RFC 6585
};

// MimeTypeEntry 类似地转换为键值对形式的JavaScript对象
const mimeTypes = {
    "text/html": ["html", "htm", "shtml"],
    "text/css": ["css"],
    "text/xml": ["xml"],
    "text/mathml": ["mml"],
    "text/plain": ["txt", "log", "cue", "ini"],
    "text/vnd.sun.j2me.app-descriptor": ["jad"],
    "text/vnd.wap.wml": ["wml"],
    "text/x-component": ["htc"],
    "text/vtt": ["vtt"],
    "text/ass": ["ass"],

    "image/gif": ["gif"],
    "image/jpeg": ["jpeg", "jpg"],
    "image/png": ["png"],
    "image/tiff": ["tif", "tiff"],
    "image/vnd.wap.wbmp": ["wbmp"],
    "image/x-icon": ["ico"],
    "image/x-jng": ["jng"],
    "image/x-ms-bmp": ["bmp"],
    "image/svg+xml": ["svg", "svgz"],
    "image/webp": ["webp"],
    "image/avif": ["avif"],
    "image/jpegxl": ["jxl"],

    "application/javascript": ["js"],
    "application/atom+xml": ["atom"],
    "application/rss+xml": ["rss"],
    "application/font-woff": ["woff"],
    "application/java-archive": ["jar", "war", "ear"],
    "application/json": ["json"],
    "application/mac-binhex40": ["hqx"],
    "application/msword": ["doc"],
    "application/pdf": ["pdf"],
    "application/postscript": ["ps", "eps", "ai"],
    "application/rtf": ["rtf"],
    "application/vnd.apple.mpegurl": ["m3u8"],
    "application/vnd.ms-excel": ["xls"],
    "application/vnd.ms-fontobject": ["eot"],
    "application/vnd.ms-powerpoint": ["ppt"],
    "application/vnd.wap.wmlc": ["wmlc"],
    "application/vnd.google-earth.kml+xml": ["kml"],
    "application/vnd.google-earth.kmz": ["kmz"],
    "application/x-7z-compressed": ["7z"],
    "application/x-cocoa": ["cco"],
    "application/x-java-archive-diff": ["jardiff"],
    "application/x-java-jnlp-file": ["jnlp"],
    "application/x-makeself": ["run"],
    "application/x-perl": ["pl", "pm"],
    "application/x-pilot": ["prc", "pdb"],
    "application/x-rar-compressed": ["rar"],
    "application/x-redhat-package-manager": ["rpm"],
    "application/x-sea": ["sea"],
    "application/x-shockwave-flash": ["swf"],
    "application/x-stuffit": ["sit"],
    "application/x-tcl": ["tcl", "tk"],
    "application/x-x509-ca-cert": ["der", "pem", "crt"],
    "application/x-xpinstall": ["xpi"],
    "application/xhtml+xml": ["xhtml"],
    "application/xspf+xml": ["xspf"],
    "application/zip": ["zip"],

    "application/octet-stream": ["bin", "exe", "dll", "deb", "dmg", "iso", "img", "msi"],

    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],

    "audio/midi": ["mid", "midi", "kar"],
    "audio/mpeg": ["mp3"],
    "audio/ogg": ["ogg", "opus"],
    "audio/x-m4a": ["m4a"],
    "audio/x-realaudio": ["ra"],
    "audio/aac": ["aac"],
    "audio/x-caf": ["caf"],
    "audio/flac": ["flac"],

    "video/3gpp": ["3gpp", "3gp"],
    "video/mp2t": ["ts", "m2ts"],
    "video/mp4": ["mp4"],
    "video/quicktime": ["mov"],
    "video/webm": ["webm", "mkv"],
    "video/x-flv": ["flv"],
    "video/x-m4v": ["m4v"],
    "video/x-mng": ["mng"],
    "video/x-ms-asf": ["asx", "asf"],
    "video/x-ms-wmv": ["wmv"],
    "video/x-msvideo": ["avi"],
    "video/ogg": ["ogv"],
};

const extensionToMime: Record<string, string> = {};
Object.entries(mimeTypes).forEach(([mime, exts]) => {
    exts.forEach(ext => {
        extensionToMime[ext] = mime;
    });
});

export const MIMEMAP = extensionToMime;
export const EXTMAP = mimeTypes as Record<string, string[]>;