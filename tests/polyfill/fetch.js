
const { XMLHttpRequest, ResponseType } = use('xhr');
/**
 * Parse XHR response headers string into Headers object
 * @param {string} headerString - Raw header string from getAllResponseHeaders()
 * @returns {Headers} Headers instance
 */
function parseHeaders(headerString) {
    const headers = new Headers();
    if (!headerString) return headers;

    for (const line of headerString.split(/\r\n/)) {
        const index = line.indexOf(':');
        if (index > 0) {
            const name = line.substring(0, index).trim();
            const value = line.substring(index + 1).trim();
            if (name) headers.append(name, value);
        }
    }
    return headers;
}

/**
 * Normalize request body to XHR-compatible format
 * @param {any} body - The request body from Request object
 * @returns {Promise<string|ArrayBuffer|null>} Normalized body for XHR.send()
 */
async function normalizeBody(body) {
    if (body == null) return null;

    if (typeof body === 'string' || body instanceof ArrayBuffer) {
        return body;
    }

    if (body instanceof Uint8Array) {
        return body.buffer;
    }

    // Handle Blob if available
    if (typeof Blob !== 'undefined' && body instanceof Blob) {
        if (typeof FileReader !== 'undefined') {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => resolve(reader.result);
                reader.onerror = () => reject(new Error('Failed to read Blob'));
                reader.readAsArrayBuffer(body);
            });
        }
        return String(body);
    }

    // Handle FormData if available
    if (typeof FormData !== 'undefined' && body instanceof FormData) {
        return body.toString();
    }

    try {
        return JSON.stringify(body);
    } catch {
        return String(body);
    }
}

/**
 * Main fetch implementation using CModuleXHR
 * @param {RequestInfo|URL} input - URL string, URL object, or Request object
 * @param {RequestInit} [init={}] - Optional request configuration
 * @returns {Promise<Response>} Promise resolving to Response object
 */
async function fetch(input, init = {}) {
    const request = new Request(input, init);

    if (request.signal?.aborted) {
        throw new DOMException('The user aborted a request.', 'AbortError');
    }

    const xhr = new XMLHttpRequest();

    return new Promise((resolve, reject) => {
        const cleanup = () => request.signal?.removeEventListener('abort', onAbort);

        const onAbort = () => {
            xhr.abort();
            cleanup();
            reject(new DOMException('The user aborted a request.', 'AbortError'));
        };

        if (request.signal) {
            request.signal.addEventListener('abort', onAbort, { once: true });
        }

        xhr.onerror = () => {
            cleanup();
            reject(new TypeError('Network request failed'));
        };

        xhr.ontimeout = () => {
            cleanup();
            reject(new DOMException('The operation timed out.', 'TimeoutError'));
        };

        xhr.onabort = () => {
            cleanup();
            reject(new DOMException('The user aborted a request.', 'AbortError'));
        };

        xhr.onload = () => {
            cleanup();

            const body = xhr.status !== 204 && xhr.status !== 205 ? xhr.response : null;
            const headers = parseHeaders(xhr.getAllResponseHeaders());

            const response = new Response(body, {
                status: xhr.status,
                statusText: xhr.statusText,
                headers
            });

            Object.defineProperty(response, 'url', {
                value: xhr.responseURL || request.url,
                writable: false,
                enumerable: true,
                configurable: true
            });

            resolve(response);
        };

        (async () => {
            try {
                xhr.open(request.method, request.url, true);

                if (init.timeout) xhr.timeout = init.timeout;

                if (request.credentials === 'include') {
                    xhr.withCredentials = true;
                }

                const accept = request.headers.get('accept');
                if (accept?.includes('application/json')) {
                    xhr.responseType = 'json';
                } else if (accept?.includes('application/octet-stream')) {
                    xhr.responseType = 'arraybuffer';
                } else {
                    xhr.responseType = 'text';
                }

                request.headers.forEach((value, key) => {
                    xhr.setRequestHeader(key, value);
                });

                const body = await normalizeBody(request.body);
                xhr.send(body ?? undefined);
            } catch (err) {
                cleanup();
                reject(err);
            }
        })();
    });
}

// --- Minimal polyfills for fetch API if needed ---

const globalObj = (typeof globalThis !== 'undefined') ? globalThis :
    (typeof global !== 'undefined') ? global :
        (typeof window !== 'undefined') ? window :
            this;

if (typeof Headers === 'undefined') {
    /** Headers class polyfill */
    globalObj.Headers = class Headers {
        constructor(init) {
            this._map = new Map();

            if (init instanceof Headers) {
                init.forEach((value, key) => this.append(key, value));
            } else if (Array.isArray(init)) {
                init.forEach(([key, value]) => this.append(key, value));
            } else if (init && typeof init === 'object') {
                Object.entries(init).forEach(([key, value]) => this.append(key, value));
            }
        }

        append(key, value) {
            key = String(key).toLowerCase();
            value = String(value);
            const existing = this._map.get(key);
            this._map.set(key, existing ? `${existing}, ${value}` : value);
        }

        delete(key) {
            this._map.delete(String(key).toLowerCase());
        }

        get(key) {
            return this._map.get(String(key).toLowerCase()) ?? null;
        }

        has(key) {
            return this._map.has(String(key).toLowerCase());
        }

        set(key, value) {
            this._map.set(String(key).toLowerCase(), String(value));
        }

        forEach(callback, thisArg) {
            this._map.forEach((value, key) => callback.call(thisArg, value, key, this));
        }
    };
}

if (typeof Request === 'undefined') {
    /** Request class polyfill */
    globalObj.Request = class Request {
        constructor(input, init = {}) {
            if (input instanceof Request) {
                this.method = init.method ?? input.method;
                this.url = input.url;
                this.headers = init.headers ? new Headers(init.headers) : input.headers;
                this.body = init.body ?? input.body;
                this.signal = init.signal ?? input.signal;
                this.credentials = init.credentials ?? input.credentials;
            } else {
                this.method = init.method ?? 'GET';
                this.url = String(input);
                this.headers = new Headers(init.headers);
                this.body = init.body;
                this.signal = init.signal;
                this.credentials = init.credentials ?? 'same-origin';
            }
        }
    };
}

if (typeof Response === 'undefined') {
    /** Response class polyfill with text() support */
    globalObj.Response = class Response {
        constructor(body, options = {}) {
            this.status = options.status ?? 200;
            this.statusText = options.statusText ?? 'OK';
            this.headers = options.headers ?? new Headers();
            this.ok = this.status >= 200 && this.status < 300;
            this._body = body;
            this._bodyUsed = false;
            this.url = options.url ?? '';
        }

        get bodyUsed() {
            return this._bodyUsed;
        }

        /**
         * Read response body as text - key requirement
         * @returns {Promise<string>} Resolves to response text
         */
        async text() {
            if (this._bodyUsed) {
                throw new TypeError('Body already read');
            }
            this._bodyUsed = true;

            if (this._body === null) return '';

            if (typeof this._body === 'string') {
                return this._body;
            }

            if (this._body instanceof ArrayBuffer) {
                const decoder = new TextDecoder();
                return decoder.decode(this._body);
            }

            if (typeof this._body === 'object') {
                return JSON.stringify(this._body);
            }

            return String(this._body);
        }

        async json() {
            const text = await this.text();
            return JSON.parse(text);
        }

        async arrayBuffer() {
            if (this._bodyUsed) {
                throw new TypeError('Body already read');
            }
            this._bodyUsed = true;

            if (this._body === null) return new ArrayBuffer(0);

            if (this._body instanceof ArrayBuffer) return this._body;

            if (typeof this._body === 'string') {
                const encoder = new TextEncoder();
                return encoder.encode(this._body).buffer;
            }

            throw new TypeError('Cannot convert body to ArrayBuffer');
        }
    };
}

if (typeof DOMException === 'undefined') {
    /** DOMException polyfill */
    globalObj.DOMException = class DOMException extends Error {
        constructor(message, name) {
            super(message);
            this.name = name;
        }
    };
}

if (!globalObj.fetch) {
    globalObj.fetch = fetch;
}
export default fetch;