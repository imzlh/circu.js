/**
 * Windows-only bindings: Registry + System Certificates
 *
 * On non-Windows platforms the module is a no-op stub.
 *
 * @example Get system HTTP proxy
 * ```ts
 * const { HKCU, readRegistry } = import.meta.use('win32');
 * const proxy = readRegistry(HKCU,
 *     'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
 *     'ProxyServer');
 * // → "host:port" or "http=host:port;https=host:port"
 * ```
 *
 * @example Get system DNS servers (per adapter, from DHCP)
 * ```ts
 * // Enumerate under HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
 * const dns = readRegistry(HKLM,
 *     'SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters',
 *     'DhcpNameServer');
 * // → "8.8.8.8 8.8.4.4" (space-separated)
 * ```
 *
 * @example Load system root CAs into OpenSSL / TLS context
 * ```ts
 * const pems = exportCerts('ROOT');  // array of PEM strings
 * const caBundle = pems.join('\n');
 * // write caBundle to a temp file and pass to tls.createContext / curl / etc.
 * ```
 */
declare namespace CModuleWin32 {
    /** Handle returned by {@link Win32Module.watchRegistry}. */
    interface RegWatch {
        /**
         * Stop watching and release all resources.
         * Safe to call multiple times. Must NOT be called from within the callback.
         */
        close(): void;
        /**
         * Unref the underlying libuv handle so it does not prevent the process from exiting.
         * The watcher continues to fire callbacks but will not keep the event loop alive.
         */
        unref(): void;
    }

    /** Registry value types that can be read and written. */
    type RegValue =
        | string       // REG_SZ / REG_EXPAND_SZ
        | number       // REG_DWORD (uint32)
        | Uint8Array   // REG_BINARY
        | string[];    // REG_MULTI_SZ

    // ── HKEY predefined root handles ─────────────────────────────────────────
    /** HKEY_CLASSES_ROOT */
    export const HKCR: number;
    /** HKEY_CURRENT_USER */
    export const HKCU: number;
    /** HKEY_LOCAL_MACHINE */
    export const HKLM: number;
    /** HKEY_USERS */
    export const HKU: number;
    /** HKEY_CURRENT_CONFIG */
    export const HKCC: number;

    // ── Registry ──────────────────────────────────────────────────────────────

    /**
     * Read a single registry value.
     *
     * Return type mirrors the registry type:
     * - `REG_SZ` / `REG_EXPAND_SZ` → `string`
     * - `REG_DWORD` → `number`
     * - `REG_QWORD` → `number` (JS float64; exact up to 2^53)
     * - `REG_MULTI_SZ` → `string[]`
     * - `REG_BINARY` / other → `Uint8Array`
     *
     * @param hive  Root handle, e.g. `HKCU`
     * @param key   Subkey path, e.g. `'Software\\MyApp'`
     * @param name  Value name
     *
     * @example
     * ```ts
     * const enabled = readRegistry(HKCU,
     *     'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
     *     'ProxyEnable') as number;  // 0 or 1
     * ```
     */
    export function readRegistry(hive: number, key: string, name: string): RegValue;

    /**
     * Write a registry value. The registry type is inferred from the JS type:
     * - `string` → `REG_SZ`
     * - `number` → `REG_DWORD`
     * - `Uint8Array` → `REG_BINARY`
     *
     * The key must already exist; this does not create subkeys.
     *
     * @example
     * ```ts
     * writeRegistry(HKCU, 'Software\\MyApp', 'LastRun', Date.now().toString());
     * ```
     */
    export function writeRegistry(hive: number, key: string, name: string, value: string | number | Uint8Array): void;

    /**
     * Delete a registry value (not a key).
     */
    export function delRegistry(hive: number, key: string, name: string): void;

    /**
     * Watch a registry key for any value changes.
     * The callback is invoked on the JS event loop whenever the key or its
     * values change. Call `.close()` on the returned handle to stop watching.
     *
     * Watching is recursive (subkeys included).
     *
     * @example Watch proxy settings
     * ```ts
     * const watcher = watchRegistry(HKCU,
     *     'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
     *     () => { console.log('Proxy settings changed'); });
     *
     * // later…
     * watcher.close();
     * ```
     */
    export function watchRegistry(hive: number, key: string, callback: () => void): RegWatch;

    // ── Certificates ──────────────────────────────────────────────────────────

    /**
     * Enumerate certificates from a Windows system store and return them as
     * PEM strings (`-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----`).
     *
     * Common store names:
     * - `"ROOT"` — Trusted Root CAs (default)
     * - `"CA"`   — Intermediate CAs
     * - `"MY"`   — Personal certificates (with private keys)
     *
     * @example Feed into a TLS context
     * ```ts
     * const caBundle = exportCerts('ROOT').join('\n');
     * // pass caBundle to whatever TLS library you use
     * ```
     */
    export function exportCerts(storeName?: 'ROOT' | 'CA' | 'MY' | string): string[];
}