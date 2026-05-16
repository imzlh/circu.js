/**
 * JSONC module - JSON with Comments parser
 * Supports JSON files with single-line (//) and multi-line (/* * /) comments
 */
declare namespace CModuleJsonC {
    /**
     * Parse a JSONC (JSON with Comments) string into a JavaScript object.
     * @param text A JSONC string to parse.
     * @returns A JavaScript object.
     */
    export function parse(text: string): any;
}