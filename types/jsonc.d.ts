/**
 * JSONC (JSON with Comments) Parser
 * 
 * Note: jsonc is a subset of JSON allowing comments.
 * for example:
 * ```jsonc
 * {
 *   // This is a comment
 *   "name": "John Doe",
 *   "age": 30, // comment can also be here
 *   "city": "New York"
 * }
 * ```
 */
declare namespace CModuleJsonC {
    /**
     * Parse a JSONC (JSON with Comments) string into a JavaScript object.
     * @param text A JSONC string to parse.
     * @returns A JavaScript object.
     */
    export function parse(text: string): any;
}