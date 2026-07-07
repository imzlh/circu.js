/**
 * Node-API native addon loader.
 */

declare namespace CModuleNodeApi {
    /**
     * Load a Node-API `.node` addon and return its exports object.
     */
    export function dlopen(path: string): unknown;
}
