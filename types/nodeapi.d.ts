/**
 * Node-API native addon loader.
 */

declare namespace CModuleNodeApi {
    /**
     * Load a Node-API `.node` addon and return its exports object.
     */
    function dlopen(path: string): any;
}
