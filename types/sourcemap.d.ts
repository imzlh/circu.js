/**
 * SourceMap module - Source map handling for debugging
 * 
 * @example
 * const sourcemap = import.meta.use('sourcemap');
 * 
 * if (sourcemap.has('bundle.js')) {
 *   const result = sourcemap.getMapping('bundle.js', 10, 5);
 *   console.log(result.original_file, result.original_line);
 * }
 */
declare namespace CModuleSourceMap {
    export interface MappingResult {
        /** Original file name */
        original_file: string;
        /** Original line number */
        original_line: number;
        /** Original column number */
        original_column: number;
        /** Function name */
        function_name: string;
        /** Whether mapping was found */
        found: boolean;
    }

    /**
     * Check if specified file has SourceMap
     * @param file_path File path
     * @returns Whether SourceMap exists
     */
    export function has(file_path: string): boolean;

    /**
     * Load SourceMap from an object, JSON string, or UTF-8 JSON bytes.
     * @param file_path File path
     * @param sourcemap SourceMap object or serialized JSON
     * @returns Operation result code
     */
    export function load(file_path: string, sourcemap: object | string | ArrayBuffer | ArrayBufferView): number;

    /**
     * Get source mapping info
     * @param file_path File path
     * @param line Compiled code line number
     * @param column Compiled code column number
     * @returns Mapping result object
     */
    export function getMapping(file_path: string, line: number, column: number): MappingResult;

    /**
     * Remove SourceMap for specified file
     * @param file_path File path
     * @returns Whether removal succeeded
     */
    export function remove(file_path: string): boolean;
}
