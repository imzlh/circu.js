/**
 * SourceMap module - Source map handling for debugging
 * 
 * @example
 * const sourcemap = import.meta.use('sourcemap');
 * 
 * if (sourcemap.has('bundle.js')) {
 *   const result = sourcemap.get('bundle.js', 10, 5);
 *   console.log(result.original_file, result.original_line);
 * }
 */
declare namespace CModuleSourceMap {
    interface MappingResult {
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
     * Load SourceMap from JavaScript object
     * @param file_path File path
     * @param sourcemap_obj SourceMap object
     * @returns Operation result code
     */
    export function load(file_path: string, sourcemap_obj: any): number;

    /**
     * Load SourceMap from JSON string
     * @param file_path File path
     * @param json_str SourceMap JSON string
     * @returns Operation result code
     */
    export function loadJSON(file_path: string, json_str: string): number;

    /**
     * Get source mapping info
     * @param file_path File path
     * @param line Compiled code line number
     * @param column Compiled code column number
     * @returns Mapping result object
     */
    export function get(file_path: string, line: number, column: number): MappingResult;

    /**
     * Remove SourceMap for specified file
     * @param file_path File path
     * @returns Whether removal succeeded
     */
    export function remove(file_path: string): boolean;
}