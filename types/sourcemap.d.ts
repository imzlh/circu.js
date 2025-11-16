
/**
 * SourceMap 模块
 */
declare namespace CModuleSourceMap {
    interface MappingResult {
        /** 原始文件名 */
        original_file: string;
        /** 原始行号 */
        original_line: number;
        /** 原始列号 */
        original_column: number;
        /** 函数名 */
        function_name: string;
        /** 是否找到映射 */
        found: boolean;
    }

    /**
     * 检查指定文件是否有 SourceMap
     * @param file_path 文件路径
     * @returns 是否有 SourceMap
     */
    export function has(file_path: string): boolean;

    /**
     * 从 JavaScript 对象加载 SourceMap
     * @param file_path 文件路径
     * @param sourcemap_obj SourceMap 对象
     * @returns 操作结果代码
     */
    export function load(file_path: string, sourcemap_obj: any): number;

    /**
     * 从 JSON 字符串加载 SourceMap
     * @param file_path 文件路径
     * @param json_str SourceMap 的 JSON 字符串
     * @returns 操作结果代码
     */
    export function loadJSON(file_path: string, json_str: string): number;

    /**
     * 获取源码映射信息
     * @param file_path 文件路径
     * @param line 编译后代码的行号
     * @param column 编译后代码的列号
     * @returns 映射结果对象
     */
    export function get(file_path: string, line: number, column: number): MappingResult;

    /**
     * 移除指定文件的 SourceMap
     * @param file_path 文件路径
     * @returns 是否成功移除
     */
    export function remove(file_path: string): boolean;
}