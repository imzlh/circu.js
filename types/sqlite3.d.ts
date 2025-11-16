declare namespace CModuleSQLite3 {
    /**
     * SQLite 数据库连接句柄
     * 封装了SQLite数据库连接，通过 open() 方法创建
     */
    export class Sqlite3Handle {
        /** @internal 内部实现的私有句柄 */
        private constructor();
    }

    /**
     * SQLite 预处理语句句柄
     * 封装了预编译的SQL语句，通过 prepare() 方法创建
     */
    export class Sqlite3Stmt {
        /** @internal 内部实现的私有语句对象 */
        private constructor();
    }

    // 核心函数定义
    /**
     * 打开数据库连接
     * @param filename 数据库文件名（支持":memory:"内存数据库）
     * @param flags 打开标志组合（使用 SQLITE_OPEN_* 常量）
     * @throws 当打开失败时抛出错误
     */
    export function open(filename: string, flags: number): Sqlite3Handle;

    /**
     * 加载SQLite扩展
     * @param db 数据库连接句柄
     * @param file 扩展文件路径
     * @param procName 可选入口函数名（默认自动推断）
     * @throws 加载失败时抛出错误
     */
    export function load_extension(db: Sqlite3Handle, file: string, procName?: string): void;

    /**
     * 关闭数据库连接
     * @param db 要关闭的数据库句柄
     * @throws 关闭失败时抛出错误
     */
    export function close(db: Sqlite3Handle): void;

    /**
     * 执行SQL语句（非查询操作）
     * @param db 数据库连接句柄
     * @param sql 要执行的SQL语句
     * @throws 执行失败时抛出错误
     */
    export function exec(db: Sqlite3Handle, sql: string): void;

    /**
     * 预处理SQL语句
     * @param db 数据库连接句柄
     * @param sql 要预处理的SQL语句
     * @throws 预处理失败时抛出错误
     */
    export function prepare(db: Sqlite3Handle, sql: string): Sqlite3Stmt;

    /**
     * 检查是否处于事务中
     * @param db 数据库连接句柄
     * @returns 如果在事务中返回 true，否则 false
     */
    export function in_transaction(db: Sqlite3Handle): boolean;

    /**
     * 释放预处理语句资源
     * @param stmt 要释放的语句句柄
     * @throws 释放失败时抛出错误
     */
    export function stmt_finalize(stmt: Sqlite3Stmt): void;

    /**
     * 获取展开后的SQL语句（含绑定参数值）
     * @param stmt 预处理语句句柄
     * @returns 展开后的SQL字符串
     */
    export function stmt_expand(stmt: Sqlite3Stmt): string;

    /**
     * 执行预处理语句并返回所有结果
     * @param stmt 预处理语句句柄
     * @param params 可选绑定参数对象或数组
     * @returns 查询结果数组，每个元素是一个对象，表示行数据
     * @throws 执行失败时抛出错误
     */
    export function stmt_all(stmt: Sqlite3Stmt, params?: object | any[]): Record<string, number | string | Uint8Array | null>[];
    
    /**
     * 执行预处理语句（非查询操作）
     * @param stmt 预处理语句句柄
     * @param params 可选绑定参数对象或数组
     * @throws 执行失败时抛出错误
     */
    export function stmt_run(stmt: Sqlite3Stmt, params?: object | any[]): void;

    export const SQLITE_OPEN_READONLY: number;
    export const SQLITE_OPEN_READWRITE: number;
    export const SQLITE_OPEN_CREATE: number;
}
