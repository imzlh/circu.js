declare namespace CModuleFSWatch {
    /**
     * 文件系统事件类型枚举
     */
    const enum FsEvent {
        /** 文件被重命名 */
        RENAME = 'rename',
        /** 文件内容被更改 */
        CHANGE = 'change'
    }

    /**
     * 文件系统监视器对象
     */
    interface FsWatcher {
        /**
         * 关闭文件系统监视器。
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 获取被监视的文件或目录路径。
         */
        readonly path: string;

        /**
         * 文件系统监视器对象的类型标签。
         */
        readonly [Symbol.toStringTag]: 'FsWatcher';
    }

    /**
     * 启动文件系统监视器。
     * @param path 要监视的文件或目录路径。
     * @param callback 事件处理回调函数。
     * @returns 返回一个 Promise，解析为 FsWatcher 对象。
     */
    function watch(path: string, callback: (filename: string, event: FsEvent) => void): Promise<FsWatcher>;

    // 导出所有内容
    export {
        FsEvent,
        FsWatcher,
        watch
    };
}
