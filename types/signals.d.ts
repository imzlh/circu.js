declare namespace CModuleSignals {
    /**
     * Signals 模块
     */

    /**
     * 信号处理对象
     */
    interface SignalHandler {
        /**
         * 关闭信号处理对象
         * @returns 返回一个 Promise，解析为 undefined。
         */
        close(): Promise<void>;

        /**
         * 获取信号名称
         * @returns 返回信号名称字符串或 null 如果信号编号为 0。
         */
        readonly signal: string | null;

        /**
         * SignalHandler 对象的类型标签
         */
        readonly [Symbol.toStringTag]: 'Signal Handler';
    }

    /**
     * 创建信号处理对象
     * @param sig_num 信号编号
     * @param func 信号处理函数
     * @returns 返回一个 Promise，解析为 SignalHandler 对象。
     */
    function signal(sig_num: number, func: () => void): Promise<SignalHandler>;

    /**
     * 信号常量对象
     */
    interface Signals {
        [signalName: string]: number;
    }

    /**
     * 信号常量
     */
    const signals: Signals;

    // 导出所有内容
    export {
        SignalHandler,
        signal,
        signals
    };
}
