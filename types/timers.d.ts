declare namespace CModuleTimers {
    /**
     * 设置定时器
     * @param func 回调函数
     * @param delay 延迟时间（毫秒）
     * @param args 回调函数参数（可选）
     * @returns 返回定时器ID。
     */
    function setTimeout(func: () => any, delay: number, ...args: any[]): number;

    /**
     * 清除定时器
     * @param timerId 定时器ID
     * @returns 返回 undefined。
     */
    function clearTimeout(timerId: number): void;

    /**
     * 设置间隔定时器
     * @param func 回调函数
     * @param interval 间隔时间（毫秒）
     * @param args 回调函数参数（可选）
     * @returns 返回间隔定时器ID。
     */
    function setInterval(func: () => any, interval: number, ...args: any[]): number;

    /**
     * 清除间隔定时器
     * @param timerId 间隔定时器ID
     * @returns 返回 undefined。
     */
    function clearInterval(timerId: number): void;

    // 导出所有内容
    export {
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval
    };
}
