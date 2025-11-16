/**
 * circu.js 静态文件服务器
 * 基于ServerResponseFile封装，支持压缩、缓存、目录浏览
 */

import { FileResponse } from './http';
import { STATUS, MIMEMAP } from './define';
import { URL } from './imports';
const { encodeString } = import.meta.use('engine');
const $fs = import.meta.use('asyncfs');
const console = import.meta.use('console');
const { DEFAULT_COMPRESSION, DEFAULT_STRATEGY, deflate } = import.meta.use('zlib');

// ============================================================================
// 类型定义
// ============================================================================

interface StaticFileOptions {
    /** 网站根目录（绝对路径） */
    root: string;
    /** 允许目录浏览 */
    directoryListing?: boolean;
    /** 索引文件列表 */
    indexFiles?: string[];
    /** 缓存时间（秒） */
    cacheControl?: number;
    /** 启用压缩（gzip/deflate） */
    compress?: boolean | 'gzip' | 'deflate';
    /** 压缩级别（0-9） */
    compressLevel?: number;
    /** 压缩策略 */
    compressStrategy?: number;
    /** 支持范围请求 */
    range?: boolean;
    /** 自定义404处理器 */
    on404?: (req: CModuleServer.HttpRequest, res: CModuleServer.HttpResponse) => void;
    /** 访问日志回调 */
    onAccess?: (info: { method: string; url: string; status: number; size: number; duration: number }) => void;
}

// ============================================================================
// 主函数：创建静态文件服务器中间件
// ============================================================================

export function createStaticFileServer(options: StaticFileOptions) {
    const {
        root,
        directoryListing = false,
        indexFiles = ['index.html', 'index.htm'],
        cacheControl = 3600,
        compress = true,
        compressLevel = DEFAULT_COMPRESSION,
        compressStrategy = DEFAULT_STRATEGY,
        range = true,
        on404,
        onAccess
    } = options;

    // 确保root以/结尾
    const $normalizedRoot = root.endsWith('/') ? root : root + '/';

    return async (req: CModuleServer.HttpRequest, res: CModuleServer.HttpResponse) => {
        const $startTime = Date.now();

        try {
            // 解析URL路径
            const $urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
            const $filePath = $normalizedRoot + $urlPath.substring(1); // 移除开头的/

            // 安全检查：防止目录遍历攻击
            if ($filePath.includes('/../') || !$filePath.startsWith($normalizedRoot)) {
                res.send(403, STATUS[403]);
                logAccess(403, 0);
                return;
            }

            // 获取文件状态
            const $stat = await $fs.stat($filePath).catch(() => null);

            // 文件不存在
            if (!$stat) {
                // 检查是否为目录（缺少尾部斜杠）
                const $dirPath = $filePath.endsWith('/') ? $filePath.slice(0, -1) : $filePath;
                const $dirStat = await $fs.stat($dirPath).catch(() => null);

                if ($dirStat?.isDirectory) {
                    // 重定向到带斜杠的URL
                    const $redirectUrl = $urlPath.endsWith('/') ? $urlPath : $urlPath + '/';
                    res.writeHead(302, { location: $redirectUrl });
                    res.end();
                    logAccess(302, 0);
                    return;
                }

                // 404处理
                handle404();
                return;
            }

            // 处理目录
            if ($stat.isDirectory) {
                // 查找索引文件
                for (const $index of indexFiles) {
                    const $indexPath = `${$filePath}${$filePath.endsWith('/') ? '' : '/'}${$index}`;
                    const $indexStat = await $fs.stat($indexPath).catch(() => null);

                    if ($indexStat?.isFile) {
                        await serveFile($indexPath, $indexStat);
                        return;
                    }
                }

                // 目录浏览
                if (directoryListing) {
                    await serveDirectory($filePath, $urlPath);
                    return;
                }

                // 禁止访问目录
                res.send(403, STATUS[403]);
                logAccess(403, 0);
                return;
            }

            // 处理文件
            await serveFile($filePath, $stat);

        } catch (error) {
            console.error('Static file server error:', error);
            res.send(500, STATUS[500]);
            logAccess(500, 0);
        }

        // ============================================================================
        // 内部辅助函数
        // ============================================================================

        async function serveFile(filePath: string, stat: CModuleAsyncFS.StatResult) {
            const $response = new FileResponse(res);

            // 设置标准头
            $response.setHeader('cache-control', `public, max-age=${cacheControl}`);

            // ETag：size-mtime
            const $etag = `"${stat.size}-${stat.mtime.getTime()}"`;
            $response.setHeader('etag', $etag);

            // Last-Modified
            $response.setHeader('last-modified', stat.mtime.toUTCString());

            // Content-Type
            const $ext = filePath.split('.').pop()?.toLowerCase() || '';
            const $mime = MIMEMAP[$ext] || 'application/octet-stream';
            $response.setHeader('content-type', $mime);

            // 304 Not Modified
            const $ifNoneMatch = req.headers['if-none-match'];
            if ($ifNoneMatch === $etag) {
                res.writeHead(304, $response['$compileHeaders']());
                res.end();
                logAccess(304, 0);
                return;
            }

            // If-Modified-Since
            const $ifModifiedSince = req.headers['if-modified-since'];
            if ($ifModifiedSince) {
                const $clientTime = new Date($ifModifiedSince).getTime();
                const $serverTime = stat.mtime.getTime();
                if ($clientTime >= $serverTime) {
                    res.writeHead(304, $response['$compileHeaders']());
                    res.end();
                    logAccess(304, 0);
                    return;
                }
            }

            // Accept-Encoding协商
            const $acceptEncoding = req.headers['accept-encoding'] || '';
            let $useCompress = compress;
            let $encoding: 'gzip' | 'deflate' | null = null;

            if (compress && shouldCompress($ext)) {
                if ($acceptEncoding.includes('gzip') && (compress === true || compress === 'gzip')) {
                    $encoding = 'gzip';
                    $response.setHeader('content-encoding', 'gzip');
                } else if ($acceptEncoding.includes('deflate') && (compress === true || compress === 'deflate')) {
                    $encoding = 'deflate';
                    $response.setHeader('content-encoding', 'deflate');
                } else {
                    $useCompress = false;
                }
            }

            // 范围请求
            let $range = undefined;
            if (range && req.headers['range']) {
                const $rangeHeader = req.headers['range'];
                const $match = $rangeHeader.match(/bytes=(\d+)-(\d*)/);
                if ($match) {
                    const $start = parseInt($match[1]!);
                    const $end = $match[2] ? parseInt($match[2]) : stat.size - 1;
                    $range = { start: $start!, end: $end };

                    $response.setHeader('content-range', `bytes ${$start}-${$end}/${stat.size}`);
                    $response.setHeader('content-length', ($end - $start + 1).toString());
                    res.writeHead(206, $response['$compileHeaders']());
                }
            }

            // 发送文件
            // @ts-ignore
            await $response.send({
                path: filePath,
                compress: $encoding || $useCompress,
                compressLevel,
                compressStrategy,
                range: $range,
                onProgress: (sent, total) => {
                    // 实时日志
                }
            });

            logAccess($range ? 206 : 200, stat.size);
        }

        async function serveDirectory(dirPath: string, urlPath: string) {
            const $dir = await $fs.readDir(dirPath);
            const $items: string[] = [];

            // 上级目录
            if (urlPath !== '/') {
                $items.push(`<a href="../">../</a>`);
            }

            // 目录项
            for await (const $entry of $dir) {
                const $name = $entry.name;
                const $isDir = $entry.isDirectory;
                const $displayName = $isDir ? `${$name}/` : $name;
                const $link = encodeURIComponent($name) + ($isDir ? '/' : '');
                $items.push(`<a href="${$link}">${$displayName}</a>`);
            }

            const $html = `<!DOCTYPE html>
<html>
<head><title>Index of ${urlPath}</title><meta charset="utf-8"></head>
<body>
<h1>Index of ${urlPath}</h1>
<hr>
<pre>${$items.join('\n')}</pre>
<hr>
</body>
</html>`;

            res.writeHead(200, {
                'content-type': 'text/html; charset=utf-8',
                'cache-control': 'no-cache'
            });
            res.end(encodeString($html).buffer);

            logAccess(200, $html.length);
        }

        function handle404() {
            if (on404) {
                on404(req, res);
            } else {
                res.send(404, STATUS[404]);
            }
            logAccess(404, 0);
        }

        function logAccess(status: number, size: number) {
            if (onAccess) {
                const $duration = Date.now() - $startTime;
                onAccess({
                    method: req.method,
                    url: req.url,
                    status,
                    size,
                    duration: $duration
                });
            }
        }

        function shouldCompress(ext: string): boolean {
            const $noCompress = [
                'zip', 'rar', '7z', 'gz', 'bz2', 'xz',
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'jxl',
                'mp4', 'mp3', 'webm', 'ogg', 'mov', 'avi',
                'pdf', 'woff', 'woff2', 'eot', 'ttf'
            ];
            return !$noCompress.includes(ext);
        }
    };
}