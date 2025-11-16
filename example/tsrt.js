/**
 * Circu.js TypeScript Runtime (tsrt.js) - Final Robust Version
 * 
 * 构建步骤:
 *   esbuild tsrt.js --bundle --target=es2024 --format=esm --outfile=tsrt.js
 *   cjsc -b cjs -s -e tsrt.js
 */

import { transform } from '../node_modules/sucrase/dist/esm/index.js';

/** @type {typeof import('../node_modules/sucrase/dist/types/index.d.ts').transform} */
const _transform = transform;

// 模块导入与配置
const { use } = import.meta;
const { onModule } = use('engine');
const { readFile, realpath } = use('fs');
const { decodeString } = use('engine');
const { load: loadSourceMap } = use('sourcemap');
const { args } = use('sys');
const { exit } = use('os');
const console = use('console');

// 常量配置
const ALLOWED_EXTENSIONS = ['js', 'ts', 'tsx', 'jsx'];
const CORE_MODULE_PREFIX = '<';

// ============================================================================
// 路径处理工具函数
// ============================================================================

/**
 * 安全获取文件扩展名
 * @param {string} filename 
 * @returns {string|null}
 */
function getExtension(filename) {
    if (!filename || typeof filename !== 'string') return null;
    const match = filename.match(/\.([^.]+)$/);
    return match ? match[1] : null;
}

/**
 * 获取当前工作目录（核心修复点）
 * @returns {string}
 */
function getCurrentDirectory() {
    try {
        return realpath('.');
    } catch (e) {
        return '';
    }
}

/**
 * 规范化路径
 * @param {string} path 
 * @returns {string}
 */
function normalizePath(path) {
    if (!path || typeof path !== 'string') return '.';
    return path
        .replace(/\\/g, '/')
        .replace(/\/+/g, '/')
        .replace(/\/\.\//g, '/')
        .replace(/\/\.$/, '');
}

/**
 * 安全拼接路径
 * @param {...string} segments 
 * @returns {string}
 */
function joinPath(...segments) {
    const valid = segments.filter(s => s && typeof s === 'string');
    return valid.length ? normalizePath(valid.join('/')) : '.';
}

/**
 * 获取目录名
 * @param {string} path 
 * @returns {string}
 */
function getDirname(path) {
    if (!path || typeof path !== 'string') return '.';
    const normalized = normalizePath(path);
    const lastSlash = normalized.lastIndexOf('/');
    return lastSlash === -1 ? '.' : normalized.substring(0, lastSlash);
}

/**
 * 分离模块名和查询字符串
 * @param {string} name 
 * @returns {{moduleName: string, query: string}}
 */
function parseModuleName(name) {
    if (!name || typeof name !== 'string') return { moduleName: '', query: '' };
    const queryIndex = name.indexOf('?');
    return queryIndex === -1
        ? { moduleName: name, query: '' }
        : { moduleName: name.substring(0, queryIndex), query: name.substring(queryIndex) };
}

// ============================================================================
// 模块解析核心逻辑
// ============================================================================

/**
 * 解析模块到真实路径
 * @param {string} moduleName 
 * @param {string} baseDir 
 * @returns {string}
 */
function resolveModulePath(moduleName, baseDir) {
    const errors = [];
    const tryPath = (path) => {
        try {
            return realpath(path);
        } catch (e) {
            errors.push(`  - ${path}: ${e.message}`);
            return null;
        }
    };

    // 1. 直接解析（如果已有扩展名）
    if (hasExtension(moduleName)) {
        const fullPath = baseDir ? joinPath(baseDir, moduleName) : moduleName;
        const result = tryPath(fullPath);
        if (result) return result;
    }

    // 2. 尝试添加扩展名
    for (const ext of ALLOWED_EXTENSIONS) {
        const fullPath = baseDir 
            ? joinPath(baseDir, `${moduleName}.${ext}`)
            : `${moduleName}.${ext}`;
        const result = tryPath(fullPath);
        if (result) return result;
    }

    // 3. 尝试 index 文件
    for (const ext of ALLOWED_EXTENSIONS) {
        const fullPath = baseDir
            ? joinPath(baseDir, moduleName, `index.${ext}`)
            : joinPath(moduleName, `index.${ext}`);
        const result = tryPath(fullPath);
        if (result) return result;
    }

    throw new Error(`Tried:\n${errors.join('\n')}`);
}

/**
 * 检查是否有允许的后缀
 * @param {string} filename 
 * @returns {boolean}
 */
function hasExtension(filename) {
    const ext = getExtension(filename);
    return ext !== null && ALLOWED_EXTENSIONS.includes(ext);
}

// ============================================================================
// 模块系统配置
// ============================================================================

onModule({
    resolve(name, parent) {
        // 参数验证
        if (!name || typeof name !== 'string') {
            throw new Error(`Invalid module name: ${JSON.stringify(name)}`);
        }
        
        const { moduleName, query } = parseModuleName(name);
        if (!moduleName) {
            throw new Error(`Empty module name in: "${name}"`);
        }
        
        // 核心修复：正确确定基础目录
        let baseDir;
        const isCoreParent = parent.startsWith(CORE_MODULE_PREFIX);
        
        if (isCoreParent) {
            // 从核心模块导入
            if (moduleName.startsWith('./') || moduleName.startsWith('../')) {
                // 相对路径：相对于当前工作目录
                baseDir = getCurrentDirectory();
            } else {
                // 绝对路径或内置模块
                baseDir = '';
            }
        } else {
            // 普通模块：相对于父目录
            baseDir = getDirname(parent);
        }
        
        try {
            const resolvedPath = resolveModulePath(moduleName, baseDir);
            return query ? `${resolvedPath}${query}` : resolvedPath;
        } catch (error) {
            const context = baseDir ? `Base directory: "${baseDir}"` : 'Relative to current directory';
            throw new Error(
                `Cannot resolve module "${name}" from "${parent}"\n` +
                `${context}\n` +
                `${error.message}`
            );
        }
    },
    
    load(resolvedName) {
        if (!resolvedName || typeof resolvedName !== 'string') {
            throw new Error(`Invalid resolved name: ${JSON.stringify(resolvedName)}`);
        }
        
        const realFileName = resolvedName.includes('?') 
            ? resolvedName.substring(0, resolvedName.indexOf('?'))
            : resolvedName;
        
        const content = decodeString(readFile(realFileName));
        const extension = getExtension(realFileName);
        
        // JS文件直接返回
        if (extension === 'js') return content;
        
        // TS/TSX/JSX需要转换
        try {
            const result = _transform(content, {
                filePath: realFileName,
                transforms: ['jsx', 'typescript'],
                jsxRuntime: 'automatic',
                preserveDynamicImport: true,
                production: true,
                sourceMapOptions: { compiledFilename: resolvedName }
            });
            
            if (result.sourceMap) {
                loadSourceMap(resolvedName, result.sourceMap);
            }
            
            return result.code;
        } catch (error) {
            throw new Error(`Transform failed for ${realFileName}: ${error.message}`);
        }
    },
    
    init(name, importMeta) {
        if (!importMeta) return;
        importMeta.name = name;
        importMeta.main = false;
        importMeta.use = use;
    }
});

// ============================================================================
// 应用入口
// ============================================================================

function run() {
    if (args.length < 2) {
        console.log(`Usage: ${args[0]} <entry point> [args...]`);
        exit(1);
    }
    
    const entry = args[1];
    import(entry).catch(error => {
        console.error('Failed to load entry module:', error);
        exit(1);
    });
}

run();