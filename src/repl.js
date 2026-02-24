"use strict";
/*
 * Circu.js Read Eval Print Loop
 *
 * Copyright (c) 2025~2026 iz
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
var _TerminalController_tty, _CompletionEngine_instances, _CompletionEngine_getContextWord, _CompletionEngine_getContextObject, _CompletionEngine_enumerateProperties, _CompletionEngine_isWordChar, _CJSRepl_instances, _CJSRepl_history, _CJSRepl_historyIndex, _CJSRepl_clipboard, _CJSRepl_colorizer, _CJSRepl_completer, _CJSRepl_cmd, _CJSRepl_cursorPos, _CJSRepl_multilineExpr, _CJSRepl_braceLevel, _CJSRepl_pstate, _CJSRepl_quoteFlag, _CJSRepl_running, _CJSRepl_term, _CJSRepl_stdin, _CJSRepl_stdout, _CJSRepl_termWidth, _CJSRepl_termCursorX, _CJSRepl_config, _CJSRepl_readlineResolver, _CJSRepl_escState, _CJSRepl_escBuffer, _CJSRepl_evalStartTime, _CJSRepl_readLineLoop, _CJSRepl_readLine, _CJSRepl_readInput, _CJSRepl_handleByte, _CJSRepl_utf8Remaining, _CJSRepl_utf8Acc, _CJSRepl_handleChar, _CJSRepl_processChar, _CJSRepl_processEscSequence, _CJSRepl_executeCommand, _CJSRepl_keyMap, _CJSRepl_lastCommand, _CJSRepl_moveCursor, _CJSRepl_insert, _CJSRepl_deleteChar, _CJSRepl_transpose, _CJSRepl_prevHistory, _CJSRepl_nextHistory, _CJSRepl_complete, _CJSRepl_showCompletions, _CJSRepl_skipWordForward, _CJSRepl_skipWordBack, _CJSRepl_printPrompt, _CJSRepl_update, _CJSRepl_moveToStart, _CJSRepl_printHighlighted, _CJSRepl_handleCommand, _CJSRepl_handleDirective, _CJSRepl_evaluate, _CJSRepl_showHelp, _CJSRepl_print, _CJSRepl_printError, _CJSRepl_alert, _CJSRepl_isWordChar, _CJSRepl_isTrailingSurrogate, _CJSRepl_onExit;
Object.defineProperty(exports, "__esModule", { value: true });
var os = import.meta.use('os');
var streams = import.meta.use('streams');
var signal = import.meta.use('signals');
var engine = import.meta.use('engine');
var console = import.meta.use('console');
// preset some envs
globalThis.console = console;
// ==================== Utilities ====================
var COLOR = {
    reset: '\x1b[0m',
    black: '\x1b[30m', red: '\x1b[31m', green: '\x1b[32m',
    yellow: '\x1b[33m', blue: '\x1b[34m', magenta: '\x1b[35m',
    cyan: '\x1b[36m', white: '\x1b[37m', gray: '\x1b[90m',
    brightRed: '\x1b[91m', brightGreen: '\x1b[92m', brightYellow: '\x1b[93m',
    brightBlue: '\x1b[94m', brightMagenta: '\x1b[95m', brightCyan: '\x1b[96m',
    brightWhite: '\x1b[97m',
};
var STYLE_MAP = {
    default: 'brightGreen', comment: 'gray', string: 'brightCyan',
    regex: 'cyan', number: 'green', keyword: 'brightWhite',
    function: 'brightYellow', type: 'brightMagenta', identifier: 'brightGreen',
    error: 'red', directive: 'gray'
};
var TerminalController = /** @class */ (function () {
    function TerminalController(fd) {
        this.fd = fd;
        _TerminalController_tty.set(this, void 0);
        if (os.guessHandle(fd) === 'tty') {
            __classPrivateFieldSet(this, _TerminalController_tty, new streams.TTY(fd, true), "f");
            __classPrivateFieldGet(this, _TerminalController_tty, "f").setMode(streams.TTY_MODE_RAW);
        }
    }
    Object.defineProperty(TerminalController.prototype, "isTTY", {
        get: function () { return !!__classPrivateFieldGet(this, _TerminalController_tty, "f"); },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(TerminalController.prototype, "size", {
        get: function () {
            if (!__classPrivateFieldGet(this, _TerminalController_tty, "f"))
                return { width: 80, height: 24 };
            return __classPrivateFieldGet(this, _TerminalController_tty, "f").getWinSize();
        },
        enumerable: false,
        configurable: true
    });
    TerminalController.prototype[(_TerminalController_tty = new WeakMap(), Symbol.dispose)] = function () {
        var _a;
        (_a = __classPrivateFieldGet(this, _TerminalController_tty, "f")) === null || _a === void 0 ? void 0 : _a.setMode(streams.TTY_MODE_NORMAL);
    };
    return TerminalController;
}());
function getenv(env) {
    try {
        return os.getenv(env);
    }
    catch (_a) {
        return null;
    }
}
// ==================== Highlighter (Optimized) ====================
var JSColorizer = /** @class */ (function () {
    function JSColorizer() {
        _JSColorizer_instances.add(this);
        _JSColorizer_str.set(this, '');
        _JSColorizer_index.set(this, 0);
        _JSColorizer_length.set(this, 0);
        _JSColorizer_start.set(this, 0);
        _JSColorizer_styles.set(this, []);
        _JSColorizer_stateStack.set(this, '');
        _JSColorizer_braceLevel.set(this, 0);
        _JSColorizer_canBeRegex.set(this, true);
        _JSColorizer_currentStyle.set(this, null);
    }
    JSColorizer.prototype.colorize = function (input, state, level) {
        var _b, _c, _d, _e, _f;
        if (state === void 0) { state = ''; }
        if (level === void 0) { level = 0; }
        __classPrivateFieldSet(this, _JSColorizer_str, input, "f");
        __classPrivateFieldSet(this, _JSColorizer_index, 0, "f");
        __classPrivateFieldSet(this, _JSColorizer_length, input.length, "f");
        __classPrivateFieldSet(this, _JSColorizer_stateStack, state, "f");
        __classPrivateFieldSet(this, _JSColorizer_braceLevel, level, "f");
        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
        __classPrivateFieldSet(this, _JSColorizer_styles, [], "f");
        while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f")) {
            __classPrivateFieldSet(this, _JSColorizer_currentStyle, null, "f");
            __classPrivateFieldSet(this, _JSColorizer_start, __classPrivateFieldGet(this, _JSColorizer_index, "f"), "f");
            var char = __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b = _c++, _c), "f"), _b];
            switch (char) {
                case ' ':
                case '\t':
                case '\r':
                case '\n': continue;
                case '+':
                case '-':
                    if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_peek).call(this) === char)
                        __classPrivateFieldSet(this, _JSColorizer_index, (_d = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _d++, _d), "f");
                    else
                        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
                    continue;
                case '/':
                    if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_peek).call(this) === '*')
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseBlockComment).call(this);
                    else if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_peek).call(this) === '/')
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseLineComment).call(this);
                    else if (__classPrivateFieldGet(this, _JSColorizer_canBeRegex, "f")) {
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseRegex).call(this);
                        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
                    }
                    else {
                        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
                        continue;
                    }
                    break;
                case "'":
                case '"':
                case '`':
                    __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseString).call(this, char);
                    __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
                    break;
                case '(':
                case '[':
                case '{':
                    __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
                    __classPrivateFieldSet(this, _JSColorizer_braceLevel, (_e = __classPrivateFieldGet(this, _JSColorizer_braceLevel, "f"), _e++, _e), "f");
                    __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_pushState).call(this, char);
                    continue;
                case ')':
                case ']':
                case '}':
                    __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
                    if (__classPrivateFieldGet(this, _JSColorizer_braceLevel, "f") > 0 && __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isBalanced).call(this, __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_lastState).call(this), char)) {
                        __classPrivateFieldSet(this, _JSColorizer_braceLevel, (_f = __classPrivateFieldGet(this, _JSColorizer_braceLevel, "f"), _f--, _f), "f");
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_popState).call(this);
                        continue;
                    }
                    __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'error', "f");
                    break;
                default:
                    if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isDigit).call(this, char)) {
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseNumber).call(this);
                        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
                    }
                    else if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isWordChar).call(this, char) || char === '$') {
                        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_parseIdentifier).call(this);
                    }
                    else {
                        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
                        continue;
                    }
            }
            if (__classPrivateFieldGet(this, _JSColorizer_currentStyle, "f"))
                __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_fillStyle).call(this, __classPrivateFieldGet(this, _JSColorizer_start, "f"), __classPrivateFieldGet(this, _JSColorizer_index, "f"));
        }
        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_fillStyle).call(this, __classPrivateFieldGet(this, _JSColorizer_length, "f"), __classPrivateFieldGet(this, _JSColorizer_length, "f"));
        return { state: __classPrivateFieldGet(this, _JSColorizer_stateStack, "f"), level: __classPrivateFieldGet(this, _JSColorizer_braceLevel, "f"), styles: __classPrivateFieldGet(this, _JSColorizer_styles, "f") };
    };
    var _JSColorizer_instances, _a, _JSColorizer_KEYWORDS, _JSColorizer_NO_REGEX, _JSColorizer_DIRECTIVES, _JSColorizer_TYPES, _JSColorizer_str, _JSColorizer_index, _JSColorizer_length, _JSColorizer_start, _JSColorizer_styles, _JSColorizer_stateStack, _JSColorizer_braceLevel, _JSColorizer_canBeRegex, _JSColorizer_currentStyle, _JSColorizer_peek, _JSColorizer_pushState, _JSColorizer_lastState, _JSColorizer_popState, _JSColorizer_isDigit, _JSColorizer_isWordChar, _JSColorizer_isBalanced, _JSColorizer_parseBlockComment, _JSColorizer_parseLineComment, _JSColorizer_parseString, _JSColorizer_parseRegex, _JSColorizer_parseNumber, _JSColorizer_parseIdentifier, _JSColorizer_fillStyle;
    _a = JSColorizer, _JSColorizer_str = new WeakMap(), _JSColorizer_index = new WeakMap(), _JSColorizer_length = new WeakMap(), _JSColorizer_start = new WeakMap(), _JSColorizer_styles = new WeakMap(), _JSColorizer_stateStack = new WeakMap(), _JSColorizer_braceLevel = new WeakMap(), _JSColorizer_canBeRegex = new WeakMap(), _JSColorizer_currentStyle = new WeakMap(), _JSColorizer_instances = new WeakSet(), _JSColorizer_peek = function _JSColorizer_peek() { return __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")]; }, _JSColorizer_pushState = function _JSColorizer_pushState(c) { __classPrivateFieldSet(this, _JSColorizer_stateStack, __classPrivateFieldGet(this, _JSColorizer_stateStack, "f") + c, "f"); }, _JSColorizer_lastState = function _JSColorizer_lastState() { var _b; return (_b = __classPrivateFieldGet(this, _JSColorizer_stateStack, "f").at(-1)) !== null && _b !== void 0 ? _b : ''; }, _JSColorizer_popState = function _JSColorizer_popState() { __classPrivateFieldSet(this, _JSColorizer_stateStack, __classPrivateFieldGet(this, _JSColorizer_stateStack, "f").slice(0, -1), "f"); }, _JSColorizer_isDigit = function _JSColorizer_isDigit(c) { return /[0-9]/.test(c); }, _JSColorizer_isWordChar = function _JSColorizer_isWordChar(c) { return /[a-zA-Z0-9_$]/.test(c); }, _JSColorizer_isBalanced = function _JSColorizer_isBalanced(a, b) {
        return (a === '(' && b === ')') || (a === '[' && b === ']') || (a === '{' && b === '}');
    }, _JSColorizer_parseBlockComment = function _JSColorizer_parseBlockComment() {
        var _b, _c;
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'comment', "f");
        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_pushState).call(this, '/');
        for (__classPrivateFieldSet(this, _JSColorizer_index, (_b = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b++, _b), "f"); __classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f") - 1; __classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _c++, _c), "f")) {
            if (__classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")] === '*' && __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f") + 1] === '/') {
                __classPrivateFieldSet(this, _JSColorizer_index, __classPrivateFieldGet(this, _JSColorizer_index, "f") + 2, "f");
                __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_popState).call(this);
                break;
            }
        }
    }, _JSColorizer_parseLineComment = function _JSColorizer_parseLineComment() {
        var _b, _c;
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'comment', "f");
        for (__classPrivateFieldSet(this, _JSColorizer_index, (_b = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b++, _b), "f"); __classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f") && __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")] !== '\n'; __classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _c++, _c), "f"))
            ;
    }, _JSColorizer_parseString = function _JSColorizer_parseString(delim) {
        var _b, _c, _d;
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'string', "f");
        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_pushState).call(this, delim);
        while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f")) {
            var c = __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b = _c++, _c), "f"), _b];
            if (c === '\n' && delim !== '`') {
                __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'error', "f");
                continue;
            }
            if (c === '\\') {
                if (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f"))
                    __classPrivateFieldSet(this, _JSColorizer_index, (_d = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _d++, _d), "f");
            }
            else if (c === delim) {
                __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_popState).call(this);
                break;
            }
        }
    }, _JSColorizer_parseRegex = function _JSColorizer_parseRegex() {
        var _b, _c, _d, _e, _f;
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'regex', "f");
        __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_pushState).call(this, '/');
        while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f")) {
            var c = __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b = _c++, _c), "f"), _b];
            if (c === '\n') {
                __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'error', "f");
                continue;
            }
            if (c === '\\') {
                if (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f"))
                    __classPrivateFieldSet(this, _JSColorizer_index, (_d = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _d++, _d), "f");
                continue;
            }
            if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_lastState).call(this) === '[') {
                if (c === ']')
                    __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_popState).call(this);
                continue;
            }
            if (c === '[') {
                __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_pushState).call(this, '[');
                if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_peek).call(this) === '[' || __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_peek).call(this) === ']')
                    __classPrivateFieldSet(this, _JSColorizer_index, (_e = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _e++, _e), "f");
                continue;
            }
            if (c === '/') {
                __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_popState).call(this);
                while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f") && __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isWordChar).call(this, __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")]))
                    __classPrivateFieldSet(this, _JSColorizer_index, (_f = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _f++, _f), "f");
                break;
            }
        }
    }, _JSColorizer_parseNumber = function _JSColorizer_parseNumber() {
        var _b;
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'number', "f");
        while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f")) {
            var c = __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")];
            if (__classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isWordChar).call(this, c) || c === '.' || c === '+' || c === '-') {
                if (c === '.' && (__classPrivateFieldGet(this, _JSColorizer_index, "f") === __classPrivateFieldGet(this, _JSColorizer_length, "f") - 1 || __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f") + 1] === '.'))
                    break;
                __classPrivateFieldSet(this, _JSColorizer_index, (_b = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b++, _b), "f");
            }
            else
                break;
        }
    }, _JSColorizer_parseIdentifier = function _JSColorizer_parseIdentifier() {
        var _b, _c;
        if (__classPrivateFieldGet(this, _JSColorizer_start, "f") > 0 && __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_start, "f") - 1] === '.' && __classPrivateFieldGet(this, _JSColorizer_braceLevel, "f") === 0) {
            __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
            while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f") && __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isWordChar).call(this, __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")]))
                __classPrivateFieldSet(this, _JSColorizer_index, (_b = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _b++, _b), "f");
            var word_1 = __classPrivateFieldGet(this, _JSColorizer_str, "f").substring(__classPrivateFieldGet(this, _JSColorizer_start, "f"), __classPrivateFieldGet(this, _JSColorizer_index, "f"));
            if (__classPrivateFieldGet(_a, _a, "f", _JSColorizer_DIRECTIVES).has(word_1)) {
                __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'directive', "f");
                return;
            }
            __classPrivateFieldSet(this, _JSColorizer_index, __classPrivateFieldGet(this, _JSColorizer_start, "f"), "f");
        }
        // Check for keywords
        __classPrivateFieldSet(this, _JSColorizer_canBeRegex, true, "f");
        while (__classPrivateFieldGet(this, _JSColorizer_index, "f") < __classPrivateFieldGet(this, _JSColorizer_length, "f") && __classPrivateFieldGet(this, _JSColorizer_instances, "m", _JSColorizer_isWordChar).call(this, __classPrivateFieldGet(this, _JSColorizer_str, "f")[__classPrivateFieldGet(this, _JSColorizer_index, "f")]))
            __classPrivateFieldSet(this, _JSColorizer_index, (_c = __classPrivateFieldGet(this, _JSColorizer_index, "f"), _c++, _c), "f");
        var word = __classPrivateFieldGet(this, _JSColorizer_str, "f").substring(__classPrivateFieldGet(this, _JSColorizer_start, "f"), __classPrivateFieldGet(this, _JSColorizer_index, "f"));
        if (__classPrivateFieldGet(_a, _a, "f", _JSColorizer_KEYWORDS).has(word)) {
            __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'keyword', "f");
            if (__classPrivateFieldGet(_a, _a, "f", _JSColorizer_NO_REGEX).has(word))
                __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
            return;
        }
        // Check if function call
        var next = __classPrivateFieldGet(this, _JSColorizer_index, "f");
        while (next < __classPrivateFieldGet(this, _JSColorizer_length, "f") && __classPrivateFieldGet(this, _JSColorizer_str, "f")[next] === ' ')
            next++;
        if (__classPrivateFieldGet(this, _JSColorizer_str, "f")[next] === '(') {
            __classPrivateFieldSet(this, _JSColorizer_currentStyle, 'function', "f");
            return;
        }
        __classPrivateFieldSet(this, _JSColorizer_currentStyle, __classPrivateFieldGet(_a, _a, "f", _JSColorizer_TYPES).has(word) ? 'type' : 'identifier', "f");
        if (__classPrivateFieldGet(this, _JSColorizer_currentStyle, "f") === 'identifier')
            __classPrivateFieldSet(this, _JSColorizer_canBeRegex, false, "f");
    }, _JSColorizer_fillStyle = function _JSColorizer_fillStyle(from, to) {
        var _b;
        while (__classPrivateFieldGet(this, _JSColorizer_styles, "f").length < from)
            __classPrivateFieldGet(this, _JSColorizer_styles, "f").push('default');
        while (__classPrivateFieldGet(this, _JSColorizer_styles, "f").length < to)
            __classPrivateFieldGet(this, _JSColorizer_styles, "f").push((_b = __classPrivateFieldGet(this, _JSColorizer_currentStyle, "f")) !== null && _b !== void 0 ? _b : 'default');
    };
    _JSColorizer_KEYWORDS = { value: new Set([
            'break', 'case', 'catch', 'continue', 'debugger', 'default', 'delete', 'do',
            'else', 'finally', 'for', 'function', 'if', 'in', 'instanceof', 'new',
            'return', 'switch', 'this', 'throw', 'try', 'typeof', 'while', 'with',
            'class', 'const', 'enum', 'import', 'export', 'extends', 'super',
            'implements', 'interface', 'let', 'package', 'private', 'protected',
            'public', 'static', 'yield', 'undefined', 'null', 'true', 'false',
            'Infinity', 'NaN', 'eval', 'arguments', 'await', 'async', 'of', 'void'
        ]) };
    _JSColorizer_NO_REGEX = { value: new Set([
            'this', 'super', 'undefined', 'null', 'true', 'false',
            'Infinity', 'NaN', 'arguments'
        ]) };
    _JSColorizer_DIRECTIVES = { value: new Set(['help', 'h', 'x', 'd', 't', 'c', 'q', 'quit', 'u']) };
    _JSColorizer_TYPES = { value: new Set(['void', 'let', 'var', 'const']) };
    return JSColorizer;
}());
// ==================== Completion Engine ====================
var CompletionEngine = /** @class */ (function () {
    function CompletionEngine() {
        _CompletionEngine_instances.add(this);
    }
    CompletionEngine.prototype.getCompletions = function (line, pos) {
        var word = __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_getContextWord).call(this, line, pos);
        var ctxObj = __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_getContextObject).call(this, line, pos - word.length);
        var completions = __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_enumerateProperties).call(this, ctxObj, word);
        return { completions: completions, position: word.length, context: ctxObj };
    };
    return CompletionEngine;
}());
_CompletionEngine_instances = new WeakSet(), _CompletionEngine_getContextWord = function _CompletionEngine_getContextWord(line, pos) {
    var s = '';
    while (pos > 0 && __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_isWordChar).call(this, line[pos - 1]))
        s = line[--pos] + s;
    return s;
}, _CompletionEngine_getContextObject = function _CompletionEngine_getContextObject(line, pos) {
    var _b;
    if (pos <= 0 || ' ~!%^&*(-+={[|:;,<>?/'.includes(line[pos - 1]))
        return globalThis;
    if (line[pos - 1] !== '.')
        return undefined;
    pos--;
    var c = line[pos - 1];
    switch (c) {
        case undefined: return '';
        case "'":
        case '"': return 'a';
        case ']': return [];
        case '}': return {};
        case '/': return / /;
        default:
            if (__classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_isWordChar).call(this, c)) {
                var base = __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_getContextWord).call(this, line, pos);
                if (['true', 'false', 'null', 'this'].includes(base) || !Number.isNaN(+base)) {
                    return eval(base);
                }
                // Check for regex flags
                if (pos - base.length >= 2 && line[pos - base.length - 1] === '/') {
                    return new RegExp('', base);
                }
                var obj = __classPrivateFieldGet(this, _CompletionEngine_instances, "m", _CompletionEngine_getContextObject).call(this, line, pos - base.length);
                if (obj == null)
                    return obj;
                return (_b = obj[base]) !== null && _b !== void 0 ? _b : eval === null || eval === void 0 ? void 0 : eval(base);
            }
            return {};
    }
}, _CompletionEngine_enumerateProperties = function _CompletionEngine_enumerateProperties(obj, prefix) {
    var seen = new Set();
    var results = [];
    for (var i = 0, curr = obj; i < 10 && curr != null; i++, curr = Object.getPrototypeOf(curr)) {
        for (var _i = 0, _b = Object.getOwnPropertyNames(curr); _i < _b.length; _i++) {
            var key = _b[_i];
            if (typeof key === 'string' && !/^\d+$/.test(key) && key.startsWith(prefix) && !seen.has(key)) {
                seen.add(key);
                results.push(key);
            }
        }
    }
    return results.sort(function (a, b) {
        if (a[0] === '_' && b[0] !== '_')
            return 1;
        if (b[0] === '_' && a[0] !== '_')
            return -1;
        return a.localeCompare(b);
    });
}, _CompletionEngine_isWordChar = function _CompletionEngine_isWordChar(c) { return /[a-zA-Z0-9_$]/.test(c); };
// ==================== REPL Core ====================
var CJSRepl = /** @class */ (function () {
    function CJSRepl() {
        var _this = this;
        var _b, _c;
        _CJSRepl_instances.add(this);
        _CJSRepl_history.set(this, []);
        _CJSRepl_historyIndex.set(this, 0);
        _CJSRepl_clipboard.set(this, '');
        _CJSRepl_colorizer.set(this, new JSColorizer());
        _CJSRepl_completer.set(this, new CompletionEngine());
        // State
        _CJSRepl_cmd.set(this, '');
        _CJSRepl_cursorPos.set(this, 0);
        _CJSRepl_multilineExpr.set(this, '');
        _CJSRepl_braceLevel.set(this, 0);
        _CJSRepl_pstate.set(this, '');
        _CJSRepl_quoteFlag.set(this, false);
        _CJSRepl_running.set(this, true);
        // Terminal
        _CJSRepl_term.set(this, void 0);
        _CJSRepl_stdin.set(this, void 0);
        _CJSRepl_stdout.set(this, void 0);
        _CJSRepl_termWidth.set(this, 80);
        _CJSRepl_termCursorX.set(this, 0);
        // Configuration
        _CJSRepl_config.set(this, {
            ps1: (_b = getenv('REPL_PS1')) !== null && _b !== void 0 ? _b : 'cjs > ',
            ps2: (_c = getenv('REPL_PS2')) !== null && _c !== void 0 ? _c : '  ... ',
            showTime: false,
            hexMode: false,
            colors: true,
            utf8: true,
        });
        // Input handling
        _CJSRepl_readlineResolver.set(this, null);
        _CJSRepl_escState.set(this, 'normal');
        _CJSRepl_escBuffer.set(this, '');
        // Performance tracking
        _CJSRepl_evalStartTime.set(this, 0);
        _CJSRepl_utf8Remaining.set(this, 0);
        _CJSRepl_utf8Acc.set(this, 0);
        // ==================== Commands ====================
        _CJSRepl_keyMap.set(this, new Map([
            ['\x01', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, 0, "f"); }], // ^A
            ['\x02', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_moveCursor).call(_this, -1); }], // ^B
            ['\x03', function () { return __awaiter(_this, void 0, void 0, function () {
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0:
                                if (__classPrivateFieldGet(this, _CJSRepl_lastCommand, "f") === '\x03') {
                                    return [2 /*return*/, { type: 'exit' }];
                                }
                                return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.gray + ' ^C (again to exit) ' + COLOR.reset)];
                            case 1:
                                _b.sent();
                                return [2 /*return*/, { type: 'continue' }];
                        }
                    });
                }); }],
            ['\x04', function () { return __awaiter(_this, void 0, void 0, function () {
                    return __generator(this, function (_b) {
                        if (__classPrivateFieldGet(this, _CJSRepl_cmd, "f").length === 0)
                            return [2 /*return*/, { type: 'exit' }];
                        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_deleteChar).call(this, 1);
                        return [2 /*return*/];
                    });
                }); }],
            ['\x05', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").length, "f"); }], // ^E
            ['\x06', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_moveCursor).call(_this, 1); }], // ^F
            ['\x07', function () { }], // ^G
            ['\x08', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_deleteChar).call(_this, -1); }], // ^H
            ['\x7f', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_deleteChar).call(_this, -1); }],
            ['\t', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_complete).call(_this); }], // Tab
            ['\n', function () { return __awaiter(_this, void 0, void 0, function () {
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0: // ^J
                            return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\n')];
                            case 1:
                                _b.sent();
                                __classPrivateFieldGet(this, _CJSRepl_history, "f").push(__classPrivateFieldGet(this, _CJSRepl_cmd, "f"));
                                return [2 /*return*/, { type: 'submit', value: __classPrivateFieldGet(this, _CJSRepl_cmd, "f") }];
                        }
                    });
                }); }],
            ['\x0b', function () {
                    __classPrivateFieldSet(_this, _CJSRepl_clipboard, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(__classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f");
                    __classPrivateFieldSet(_this, _CJSRepl_cmd, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(0, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f");
                }],
            ['\x0d', function () { return __awaiter(_this, void 0, void 0, function () {
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0: // ^M
                            return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\n')];
                            case 1:
                                _b.sent();
                                __classPrivateFieldGet(this, _CJSRepl_history, "f").push(__classPrivateFieldGet(this, _CJSRepl_cmd, "f"));
                                return [2 /*return*/, { type: 'submit', value: __classPrivateFieldGet(this, _CJSRepl_cmd, "f") }];
                        }
                    });
                }); }],
            ['\x0e', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_nextHistory).call(_this); }], // ^N
            ['\x10', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_prevHistory).call(_this); }], // ^P
            ['\x11', function () { __classPrivateFieldSet(_this, _CJSRepl_quoteFlag, true, "f"); }], // ^Q
            ['\x14', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_transpose).call(_this); }], // ^T
            ['\x18', function () { __classPrivateFieldSet(_this, _CJSRepl_cmd, '', "f"); __classPrivateFieldSet(_this, _CJSRepl_cursorPos, 0, "f"); }], // ^X
            ['\x19', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_insert).call(_this, __classPrivateFieldGet(_this, _CJSRepl_clipboard, "f")); }], // ^Y
            // Arrow keys
            ['\x1b[A', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_prevHistory).call(_this); }],
            ['\x1b[B', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_nextHistory).call(_this); }],
            ['\x1b[C', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_moveCursor).call(_this, 1); }],
            ['\x1b[D', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_moveCursor).call(_this, -1); }],
            ['\x1b[H', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, 0, "f"); }], // Home
            ['\x1b[F', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").length, "f"); }], // End
            ['\x1b[3~', function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_deleteChar).call(_this, 1); }], // Delete
            // Word navigation
            ['\x1bb', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordBack).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f"); }],
            ['\x1bf', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordForward).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f"); }],
            ['\x1b[1;5D', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordBack).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f"); }], // Ctrl-Left
            ['\x1b[1;5C', function () { __classPrivateFieldSet(_this, _CJSRepl_cursorPos, __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordForward).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f"); }], // Ctrl-Right
            // Kill operations
            ['\x1bd', function () {
                    var end = __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordForward).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f"));
                    __classPrivateFieldSet(_this, _CJSRepl_clipboard, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(__classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f"), end), "f");
                    __classPrivateFieldSet(_this, _CJSRepl_cmd, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(0, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")) + __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(end), "f");
                }],
            ['\x1b\x7f', function () {
                    var start = __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_skipWordBack).call(_this, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f"));
                    __classPrivateFieldSet(_this, _CJSRepl_clipboard, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(start, __classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f");
                    __classPrivateFieldSet(_this, _CJSRepl_cmd, __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(0, start) + __classPrivateFieldGet(_this, _CJSRepl_cmd, "f").slice(__classPrivateFieldGet(_this, _CJSRepl_cursorPos, "f")), "f");
                    __classPrivateFieldSet(_this, _CJSRepl_cursorPos, start, "f");
                }],
        ]));
        _CJSRepl_lastCommand.set(this, '');
        __classPrivateFieldSet(this, _CJSRepl_stdout, new streams.Pipe(), "f");
        __classPrivateFieldGet(this, _CJSRepl_stdout, "f").open(os.STDOUT_FILENO);
        __classPrivateFieldSet(this, _CJSRepl_term, new TerminalController(os.STDIN_FILENO), "f");
        __classPrivateFieldSet(this, _CJSRepl_termWidth, __classPrivateFieldGet(this, _CJSRepl_term, "f").size.width, "f");
        if (__classPrivateFieldGet(this, _CJSRepl_term, "f").isTTY) {
            __classPrivateFieldSet(this, _CJSRepl_stdin, new streams.TTY(os.STDIN_FILENO, true), "f");
        }
        else {
            __classPrivateFieldSet(this, _CJSRepl_stdin, new streams.Pipe(), "f");
            __classPrivateFieldGet(this, _CJSRepl_stdin, "f").open(os.STDIN_FILENO);
        }
        // Cleanup on exit
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_onExit).call(this, function () {
            __classPrivateFieldGet(_this, _CJSRepl_term, "f")[Symbol.dispose]();
        });
    }
    CJSRepl.prototype.start = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, 'Circu.js REPL. enter ".help" for help.\n')];
                    case 1:
                        _b.sent();
                        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_readInput).call(this);
                        return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_readLineLoop).call(this)];
                    case 2:
                        _b.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    CJSRepl.prototype.handleCtrlC = function () {
        var _this = this;
        if (__classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f")) {
            __classPrivateFieldSet(this, _CJSRepl_cmd, '', "f");
            __classPrivateFieldSet(this, _CJSRepl_cursorPos, 0, "f");
            __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '^C\n').then(function () {
                if (__classPrivateFieldGet(_this, _CJSRepl_readlineResolver, "f"))
                    __classPrivateFieldGet(_this, _CJSRepl_readlineResolver, "f").call(_this, null);
            });
        }
    };
    return CJSRepl;
}());
_CJSRepl_history = new WeakMap(), _CJSRepl_historyIndex = new WeakMap(), _CJSRepl_clipboard = new WeakMap(), _CJSRepl_colorizer = new WeakMap(), _CJSRepl_completer = new WeakMap(), _CJSRepl_cmd = new WeakMap(), _CJSRepl_cursorPos = new WeakMap(), _CJSRepl_multilineExpr = new WeakMap(), _CJSRepl_braceLevel = new WeakMap(), _CJSRepl_pstate = new WeakMap(), _CJSRepl_quoteFlag = new WeakMap(), _CJSRepl_running = new WeakMap(), _CJSRepl_term = new WeakMap(), _CJSRepl_stdin = new WeakMap(), _CJSRepl_stdout = new WeakMap(), _CJSRepl_termWidth = new WeakMap(), _CJSRepl_termCursorX = new WeakMap(), _CJSRepl_config = new WeakMap(), _CJSRepl_readlineResolver = new WeakMap(), _CJSRepl_escState = new WeakMap(), _CJSRepl_escBuffer = new WeakMap(), _CJSRepl_evalStartTime = new WeakMap(), _CJSRepl_utf8Remaining = new WeakMap(), _CJSRepl_utf8Acc = new WeakMap(), _CJSRepl_keyMap = new WeakMap(), _CJSRepl_lastCommand = new WeakMap(), _CJSRepl_instances = new WeakSet(), _CJSRepl_readLineLoop = function _CJSRepl_readLineLoop() {
    return __awaiter(this, void 0, void 0, function () {
        var line, e_1;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 5, , 7]);
                    _b.label = 1;
                case 1:
                    if (!__classPrivateFieldGet(this, _CJSRepl_running, "f")) return [3 /*break*/, 4];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_readLine).call(this)];
                case 2:
                    line = _b.sent();
                    if (line === null)
                        return [3 /*break*/, 4];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleCommand).call(this, line)];
                case 3:
                    _b.sent();
                    return [3 /*break*/, 1];
                case 4: return [3 /*break*/, 7];
                case 5:
                    e_1 = _b.sent();
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_printError).call(this, e_1)];
                case 6:
                    _b.sent();
                    return [3 /*break*/, 7];
                case 7: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_readLine = function _CJSRepl_readLine() {
    var _this = this;
    return new Promise(function (resolve) {
        __classPrivateFieldSet(_this, _CJSRepl_readlineResolver, resolve, "f");
        __classPrivateFieldSet(_this, _CJSRepl_cmd, '', "f");
        __classPrivateFieldSet(_this, _CJSRepl_cursorPos, 0, "f");
        __classPrivateFieldSet(_this, _CJSRepl_historyIndex, __classPrivateFieldGet(_this, _CJSRepl_history, "f").length, "f");
        __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_printPrompt).call(_this).then(function () { return __classPrivateFieldGet(_this, _CJSRepl_instances, "m", _CJSRepl_update).call(_this); });
    });
}, _CJSRepl_readInput = function _CJSRepl_readInput() {
    return __awaiter(this, void 0, void 0, function () {
        var buf, n, i;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    buf = new Uint8Array(256);
                    _b.label = 1;
                case 1:
                    if (!__classPrivateFieldGet(this, _CJSRepl_running, "f")) return [3 /*break*/, 3];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_stdin, "f").read(buf)];
                case 2:
                    n = _b.sent();
                    if (!n)
                        return [3 /*break*/, 1];
                    for (i = 0; i < n; i++) {
                        if (!__classPrivateFieldGet(this, _CJSRepl_running, "f"))
                            return [2 /*return*/];
                        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleByte).call(this, buf[i]);
                    }
                    return [3 /*break*/, 1];
                case 3: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_handleByte = function _CJSRepl_handleByte(byte) {
    var _b;
    if (!__classPrivateFieldGet(this, _CJSRepl_config, "f").utf8) {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleChar).call(this, byte);
        return;
    }
    // UTF-8 decode
    if ((byte & 0x80) === 0) {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleChar).call(this, byte);
    }
    else if ((byte & 0xe0) === 0xc0) {
        __classPrivateFieldSet(this, _CJSRepl_utf8Remaining, 1, "f");
        __classPrivateFieldSet(this, _CJSRepl_utf8Acc, byte & 0x1f, "f");
    }
    else if ((byte & 0xf0) === 0xe0) {
        __classPrivateFieldSet(this, _CJSRepl_utf8Remaining, 2, "f");
        __classPrivateFieldSet(this, _CJSRepl_utf8Acc, byte & 0x0f, "f");
    }
    else if ((byte & 0xf8) === 0xf0) {
        __classPrivateFieldSet(this, _CJSRepl_utf8Remaining, 3, "f");
        __classPrivateFieldSet(this, _CJSRepl_utf8Acc, byte & 0x07, "f");
    }
    else if ((byte & 0xc0) === 0x80 && __classPrivateFieldGet(this, _CJSRepl_utf8Remaining, "f") > 0) {
        __classPrivateFieldSet(this, _CJSRepl_utf8Acc, (__classPrivateFieldGet(this, _CJSRepl_utf8Acc, "f") << 6) | (byte & 0x3f), "f");
        if (__classPrivateFieldSet(this, _CJSRepl_utf8Remaining, (_b = __classPrivateFieldGet(this, _CJSRepl_utf8Remaining, "f"), --_b), "f") === 0) {
            __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleChar).call(this, __classPrivateFieldGet(this, _CJSRepl_utf8Acc, "f"));
        }
    }
    else {
        __classPrivateFieldSet(this, _CJSRepl_utf8Remaining, 0, "f");
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleChar).call(this, byte);
    }
}, _CJSRepl_handleChar = function _CJSRepl_handleChar(code) {
    var char = String.fromCodePoint(code);
    switch (__classPrivateFieldGet(this, _CJSRepl_escState, "f")) {
        case 'normal':
            if (char === '\x1b') {
                __classPrivateFieldSet(this, _CJSRepl_escState, 'esc', "f");
                __classPrivateFieldSet(this, _CJSRepl_escBuffer, char, "f");
            }
            else {
                __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_processChar).call(this, char);
            }
            break;
        case 'esc':
            __classPrivateFieldSet(this, _CJSRepl_escBuffer, __classPrivateFieldGet(this, _CJSRepl_escBuffer, "f") + char, "f");
            if (char === '[')
                __classPrivateFieldSet(this, _CJSRepl_escState, 'csi', "f");
            else if (char === 'O')
                __classPrivateFieldSet(this, _CJSRepl_escState, 'osc', "f");
            else {
                __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_processEscSequence).call(this, __classPrivateFieldGet(this, _CJSRepl_escBuffer, "f"));
                __classPrivateFieldSet(this, _CJSRepl_escState, 'normal', "f");
            }
            break;
        case 'csi':
        case 'osc':
            __classPrivateFieldSet(this, _CJSRepl_escBuffer, __classPrivateFieldGet(this, _CJSRepl_escBuffer, "f") + char, "f");
            if ((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || char === '~') {
                __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_processEscSequence).call(this, __classPrivateFieldGet(this, _CJSRepl_escBuffer, "f"));
                __classPrivateFieldSet(this, _CJSRepl_escState, 'normal', "f");
            }
            break;
    }
}, _CJSRepl_processChar = function _CJSRepl_processChar(char) {
    if (__classPrivateFieldGet(this, _CJSRepl_quoteFlag, "f")) {
        if (__spreadArray([], char, true).length === 1)
            __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_insert).call(this, char);
        __classPrivateFieldSet(this, _CJSRepl_quoteFlag, false, "f");
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_update).call(this);
        return;
    }
    var cmd = __classPrivateFieldGet(this, _CJSRepl_keyMap, "f").get(char);
    if (cmd) {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_executeCommand).call(this, cmd, char);
    }
    else if (__spreadArray([], char, true).length === 1 && char >= ' ') {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_insert).call(this, char);
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_update).call(this);
    }
    else {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_alert).call(this);
    }
}, _CJSRepl_processEscSequence = function _CJSRepl_processEscSequence(seq) {
    var _b;
    var cmd = (_b = __classPrivateFieldGet(this, _CJSRepl_keyMap, "f").get(seq)) !== null && _b !== void 0 ? _b : __classPrivateFieldGet(this, _CJSRepl_keyMap, "f").get(seq.slice(1));
    if (cmd) {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_executeCommand).call(this, cmd, seq);
    }
    else {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_alert).call(this);
    }
}, _CJSRepl_executeCommand = function _CJSRepl_executeCommand(cmd, input) {
    return __awaiter(this, void 0, void 0, function () {
        var result, _b, resolver, resolver;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    __classPrivateFieldSet(this, _CJSRepl_lastCommand, input, "f");
                    return [4 /*yield*/, cmd.call(this, input)];
                case 1:
                    result = _c.sent();
                    _b = result === null || result === void 0 ? void 0 : result.type;
                    switch (_b) {
                        case 'submit': return [3 /*break*/, 2];
                        case 'cancel': return [3 /*break*/, 3];
                        case 'exit': return [3 /*break*/, 4];
                    }
                    return [3 /*break*/, 5];
                case 2:
                    __classPrivateFieldSet(this, _CJSRepl_historyIndex, __classPrivateFieldGet(this, _CJSRepl_history, "f").length, "f");
                    if (__classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f")) {
                        resolver = __classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f");
                        __classPrivateFieldSet(this, _CJSRepl_readlineResolver, null, "f");
                        resolver(result.value);
                    }
                    return [3 /*break*/, 7];
                case 3:
                    if (__classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f")) {
                        resolver = __classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f");
                        __classPrivateFieldSet(this, _CJSRepl_readlineResolver, null, "f");
                        resolver(null);
                    }
                    return [3 /*break*/, 7];
                case 4:
                    __classPrivateFieldSet(this, _CJSRepl_running, false, "f");
                    if (__classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f")) {
                        __classPrivateFieldGet(this, _CJSRepl_readlineResolver, "f").call(this, null);
                    }
                    return [3 /*break*/, 7];
                case 5:
                    __classPrivateFieldSet(this, _CJSRepl_cursorPos, Math.max(0, Math.min(__classPrivateFieldGet(this, _CJSRepl_cmd, "f").length, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f"))), "f");
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_update).call(this)];
                case 6:
                    _c.sent();
                    _c.label = 7;
                case 7: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_moveCursor = function _CJSRepl_moveCursor(delta) {
    var newPos = Math.max(0, Math.min(__classPrivateFieldGet(this, _CJSRepl_cmd, "f").length, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") + delta));
    if (newPos !== __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")) {
        if (delta > 0 && newPos < __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length && __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isTrailingSurrogate).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[newPos])) {
            __classPrivateFieldSet(this, _CJSRepl_cursorPos, newPos + 1, "f");
        }
        else if (delta < 0 && newPos > 0 && __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isTrailingSurrogate).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[newPos])) {
            __classPrivateFieldSet(this, _CJSRepl_cursorPos, newPos - 1, "f");
        }
        else {
            __classPrivateFieldSet(this, _CJSRepl_cursorPos, newPos, "f");
        }
    }
}, _CJSRepl_insert = function _CJSRepl_insert(str) {
    __classPrivateFieldSet(this, _CJSRepl_cmd, __classPrivateFieldGet(this, _CJSRepl_cmd, "f").slice(0, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")) + str + __classPrivateFieldGet(this, _CJSRepl_cmd, "f").slice(__classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")), "f");
    __classPrivateFieldSet(this, _CJSRepl_cursorPos, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") + str.length, "f");
}, _CJSRepl_deleteChar = function _CJSRepl_deleteChar(dir) {
    if (dir < 0 && __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") > 0) {
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_moveCursor).call(this, -1);
        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_deleteChar).call(this, 1);
        return;
    }
    if (dir > 0 && __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") < __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length) {
        var end = __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") + 1;
        while (end < __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length && __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isTrailingSurrogate).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[end]))
            end++;
        __classPrivateFieldSet(this, _CJSRepl_cmd, __classPrivateFieldGet(this, _CJSRepl_cmd, "f").slice(0, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")) + __classPrivateFieldGet(this, _CJSRepl_cmd, "f").slice(end), "f");
    }
}, _CJSRepl_transpose = function _CJSRepl_transpose() {
    var _b;
    if (__classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") === 0 || __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length < 2)
        return;
    var pos = __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") === __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length ? __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f") - 1 : __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f");
    var chars = __spreadArray([], __classPrivateFieldGet(this, _CJSRepl_cmd, "f"), true);
    _b = [chars[pos], chars[pos - 1]], chars[pos - 1] = _b[0], chars[pos] = _b[1];
    __classPrivateFieldSet(this, _CJSRepl_cmd, chars.join(''), "f");
    __classPrivateFieldSet(this, _CJSRepl_cursorPos, pos + 1, "f");
}, _CJSRepl_prevHistory = function _CJSRepl_prevHistory() {
    var _b;
    var _c;
    if (__classPrivateFieldGet(this, _CJSRepl_historyIndex, "f") > 0) {
        if (__classPrivateFieldGet(this, _CJSRepl_historyIndex, "f") === __classPrivateFieldGet(this, _CJSRepl_history, "f").length) {
            __classPrivateFieldGet(this, _CJSRepl_history, "f").push(__classPrivateFieldGet(this, _CJSRepl_cmd, "f"));
        }
        __classPrivateFieldSet(this, _CJSRepl_historyIndex, (_c = __classPrivateFieldGet(this, _CJSRepl_historyIndex, "f"), _c--, _c), "f");
        __classPrivateFieldSet(this, _CJSRepl_cmd, (_b = __classPrivateFieldGet(this, _CJSRepl_history, "f")[__classPrivateFieldGet(this, _CJSRepl_historyIndex, "f")]) !== null && _b !== void 0 ? _b : '', "f");
        __classPrivateFieldSet(this, _CJSRepl_cursorPos, __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length, "f");
    }
}, _CJSRepl_nextHistory = function _CJSRepl_nextHistory() {
    var _b;
    var _c;
    if (__classPrivateFieldGet(this, _CJSRepl_historyIndex, "f") < __classPrivateFieldGet(this, _CJSRepl_history, "f").length - 1) {
        __classPrivateFieldSet(this, _CJSRepl_historyIndex, (_c = __classPrivateFieldGet(this, _CJSRepl_historyIndex, "f"), _c++, _c), "f");
        __classPrivateFieldSet(this, _CJSRepl_cmd, (_b = __classPrivateFieldGet(this, _CJSRepl_history, "f")[__classPrivateFieldGet(this, _CJSRepl_historyIndex, "f")]) !== null && _b !== void 0 ? _b : '', "f");
        __classPrivateFieldSet(this, _CJSRepl_cursorPos, __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length, "f");
    }
}, _CJSRepl_complete = function _CJSRepl_complete() {
    return __awaiter(this, void 0, void 0, function () {
        var _b, completions, position, common, i, j, i;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    _b = __classPrivateFieldGet(this, _CJSRepl_completer, "f").getCompletions(__classPrivateFieldGet(this, _CJSRepl_cmd, "f"), __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")), completions = _b.completions, position = _b.position;
                    if (completions.length === 0) {
                        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_alert).call(this);
                        return [2 /*return*/];
                    }
                    common = completions[0];
                    for (i = 1; i < completions.length; i++) {
                        j = position;
                        while (j < common.length && j < completions[i].length && common[j] === completions[i][j]) {
                            j++;
                        }
                        common = common.substring(0, j);
                    }
                    if (common.length > position) {
                        for (i = position; i < common.length; i++) {
                            __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_insert).call(this, common[i]);
                        }
                        __classPrivateFieldSet(this, _CJSRepl_lastCommand, '', "f");
                        return [2 /*return*/];
                    }
                    if (!(__classPrivateFieldGet(this, _CJSRepl_lastCommand, "f") === '\t')) return [3 /*break*/, 2];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_showCompletions).call(this, completions)];
                case 1:
                    _c.sent();
                    return [2 /*return*/];
                case 2:
                    __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_alert).call(this);
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_showCompletions = function _CJSRepl_showCompletions(list) {
    return __awaiter(this, void 0, void 0, function () {
        var maxWidth, cols, rows, row, line, col, idx, item;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    maxWidth = Math.max.apply(Math, list.map(function (s) { return s.length; })) + 2;
                    cols = Math.max(1, Math.floor(__classPrivateFieldGet(this, _CJSRepl_termWidth, "f") / maxWidth));
                    rows = Math.ceil(list.length / cols);
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\n')];
                case 1:
                    _b.sent();
                    row = 0;
                    _b.label = 2;
                case 2:
                    if (!(row < rows)) return [3 /*break*/, 5];
                    line = [];
                    for (col = 0; col < cols; col++) {
                        idx = col * rows + row;
                        if (idx < list.length) {
                            item = list[idx];
                            line.push(col === cols - 1 ? item : item.padEnd(maxWidth));
                        }
                    }
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, line.join('') + '\n')];
                case 3:
                    _b.sent();
                    _b.label = 4;
                case 4:
                    row++;
                    return [3 /*break*/, 2];
                case 5: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_printPrompt).call(this)];
                case 6:
                    _b.sent();
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f"))];
                case 7:
                    _b.sent();
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_skipWordForward = function _CJSRepl_skipWordForward(pos) {
    while (pos < __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length && !__classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isWordChar).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[pos]))
        pos++;
    while (pos < __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length && __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isWordChar).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[pos]))
        pos++;
    return pos;
}, _CJSRepl_skipWordBack = function _CJSRepl_skipWordBack(pos) {
    while (pos > 0 && !__classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isWordChar).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[pos - 1]))
        pos--;
    while (pos > 0 && __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_isWordChar).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f")[pos - 1]))
        pos--;
    return pos;
}, _CJSRepl_printPrompt = function _CJSRepl_printPrompt() {
    return __awaiter(this, void 0, void 0, function () {
        var timeStr, prompt;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    timeStr = __classPrivateFieldGet(this, _CJSRepl_config, "f").showTime ? "".concat((performance.now() / 1000).toFixed(6), " ") : '';
                    prompt = __classPrivateFieldGet(this, _CJSRepl_multilineExpr, "f")
                        ? ' '.repeat(__classPrivateFieldGet(this, _CJSRepl_config, "f").ps1.length) + __classPrivateFieldGet(this, _CJSRepl_config, "f").ps2
                        : timeStr + __classPrivateFieldGet(this, _CJSRepl_config, "f").ps1;
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, prompt)];
                case 1:
                    _b.sent();
                    __classPrivateFieldSet(this, _CJSRepl_termCursorX, __spreadArray([], prompt, true).length % __classPrivateFieldGet(this, _CJSRepl_termWidth, "f"), "f");
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_update = function _CJSRepl_update() {
    return __awaiter(this, void 0, void 0, function () {
        var fullExpr, startOffset, styles, cmdWidth, targetX, linesUp;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: 
                // Move to start
                return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_moveToStart).call(this)];
                case 1:
                    // Move to start
                    _b.sent();
                    if (!__classPrivateFieldGet(this, _CJSRepl_config, "f").colors) return [3 /*break*/, 3];
                    fullExpr = __classPrivateFieldGet(this, _CJSRepl_multilineExpr, "f") ? __classPrivateFieldGet(this, _CJSRepl_multilineExpr, "f") + '\n' + __classPrivateFieldGet(this, _CJSRepl_cmd, "f") : __classPrivateFieldGet(this, _CJSRepl_cmd, "f");
                    startOffset = fullExpr.length - __classPrivateFieldGet(this, _CJSRepl_cmd, "f").length;
                    styles = __classPrivateFieldGet(this, _CJSRepl_colorizer, "f").colorize(fullExpr, __classPrivateFieldGet(this, _CJSRepl_pstate, "f"), __classPrivateFieldGet(this, _CJSRepl_braceLevel, "f")).styles;
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_printHighlighted).call(this, fullExpr.slice(startOffset), styles.slice(startOffset))];
                case 2:
                    _b.sent();
                    return [3 /*break*/, 5];
                case 3: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, __classPrivateFieldGet(this, _CJSRepl_cmd, "f"))];
                case 4:
                    _b.sent();
                    _b.label = 5;
                case 5: 
                // Clear rest of line
                return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\x1b[J')];
                case 6:
                    // Clear rest of line
                    _b.sent();
                    cmdWidth = __spreadArray([], __classPrivateFieldGet(this, _CJSRepl_cmd, "f").slice(0, __classPrivateFieldGet(this, _CJSRepl_cursorPos, "f")), true).length;
                    targetX = (__classPrivateFieldGet(this, _CJSRepl_termCursorX, "f") + cmdWidth + 1) % __classPrivateFieldGet(this, _CJSRepl_termWidth, "f");
                    linesUp = Math.floor((__classPrivateFieldGet(this, _CJSRepl_termCursorX, "f") + cmdWidth) / __classPrivateFieldGet(this, _CJSRepl_termWidth, "f"));
                    if (!(linesUp > 0)) return [3 /*break*/, 8];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, "\u001B[".concat(linesUp, "A"))];
                case 7:
                    _b.sent();
                    _b.label = 8;
                case 8:
                    if (!(targetX < __classPrivateFieldGet(this, _CJSRepl_termWidth, "f") - 1)) return [3 /*break*/, 10];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, "\u001B[".concat(targetX, "G"))];
                case 9:
                    _b.sent();
                    _b.label = 10;
                case 10: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_moveToStart = function _CJSRepl_moveToStart() {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: 
                // Simplified: just CR and clear
                return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\r\x1b[J')];
                case 1:
                    // Simplified: just CR and clear
                    _b.sent();
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_printPrompt).call(this)];
                case 2:
                    _b.sent();
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_printHighlighted = function _CJSRepl_printHighlighted(str, styles) {
    return __awaiter(this, void 0, void 0, function () {
        var currentStyle, i, style;
        var _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    currentStyle = null;
                    i = 0;
                    _c.label = 1;
                case 1:
                    if (!(i < str.length)) return [3 /*break*/, 9];
                    style = (_b = styles[i]) !== null && _b !== void 0 ? _b : 'default';
                    if (!(style !== currentStyle)) return [3 /*break*/, 6];
                    if (!currentStyle) return [3 /*break*/, 3];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.reset)];
                case 2:
                    _c.sent();
                    _c.label = 3;
                case 3:
                    if (!(style !== 'default')) return [3 /*break*/, 5];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR[STYLE_MAP[style]])];
                case 4:
                    _c.sent();
                    _c.label = 5;
                case 5:
                    currentStyle = style;
                    _c.label = 6;
                case 6: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, str[i])];
                case 7:
                    _c.sent();
                    _c.label = 8;
                case 8:
                    i++;
                    return [3 /*break*/, 1];
                case 9:
                    if (!currentStyle) return [3 /*break*/, 11];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.reset)];
                case 10:
                    _c.sent();
                    _c.label = 11;
                case 11: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_handleCommand = function _CJSRepl_handleCommand(line) {
    return __awaiter(this, void 0, void 0, function () {
        var directive, handled, highlight;
        var _b;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    if (line === '?') {
                        __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_showHelp).call(this);
                        return [2 /*return*/];
                    }
                    directive = (_b = line.match(/^\.([a-z]+)\s*/)) === null || _b === void 0 ? void 0 : _b[1];
                    if (!directive) return [3 /*break*/, 2];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_handleDirective).call(this, directive, line.slice(directive.length + 1))];
                case 1:
                    handled = _c.sent();
                    if (!handled)
                        return [2 /*return*/];
                    line = line.slice(directive.length + 1).trim();
                    _c.label = 2;
                case 2:
                    if (!line)
                        return [2 /*return*/];
                    // Accumulate multiline
                    if (__classPrivateFieldGet(this, _CJSRepl_multilineExpr, "f")) {
                        line = __classPrivateFieldGet(this, _CJSRepl_multilineExpr, "f") + '\n' + line;
                    }
                    highlight = __classPrivateFieldGet(this, _CJSRepl_colorizer, "f").colorize(line, __classPrivateFieldGet(this, _CJSRepl_pstate, "f"), __classPrivateFieldGet(this, _CJSRepl_braceLevel, "f"));
                    if (highlight.state || highlight.level > 0) {
                        __classPrivateFieldSet(this, _CJSRepl_multilineExpr, line, "f");
                        __classPrivateFieldSet(this, _CJSRepl_pstate, highlight.state, "f");
                        __classPrivateFieldSet(this, _CJSRepl_braceLevel, highlight.level, "f");
                        return [2 /*return*/];
                    }
                    __classPrivateFieldSet(this, _CJSRepl_multilineExpr, '', "f");
                    __classPrivateFieldSet(this, _CJSRepl_pstate, '', "f");
                    __classPrivateFieldSet(this, _CJSRepl_braceLevel, 0, "f");
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_evaluate).call(this, line)];
                case 3:
                    _c.sent();
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_handleDirective = function _CJSRepl_handleDirective(cmd, rest) {
    return __awaiter(this, void 0, void 0, function () {
        var _b, file;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    _b = cmd;
                    switch (_b) {
                        case 'h': return [3 /*break*/, 1];
                        case 'help': return [3 /*break*/, 1];
                        case 'load': return [3 /*break*/, 2];
                        case 'x': return [3 /*break*/, 4];
                        case 'd': return [3 /*break*/, 5];
                        case 't': return [3 /*break*/, 6];
                        case 'clear': return [3 /*break*/, 7];
                        case 'q': return [3 /*break*/, 9];
                        case 'u': return [3 /*break*/, 11];
                    }
                    return [3 /*break*/, 12];
                case 1:
                    __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_showHelp).call(this);
                    return [2 /*return*/, false];
                case 2:
                    file = rest.trim() || 'script.js';
                    return [4 /*yield*/, Promise.resolve("".concat(file.endsWith('.js') ? file : file + '.js')).then(function (s) { return require(s); })];
                case 3:
                    _c.sent();
                    return [2 /*return*/, false];
                case 4:
                    __classPrivateFieldGet(this, _CJSRepl_config, "f").hexMode = true;
                    return [2 /*return*/, false];
                case 5:
                    __classPrivateFieldGet(this, _CJSRepl_config, "f").hexMode = false;
                    return [2 /*return*/, false];
                case 6:
                    __classPrivateFieldGet(this, _CJSRepl_config, "f").showTime = !__classPrivateFieldGet(this, _CJSRepl_config, "f").showTime;
                    return [2 /*return*/, false];
                case 7: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, '\x1b[H\x1b[J')];
                case 8:
                    _c.sent();
                    return [2 /*return*/, false];
                case 9:
                    __classPrivateFieldSet(this, _CJSRepl_running, false, "f");
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, 'Press any key to exit...')];
                case 10:
                    _c.sent();
                    return [2 /*return*/, false];
                case 11:
                    rest = rest.trim();
                    // @ts-ignore
                    globalThis[rest] = import.meta.use(rest);
                    return [2 /*return*/, false];
                case 12: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, "Unknown directive: .".concat(cmd, "\n"))];
                case 13:
                    _c.sent();
                    return [2 /*return*/, false];
            }
        });
    });
}, _CJSRepl_evaluate = function _CJSRepl_evaluate(expr) {
    return __awaiter(this, void 0, void 0, function () {
        var result, time, hex, e_2;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    _b.trys.push([0, 7, 9, 10]);
                    __classPrivateFieldSet(this, _CJSRepl_evalStartTime, performance.now(), "f");
                    return [4 /*yield*/, engine.eval(expr, '<eval>', engine.EVAL_ASYNC | engine.EVAL_NEW_BACKTRACE)];
                case 1:
                    result = (_b.sent()).value;
                    time = performance.now() - __classPrivateFieldGet(this, _CJSRepl_evalStartTime, "f");
                    if (__classPrivateFieldGet(this, _CJSRepl_config, "f").showTime) {
                        __classPrivateFieldGet(this, _CJSRepl_config, "f").showTime = false; // Show once
                    }
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.brightWhite)];
                case 2:
                    _b.sent();
                    if (!(__classPrivateFieldGet(this, _CJSRepl_config, "f").hexMode && (typeof result === 'number' || typeof result === 'bigint'))) return [3 /*break*/, 4];
                    hex = typeof result === 'bigint'
                        ? '0x' + result.toString(16)
                        : '0x' + Math.floor(result).toString(16);
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, hex + (typeof result === 'bigint' ? 'n' : ''))];
                case 3:
                    _b.sent();
                    return [3 /*break*/, 5];
                case 4:
                    console.log(result);
                    _b.label = 5;
                case 5: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.reset + '\n')];
                case 6:
                    _b.sent();
                    // @ts-ignore
                    globalThis._ = result;
                    return [3 /*break*/, 10];
                case 7:
                    e_2 = _b.sent();
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_printError).call(this, e_2)];
                case 8:
                    _b.sent();
                    return [3 /*break*/, 10];
                case 9:
                    engine.gc.run();
                    return [7 /*endfinally*/];
                case 10: return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_showHelp = function _CJSRepl_showHelp() {
    var sel = function (n) { return n ? '*' : ' '; };
    console.log(".h          this help\n" +
        ".x         ".concat(sel(__classPrivateFieldGet(this, _CJSRepl_config, "f").hexMode), " hexadecimal number display\n") +
        ".d         ".concat(sel(!__classPrivateFieldGet(this, _CJSRepl_config, "f").hexMode), " decimal number display\n") +
        ".t         ".concat(sel(__classPrivateFieldGet(this, _CJSRepl_config, "f").showTime), " toggle timing display\n") +
        ".u          use a built-in c-module and save it to globalThis\n" +
        ".c          clear the terminal\n" +
        ".q          exit");
}, _CJSRepl_print = function _CJSRepl_print(str) {
    return __awaiter(this, void 0, void 0, function () {
        var buf;
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0:
                    buf = engine.encodeString(str);
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_stdout, "f").write(buf)];
                case 1:
                    _b.sent();
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_printError = function _CJSRepl_printError(err) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_b) {
            switch (_b.label) {
                case 0: return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.brightRed)];
                case 1:
                    _b.sent();
                    if (!!(err instanceof Error)) return [3 /*break*/, 3];
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, 'Throw: ')];
                case 2:
                    _b.sent();
                    _b.label = 3;
                case 3:
                    console.log(err);
                    return [4 /*yield*/, __classPrivateFieldGet(this, _CJSRepl_instances, "m", _CJSRepl_print).call(this, COLOR.reset + '\n')];
                case 4:
                    _b.sent();
                    return [2 /*return*/];
            }
        });
    });
}, _CJSRepl_alert = function _CJSRepl_alert() {
    __classPrivateFieldGet(this, _CJSRepl_stdout, "f").write(new Uint8Array([0x07]));
}, _CJSRepl_isWordChar = function _CJSRepl_isWordChar(c) { return /[a-zA-Z0-9_$]/.test(c); }, _CJSRepl_isTrailingSurrogate = function _CJSRepl_isTrailingSurrogate(c) {
    var code = c === null || c === void 0 ? void 0 : c.codePointAt(0);
    return code !== undefined && code >= 0xdc00 && code < 0xe000;
}, _CJSRepl_onExit = function _CJSRepl_onExit(callback) {
    // Simple cleanup registration
    // In real implementation, use addEventListener('beforeExit') or similar
};
// prevent default unhandled rejections
engine.onEvent(function (e) { return false; });
// Start REPL
var repl = new CJSRepl();
repl.start();
// bind exit handler
signal.signal(signal.signals.SIGINT, function () {
    console.log('Got SIGINT, exiting...');
    repl.handleCtrlC();
});
