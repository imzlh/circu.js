/**
 * txiki.js XML Module - TypeScript Definitions
 * Based on libexpat
 */

/**
 * @example Example 1: 基本XML解析
 * ```ts
 * const { XMLParser } = import.meta.use('xml');
 *
 * const parser = new XMLParser();
 *
 * parser
 *   .on("startElement", (name, attrs) => {
 *     console.log(`<${name}>`, attrs);
 *   })
 *   .on("endElement", (name) => {
 *     console.log(``);
 *   })
 *   .on("characterData", (data) => {
 *     const trimmed = data.trim();
 *     if (trimmed) console.log(`Text: ${trimmed}`);
 *   });
 *
 * const xml1 = `
 *   <root>
 *     <item id="1">Hello World</item>
 *     <item id="2">txiki.js</item>
 *   </root>
 * `;
 *
 * parser.parse(xml1);
 *
 * ```
 * @example Example 2: 命名空间感知解析
 * ```ts
 * const parser2 = new XMLParser({
 *   namespace: true,
 *   namespaceSeparator: ":"
 * });
 *
 * parser2
 *   .on("startNamespace", (prefix, uri) => {
 *     console.log(`xmlns${prefix ? `:${prefix}` : ""} = "${uri}"`);
 *   })
 *   .on("startElement", (name, attrs) => {
 *     console.log(`Element: ${name}`, attrs);
 *   });
 *
 * const xml2 = `
 *   <root xmlns="http://example.com/ns" xmlns:foo="http://foo.com">
 *     <foo:item>Content</foo:item>
 *   </root>
 * `;
 *
 * parser2.parse(xml2);
 * ```
 * @example Example 3: 流式解析及错误处理
 * ```ts
 * const parser3 = new XMLParser();
 * const elements: string[] = [];
 *
 * parser3
 *   .on("startElement", (name) => {
 *     elements.push(name);
 *   })
 *   .on("endElement", () => {
 *     elements.pop();
 *   });
 *
 * try {
 *   // 分块解析
 *   parser3.parse("<root><item>", false);
 *   parser3.parse("Hello</item>", false);
 *   parser3.parse("</root>", true);
 *
 *   console.log("解析成功！");
 * } catch (err) {
 *   console.error(`解析错误在第 ${parser3.line} 行, 第 ${parser3.column} 列:`, err);
 * }
 *
 * ```
 * @example Example 4: 构建XML字符串
 * ```ts
 * const { XMLParser } = import.meta.use('xml');
 * const parser4 = new XMLParser();
 *
 * parser4
 *   .on("comment", (data) => {
 *     console.log(`Comment: ${data}`);
 *   })
 *   .on("startCDATA", () => {
 *     console.log("CDATA 开始");
 *   })
 *   .on("characterData", (data) => {
 *     console.log(`数据: ${data}`);
 *   })
 *   .on("endCDATA", () => {
 *     console.log("CDATA 结束");
 *   });
 *
 * const xml4 = `
 *   <root>
 *     <!-- 这是一个注释 -->
 *     <!--[CDATA[<Special--> &amp; "Characters"]]&gt;
 *   </root>
 * `;
 *
 * parser4.parse(xml4);
 *
 * ```
 * @example Example 5: 构建XML字符串
 * ```ts
 * const { XMLParser } = import.meta.use('xml');
 * const parser5 = new XMLParser();
 *
 * parser5.on("processingInstruction", (target, data) => {
 *   console.log(`PI: `);
 * });
 *
 * const xml5 = `<root>`;
 *
 * parser5.parse(xml5);
 *
 * ```
 * @example Example 6: 转义XML内容
 * ```ts
 * import { escape } from "@tjs/xml";
 *
 * const userInput = '<script>alert("XSS")</script>';
 * const safeXML = `<content>${escape(userInput)}</content>`;
 *
 * console.log(safeXML);
 * // 输出: <content>&lt;script&gt;alert("XSS")&lt;/script&gt;</content>
 *
 * // Example 7: 构建类似DOM的结构
 * import { XMLParser, XMLAttributes } from "@tjs/xml";
 *
 * interface XMLNode {
 *   name: string;
 *   attrs: XMLAttributes;
 *   children: (XMLNode | string)[];
 * }
 *
 * function parseToTree(xml: string): XMLNode | null {
 *   const parser = new XMLParser();
 *   const stack: XMLNode[] = [];
 *   let root: XMLNode | null = null;
 *
 *   parser
 *     .on("startElement", (name, attrs) =&gt; {
 *       const node: XMLNode = { name, attrs, children: [] };
 *       if (stack.length &gt; 0) {
 *         stack[stack.length - 1].children.push(node);
 *       } else {
 *         root = node;
 *       }
 *       stack.push(node);
 *     })
 *     .on("endElement", () =&gt; {
 *       stack.pop();
 *     })
 *     .on("characterData", (data) =&gt; {
 *       const trimmed = data.trim();
 *       if (trimmed &amp;&amp; stack.length &gt; 0) {
 *         stack[stack.length - 1].children.push(trimmed);
 *       }
 *     });
 *
 *   parser.parse(xml);
 *   return root;
 * }
 *
 * const tree = parseToTree("<root><item id="1">Hello</item></root>");
 * console.log(JSON.stringify(tree, null, 2));
 * ```
 */
declare namespace CModuleXML {
    /**
     * XML Parser Options
     */
    export interface XMLParserOptions {
        /** Enable namespace processing */
        namespace?: boolean;
        /** Namespace separator character (default: '|') */
        namespaceSeparator?: string;
    }

    /**
     * Attributes object
     */
    export interface XMLAttributes {
        [key: string]: string;
    }

    /**
     * XML Parser Event Handlers
     */
    export interface XMLParserHandlers {
        /** Called when an opening tag is encountered */
        startElement?: (name: string, attrs: XMLAttributes) => void;

        /** Called when a closing tag is encountered */
        endElement?: (name: string) => void;

        /** Called when character data is encountered */
        characterData?: (data: string) => void;

        /** Called when a comment is encountered */
        comment?: (data: string) => void;

        /** Called at the start of a CDATA section */
        startCDATA?: () => void;

        /** Called at the end of a CDATA section */
        endCDATA?: () => void;

        /** Called when a processing instruction is encountered */
        processingInstruction?: (target: string, data: string) => void;

        /** Called when a namespace declaration starts */
        startNamespace?: (prefix: string | null, uri: string) => void;

        /** Called when a namespace declaration ends */
        endNamespace?: (prefix: string | null) => void;
    }

    /**
     * XML Parser Class
     */
    export class XMLParser {
        /**
         * Create a new XML parser
         * @param options Parser configuration options
         */
        constructor(options?: XMLParserOptions);

        /**
         * Register an event handler
         * @param event Event name
         * @param handler Event handler function
         * @returns this for chaining
         */
        on<K extends keyof XMLParserHandlers>(
            event: K,
            handler: XMLParserHandlers[K]
        ): this;

        /**
         * Parse XML data
         * @param data XML string to parse
         * @param isFinal Whether this is the final chunk (default: true)
         * @returns true if parsing succeeded, false otherwise
         */
        parse(data: string, isFinal?: boolean): boolean;

        /**
         * Stop the parser
         */
        stop(): void;

        /**
         * Reset the parser to initial state
         * @param encoding Optional encoding to use after reset
         */
        reset(encoding?: string): boolean;

        /**
         * Current line number in the XML document
         */
        readonly line: number;

        /**
         * Current column number in the XML document
         */
        readonly column: number;
    }

    /**
     * Escape XML special characters in a string
     * @param str String to escape
     * @returns Escaped string safe for XML content
     */
    export function escape(str: string): string;

    /**
     * Expat library version string
     */
    export const EXPAT_VERSION: string;
}