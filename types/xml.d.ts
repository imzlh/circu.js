/**
 * txiki.js XML Module - TypeScript Definitions
 * Based on libexpat.
 *
 * @example Basic parsing
 * ```ts
 * const xml = import.meta.use('xml');
 *
 * const parser = new xml.Parser();
 * parser
 *   .on('startElement', (name, attrs) => {
 *     console.log(name, attrs);
 *   })
 *   .on('characterData', (data) => {
 *     const text = data.trim();
 *     if (text) console.log(text);
 *   });
 *
 * parser.parse('<root><item id="1">Hello</item></root>');
 * ```
 *
 * @example Streaming parse
 * ```ts
 * const xml = import.meta.use('xml');
 * const parser = new xml.Parser();
 *
 * parser.parse('<root><item>', false);
 * parser.parse('Hello</item>', false);
 * parser.parse('</root>', true);
 * ```
 *
 * @example Namespace parsing
 * ```ts
 * const xml = import.meta.use('xml');
 * const parser = new xml.Parser({ namespace: true, namespaceSeparator: ':' });
 *
 * parser.on('startNamespace', (prefix, uri) => {
 *   console.log(prefix, uri);
 * });
 *
 * parser.parse('<root xmlns:app="urn:app"><app:item /></root>');
 * ```
 *
 * @example Escaping text
 * ```ts
 * const xml = import.meta.use('xml');
 *
 * const userInput = '<script>alert("XSS")</script>';
 * const safeXML = `<content>${xml.escape(userInput)}</content>`;
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
    export class Parser {
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

}
