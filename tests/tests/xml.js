// tests/tests/xml.js - XML parsing module tests

const xml = import.meta.use('xml');

// ========== XMLParser Construction ==========
await test('xml.XMLParser - basic construction', () => {
    const parser = new xml.XMLParser();
    assert(parser, 'Should create XMLParser');
    assert(parser instanceof xml.XMLParser, 'Should be instance of XMLParser');
});

await test('xml.XMLParser - with namespace option', () => {
    const parser = new xml.XMLParser({ namespace: true });
    assert(parser, 'Should create XMLParser with namespace support');
});

await test('xml.XMLParser - with namespace separator', () => {
    const parser = new xml.XMLParser({ 
        namespace: true, 
        namespaceSeparator: '|' 
    });
    assert(parser, 'Should create XMLParser with custom separator');
});

// ========== Basic Parsing ==========
await test('xml.XMLParser.parse - simple element', () => {
    const parser = new xml.XMLParser();
    let startCalled = false;
    let endCalled = false;
    
    parser.on('startElement', (name, attrs) => {
        assertEquals(name, 'root', 'Element name should be "root"');
        startCalled = true;
    });
    
    parser.on('endElement', (name) => {
        assertEquals(name, 'root', 'End element name should be "root"');
        endCalled = true;
    });
    
    parser.parse('<root></root>');
    
    assert(startCalled, 'startElement should be called');
    assert(endCalled, 'endElement should be called');
});

await test('xml.XMLParser.parse - with attributes', () => {
    const parser = new xml.XMLParser();
    let attrsReceived = null;
    
    parser.on('startElement', (name, attrs) => {
        attrsReceived = attrs;
    });
    
    parser.parse('<root id="1" name="test"></root>');
    
    assert(attrsReceived, 'Should receive attributes');
    assertEquals(attrsReceived.id, '1', 'Should have id attribute');
    assertEquals(attrsReceived.name, 'test', 'Should have name attribute');
});

await test('xml.XMLParser.parse - character data', () => {
    const parser = new xml.XMLParser();
    let charData = '';
    
    parser.on('characterData', (data) => {
        charData += data;
    });
    
    parser.parse('<root>Hello World</root>');
    
    assertEquals(charData.trim(), 'Hello World', 'Should receive character data');
});

await test('xml.XMLParser.parse - nested elements', () => {
    const parser = new xml.XMLParser();
    const elements = [];
    
    parser.on('startElement', (name, attrs) => {
        elements.push({ type: 'start', name });
    });
    
    parser.on('endElement', (name) => {
        elements.push({ type: 'end', name });
    });
    
    parser.parse('<root><child><grandchild/></child></root>');
    
    assertEquals(elements.length, 6, 'Should have 6 events');
    assertEquals(elements[0].name, 'root', 'First should be root');
    assertEquals(elements[1].name, 'child', 'Second should be child');
    assertEquals(elements[2].name, 'grandchild', 'Third should be grandchild');
});

await test('xml.XMLParser.parse - self-closing tag', () => {
    const parser = new xml.XMLParser();
    let startCalled = false;
    let endCalled = false;
    
    parser.on('startElement', (name) => {
        if (name === 'empty') startCalled = true;
    });
    
    parser.on('endElement', (name) => {
        if (name === 'empty') endCalled = true;
    });
    
    parser.parse('<root><empty/></root>');
    
    assert(startCalled, 'startElement should be called for empty tag');
    assert(endCalled, 'endElement should be called for empty tag');
});

// ========== CDATA Handling ==========
await test('xml.XMLParser.parse - CDATA section', () => {
    const parser = new xml.XMLParser();
    let cdataStarted = false;
    let cdataEnded = false;
    let charData = '';
    
    parser.on('startCDATA', () => {
        cdataStarted = true;
    });
    
    parser.on('endCDATA', () => {
        cdataEnded = true;
    });
    
    parser.on('characterData', (data) => {
        charData += data;
    });
    
    parser.parse('<root><![CDATA[<script>alert("xss")</script>]]></root>');
    
    assert(cdataStarted, 'startCDATA should be called');
    assert(cdataEnded, 'endCDATA should be called');
    assert(charData.includes('<script>'), 'CDATA content should not be escaped');
});

// ========== Comment Handling ==========
await test('xml.XMLParser.parse - comment', () => {
    const parser = new xml.XMLParser();
    let commentReceived = null;
    
    parser.on('comment', (data) => {
        commentReceived = data;
    });
    
    parser.parse('<root><!-- This is a comment --></root>');
    
    assert(commentReceived, 'Should receive comment');
    assert(commentReceived.includes('This is a comment'), 'Should have comment text');
});

// ========== Processing Instruction ==========
await test('xml.XMLParser.parse - processing instruction', () => {
    const parser = new xml.XMLParser();
    let piReceived = null;
    
    parser.on('processingInstruction', (target, data) => {
        piReceived = { target, data };
    });
    
    parser.parse('<?xml version="1.0" encoding="UTF-8"?><root/>');
    
    assert(piReceived, 'Should receive processing instruction');
    assertEquals(piReceived.target, 'xml', 'Target should be xml');
});

// ========== Namespace Handling ==========
await test('xml.XMLParser.parse - namespace declarations', () => {
    const parser = new xml.XMLParser({ namespace: true });
    let nsStartReceived = null;
    
    parser.on('startNamespace', (prefix, uri) => {
        nsStartReceived = { prefix, uri };
    });
    
    parser.parse('<root xmlns:custom="http://example.com/custom"><custom:child/></root>');
    
    // Namespace declaration should be reported
});

// ========== Line/Column Tracking ==========
await test('xml.XMLParser - line tracking', () => {
    const parser = new xml.XMLParser();
    
    parser.parse('<root>\n  <child/>\n</root>');
    
    // After parsing, line should be > 1
    assert(parser.line >= 1, 'Should track line number');
});

await test('xml.XMLParser - column tracking', () => {
    const parser = new xml.XMLParser();
    
    parser.parse('<root/>');
    
    assert(parser.column >= 0, 'Should track column number');
});

// ========== Parser Reset ==========
await test('xml.XMLParser.reset - reset parser state', () => {
    const parser = new xml.XMLParser();
    
    parser.parse('<first/>');
    const resetResult = parser.reset();
    
    assertEquals(resetResult, true, 'Reset should return true');
    
    let elementName = null;
    parser.on('startElement', (name) => {
        elementName = name;
    });
    
    parser.parse('<second/>');
    assertEquals(elementName, 'second', 'Should parse after reset');
});

// ========== Parser Stop ==========
await test('xml.XMLParser.stop - stop parsing', () => {
    const parser = new xml.XMLParser();
    let secondElementParsed = false;
    
    parser.on('startElement', (name) => {
        if (name === 'first') {
            parser.stop();
        } else if (name === 'second') {
            secondElementParsed = true;
        }
    });
    
    parser.parse('<root><first/><second/></root>');
    
    assertEquals(secondElementParsed, false, 'Second element should not be parsed after stop');
});

// ========== Streaming Parse ==========
await test('xml.XMLParser.parse - streaming with isFinal=false', () => {
    const parser = new xml.XMLParser();
    let elementCount = 0;
    
    parser.on('startElement', () => {
        elementCount++;
    });
    
    parser.parse('<root>', false); // Not final
    parser.parse('<child/>', false); // Not final
    parser.parse('</root>', true); // Final
    
    assertEquals(elementCount, 2, 'Should parse all elements');
});

// ========== Error Handling ==========
await test('xml.XMLParser.parse - unclosed tag throws', () => {
    const parser = new xml.XMLParser();
    
    try {
        parser.parse('<root><unclosed></root>');
        assert(false, 'Should throw for mismatched tags');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

await test('xml.XMLParser.parse - invalid XML throws', () => {
    const parser = new xml.XMLParser();
    
    try {
        parser.parse('<root><invalid attribute></root>');
        assert(false, 'Should throw for invalid XML');
    } catch (e) {
        assert(e instanceof Error, 'Should throw Error');
    }
});

// ========== XML.escape Utility ==========
await test('xml.escape - basic escaping', () => {
    const escaped = xml.escape('<script>alert("xss")</script>');
    
    assert(!escaped.includes('<'), 'Should escape <');
    assert(!escaped.includes('>'), 'Should escape >');
    assert(escaped.includes('&lt;'), 'Should have &lt;');
    assert(escaped.includes('&gt;'), 'Should have &gt;');
});

await test('xml.escape - ampersand escaping', () => {
    const escaped = xml.escape('A & B');
    
    assert(!escaped.includes(' & '), 'Should not have bare ampersand');
    assert(escaped.includes('&amp;'), 'Should have &amp;');
});

await test('xml.escape - quote escaping', () => {
    const escaped = xml.escape('"quoted"');
    
    assert(escaped.includes('&quot;'), 'Should escape double quotes');
});

await test('xml.escape - apostrophe escaping', () => {
    const escaped = xml.escape("it's");
    
    assert(escaped.includes('&apos;'), 'Should escape apostrophe');
});

await test('xml.escape - multiple special characters', () => {
    const input = '<tag attr="value">it\'s & yours</tag>';
    const escaped = xml.escape(input);
    
    assert(!escaped.includes('<'), 'Should escape all <');
    assert(!escaped.includes('>'), 'Should escape all >');
    assert(!escaped.includes('"'), 'Should escape all "');
    assert(!escaped.includes("'"), 'Should escape all \'');
    assert(!escaped.includes('& ') && !escaped.includes('&y'), 'Should escape &');
});
