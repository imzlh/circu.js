const { parse } = import.meta.use('jsonc');
const console = import.meta.use('console');

// Test 1: Basic JSON parsing
console.log("=== Test 1: Basic JSON ===");
const basicJSON = `{
    "name": "test",
    "version": 1.0,
    "enabled": true,
    "nullable": null
}`;
try {
    const result1 = parse(basicJSON);
    console.log("✓ Basic JSON parsed successfully");
    console.log("  name:", result1.name);
    console.log("  version:", result1.version);
    console.log("  enabled:", result1.enabled);
    console.log("  nullable:", result1.nullable);
} catch (e) {
    console.log("✗ Basic JSON failed:", e.message);
}

// Test 2: Single line comments
console.log("\n=== Test 2: Single Line Comments ===");
const withSingleComments = `{
    // This is a comment
    "name": "test", // inline comment
    "version": 2.0
    // trailing comment
}`;
try {
    const result2 = parse(withSingleComments);
    console.log("✓ Single line comments parsed successfully");
    console.log("  name:", result2.name);
    console.log("  version:", result2.version);
} catch (e) {
    console.log("✗ Single line comments failed:", e.message);
}

// Test 3: Multi-line comments
console.log("\n=== Test 3: Multi-line Comments ===");
const withMultiComments = `{
    /* This is a
       multi-line comment */
    "name": "test",
    /* Another comment */
    "description": "test object"
}`;
try {
    const result3 = parse(withMultiComments);
    console.log("✓ Multi-line comments parsed successfully");
    console.log("  name:", result3.name);
    console.log("  description:", result3.description);
} catch (e) {
    console.log("✗ Multi-line comments failed:", e.message);
}

// Test 4: Arrays with trailing commas
console.log("\n=== Test 4: Arrays with Trailing Commas ===");
const arrayWithTrailingComma = `{
    "dependencies": [
        "package1",
        "package2",
        "package3", // trailing comma
    ],
    "scripts": [
        "start",
        "build", // another trailing comma  
    ]
}`;
try {
    const result4 = parse(arrayWithTrailingComma);
    console.log("✓ Arrays with trailing commas parsed successfully");
    console.log("  dependencies:", result4.dependencies);
    console.log("  scripts:", result4.scripts);
} catch (e) {
    console.log("✗ Arrays with trailing commas failed:", e.message);
}

// Test 5: Objects with trailing commas
console.log("\n=== Test 5: Objects with Trailing Commas ===");
const objectWithTrailingComma = `{
    "compilerOptions": {
        "target": "esnext",
        "module": "esnext", // trailing comma
    },
    "include": [
        "src/**/*"
    ], // another trailing comma
}`;
try {
    const result5 = parse(objectWithTrailingComma);
    console.log("✓ Objects with trailing commas parsed successfully");
    console.log("  compilerOptions:", result5.compilerOptions);
    console.log("  include:", result5.include);
} catch (e) {
    console.log("✗ Objects with trailing commas failed:", e.message);
}

// Test 6: Complex tsconfig.json example
console.log("\n=== Test 6: Complex tsconfig.json Example ===");
const tsconfigExample = `{
    // Visit https://aka.ms/tsconfig to read more about this file
    "compilerOptions": {
        // File Layout
        "rootDir": "./",
        "outDir": "./dist",
        
        // Environment Settings  
        "module": "esnext",
        "target": "esnext",
        "moduleResolution": "node",
        "resolveJsonModule": true,
        "allowSyntheticDefaultImports": true,
        
        "typeRoots": [
            "types/", // custom types
        ],
        
        "lib": [
            "esnext", // ES next features
        ],
        
        // Other Outputs
        "sourceMap": true,
        "declaration": true,
        "declarationMap": true,
        
        /* Stricter Typechecking Options */
        "noUncheckedIndexedAccess": true,
        "exactOptionalPropertyTypes": true,
        
        // Style Options (commented out)
        // "noImplicitReturns": true,
        // "noImplicitOverride": true,
        
        // Recommended Options
        "strict": true,
        "jsx": "react-jsx",
        "verbatimModuleSyntax": true,
        "isolatedModules": true,
        
        "moduleDetection": "force",
        "skipLibCheck": false,
        "allowJs": true,
    },
    
    "typedocOptions": {
        "name": "circu.js",
        "entryPoints": [
            "types/", // entry point
        ],
        "entryPointStrategy": "expand",
        "out": "../api/",
        "disableSources": true, // disable source links
    },
}`;
try {
    const result6 = parse(tsconfigExample);
    console.log("✓ Complex tsconfig.json parsed successfully");
    console.log("  compilerOptions.target:", result6.compilerOptions.target);
    console.log("  compilerOptions.lib:", result6.compilerOptions.lib);
    console.log("  typedocOptions.name:", result6.typedocOptions.name);
} catch (e) {
    console.log("✗ Complex tsconfig.json failed:", e.message);
}

// Test 7: Error cases with line numbers
console.log("\n=== Test 7: Error Cases with Line Numbers ===");

// Test 7a: Unclosed string
console.log("--- Test 7a: Unclosed String ---");
const unclosedString = `{
    "name": "unclosed string,
    "version": 1.0
}`;
try {
    const result7a = parse(unclosedString);
    console.log("✗ Unclosed string should have failed");
} catch (e) {
    console.log("✓ Unclosed string correctly failed with:", e.message);
}

// Test 7b: Missing comma
console.log("--- Test 7b: Missing Comma ---");
const missingComma = `{
    "name": "test"
    "version": 1.0
}`;
try {
    const result7b = parse(missingComma);
    console.log("✗ Missing comma should have failed");
} catch (e) {
    console.log("✓ Missing comma correctly failed with:", e.message);
}

// Test 7c: Invalid number
console.log("--- Test 7c: Invalid Number ---");
const invalidNumber = `{
    "version": 1.2.3.4,
    "count": 123abc
}`;
try {
    const result7c = parse(invalidNumber);
    console.log("✗ Invalid number should have failed");
} catch (e) {
    console.log("✓ Invalid number correctly failed with:", e.message);
}

// Test 8: Nested structures
console.log("\n=== Test 8: Nested Structures ===");
const nestedStructures = `{
    "level1": {
        "level2": {
            "level3": [
                {
                    "id": 1,
                    "name": "item1", // comment in nested array
                },
                {
                    "id": 2,
                    "name": "item2",
                }, // trailing comma in nested array
            ], // trailing comma
        },
        "array": [1, 2, 3, ],
    },
    /* Multi-line
       comment in
       nested structure */
    "simple": "value",
}`;
try {
    const result8 = parse(nestedStructures);
    console.log("✓ Nested structures parsed successfully");
    console.log("  level1.level2.level3 length:", result8.level1.level2.level3.length);
    console.log("  level1.array:", result8.level1.array);
    console.log("  simple:", result8.simple);
} catch (e) {
    console.log("✗ Nested structures failed:", e.message);
}

// Test 9: Empty structures
console.log("\n=== Test 9: Empty Structures ===");
const emptyStructures = `{
    "emptyObject": {},
    "emptyArray": [],
    "nullValue": null,
    "falseValue": false,
    "trueValue": true,
    // "commented": "value",
}`;
try {
    const result9 = parse(emptyStructures);
    console.log("✓ Empty structures parsed successfully");
    console.log("  emptyObject:", result9.emptyObject);
    console.log("  emptyArray:", result9.emptyArray);
    console.log("  nullValue:", result9.nullValue);
    console.log("  falseValue:", result9.falseValue);
    console.log("  trueValue:", result9.trueValue);
} catch (e) {
    console.log("✗ Empty structures failed:", e.message);
}

// Test 10: Numbers in various formats
console.log("\n=== Test 10: Various Number Formats ===");
const numberFormats = `{
    "integer": 42,
    "negative": -123,
    "float": 3.14159,
    "scientific": 1.23e+10,
    "negativeScientific": -4.56e-5,
    "zero": 0,
    "negativeZero": -0,
    // "hex": 0xFF, // JSON doesn't support hex
}`;
try {
    const result10 = parse(numberFormats);
    console.log("✓ Number formats parsed successfully");
    console.log("  integer:", result10.integer);
    console.log("  negative:", result10.negative);
    console.log("  float:", result10.float);
    console.log("  scientific:", result10.scientific);
    console.log("  negativeScientific:", result10.negativeScientific);
    console.log("  zero:", result10.zero);
    console.log("  negativeZero:", result10.negativeZero);
} catch (e) {
    console.log("✗ Number formats failed:", e.message);
}

console.log("\n=== All Tests Completed ===");