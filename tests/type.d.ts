declare function test(name: string, fn: () => void | Promise<void>): Promise<void>;
declare function assert(value: any, message?: string): asserts value;
// declare function assertEquals(actual: any, expected: any, message?: string): asserts actual is typeof expected;
declare function panic(message: string): never;
// require('server') -> CModuleServer
declare const use: ImportMeta['use'];