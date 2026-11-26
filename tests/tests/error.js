const error = import.meta.use('error');

function assertTypeError(fn, message) {
    let caught;
    try {
        fn();
    } catch (cause) {
        caught = cause;
    }
    assert(caught instanceof TypeError, message);
}

await test('error - constructs coded errors safely', () => {
    const direct = error.Error(error.errno.EINVAL);
    assert(direct instanceof Error, 'direct Error call should return an Error');
    assertEquals(direct.name, 'IOError');
    assertEquals(direct.code, error.errno.EINVAL);

    const constructed = new error.Error(error.errno.EINVAL);
    assert(constructed instanceof Error, 'new Error call should return an Error');
    assertEquals(constructed.name, 'IOError');
    assertEquals(constructed.code, error.errno.EINVAL);
});

await test('error - exposes libuv error names and messages', () => {
    assertEquals(error.getErrorName.length, 1);
    assertEquals(error.getErrorMessage.length, 1);
    assertEquals(error.getErrorName(error.errno.EINVAL), 'EINVAL');
    assertEquals(error.getErrorMessage(error.errno.EINVAL), 'invalid argument');
    assertEquals(error.getErrorName(-424242), 'Unknown system error -424242');
    assertEquals(error.getErrorMessage(-424242), 'Unknown system error -424242');
    assertTypeError(() => error.getErrorName(), 'getErrorName() should require an error code');
    assertTypeError(() => error.getErrorMessage(), 'getErrorMessage() should require an error code');
});

await test('error - rejects a missing error code without reading argv out of bounds', () => {
    assertTypeError(() => error.Error(), 'Error() should require an error code');
    assertTypeError(() => new error.Error(), 'new Error() should require an error code');
});
