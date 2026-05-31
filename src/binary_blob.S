/* binary_blob.S — embeds CJS_BLOB_PATH at link time via .incbin.
 * Only compiled when CJS_BLOB_INCBIN is defined (GCC/Clang builds).
 * CJS_BLOB_PATH must be defined as a string literal by the build system. */

#if defined(__APPLE__)
    .section __DATA,__cjs_blob
#else
    .section .rodata
#endif

    .global _cjs_blob_start
    .global _cjs_blob_end

#if defined(__APPLE__)
    /* Mach-O doesn't use the leading underscore in .global but the C
       extern declaration does — the assembler adds it automatically. */
_cjs_blob_start:
    .incbin CJS_BLOB_PATH
_cjs_blob_end:
#else
_cjs_blob_start:
    .incbin CJS_BLOB_PATH
_cjs_blob_end:
#endif
