(module
  (import "env" "console_log" (func $js_console_log (param i32 i32)))  ;; ptr, len

  (memory (export "memory") 1)
  (data (i32.const 0) "Hello, I am calling JS from WASM!\00")

  (func $trigger (export "trigger")
    i32.const 0      ;; ptr
    i32.const 35     ;; len
    call $js_console_log
  )
)