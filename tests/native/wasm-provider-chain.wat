(module
  (type $i32-result (func (result i32)))
  (type $i64-result (func (result i64)))

  (import "provider" "throwing" (func $provider_throwing (type $i32-result)))
  (import "provider" "wrong" (func $provider_wrong (type $i64-result)))

  (global $after_throw (export "afterThrow") (mut i32) (i32.const 0))
  (global $after_wrong (export "afterWrong") (mut i32) (i32.const 0))

  ;; The globals make execution after a provider call observable. If the
  ;; provider trapped, neither assignment may run in any consumer module.
  (func (export "throwing") (type $i32-result)
    call $provider_throwing
    i32.const 1
    global.set $after_throw)

  (func (export "wrong") (type $i64-result)
    call $provider_wrong
    i32.const 1
    global.set $after_wrong)

  ;; Does not call a provider. Calling this immediately after a caught chain
  ;; failure detects an exception left stale on an intermediate instance.
  (func (export "probe") (type $i32-result)
    i32.const 42))
