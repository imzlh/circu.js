circu.js/src/vm.c
1. tjs__eval_bytecode（约第 565-590 行）：错误路径泄漏 obj
问题：obj 由 JS_ReadObject 返回、本应由后面的 JS_EvalFunction(ctx, obj) 消费；但若 JS_ResolveModule(...) < 0 或 JS_GetImportMeta 返回异常时 goto error，此时还没走到 JS_EvalFunction，obj（一个有效的 module 引用）没有被 free → 内存泄漏。（初始 JS_IsException(obj) 那条不算，异常值非引用计数。）
改法：在 error: 之前对这两条提前返回的路径补 JS_FreeValue(ctx, obj)；或在 error: 标签处统一释放（需保证 obj 在该作用域可见且未被消费）。
2. 全局 vm_exit_code（int8_t）被主线程与 worker 共享（逻辑问题，非崩溃）
问题：TJS_Stop 只在 !is_worker 时设置 vm_exit_code，但 uv__stop 对主/worker 都用全局 vm_exit_code 派发 EV_EXIT；worker 退出时拿到的是主运行时的退出码。多 worker 还存在跨线程读写同一全局的竞态。
改法：把退出码做成每个 TJSRuntime 的字段，EV_EXIT 用对应运行时自己的退出码。
3. atomic_add_int（第 78 行）把 int* 强转为 _Atomic(uint32_t)*（代码质量/可移植性）
问题：对 sab->ref_count（声明为 int）用 _Atomic(uint32_t)* 别名访问，严格来说是类型别名 UB，个别平台/优化下可能出问题。
改法：把 TJSSABHeader.ref_count 直接声明为 _Atomic int，用 atomic_fetch_add 直接操作。

circu.js/src/modules.c
1. tjs__normalize_pathsep（Windows 路径，约第 430 行）通过 const char* 写入 → UB/内存损坏
问题：函数签名是 const char *name，但 Windows 分支里 for (p = name; ...) p[0] = TJS__PATHSEP; 直接改写。在 tjs__module_normalizer 中第一次调用是 tjs__normalize_pathsep(name)，而 name 是 QuickJS 传入的 import 说明符（const，可能只读/共享），原地改写它是未定义行为，Windows 上可能崩溃或损坏 specifier。（第二次对 filename 调用是 OK 的，那是可写的 malloc 内存。）
改法：参数改成 char * 且只对可写的 filename 归一化；不要改写传入的 name（需要时先 js_strdup 一份再处理）。
2. tjs__module_loader JS-loader 返回字符串分支（约第 305 行）未检查 JS_ToCStringLen
问题：const char *str = JS_ToCStringLen(ctx, &strlen, ret); 之后直接 dbuf_put(&dbuf, str, strlen+1)，没判 str==NULL。转换失败（OOM 等）时 str 为 NULL 且 strlen 未初始化 → 空指针解引用 / 越界。
改法：if (!str) { JS_FreeValue(ctx, ret); return NULL; } 后再 dbuf_put。
附带：该分支用的是裸 dbuf_init(&dbuf)，而函数其他路径用 tjs_dbuf_init（绑定 JS 分配器）；虽然 free 自洽不致崩，但分配器不一致，建议统一为 tjs_dbuf_init。
3. 代码质量：同一分支里局部变量 size_t strlen 遮蔽了 libc 的 strlen
问题：靠"该分支 goto compile 跳过了后续 strlen() 调用"才不冲突，非常脆弱。
改法：把局部变量改名（如 slen）。

circu.js/src/mod_fswatch.c
1.【内存泄露 / GC 正确性，头号】tjs_fswatch_mark 漏标 fw->this_val 自引用
static void tjs_fswatch_mark(JSRuntime *rt, JSValue val, JS_MarkFunc *mark_func) {
    TJSFsWatch *fw = tjs_fswatch_get(val);
    if (fw) {
        JS_MarkValue(rt, fw->callback, mark_func);
        // ← 缺 JS_MarkValue(rt, fw->this_val, mark_func);
    }
}
​
tjs_fs_watch 结尾 fw->this_val = JS_DupValue(ctx, obj) 制造了一个 obj→opaque→this_val→obj 的自引用（给 obj 加了 +1 引用计数）。QuickJS 的循环回收要求 gc_mark 必须上报对象持有的所有引用，包括这个自引用。这里漏标 → 循环回收器永远看到 obj 还有一个"来自外部"的引用计数 → 永远不回收它。
后果：用户若只是丢弃 watcher 而没调用 close()，这个 watcher（TJSFsWatch + uv handle）就永久泄露；而且这里没有 uv_unref（不像 mod_signals.c），泄露的 handle 还会一直 ref 住事件循环，导致进程无法干净退出。
对照：mod_socket.c 的 gc_mark 是有 JS_MarkValue(rt, s->this_obj, ...) 的——本文件与之不一致，应当补上。
方向性说明：gc_mark 上报的引用比实际少，最坏只会"漏收/泄露"（不会 UAF，方向是安全的）；但确实是泄露。
改法：在 tjs_fswatch_mark 里补 JS_MarkValue(rt, fw->this_val, mark_func)（让无外部引用、又没显式 close 的 watcher 能被循环回收并触发 finalizer→uv_close）。若确实想"未 close 永不回收"，那也应改用 uv_unref 等机制，而不是靠漏标 mark 来实现——后者破坏 GC 记账一致性。
3.【健壮性】uv__fs_event_cb 的 CHECK(0 && "invalid fs events") 分支
当 events 既无 UV_RENAME 又无 UV_CHANGE 时走该分支：CHECK 是 abort 型宏（外部 fs 事件理论上可触发）。更糟的是若某构建把 CHECK 编译为空，event 变量未初始化就被 args[1]=event 使用并 JS_FreeValue → 崩。
改法：该分支直接 return（什么都不派发），不要依赖 CHECK 兜底，避免未初始化 event 的二次风险。

circu.js/src/mod_signals.c
1.【低优先 / 再入 UAF 隐患，全代码库通病】信号回调里 sh->func 是借用引用
static void uv__signal_cb(uv_signal_t *handle, int sig_num) {
    TJSSignalHandler *sh = handle->data;
    tjs_call_handler(sh->ctx, sh->func, 0, NULL);   // 借用 sh->func，未 dup
}
​
若 JS 处理函数在执行过程中把对自身 handler 对象的最后一个引用置空（且该闭包没被别处引用），handler 对象引用计数归零会立即触发 finalizer → JS_FreeValueRT(rt, sh->func)，把正在执行的函数对象释放掉 → 潜在 UAF。这是借用式回调的通用风险（timers/streams/socket poll 同理）。
建议（防御性）：回调期间对 sh/sh->func 各 JS_DupValue 一次、调用后再 free；或确认 tjs_call_handler 内部已 dup（待核对 utils.c 里 tjs_call_handler 是否 dup func——若它内部已 dup 则此条可消除）。
2.【行为提醒，非 bug】handle 被 uv_unref 且无自钉，未持有引用会"静默失效"
tjs_signal 里 uv_unref(&sh->handle)，且对象不像 mod_socket.c 那样自钉。若 JS 侧 tjs.signal(SIG, cb) 的返回对象未被保存，它会被 GC → finalizer → uv_close，信号处理器静默停止。这是 txiki 的既定约定（调用方需持有句柄），但容易踩，值得在文档/JS 包装层提示。

circu.js/src/mod_dns.c
1.【UAF / SEGV，头号】自研 UDP DNS 查询的 handle/ctx 无任何属主，退出时回调踩已释放 ctx
tjs_dns_query 里 dns_udp_ctx_t（含 udp、timeout_timer 两个 libuv handle + send_req）是裸 malloc，只被 handle 的 .data 引用，没有任何 JS 对象持有它，也没有 finalizer。它只能靠 udp_recv_callback/udp_timeout_callback/udp_send_callback(错误) 三条回调之一来 uv_close 收尾。
触发链（进程退出/运行时销毁时仍有 DNS 查询在途，比如 5s 超时还没到）：vm.c::TJS_FreeRuntime 先 JS_FreeContext/JS_FreeRuntime——没有任何东西关闭这两个 DNS handle（没有 finalizer 去调度 uv_close）——之后才用 uv_run 清扫 loop。此时：
若清扫期间超时定时器到点或 DNS 响应到达 → udp_timeout_callback/udp_recv_callback 用 ctx->ctx（已释放的 JSContext）和 ctx->reject_func（已死 runtime 的 JSValue）去 JS_NewError/JS_Call → UAF/SEGV，正是你说的高频崩溃模式；
若没触发 → 两个 handle 始终开着，uv_loop_close 返回 EBUSY（debug 下可能断言）+ ctx/handle 泄露。
这比 mod_udp.c 更糟：那里 handle 至少挂在 GC 对象上、finalizer 会调度 uv_close；这里连属主都没有。
改法：把 dns_udp_ctx_t 纳入运行时可枚举/可取消的在途请求集合（或挂到一个 JS 包装对象+finalizer 上），在 context 销毁前统一 uv_udp_recv_stop+uv_timer_stop+uv_close 并结清 promise；回调入口再加"运行时正在销毁则只释放、不碰 ctx/JSValue"的护栏。
同源风险：异步 uv__getaddrinfo_cb 也用 gr->ctx 在回调里 TJS_SettlePromise/js_free(ctx,gr)，退出时被 UV_ECANCELED 回调同样会踩已死 ctx（线程池请求，uv_loop_close 前若 ctx 已释放即 UAF）。属同一类，需一并加销毁护栏。
2.【逻辑→进程 abort】tjs_addrinfo2obj 用 CHECK_EQ 对外部解析结果做断言
for (ptr = ai; ptr; ptr = ptr->ai_next) {
    CHECK_EQ(ptr->ai_socktype, SOCK_STREAM);   // ← 不等就 abort 整个进程
​
虽然 hints 设了 SOCK_STREAM，但部分平台/解析器（数字地址、特定 nsswitch 配置）仍可能返回 ai_socktype==0 或非 STREAM 项 → CHECK_EQ 直接 abort，等于一次 DNS 解析就能崩掉进程。
改法：把断言改成"跳过非 SOCK_STREAM 项"的普通过滤，不要对系统/外部数据用 abort 型宏。
3.【逻辑】AAAA 默认服务器用 IPv6 字面量喂给 uv_ip4_addr，且返回值被忽略
const char* server = qtype == DNS_AAAA ? "2001:4860:4860::8888" : "8.8.8.8";
...
uv_ip4_addr(server, 53, &req_ctx->server_addr);   // IPv6 串解析必失败，返回值没查
​
server_addr 是 struct sockaddr_in（仅 IPv4），uv_ip4_addr 解析 IPv6 字面量会失败，但返回值被丢弃 → server_addr 保持全零 → 查询被发往 0.0.0.0:53，默认 AAAA 查询直接不可用。而且"查 AAAA 记录"和"用 IPv6 DNS 服务器"本就是两回事（DNS 传输用 IPv4 也能查 AAAA）。
改法：默认服务器统一用 IPv4（如 8.8.8.8）与 sockaddr_in；要支持自定义 IPv6 服务器则改 sockaddr_storage + 按族选 uv_ip4_addr/uv_ip6_addr，并检查返回值。
4.【内存安全 / 可移植性】报文解析里大量未对齐读
parse_dns_response/dns_answer_to_js/build_dns_query 里 ntohs(*(uint16_t*)(packet+pos))、*(uint32_t*)(params+4) 等在任意偏移上做多字节指针解引用。x86 无碍，但在严格对齐架构（ARM 等）上是 UB，可能 SIGBUS。
改法：统一用 memcpy 到本地变量再 ntohs/ntohl（如头部解析已用 memcpy(&hdr,...) 的写法，推广到全部字段）。
附带：此路径全程用裸 malloc/free/calloc/strdup，绕过运行时内存计费（与其余模块不一致，DEBUG 下计数会漂）。
5.【次要】
同步提交失败分支（uv_udp_send 返回 <0）里 JS_FreeValue(promise) 后改为 throw，使该函数有时返回 promise、有时抛异常，调用方需两头兼容（行为不一致，非内存 bug）。
uv_udp_init/uv_udp_recv_start/uv_timer_init/uv_timer_start 返回值均未检查。

circu.js/src/mod_udp.c
1.【UAF / SEGV，头号】在途 send 的完成回调 uv__udp_send_cb 会在 ctx 被释放后引用它
TJSSendReq 不挂在 u 上、也没 pin UDP 的 JS 对象，发送在途时没有任何东西阻止 UDP 对象被回收：
static void uv__udp_send_cb(uv_udp_send_t *req, int status) {
    TJSUdp *u = req->handle->data;
    JSContext *ctx = u->ctx;                       // ← 退出时 ctx 已被 JS_FreeRuntime 释放
    ...
    TJS_SettlePromise(ctx, &sr->result, ...);      // ← UAF
    tjs_udp_send_req_free(ctx, sr);                // ← 同样用已死 ctx 释放
}
​
触发链（进程退出 / 运行时销毁时仍有 send 在途）：vm.c::TJS_FreeRuntime 顺序是先 JS_FreeContext/JS_FreeRuntime（此时 udp finalizer 跑 maybe_close 调度 uv_close），之后才用 5 次 uv_run 清扫 loop。清扫阶段 libuv 把在途的 uv_udp_send_t 以 UV_ECANCELED 回调 uv__udp_send_cb——但此刻 u->ctx 指向已释放的 context → tjs_new_error(ctx,...) / TJS_SettlePromise(ctx,...) 直接 UAF/崩溃。这正是你说的"回调里 ctx/rt 已回收"的高频崩溃模式。
注意：普通运行期的 GC 不会触发它——那时 u 在 close_cb 前仍有效、ctx 也活着，send_cb 先于 close_cb 跑，安全。问题只在 ctx 已销毁后的 loop 清扫阶段。
对比：recv 路径在 teardown 时是安全的——finalizer 已用 tjs_udp_read_clear_rt 释放缓冲、uv_close 立即停掉 recv，uv__udp_recv_cb 不会再触发。只有 send 会遗留一个引用 ctx 的孤儿回调。
改法（任一）：(a) 在 context 销毁前先 drain/cancel 在途 UDP 发送；或 (b) 给运行时加一个"正在销毁"标志，uv__udp_send_cb 进入即检查，若运行时已死则只做不依赖 ctx 的释放（用保存的 rt 走 *_rt 释放 sr）而跳过 TJS_SettlePromise；或 (c) 让 u 维护在途 send 链表，finalizer 里就地用 *_rt 结清并把 sr->req 解绑，使后续回调无需碰 ctx。
所以正常结算后 p->p 与 rfuncs 都被置 JS_UNDEFINED，TJS_IsPromisePending（即 !JS_IsUndefined(p->p)）能正确反映状态 → mod_streams.c 里 connect/shutdown 基于 .p 复位的复用守卫是可靠的，之前标的"脆弱复位"可降级。
但 mod_streams.c 退出期 shutdown_promise 的 UAF 仍然成立：那条问题是 finalizer 用 TJS_FreePromiseRT 释放了 promise（且若未配套 TJS_ClearPromise，rfuncs 即成悬空且非 UNDEFINED），随后退出 drain 里 uv__shutdown_cb 又对它 TJS_SettlePromise → JS_Call 一个已释放的 resolving func → UAF。这与"正常结算复位"是两码事，保留。
2.【逻辑，UDP 语义】tjs_udp_send 的"部分发送后再异步发余量"分支对 UDP 是错的
r = uv_udp_try_send(&u->udp, &b, 1, sa);
if (r == size) { ... return resolved; }
if (r >= 0) { buf += r; size -= r; }   // ← 把一个数据报拆成两半
​
UDP 数据报是原子的：uv_udp_try_send 对 UDP 要么整包发出（返回 size）、要么 UV_EAGAIN（负），不会返回 0<r<size 的部分计数。所以这个 buf+=r; size-=r; 分支对 UDP 实际是死代码；万一某平台真返回部分值，就会把半个数据报当成新数据报再发出去，产生损坏的报文。
改法：去掉部分推进逻辑，try_send 非 size 即视为需整包异步重发（拷贝原始完整 buf/size）。
3.【代码质量】sr->tarray 的 pin 是冗余的
tjs_udp_send 既 sr->data = js_malloc + memcpy（真正用于发送的是 sr->data），又 sr->tarray = JS_DupValue(argv[0])。数据已拷贝，发送不再依赖用户原 buffer，多 pin 一份 tarray 直到回调才释放属于无谓持有（不是 bug，但可省）。

circu.js/src/mod_socket.c
1.【UAF / SEGV，头号】tjs_sock_poll_close_cb 在 close_cb 里释放 JSValue，运行时销毁时 ctx/rt 已没了
static void tjs_sock_poll_close_cb(uv_handle_t *handle) {
    tjs_sock_t *s = uv_handle_get_data(handle);
    ...
    if (s->finalized) {
        JS_FreeValue(s->jsctx, s->this_obj);   // ← 在 close_cb 里释放 JSValue
        s->this_obj = JS_UNDEFINED;
        tjs__free(s);
    }
}
​
触发链：socket 正在 poll、没被显式 close()，进程退出。tjs_sock_finalizer 在 JS_FreeRuntime 内运行 → close_sock 调 uv_close(&s->poll, tjs_sock_poll_close_cb)；随后 finalizer 里 uv_is_closing(&s->poll) 为真 → 跳过释放，把 this_obj/s 留给 close_cb。但 tjs_sock_poll_close_cb 是在 vm.c::TJS_FreeRuntime 末尾那 5 次 uv_run(NOWAIT) 清扫阶段才触发的——此时 JS_FreeContext/JS_FreeRuntime 已执行完，s->jsctx 指向已释放的 context，s->this_obj 是已销毁 runtime 里的 JSValue → JS_FreeValue 直接 UAF/崩溃。这正是你说的高频崩溃模式。
改法：照搬 mod_streams.c/mod_worker.c 的安全套路——在 finalizer 里（rt 还活着时）用 JS_FreeValueRT 释放 this_obj 和 callback 并置 UNDEFINED，close_cb 里只做 tjs__free(s)，绝不碰任何 JSValue。
2.【内存泄露，与 #1 同根】显式 close() 后再被 GC，s 和 this_obj 永不释放
close_cb 和 finalizer 的协调用了两套不一致的判据，反方向也会漏：
JS 调 socket.close() → close_sock 调 uv_close(..., close_cb)，但没碰 this_obj（self-pin 仍在）。
close_cb 先触发：此刻 s->finalized == false → 它什么都不释放就返回。
之后对象被 cycle-GC → finalizer：close_sock 因 s->closed 立即返回；接着 if (!uv_is_closing(&s->poll)) —— handle 早已关闭，uv_is_closing 返回真 → finalizer 也跳过释放，指望 close_cb 来做，可 close_cb 早跑完了。
→ 结果 tjs_sock_t 和 this_obj 这个引用永久泄露。每个"显式关闭过再丢弃"的 socket 都漏。
改法：同 #1。把 JSValue 释放固定放在 finalizer（rt 存活）、把 s 的释放用"finalized 标志 + close_cb 仅 free 结构体"来唯一收口，让两条路径不再各自判断、互相踏空。
3.【生命周期设计】this_obj 从创建起就自引用，整生命周期自钉
tjs_sock_new_from_fd 里 s->this_obj = JS_DupValue(ctx, obj)——socket 一创建就持有自己的强引用，且 close() 不解除它。这意味着 socket 永远无法靠引用计数归零回收，必须等 cycle GC（mark-sweep）。gc_mark 标了 this_obj，所以不是真泄露，但：(a) 大量短生命周期 socket 会堆积到下次 GC 才释放；(b) 它正是 #1/#2 协调复杂度的来源。
建议：改成只在 poll 进行期间临时 pin（uv_poll_start 时 dup、poll_stop/close 时 unpin），与 mod_streams.c 的 pin 模型一致，能同时简化 #1/#2。
4.【逻辑 / IPv6 被截断】tjs_sock_sockaddr_inet 把地址 realloc 到 sizeof(struct sockaddr)
struct sockaddr_storage *ss = js_malloc(ctx, sizeof(*ss));   // 128B
tjs_obj2addr(ctx, argv[0], ss);
struct sockaddr *addr = js_realloc(ctx, ss, sizeof(struct sockaddr)); // 缩到 16B
return TJS_NewUint8Array(ctx, (uint8_t*)addr, sizeof(struct sockaddr));
​
sizeof(struct sockaddr) 只有 16 字节，够 IPv4 (sockaddr_in)，但 sockaddr_in6 需要 28 字节 → IPv6 地址会被截断，生成错误的 sockaddr。
改法：按地址族返回正确长度（ss_family 判断 sizeof(sockaddr_in) / sizeof(sockaddr_in6)），不要硬缩到 sizeof(struct sockaddr)。
5.【内存安全 / 健壮性】recvmsg 多处 js_malloc 未判空
msg.msg_name、msg.msg_control、iov.iov_base = js_malloc(ctx, bufsz) 均未检查 NULL，OOM 时会把 NULL 传给 recvmsg，成功分支还会 TJS_NewUint8Array(NULL,...)。
改法：每个 js_malloc 后判空并清理已分配项再抛 OOM。
（注：成功路径不 js_free 这些缓冲是对的——TJS_NewUint8Array 接管所有权，这点与 tjs_sock_recv 成功分支不 free buf 的写法一致，已核对一致、无泄露。）
6.【健壮性】tjs_sock_accept 未检查 tjs_sock_new_from_fd 异常
若 newSock 是异常值，仍对它 JS_SetPropertyStr(..., "_sockaddr", ...)，且新建的 Uint8Array 会落空。建议先判 JS_IsException(newSock)。


circu.js/src/mod_engine.c
1.【逻辑 / 函数完全失效】tjs_proimise_result 把 this_val 当成了参数
static JSValue tjs_proimise_result(JSContext* ctx, JSValueConst promise, int argc, JSValueConst* argv) {
    if (argc == 0 || !JS_IsPromise(promise)) { ... }
​
它经 TJS_CFUNC_DEF("promiseResult", 1, ...) 注册，用的是通用 cfunc 签名 (ctx, this_val, argc, argv)。所以第二个形参 promise 实际是 this_val，真正的 promise 在 argv[0]。JS 调 promiseResult(p) 时 this_val 是 undefined → JS_IsPromise 为假 → 永远抛 "argument must be a Promise"，这个 API 根本用不了。
改法：签名改成标准 (ctx, this_val, argc, argv)，函数体里读 argv[0]。可直接对照同文件 tjs_waitIO 的正确写法（它就是用 argv[0]）。
2.【引用计数泄露】tjs_waitIO 的 FULFILLED/REJECTED 分支多持有一个引用
case JS_PROMISE_FULFILLED: {
    JSValue result = JS_PromiseResult(ctx, argv[0]);  // 已 +1（owned）
    return JS_DupValue(ctx, result);                  // 又 +1，原 result 永不释放
}
case JS_PROMISE_REJECTED: {
    JSValue error = JS_PromiseResult(ctx, argv[0]);   // +1
    return JS_Throw(ctx, JS_DupValue(ctx, error));    // Throw 吃掉 dup 的那个，原 error 泄露
}
​
JS_PromiseResult 返回的是已 dup 的 owned 引用。这里再 JS_DupValue 一次却不释放原值，每次 await 一个 settled promise 都会泄露一个对结果对象的引用（结果对象/其整条引用链都不会被回收）。
改法：FULFILLED 直接 return result;；REJECTED 直接 return JS_Throw(ctx, error);（去掉多余的 JS_DupValue）。注意同文件 tjs_proimise_result 的 FULFILLED 写的是对的（return JS_PromiseResult(...) 不重复 dup），可作对照。
3.【引用计数泄露 + fallthrough】tjs_deserialize 丢失 module 值的引用
JSValue ret = JS_ReadObject(ctx, buf, len, flags);
switch (JS_VALUE_GET_NORM_TAG(ret)){
    case JS_TAG_MODULE:
        return module_new(ctx, (JSModuleDef*)JS_VALUE_GET_PTR(ret));  // ret 的引用从未释放
    case JS_TAG_FUNCTION_BYTECODE:
        // to do...        <-- 空 case 直接 fallthrough 到 default
    default:
        return ret;
}
​
MODULE 分支只取了裸指针交给 module_new，但 ret（tag=MODULE，持 +1）既没被 module_new 接管也没 JS_FreeValue → module 引用泄露（靠泄露才让 def 不被释放，见下面第 6 条）。
JS_TAG_FUNCTION_BYTECODE 空 case 落到 default，是隐式 fallthrough（功能上能返回，但属于易错写法，应显式处理或加注释）。
另外没判 JS_IsException(ret)（虽然异常会落到 default 原样返回，勉强 OK，但最好显式判）。
4.【内存安全】encodeString / encodeU16String 未判 JS_ToCStringLen* 失败
size_t strlen;
const char* str = JS_ToCStringLen(ctx, &strlen, argv[0]);   // 可能返回 NULL
JSValue buffer = JS_NewUint8ArrayCopy(ctx, (uint8_t*)str, strlen);  // NULL 解引用 + strlen 未初始化
​
JS_ToCStringLen（及 U16 版 JS_ToCStringLenUTF16）失败时返回 NULL，此时 strlen 也未被写入，下一行就是 NULL 解引用 + 读未初始化长度。
改法：两处都加 if (!str) return JS_EXCEPTION; 再继续。
5.【内存安全 / 逻辑】js_module_unref 释放的目标几乎肯定不对
tjs_module_export_t* me = ...; // 里面存了 me->var = def（DefineModuleExport 返回的 var_ref）
if (name_atom == me->atom){
    JS_FreeModuleExport(JS_GetRuntime(ctx), mt->def);  // 传的是整个模块 def，不是这个 export
    JS_FreeAtom(ctx, me->atom);
    list_del(&me->list); js_free(ctx, me); ...
}
​
两个强烈的不对劲信号：(a) me->var 被存下来却全程没人读；(b) 这里释放单个 export 却把 mt->def（整模块）传进去。而 js_module_finalizer 里对应的那行 JS_FreeModuleExport(rt, me->var) 是被注释掉的。两边对不上，unref 这个调用很可能释放错对象（要么误释放整模块的导出表造成后续 UAF/二次释放，要么根本没释放到目标 export 而泄露）。
改法：确认该自定义 API 的签名；按 me->var 的存储意图，应是 JS_FreeModuleExport(rt, me->var)，并让 finalizer 与 unref 二者的释放策略保持一致（只在一处释放，避免重复）。
6.【引用计数 / 所有权模型】module_new 对 module def 的所有权不清，构造器同样泄露
module_new 只 mt->def = def，而 js_module_finalizer 不释放 def。于是：
js_module_constructor 里 JS_Eval(..., COMPILE_ONLY) 得到的 compiled（tag=MODULE，+1）传给 module_new 后从不 JS_FreeValue → 和第 3 条一样泄露一个 module 引用；
这其实是"靠泄露保活"——因为 finalizer 不放 def，如果哪天补上 JS_FreeValue(compiled) 又会让 mt->def 悬空。
所以需要定一个明确的所有权模型：让 module_new 接管这个 module 引用（内部持有 JS_MKPTR(JS_TAG_MODULE, def) 并在 finalizer 用 JS_FreeValue 释放），调用方（构造器、deserialize）随后释放自己手里的 compiled/ret。注意 static_create/static_from 走的是 JS_NewCModule* 返回裸 def，没有多余 JSValue 引用，要和这两条路径区别对待。
7.【健壮性 / OOM】未判空
module_new：JS_NewObjectClass 的 obj 未判异常、js_malloc(mt) 未判 NULL → OOM 时 init_list_head(&mt->local_def) 直接 NULL 解引用。
js_module_export：me = js_malloc(...) 未判 NULL → me->atom = name NULL 解引用。
8.【代码质量】
tjs_encodeString 里局部 size_t strlen 遮蔽 libc strlen（与之前 modules.c 同类问题），建议改名。

1.【多线程 / 内存计账，重点】udata 跨运行时分配又跨线程释放
tjs_worker_constructor（主线程）用 udata = JS_WriteObject(ctx, ...) 分配序列化缓冲——这条分配是记在主 runtime 的内存账上的（js_malloc_rt 会累加主 rt 的 malloc_size）。但它在 worker_entry（子线程）里被 tjs__free(wd->udata) 释放：
wrt->builtins.worker_udata = JS_ReadObject(ctx, wd->udata, ...);
tjs__free(wd->udata);   // 子线程释放主 rt 记账的内存
​
tjs__free 走的是全局 mimalloc，绕过了主 rt 的记账，于是主 runtime 的 malloc_size 永远少减了 udata_size。在 DEBUG（JS_DUMP_LEAKS）下主线程 JS_FreeRuntime 会因残留计数触发断言/报"泄露"；设了 mem_limit 时配额会漂移。真实内存虽被 mimalloc 回收，但账目错乱。
改法：子线程不要释放 udata；因为 worker_entry 是在 uv_sem_post 之前就读完并清空了 udata，主线程 uv_sem_wait 返回后 udata 必然已被消费，所以把释放挪回主线程：worker 只 JS_ReadObject、不 free；主线程 uv_sem_wait 之后 js_free(ctx, udata)（用主 ctx 的 js_free 才能正确减账）。
2.【健壮性 / 异常未清】worker_entry 没检查 JS_ReadObject 的异常
wrt->builtins.worker_udata = JS_ReadObject(...) 若反序列化失败会返回 JS_EXCEPTION，随后在 tjs__mod_worker_init 里被 JS_SetPropertyStr(ctx, ns, "workerData", ...) 当普通值塞进命名空间，并且 ctx 上遗留一个未清的 pending exception，污染紧接着的 tjs__run_main 求值。
改法：JS_IsException 判断，失败时 JS_GetException 清掉并回退为 JS_UNDEFINED。
3.【并发 / 全局变量】vm_exit_code 被跨线程读写（与 worker 相关，重申）
uv__stop（可能跑在 worker 的 loop 线程）读全局 int8_t vm_exit_code 并 tjs__dispatch_event2(EV_EXIT, ...)；主线程 TJS_Stop 又会写它。这个全局变量同时承担"主进程退出码"和"被各线程读写"，既有数据竞争又语义错乱（worker 的退出会读到主线程的码）。
改法：退出码移入 TJSRuntime（每个 rt 一份），跨线程访问的那一份用原子类型；TJS_Stop 对 worker 不应触碰主码（现在用 !is_worker 勉强规避，但读侧仍是裸全局）。
4.【可能 hang / 阻塞主循环】tjs_worker_finalizer 在 GC 中同步 uv_thread_join
当 Worker 对象在正常运行期被 GC（不是退出阶段），finalizer 会 TJS_Stop + uv_thread_join 在主线程 GC 过程里同步阻塞，直到子线程退出。若子线程正卡在一段同步 JS（死循环 / 阻塞 syscall），TJS_Stop 的 async 唤不醒它 → 主线程在 GC 里永久卡死。这是潜在挂起（非 SEGV，但同样是"高频崩溃/卡死"来源）。
缓解：worker 退出尽量走显式 terminate()；或在 join 前给子线程一个可中断点 / 超时策略。
5.【内存泄露】提前终止时在途消息的 SAB 引用计数泄露
tjs_msgpipe_postmessage 成功 uv_write 后对每个 SAB tjs__sab_dup(+1)，约定由接收端 uv__read_cb 读到后 tjs__sab_free(-1)。若消息还没被对端读到、worker 就被 terminate/销毁，那个 transit 的 +1 永远不会被减 → SharedArrayBuffer 底层内存泄露（refcount 到不了 0）。在途 uv_write 被 uv_close 取消时 uv__write_cb 也只释放 wr，不碰 SAB，同样漏减。
改法：在管道 finalizer/关闭路径里，对"已 dup 但未送达"的 SAB 做补偿性 tjs__sab_free（需要记录每条在途写持有的 sab 列表，挂到 TJSMessagePipeWriteReq 上，write_cb/close 时统一减）。

circu.js/src/mod_streams.c
1.【UAF / 双重释放，重点】tjs_stream_shutdown 没有 pin 住流对象，而 shutdown_promise 存在 s 内部
对比同文件 tjs_tcp_connect / tjs_pipe_connect：它们在返回前都调用了 stream_pin(ctx, t, this_val)，让 s->obj 自持一个引用，保证 connect 在途时流的 JS 包装对象不会被 GC，因此 uv__connect_cb 里访问/结算 s->connect_promise 是安全的（完成后再 stream_unpin）。
而 tjs_stream_shutdown 没有任何 stream_pin，但 shutdown_promise 同样是内嵌在 s 里的字段。于是出现这条竞争：
s.shutdown();   // 异步 shutdown 在途，但 s 没被 pin
s = null;       // 丢掉唯一引用（返回的 promise 不引用 s 的包装对象）
// GC 回收 s 的包装对象 → tjs_stream_finalizer 运行
​
tjs_stream_finalizer 里会：
if (!JS_IsUndefined(s->shutdown_promise.p))
    TJS_FreePromiseRT(rt, &s->shutdown_promise);   // 把 promise 的 p / resolve / reject 都释放了
...
maybe_close(s);   // 此时 s->closed==0 → uv_close
​
随后 uv_close 会让在途的 shutdown 请求以 UV_ECANCELED 触发 uv__shutdown_cb：
TJS_RejectPromise(ctx, &s->shutdown_promise, 1, &arg);  // 操作已被 finalizer 释放的 promise → UAF/双重释放
​
即对已经释放的 resolve/reject 函数再次使用并释放，正是典型的崩溃来源。
为什么 connect 没事、write 也没事：connect 靠 stream_pin 保活；write 的 promise 放在堆上独立的 TJSWriteReq 里（finalizer 完全不碰它，uv__write_cb 自己释放），所以两者都安全。唯独 shutdown 既把 promise 放在 s 内、又不 pin。
改法：tjs_stream_shutdown 在 uv_shutdown 成功后像 connect 一样 stream_pin(ctx, s, this_val)；并在 uv__shutdown_cb 结算完、js_free(req) 前后 stream_unpin(s)。（或者把 shutdown_promise 改成像 write 那样放进堆分配的请求结构里，与 s 解耦。）
2.【次要 / 健壮性】单一 pin 引用模型 + promise 复用守卫
stream_pin 用 JS_IsUndefined(s->obj) 做幂等，整个流最多只持有"一个"自引用。目前靠 uv__connect_cb 里 if (!uv_is_active(&s->h.handle)) stream_unpin(s); 这种"是否还在 read"判断勉强协调，较脆弱：一旦未来新增"connect 在途同时又有别的在途异步操作"，先完成的一方 stream_unpin 会过早把另一方的保活也撤掉。建议改成显式计数的 pin（引用计数）而非布尔自引用。
connect/shutdown 的"already in progress"守卫用 !JS_IsUndefined(s->connect_promise.p) 判断；这依赖 TJS_ResolvePromise/RejectPromise 结算后把 .p 复位成 JS_UNDEFINED。若结算后未复位，第二次 connect()/shutdown() 会被永久挡住（"connect already in progress"）。建议确认结算函数是否复位 .p，否则在 uv__connect_cb/uv__shutdown_cb 结算后手动 s->connect_promise.p = JS_UNDEFINED。
3.【逻辑，较轻】startRead 与一次性 read 可叠加调用
tjs_stream_read 只用 s->read_req 判重，挡不住"已 startRead() 后再 read(buf)"：后者会再次 uv_read_start 覆盖回调为 one-shot 路径，造成读路径状态错乱（流式 read_buf 与一次性 read_req 混用）。建议进入 read()/startRead() 时互斥检查对方是否已激活。

 顺带一个贯穿全库的关键点：tjs_call_handler 没有 qrt->freeing 短路
tjs__dispatch_event 开头有 if (qrt->freeing || JS_IsUndefined(dispatch_event_func)) return; 的退出期护栏；但 tjs_call_handler 没有这层判断，会无条件 JS_Call(func1, …)。也就是说在 TJS_FreeRuntime 的 JS_FreeContext 之后的 uv_run drain 阶段，任何仍经 tjs_call_handler 触发的 handle 回调都会调进已释放的 ctx → 正是 DNS / socket 退出期那一类 SEGV 的放大器。
由此进一步印证全库正确的修法：必须在 JS_FreeContext 之前就 uv_close/取消掉所有在途 handle（signals/fswatch 靠 finalizer 做到了；dns 的裸 dns_udp_ctx_t、socket 的 close_cb-free-JSValue 没做到）。可选增强：给 tjs_call_handler 也加一个 if (TJS_GetRuntime(ctx)->freeing) { /* 不派发，仅释放 */ } 的护栏作为兜底。

circu.js/src/mod_error.c
1.【多线程，中低】未知错误码下 uv_strerror/uv_err_name 非线程安全
tjs_new_error / tjs__error_strerr 等都直接用 uv_strerror(err) / uv_err_name(err)。对已知 uv 码它们返回 const 字面量（安全）；但对未知码，libuv 会写入/返回一个进程级静态缓冲区。本项目有 worker 多线程，多个线程并发传未知码时存在数据竞争 / 串出乱码字符串的风险。
改法：未知码路径改用线程安全变体（uv_strerror_r/uv_err_name_r）或自带栈上缓冲格式化。
2.【质量/健壮性，低】构造函数不检查 JS_NewError/JS_NewString 异常，且 tjs_new_error 漏了末尾兜底
obj = JS_NewError(ctx);                                  // 未判异常
JS_DefinePropertyValue(ctx, obj, JS_ATOM_message,
    JS_NewString(ctx, buf), ...);                        // OOM 时把 exception 当属性值塞入
return obj;                                              // ← 缺 if(JS_IsException(obj)) obj=JS_NULL;
​
tjs_new_error_path / tjs_throw_errno / tjs_throw_errno_path 末尾都有 if (JS_IsException(obj)) obj = JS_NULL; 兜底，唯独 tjs_new_error 没有，不一致。OOM 边角才触发，低优先。
改法：给 tjs_new_error 补同样的异常兜底（并可在 JS_NewError 后早判一次）。
3.【质量，低】tjs__error_strerr 用 JS_ToUint32 接收本应为负的 uv errno，与构造器不一致
tjs_error_constructor 用 JS_ToInt32（对负的 UV_* 正确），而 tjs__error_strerr 用 JS_ToUint32。虽然 uint32 的位模式传入 int 形参会 round-trip 还原回负值、功能上仍正确，但语义不一致，应统一为 JS_ToInt32。

circu.js/src/mod_os.c
1.【内存安全，头号 UAF】tjs_random：先取 ArrayBuffer 指针，后做可触发用户代码的 JS_ToIndex
uint8_t *buf = JS_GetArrayBuffer(ctx, &size, argv[0]);   // ← 先拿到裸指针
...
if (!JS_IsUndefined(argv[1]) && JS_ToIndex(ctx, &off, argv[1])) ...   // 可能跑用户 valueOf
if (!JS_IsUndefined(argv[2]) && JS_ToIndex(ctx, &len, argv[2])) ...   // 可能跑用户 valueOf
...
int r = uv_random(NULL, NULL, buf + off, len, 0, NULL);  // ← buf 可能已悬空
​
若 argv[1]/argv[2] 是带 valueOf/toString 的对象，JS_ToIndex 会回调进 JS，用户可在其中 detach / transfer / resize 这个 ArrayBuffer，使 buf 指向已释放/已搬移的内存 → uv_random 往里写 → UAF / 堆破坏。
改法：把 JS_GetArrayBuffer 移到所有 JS_ToIndex 之后再取指针（并在取指针后再做 off+len>size 校验）；或转换后重新校验 buffer 未 detach。
2.【内存安全 / fd 泄露，中】tjs_recv_fd：校验失败不 close 已收 fd，且未查 MSG_CTRUNC
ret = recvmsg(sock_fd, &msg, 0);
...
struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
if (cmsg == NULL || ... || cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
    return JS_ThrowInternalError(ctx, "invalid control message");  // ← 此时 fd 可能已被内核装入本进程
​
只要 recvmsg 成功且对端确实通过 SCM_RIGHTS 传了 fd，内核已把 fd 装进本进程的 fd 表；任何校验失败（或对端发了多个 fd、或 MSG_CTRUNC 截断）这里直接抛异常 → 收到的 fd 泄露（长期运行耗尽 fd，且安全相关）。
改法：校验失败/截断分支里先 close(received_fd)（多 fd 则全部 close），并检查 msg.msg_flags & MSG_CTRUNC。
3.【逻辑，中低】tjs_exit：worker 线程里 exit(status) 杀掉整个进程
tjs_exit 末尾直接 exit(status)。若它在某个 worker 线程上下文被调用，会终止整个进程（含主线程和其它 worker），而不是仅结束当前 worker。视 os.exit 预期语义而定，可能需要在 worker 里改成只停该 worker 的 loop。
4.【逻辑/质量，低】tjs_sleep
if (argc == 0 || -1 == JS_ToInt64(ctx, &time, argv[0])) return JS_ThrowTypeError(...);
uv_sleep(time);   // uv_sleep 取 unsigned int
​
uv_sleep 同步阻塞当前事件循环线程；且 time 为负时经 int64→unsigned 截断成超大值（近乎永久睡眠），>UINT_MAX 也会截断。建议夹取为非负、范围内，并明确其阻塞语义。
5.【健壮性，低】tjs_network_interfaces 未知地址族时读未初始化栈
buf 仅在 AF_INET/AF_INET6 两分支被填充；若某接口地址族都不是，JS_NewString(ctx, buf) 会读未初始化的 buf。极少触发，建议 buf[0]=0 兜底。

circu.js/src/mod_http.c
1.【内存安全 / 再入，头号】execute() 解析期间回调重入或 detach 输入 buffer → 读悬空 data
uint8_t* data = JS_GetAnyBuffer(ctx, &len, argv[0]);   // 拿到 backing store 裸指针
tjs_llhttp_set_ref(ctx, &p->current_buf, JS_DupValue(ctx, argv[0]));  // 只 dup 了对象
p->cur_base = data; p->cur_len = len;
llhttp_errno_t err = llhttp_execute(&p->parser, (const char*) data, len);  // 跨多个回调读 data
​
llhttp_execute 会在解析过程中多次回调进 JS（tjs_llhttp_emit → JS_Call）。回调里的 JS 可以：
detach / transfer 这个 ArrayBuffer：current_buf 的 dup 只钉住了对象，并不能阻止 backing store 被 detach 释放；之后 llhttp 继续用 data 解析后续字节 → 读已释放内存（UAF 读）。
重入 execute() 或 reset()：llhttp 本身不可重入，且嵌套 execute 会把 cur_base/cur_len/current_buf 改掉，外层 emit 再算偏移时 cur_base 已被置 NULL；reset() 更会在 llhttp_execute 栈内 memset(settings)+llhttp_init → 解析器状态错乱。
改法：解析期间设一个"running"标志，重入 execute()/reset() 直接抛错；并在回调返回后/关键路径校验 buffer 是否已 detach（或文档约定回调内禁止动输入 buffer）。这是本文件最值得修的一条。
2.【内存安全，潜在 NULL 解引用崩溃】tjs_llhttp_static_status_text：范围检查不充分
if (-1 == JS_ToInt32(ctx, &status, argv[0]) || status < 100 || status >= 600)
    return JS_ThrowTypeError(...);
return JS_NewString(ctx, llhttp_status_name((llhttp_status_t) status));
​
100–599 只保证"在区间内"，但 llhttp_status_name 对区间内却未命名的状态码（如 199、209、420…）很可能返回 NULL，JS_NewString(ctx, NULL) 会 strlen(NULL) → SEGV。
改法：对 llhttp_status_name 的返回值判 NULL（NULL 则返回空串或抛错）。同理建议核实 llhttp_static_strerr 里 llhttp_errno_name 对越界 err 是否恒返回非 NULL（若是 switch+default 则安全，否则也要判）。
3.【质量，低】finalizer 用 JS_FreeValue(ctx, …) 而非 JS_FreeValueRT(rt, …)
static void tjs_llhttp_parser_finalizer(JSRuntime* rt, JSValue val) {
    ...
    JSContext* ctx = p->ctx;
    for(...) JS_FreeValue(ctx, p->events[i]);   // 应用 JS_FreeValueRT(rt, …)
    ...
}
​
finalizer 形参已给了 rt，但这里全程用 ctx 释放。退出期 finalizer 里用 ctx 不如用 rt 稳妥（与本库 signals/fswatch 用 JS_FreeValueRT 的安全范式不一致）。js_free(ctx,p) 可保留。建议改用 *_RT。
4.【健壮性,低】execute() 对 argc==0 直接 return JS_EXCEPTION 但未设异常
data = argc==0 ? NULL : JS_GetAnyBuffer(...)，if(!data) return JS_EXCEPTION; —— argc==0 这条会抛出一个"无 pending 异常"的 JS_EXCEPTION（也覆盖合法空 buffer 的边角）。建议显式 JS_ThrowTypeError。
5.【逻辑,低】reset() 拒绝 HTTP_BOTH，而构造器允许
ctor 允许 HTTP_BOTH(0)，reset() 的校验 type32 != HTTP_REQUEST && type32 != HTTP_RESPONSE 却拒绝 BOTH，行为不一致（argc==0 走 p->type 不受影响）。统一一下即可。

circu.js/src/mod_xml.c
1.【内存泄露，头号高频】INVOKE_HANDLER：handler 未注册/非函数时，预创建的参数 JSValue 永不释放
#define INVOKE_HANDLER(state, handler_name, argc, ...) do { \
    JSValue handler = JS_GetPropertyStr(...); \
    if (JS_IsFunction((state)->ctx, handler)) { \
        JSValue args[] = { __VA_ARGS__ }; \
        JSValue ret = JS_Call(...); \
        ... \
        for (int i = 0; i < argc; i++) JS_FreeValue((state)->ctx, args[i]); \  // 只在 if 内释放
    } \
    JS_FreeValue((state)->ctx, handler); \
} while(0)
​
而调用方在进宏之前就创建了参数值：
JSValue name_val = JS_NewString(state->ctx, name);
JSValue attrs_val = xml_attrs_to_obj(state->ctx, attrs);   // 一个新 JS 对象
INVOKE_HANDLER(state, "startElement", 2, name_val, attrs_val);
​
只要该事件没注册 handler（或被 on() 设成了非函数——on() 不校验类型），JS_IsFunction 为假 → 整个 if 跳过 → name_val/attrs_val 这些 refcount=1 的值无人释放 → 泄露。
这是高频路径：用户通常只注册部分事件（比如只听 startElement，不听 characterData/comment/PI/namespace）。每个未监听的回调每次触发都泄露——尤其 characterData 对每个文本节点都 fire，会持续泄露 JS 字符串；startElement 还会泄露整个 attrs 对象。
改法：无论 handler 是否为函数都要释放这些参数值。可在宏里加 else { JSValue _a[]={__VA_ARGS__}; for(...) JS_FreeValue(ctx,_a[i]); }，或重构成"先建 args 数组，调用与否都统一在末尾释放"（注意 argc==0 的 startCDATA/endCDATA 不能声明零长数组）。
2.【再入，中低】解析回调内重入 parse()/reset()/stop()
XML_Parse 执行期间会回调进 JS；JS 回调里若再调用同一 parser 的 parse() 或 reset()（XML_ParserReset）→ expat 对同一 XML_Parser 不可重入，会破坏内部状态。reset() 还会在外层 XML_Parse 栈内重置 user data。
改法：加一个 parsing 标志，重入 parse()/reset() 直接抛错。
3.【质量，低】current_data 是死字段
结构体里 current_data 被 init/mark/free，但全程从未被赋过 JS_UNDEFINED 以外的值。要么接上用途，要么删掉以免误导。
4.【质量/边角，低】
tjs_xml_escape 用 JS_ToCString（无长度版），输入含内嵌 \0 时会被 strlen 截断。
constructor 里空字符串 separator 会退化成 separator[0]=='\0' 传给 XML_ParserCreateNS。