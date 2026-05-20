# 当前进度

## 文档用途

- 本文件作为当前项目的统一进度与分析同步文档。
- 后续新的逆向结果、hook 结论、函数重命名、结构体修复与下一步计划，都持续追加或修订到这里。
- 当前重点分析对象为 `libmetasec_ml.so` 与 `libsscronet.so`，目标是还原 `X-Perseus`、`X-Medusa`、`X-Argus`、`X-Gorgon`、`X-Helios`、`X-Ladon`、`X-Khronos` 的生成链，优先聚焦 `X-Ladon`。

---

## unidbg 当前进度

### libmetasec_ml.so

- 已经在 unidbg 中完成 `JNI_OnLoad`。
- 关键处理包括：为 `com/bytedance/mobsec/metasec/ml/MS` 补齐继承链 `MS -> m2 -> f3 -> java/lang/Object`。
- 额外为 VM 挂载了 `AbstractJni`，并最小实现了 `MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;`，使初始化流程可以继续执行。
- 目前已确认 `JNI_OnLoad` 阶段会注册 `ms/bd/c/f3->a(...)` native，并调用一次 `MS.b(...)`，该调用在当前测试下返回 `null` 也不会阻塞初始化完成。

### libsscronet.so

- 当前已经切换到 `libsscronet.so` 进行加载测试。
- 现阶段日志显示大量缺失依赖与缺失符号，主要来自 `libandroid.so`、`libc++_shared.so` 及其导出的 C++/Android NDK 符号。
- 当前测试代码里没有再调用 `vm.setJni(...)`，因此在 `JNI_OnLoad` 过程中一旦执行到 `GetStaticMethodID`，会直接报 `Please vm.setJni(jni)`。
- 这说明 `libsscronet.so` 至少也需要一层 `Jni` 桥接，后续大概率还需要补依赖 so 或导出关键符号桩。

### 下一步建议（unidbg）

- 若继续跑 `libsscronet.so`，先恢复或补充 `vm.setJni(new AbstractJni(){...})`，避免在首次 Java 交互时直接失败。
- 然后区分两类问题逐步处理：一类是 Java/JNI 侧缺方法、缺类；另一类是本地依赖 so 与 C++ 符号缺失。
- 对于“如何加入其他 so”，优先让依赖 so 随 APK 一起被 `findLibrary` 找到；若 APK 中没有，再考虑手工 `loadLibrary(File, false)` 或补 resolver/符号桩。

---

## Binary Ninja / 运行时分析总览

### 当前 Binary Ninja MCP 已确认的目标文件

- `libmetasec_ml.so`
- `libsscronet.so`

### 已确认的跨 so 回调关系

运行时 trace 已确认：

- `libsscronet.so` 维护一个 mssdk callback slot。
- 该 slot 在运行时被写为 `libmetasec_ml.so + 0x2c6858`。
- 该回调会在请求处理时被 `libsscronet.so` 调用。
- 回调输入至少包括：
  - URL
  - header blob
- 回调输出是一整段 `header\r\nvalue\r\n...` 格式的签名头文本。

trace 中已观测到的回调返回头包括：

- `X-Perseus`
- `X-Medusa`
- `X-Argus`
- `X-Gorgon`
- `X-Helios`
- `X-Ladon`
- `X-Khronos`

---

## libsscronet.so 侧结论

### callback slot

`libsscronet.so` 中存在一个全局 callback slot：

- `data_8cce00`

它对应运行时 trace 中的：

- `qword_4CCE00`

### callback 注册函数

当前已确认至少有两个写 slot 的函数：

- `libsscronet.so + 0x574508`
  - 行为：`data_8cce00 = arg2`
- `libsscronet.so + 0x75b078`
  - 行为：`data_8cce00 = arg1`

此外，Binary Ninja 里还能搜索到：

- `Cronet_EngineParams_bypass_mssdk_get`
- `Cronet_EngineParams_bypass_mssdk_set`

这说明 `mssdk`/`bypass_mssdk` 是 Cronet engine 参数体系的一部分。

### callback 调用主链

已确认的关键调用流程：

- `sub_757200`
  - 是 Cronet 请求处理/预处理主流程的一部分。
  - 会读取请求 header、URL 与各种网络参数。
  - 在满足条件时，读取 `data_8cce00` 并发起 mssdk callback。

- `sub_75a9f4`
  - 会直接调用 callback。
  - 会把 callback 返回结果按 `\r\n` 拆分。
  - 会把拆出的键值对写回请求 header 容器。
  - 会补写 `x-metasec-mssdk-used`。

因此，`libsscronet.so` 的角色可以概括为：

- 准备 URL 和 header blob
- 调 `libmetasec_ml.so` 的 signer callback
- 接收签名头文本
- 回填到请求中

---

## libmetasec_ml.so 侧结论

### 核心回调函数

运行时 callback target 已定位到：

- 原始地址：`sub_6c6858`
- 已重命名：`mcp_mssdk_callback_build_signed_headers`

当前可以确定：

- 参数 1：URL
- 参数 2：header blob
- 返回值：一整段 `header\r\nvalue\r\n...` 文本

### 已完成的函数重命名

当前已在 Binary Ninja 中完成以下重命名：

- `sub_6c6858` → `mcp_mssdk_callback_build_signed_headers`
- `sub_6c6318` → `mcp_serialize_header_pairs_to_crlf_blob`
- `sub_6c9828` → `mcp_build_and_serialize_signed_headers`
- `sub_6c6828` → `mcp_init_header_pair_collection_from_template`
- `sub_659050` → `mcp_assign_cstr_to_string_object`
- `sub_6c98f4` → `mcp_populate_string_context_from_cstr`
- `sub_6c9810` → `mcp_reset_string_builder_state`
- `sub_6c9890` → `mcp_copy_builder_output_to_string_context`
- `sub_6c9898` → `mcp_finalize_string_builder_state`
- `sub_6c9880` → `mcp_merge_intermediate_header_components`
- `sub_6c98ec` → `mcp_destroy_signed_header_build_context`
- `sub_6b7724` → `mcp_build_intermediate_header_components`

说明：

- `sub_65901c` 曾尝试重命名失败，MCP 返回 404。

### 已修复/补充的结构体

当前已在 Binary Ninja 中补了两版结构体，后续以更接近真实布局的版本为准。

#### `MssdkStringRef`

用于表示内部字符串对象，当前只确认它至少包含：

- vtable
- alloc/len 类字段
- data 指针

#### `HeaderPairNode`

用于表示最终序列化前的一条 header pair 节点。当前按访问偏移推断的重要字段：

- `key_data` @ `+0x20`
- `key_len_u16` @ `+0x38`
- `value_data` @ `+0x40`
- `value_len_u16` @ `+0x68`

#### `HeaderPairList`

用于表示 header pair 集合。当前推断重要字段：

- 头指针/上下文
- `head`
- `count`

### 返回值序列化链

已确认：

- `mcp_serialize_header_pairs_to_crlf_blob`
  - 会遍历内部 header pair 集合
  - 按 `key\r\nvalue\r\n` 序列化

因此，最终 callback 返回值并不是单独某一个 header，而是整组签名头的拼接结果。

### 中间 map / 组件构造链

当前已确认：

- `mcp_build_intermediate_header_components`
  - 不是直接计算签名值的函数
  - 更像是把 `key/value` 插入内部哈希表/容器

- `sub_6c6030`
  - 会把输入 header blob 按 `\r\n` 切开
  - 两行一组导入内部 map
  - 这是“输入 header 导入器”

- `sub_6cb1f0`
  - 会从另一个对象/容器里枚举 key/value
  - 再调用 `mcp_build_intermediate_header_components`
  - 也是上下文导入器

- `sub_6b9f3c`、`sub_6b6e54`
  - 更像“签名头生成器/派生字段生成器”
  - 内部包含格式化、对象构造和多次 `mcp_build_intermediate_header_components(...)`

---

## X-Ladon 当前专项结论

### 已确认的事实

- `X-Ladon` 不存在于 `libmetasec_ml.so` 的明文字符串搜索结果中。
- 它不是从输入 header blob 直接导入的。
- 它是在 `libmetasec_ml.so` 内部生成后，再通过 `mcp_build_intermediate_header_components` 插入到最终 header map 中。
- 它属于与 `X-Khronos`、`X-Gorgon`、`X-Argus`、`X-Helios` 同一批生成的签名头之一。

### 已抓到的 X-Ladon 值

不同请求上下文下，已经观察到至少以下值：

- `Oe40ww==`
- `dYDWMg==`

这说明：

- `X-Ladon` 是动态值，不是固定常量。
- 值形态短小，且是标准 base64 形态。
- 很可能是某个较小二进制结果的 base64 编码，而不是大块 payload。

### 与 X-Ladon 相关的关键 hook 结论

#### 1. 插入点已确认

hook `libmetasec_ml.so + 0x2b7724`（`mcp_build_intermediate_header_components`）时，已经直接抓到：

- `key = X-Ladon`
- `value = dYDWMg==`（当前这次请求）

并且同一批还抓到了：

- `X-Khronos`
- `X-Gorgon`
- `X-Argus`
- `X-Helios`

#### 2. 同进程链路已基本闭环

在同一个进程、同一条执行流里，已经观察到：

- `sub_6cb884` caller=`+0x2beef8` 写 `slot 8`
- `sub_6cb884` caller=`+0x2bef08` 写 `slot 9`
- 紧接着 `mcp_build_intermediate_header_components` caller=`+0x2be2bc` 插入：
  - `X-Khronos`
  - `X-Gorgon`
  - `X-Argus`
  - `X-Ladon`
  - `X-Helios`

因此当前最合理的判断是：

- `slot 8/9/0xa` 是该组签名头的输入槽
- `+0x2beef8/+0x2bef08` 是 `X-Ladon` 所在组 header pair 的直接装配点
- `+0x2be2bc` 是该组 header pair 被统一插入 map 的点

### 当前对 X-Ladon 生成逻辑的判断

当前已经可以比较稳地说：

- `X-Ladon` 的直接上游不在 `libsscronet.so`
- 不在最终序列化函数
- 也不在输入 header 导入链
- 而在 `libmetasec_ml.so` 内部某个“slot 装配函数”中
- `+0x2beef8` / `+0x2bef08` 是其最直接的运行时装配证据

### 当前还差的最后一小步

虽然链路基本闭环，但还需要在同一个进程里补一次更精确的 hook，确认：

- caller=`+0x2beef8` 写入的 slot 8 内容是否明确就是 `"X-Ladon"`
- caller=`+0x2bef08` 写入的 slot 9 内容是否明确就是当前值，例如 `"dYDWMg=="`

这一步是把“高度确定”变成“完全实锤”。

---

## 当前建议的后续 hook 方案

### 最小补证方案

在同一个进程里继续 hook `sub_6cb884`，但只过滤以下 caller：

- `libmetasec_ml.so + 0x2beef8`
- `libmetasec_ml.so + 0x2bef08`

并把 `arg2` 当作字符串对象解码打印。

预期输出类似：

- `caller=+0x2beef8 slot=8 value="X-Ladon"`
- `caller=+0x2bef08 slot=9 value="dYDWMg=="`

### 下一层深入方案

在完成上述补证后，直接 hook 包含 `+0x2beef8/+0x2bef08` 的完整函数入口，观察：

- 入口参数
- 执行前后 slot 8/9/0xa 的内容
- value 是在哪一步变成最终 base64 值

目标是继续确认：

- `X-Ladon` value 是否由小型二进制结果经 base64 编码得到
- 它依赖哪些输入参数，例如：
  - URL
  - 时间戳
  - trace id
  - cookie
  - 其他内部派生字段

---

## 当前阶段结论摘要

到目前为止，已经完成的核心结论如下：

1. `libsscronet.so` 不负责生成 `X-Ladon`，它只负责注册 callback、传入 URL/header blob，并接收签名头结果。
2. `libmetasec_ml.so` 的 `mcp_mssdk_callback_build_signed_headers` 是签名头返回主入口。
3. 最终返回值是由内部 header pair 集合经 `mcp_serialize_header_pairs_to_crlf_blob` 序列化得到。
4. `X-Ladon` 是内部动态生成的签名头之一。
5. 它与 `X-Khronos`、`X-Gorgon`、`X-Argus`、`X-Helios` 属于同一批 header。
6. `X-Ladon` 当前已观察到的值至少包括：
   - `Oe40ww==`
   - `dYDWMg==`
7. 同进程 hook 已显示它的直接装配链在：
   - `+0x2beef8`
   - `+0x2bef08`
   - `+0x2be2bc`

---

## 后续维护要求

- 后续新的 hook 结果、Binary Ninja 重命名、结构体修复、偏移确认、参数生成推断，继续同步写入本文件。
- 如果已有结论被新的运行时证据修正，应直接更新对应章节，而不是另起一份分散记录。
