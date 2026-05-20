# libmetasec_ml.so / libsscronet.so 分析同步

> 本文件用于持续同步当前逆向分析成果。后续新的 hook 结果、Binary Ninja 重命名、结构体修复、链路确认与下一步计划，都继续追加或修订到这里。

## 1. 当前目标

当前重点目标是还原 `libmetasec_ml.so` 与 `libsscronet.so` 中以下签名头的生成链：

- `X-Perseus`
- `X-Medusa`
- `X-Argus`
- `X-Gorgon`
- `X-Helios`
- `X-Ladon`
- `X-Khronos`

当前优先聚焦：`X-Ladon`。

---

## 2. 已确认的整体关系

### 2.1 Binary Ninja 当前目标文件

- `libmetasec_ml.so`
- `libsscronet.so`

### 2.2 跨 so 调用关系

运行时 trace 已确认：

- `libsscronet.so` 维护一个 mssdk callback slot。
- 该 slot 在运行时被写为 `libmetasec_ml.so + 0x2c6858`。
- `libsscronet.so` 在请求处理过程中会调用这个 callback。
- callback 输入至少包括：
  - URL
  - header blob
- callback 返回值是一整段 `header\r\nvalue\r\n...` 格式的文本。

trace 中已实际观测到 callback 返回头包括：

- `X-Perseus`
- `X-Medusa`
- `X-Argus`
- `X-Gorgon`
- `X-Helios`
- `X-Ladon`
- `X-Khronos`

---

## 3. libsscronet.so 侧结论

### 3.1 callback slot

`libsscronet.so` 中存在全局 callback slot：

- `data_8cce00`

对应运行时 trace 中的：

- `qword_4CCE00`

### 3.2 callback 注册点

当前已确认至少两个写 slot 的函数：

- `libsscronet.so + 0x574508`
  - 行为：`data_8cce00 = arg2`
- `libsscronet.so + 0x75b078`
  - 行为：`data_8cce00 = arg1`

另外 Binary Ninja 中可见：

- `Cronet_EngineParams_bypass_mssdk_get`
- `Cronet_EngineParams_bypass_mssdk_set`

这说明 `mssdk/bypass_mssdk` 属于 Cronet engine 参数体系的一部分。

### 3.3 callback 调用链

已确认的关键逻辑：

- `sub_757200`
  - 属于 Cronet 请求处理/预处理主流程。
  - 会读取请求 header、URL 与各种网络参数。
  - 在满足条件时读取 `data_8cce00` 并发起 mssdk callback。

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

## 4. libmetasec_ml.so 侧结论

### 4.1 核心回调函数

运行时 callback target 已定位到：

- 原始函数：`sub_6c6858`
- 已重命名：`mcp_mssdk_callback_build_signed_headers`

当前可以确认：

- 参数 1：URL
- 参数 2：header blob
- 返回值：一整段 `header\r\nvalue\r\n...` 文本

### 4.2 已完成的函数重命名

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
- `sub_6c6030` → `mcp_import_header_blob_into_component_map`
- `sub_6cb1f0` → `mcp_import_object_pairs_into_component_map`
- `sub_6b9f3c` → `mcp_build_signed_header_family_variant_b`
- `sub_6b6e54` → `mcp_build_signed_header_family_variant_a`
- `sub_6be27c` → `mcp_build_header_batch_slots_8_9_10`
- `sub_6be568` → `mcp_dispatch_signed_header_batch_from_slots`
- `sub_6b8a68` → `mcp_build_header_batch_slots_variant_a`
- `sub_6b8d50` → `mcp_dispatch_signed_header_batch_variant_a`
- `sub_6bee98` → `mcp_f0_batch_submit_from_slot8_slot9`
- `sub_6cb788` → `mcp_dispatch_via_selector_table`
- `sub_6cb7c4` → `mcp_init_batch_slot_context`
- `sub_6cb878` → `mcp_get_batch_slot`
- `sub_6cb884` → `mcp_set_batch_slot`
- `sub_6ccec0` → `mcp_runtime_record_submit_and_consume`
- `sub_6ce7c8` → `mcp_execute_slot_bytecode_program`
- `sub_6cd23c` → `mcp_enqueue_runtime_record`

说明：

- `sub_65901c` 曾尝试重命名失败，MCP 返回 404。

### 4.3 已修复/补充的结构体

#### `MssdkStringRef`

用于表示内部字符串对象，当前只确认它至少包含：

- vtable
- alloc/len 类字段
- data 指针

#### `HeaderPairNode`

用于表示最终序列化前的一条 header pair 节点。按当前访问偏移推断的重要字段：

- `key_data` @ `+0x20`
- `key_len_u16` @ `+0x38`
- `value_data` @ `+0x40`
- `value_len_u16` @ `+0x68`

#### `FxxExecutorSelector`

用于表示 `mcp_dispatch_via_selector_table` 所消费的执行器对象的当前临时命名版本。按当前证据确认：

- `selector` 位于 `+0x58`
- 该字段决定从 `data_8f0ef8` 分发表中选哪个真实 callee

#### `FxxProgramRecord`

用于表示 `mcp_execute_slot_bytecode_program` 所执行的一条 `Fxx` 程序记录的当前临时命名版本。按当前证据确认：

- 单条记录大小为 `0x30`
- `opcode_selector` 位于 `+0x28`
- 前几个字节参与编码 `srcA / srcB / dst` 或其他操作数语义

#### `FxxProgramCursor`

用于表示传给解释器的程序游标对象的当前临时命名版本。按当前证据推断：

- `base` 指向记录数组起始地址
- `cursor` / `end` 表示程序块边界或当前推进状态
- 不同程序块在运行时可见 `F21`、`F22`、`F23` 等标识

#### `FxxBatchFrame`

用于表示当前 `Fxx` 规则执行时使用的大型 batch 状态对象的当前临时命名版本。按当前证据确认：

- `record_index` 位于 `+0x0c`
- slot 数组起始于 `+0x6070`
- 是当前 `X-Ladon` 数据流分析最核心的状态对象

#### `HeaderAssemblySlots`

用于表示当前装配链里与最终 header pair 最相关的几个 slot 的语义视角：

- `slot6_result_key`
- `slot7_result_value`
- `slot8_key_input`
- `slot9_value_input`
- `slot10_aux_input`


已确认：

- `mcp_serialize_header_pairs_to_crlf_blob`
  - 会遍历内部 header pair 集合
  - 按 `key\r\nvalue\r\n` 序列化

因此最终 callback 返回值不是单独某一个 header，而是整组签名头的拼接结果。

### 4.5 中间 map / 组件构造链

当前已确认：

- `mcp_build_intermediate_header_components`
  - 不是直接计算签名值的函数
  - 更像把 `key/value` 插入内部哈希表/容器

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

## 5. X-Ladon 专项结论

### 5.1 已确认事实

- `X-Ladon` 不存在于 `libmetasec_ml.so` 的明文字符串搜索结果中。
- 它不是从输入 header blob 直接导入的。
- 它是在 `libmetasec_ml.so` 内部生成后，再通过 `mcp_build_intermediate_header_components` 插入到最终 header map 中。
- 它属于与 `X-Khronos`、`X-Gorgon`、`X-Argus`、`X-Helios` 同一批生成的签名头之一。

### 5.2 已抓到的 X-Ladon 值

不同请求上下文下，已经观察到至少以下值：

- `Oe40ww==`
- `dYDWMg==`

这说明：

- `X-Ladon` 是动态值，不是固定常量。
- 值形态短小，且是标准 base64 形态。
- 很可能是某个较小二进制结果的 base64 编码，而不是大块 payload。

### 5.3 插入点已确认

hook `libmetasec_ml.so + 0x2b7724`（`mcp_build_intermediate_header_components`）时，已经直接抓到：

- `key = X-Ladon`
- `value = dYDWMg==`（某次请求）

并且同一批还抓到了：

- `X-Khronos`
- `X-Gorgon`
- `X-Argus`
- `X-Helios`

### 5.4 同进程链路已基本闭环

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

### 5.5 当前判断

当前已经可以比较稳地说：

- `X-Ladon` 的直接上游不在 `libsscronet.so`
- 不在最终序列化函数
- 不在输入 header 导入链
- 而在 `libmetasec_ml.so` 内部某个“slot 装配函数”中
- `+0x2beef8` / `+0x2bef08` 是其最直接的运行时装配证据

### 5.7 X-Ladon 调用栈结论（新增）

针对 `mcp_build_intermediate_header_components` 且过滤 `key == "X-Ladon"` 的 hook，已抓到稳定的三次命中，value 分别为：

- `7bKFPA==`
- `s4aWoA==`
- `OfK7Dw==`

这再次说明：

- `X-Ladon` 是动态值
- 值为短小 base64
- 很可能来自某个较小二进制结果的编码

三次命中的 native stack 完全一致，稳定调用链如下：

- `libmetasec_ml.so + 0x2be2c0`
- `libmetasec_ml.so + 0x2ccea4`
- `libmetasec_ml.so + 0x457698`
- `libmetasec_ml.so + 0x2dd27c`
- `libmetasec_ml.so + 0x2ccf64`
- `libmetasec_ml.so + 0x2cb7b8`
- `libmetasec_ml.so + 0x2bef14`
- 之后进入更高层框架/循环调度区：
  - `+0x4b7548`
  - `+0x445910`
  - `+0x43c6e8`

当前基于栈的层次判断：

- `+0x2be2c0`：直接调用 `mcp_build_intermediate_header_components` 的近端插入层
- `+0x2bef14`：最值得优先识别的“直接批量装配函数”候选点
- `+0x2cb7b8 / +0x2ccf64 / +0x2dd27c / +0x457698 / +0x2ccea4`：更高层批处理/框架调度候选链

因此当前对“总控函数”的判断分为两层：

1. **直接批量装配总控候选**
   - 包含 `+0x2beef8 / +0x2bef08 / +0x2bef14` 的完整函数
   - 该函数大概率直接负责装配 `X-Khronos / X-Gorgon / X-Argus / X-Ladon / X-Helios` 这一组 header

2. **更高层调度总控候选**
   - 由以下栈点对应函数组成：
     - `+0x2cb7b8`
     - `+0x2ccf64`
     - `+0x2dd27c`
     - `+0x457698`
     - `+0x2ccea4`
   - 这些点更像统一执行框架或批量调度层

### 5.8 当前思路评估（新增）

当前思路的阶段性判断如下：

- 方向是对的：已经确认 `X-Ladon` 内部生成、批量插入、并且与其他签名头同批出现。
- 但切入点需要上移：
  - `sub_6cb884`
  - `sub_6bee98`
  这类点更偏对象搬运/包装层，继续深挖其 slot 对象字段，信息密度已经明显下降。

当前更优的策略是：

- 不再优先纠缠 slot 8/9 的对象解码细节
- 转而优先识别并重命名调用栈上方的“直接批量装配函数”和“更高层调度函数”
- 从函数层次上还原：
  - 谁在组织这一批 header
  - 谁在直接产出短 base64 值

### 5.9 推荐的下一步（更新）

当前建议的最高优先级动作不是继续补 hook，而是：

1. 在 Binary Ninja 中把以下栈地址映射回具体函数：
   - `0x2be2c0`
   - `0x2ccea4`
   - `0x457698`
   - `0x2dd27c`
   - `0x2ccf64`
   - `0x2cb7b8`
   - `0x2bef14`

2. 优先重命名包含以下偏移的完整函数：
   - `+0x2beef8`
   - `+0x2bef08`
   - `+0x2bef14`

3. 再确认 `+0x2cb7b8 / +0x2ccf64 / +0x2dd27c / +0x457698 / +0x2ccea4` 分别属于哪些函数，以及它们之间的调用关系。

当前最有可能的产出路径是：

- 先锁定直接 header group builder
- 再锁定更高层 batch dispatcher
- 最后再按需回头细修结构体字段

### 5.9 运行时执行链进一步收缩（新增）

继续沿 `F0` 执行链分析后，当前已确认：

#### 1. `sub_6cb788` 的角色

`sub_6cb788` 是统一的运行时跳板，核心逻辑为：

- 从执行器对象取 selector：`*(arg1 + 0x58)`
- 用 selector 索引全局分发表：`data_8f0ef8`
- 调用对应的真实 callee

运行时 hook 已确认，在当前这条 `F0` 路径里：

- `selector_u64 = 1`
- `dispatch_entry_addr = data_8f0ef8 + 8`
- `dispatch_entry_value = libmetasec_ml.so + 0x2ccec0`

因此当前最重要的收敛结论是：

- **当前 `F0` 路径的真实运行时执行函数固定为 `libmetasec_ml.so + 0x2ccec0`。**

#### 2. `sub_6bee98` 的修正定位

`sub_6bee98` 不是 `X-Ladon` 的算法函数，而是：

- 初始化一个大 batch 上下文对象
- 写 slot 8 / slot 9
- 调 `sub_6cb788(data_992ef8, &var_6450)` 提交任务

因此当前更准确的角色定义为：

- **F0 batch 提交器**

#### 3. `mcp_dispatch_signed_header_batch_from_slots` 的修正定位

该函数不是 runtime dispatcher 本体，而是在做：

- 构造 `CF10 ~ CF1C` 的规则描述
- 调 `sub_6cb650(...)` 建立规则表/执行器
- 调 `sub_6cb690(x0, "F0")` 获得并注册 `F0` 执行器对象

因此当前更准确的角色定义为：

- **F0 规则表 / 执行器构建器**

#### 4. `sub_6c31d8` / `sub_6bc0ec` / `sub_6c454c` / `sub_6c561c` 的共性

这些函数都具有相同的结构：

- 构造一批 `CFxx -> handler` 规则项
- 调 `sub_6cb650(...)`
- 再调 `sub_6cb690(x0, "F0" / "F1" / ...)`
- 把结果保存到 `data_992xxx`

说明 `libmetasec_ml.so` 中存在多组相似的：

- rule-table builder
- executor registrar
- batch submitter
- runtime trampoline
- concrete callee

这是一套通用的规则执行框架，而不是单一一条 `F0` 逻辑。

### 5.10 `sub_6ccec0` 角色定位（新增）

`sub_6ccec0` 当前已确认不是 `X-Ladon` 的值生成函数。

它的主要行为是：

- 从 `arg1` 相关结构中取出一条记录
- 设置 `x19 + 0x10` 指向该记录
- 调 `sub_6cd23c(&data_9939b0, &var_58, 1)`
- 调 `sub_6ce7c8(&x21[2], x19)`
- `noreturn`

因此当前更合理的角色定义为：

- **运行时记录提交 / 中转函数**
- 或 **解释执行入口前置包装器**

结论：

- `X-Ladon` 在进入 `sub_6ccec0` 前，大概率已经完成批处理对象的主要装配
- `sub_6ccec0` 更像把一条记录挂接到全局结构，再交给后续解释执行器消费

### 5.11 `sub_6ce7c8` 角色定位（新增）

`sub_6ce7c8` 是目前已经确认的最核心一层：

- 输入是一串固定长度 `0x30` 字节记录
- 每条记录在 `+0x28` 位置带一个 opcode/type
- 根据 `jump_table_8f0f20` 分派不同分支处理
- 操作的核心数据区是：`arg2 + 0x6070` 这一片 slot 数组

当前已明确看到的一个分支逻辑为：

- 从记录中解析三个 8-bit 索引：`srcA / srcB / dst`
- 执行：`slot[dst] = slot[srcA] + slot[srcB]`

因此当前更准确的角色定义为：

- **slot-machine / 规则解释执行核心**
- **批处理记录解释器**

这说明：

- `X-Ladon` 更像是经过多条规则记录归约后得到的结果
- 它不是普通 helper 函数一次性直接算出来的

### 5.12 当前对 X-Ladon 生成方式的最新判断（更新）

到目前为止，对 `X-Ladon` 生成方式的判断更新为：

- 它不是注册器算的
- 不是 batch 提交器算的
- 不是 dispatch trampoline 算的
- 不是 `sub_6ccec0` 直接算的
- 它更可能是：
  - 先将输入和中间状态放入 slot 数组
  - 再由 `sub_6ce7c8` 解释执行一组记录
  - 最终某个 slot 的结果被后续装配器拿去生成 `X-Ladon`

因此后续分析方向应从“找哪个普通函数直接返回值”切换为：

- **找 `X-Ladon` 最终对应哪个 slot**
- **找哪些记录 / opcode 链最终写入该 slot**

### 5.13 运行时执行链最终收敛（更新）

最新运行时 hook 已确认：

- `mcp_dispatch_via_selector_table` 在当前这类路径中：
  - `selector_u64 = 1`
  - `dispatch_entry_value = libmetasec_ml.so + 0x2ccec0`
- 说明当前观察到的多个 `Fxx` 程序块，最终都进入同一个 runtime 执行函数：
  - **`sub_6ccec0`**

这意味着：

- 不同 `Fxx` 更像是不同程序块 / 记录块
- 它们不是分发到不同的大函数
- 而是共享同一个解释执行内核链：
  - `sub_6ccec0` -> `sub_6ce7c8`

### 5.14 当前策略结论（更新）

当前最优分析策略已经收敛为：

- 不再优先继续分析外围：
  - 注册器
  - 提交器
  - dispatch trampoline
  - runtime record submitter
- 当前真正应聚焦的是：
  - `mcp_execute_slot_bytecode_program`
  - `BatchDispatchFrame.slots[]`
  - `RuntimeRecordHeader` 的 opcode / srcA / srcB / dst 语义

后续最有价值的问题是：

1. `X-Ladon` 最终取自哪个 slot
2. 哪些 `Fxx` 程序块会写这个 slot
3. 哪些 record / opcode 组成了它的计算图

### 5.15 `sub_6ce7c8` 内部结构与解释器模型（新增）

当前对 `sub_6ce7c8` 的内部角色已经可以进一步细化：

- `sub_6ce7c8` 不是普通 helper，而是当前 `Fxx` 框架的**核心解释器主循环**。
- 参数 `arg1` 不是单条 record，而是指向程序记录数组基址的引用。
- 参数 `arg2` 是当前 batch/frame 状态对象。
- 入口会先把 `arg2 + 0x0c` 清零，因此可稳定确认：
  - `record_index` 位于 `+0x0c`
- 随后会读取首条记录 `+0x28` 的字段，并通过 `jump_table_8f0f20` 进入对应 handler。

当前已确认的稳定布局如下。

#### 1. `FxxProgramRecord`

`sub_6ce7c8` 以固定步长 `0x30` 遍历 record，因此单条记录大小已经可以确认：

- 单条记录大小：`0x30`
- `opcode_selector` 位于：`+0x28`

并且在 `0x6ce82c` 这类 handler 中，record 前 3 个字节会被拼成一个 24-bit 操作数，随后拆成：

- `byte0 -> srcA`
- `byte1 -> srcB`
- `byte2 -> dst`

当前最稳妥的结构体语义应先保守命名为：

- `operand0`
- `operand1`
- `operand2`

因为不同 handler 可能会对这三个字节赋予不同解释，而不一定永远都是 `srcA/srcB/dst`。

#### 2. `FxxBatchFrame`

当前可以稳定确认：

- `record_index` @ `+0x0c`
- `runtime_record_ctx` @ `+0x10`
- `slots[]` 起始于 `+0x6070`
- `aux_region_a` 起始于 `+0x6170`
- `aux_region_b` 起始于 `+0x61f0`

其中：

- `slots[]` 是解释器的核心运算区
- `aux_region_a / aux_region_b` 更像解释器工作区或辅助 scratch 区
- `+0x20 .. +0x606f` 之间仍有大块运行时元数据/对象表区域，当前还不宜过早强命名

#### 3. 已确认的一个 handler 语义

当前已稳定确认 `0x6ce82c` 所在分支的语义为：

- 从当前 record 取三个 8-bit 操作数字段
- 解释成 `srcA / srcB / dst`
- 执行：
  - `slot[dst] = slot[srcA] + slot[srcB]`
- 之后推进 `record_index`
- 再读取下一条 record 的 `opcode_selector`
- 继续通过 `jump_table_8f0f20` dispatch

这说明：

- `sub_6ce7c8` 的本质确实是 **slot-machine / bytecode interpreter**
- `X-Ladon` 更可能是多条 record 归约执行后的产物，而不是某个普通 helper 一次性返回的字符串

### 5.16 基于手工 FP 栈的进一步函数定位（新增）

结合 `mcp_build_intermediate_header_components` 命中时的手工 FP 栈，当前对若干关键栈点的理解进一步收敛为：

#### 1. `+0x2be2c0`

- 位于 `sub_6be27c`
- 是近端 header pair 装配/插入层
- 会消费 `slot 8/9/10`
- 再交给 `mcp_build_intermediate_header_components`

因此它不是 `X-Ladon` 的直接生产点，而是最终消费点。

#### 2. `+0x2bef14`

- 位于 `sub_6befc0`
- 当前看起来更像薄桥接层
- 主要行为是读取 `slot 8/9/10`

因此它的重要性低于解释器内部的真实算子函数。

#### 3. `+0x2b813c`

- 位于 `sub_6b810c`
- 会从当前 frame 取 `slot 8/9`
- 再调用 `sub_6bee98(...)`

这进一步支持：

- `sub_6bee98` 是 batch submitter / 重新提交层
- 不是 header 值直接生成器

#### 4. `+0x2d8228`

该地址落在 `sub_6d824c` 中，当前已确认它不是外围包装器，而是解释器里的**具体逻辑算子 handler**。其行为特征包括：

- 多次从 `slots[]` 读取源值
- 执行按位组合逻辑（如 AND / OR / NOT 类组合）
- 把结果写回目标 slot
- 再把部分 slot 值写回对象字段
- 随后继续跳转到下一条 opcode handler

因此它代表的已经是解释器内部真实运算层，而不是框架外壳。

#### 5. `+0x2dc674`

该地址落在 `sub_6dc694` 中，也属于解释器内部的**具体 handler**。当前可见行为包括：

- 从对象字段取值写入 slot
- 执行整型加法类 slot 运算
- 把 slot 值写回对象字段
- 推进 record index 后继续 dispatch

它很可能属于“对象字段 <-> slot 状态”之间的桥接型解释器节点。

#### 6. `+0x303714`

该地址落在 `sub_703740` 中。当前判断它也不是高层调度壳，而是一个专门的解释器 helper / handler，特征包括：

- 对 slot 执行与运算或带立即数/字段值的组合运算
- 从对象字段重新抽值回 slot
- 推进 `record_index`

说明该点同样位于解释器内部的数据搬运/归约层。

#### 7. `+0x457698`

当前虽然还未完全映射回完整函数入口，但从多次重复出现在不同段之间的栈形态看，它更像：

- 公共调度桥
- 或更高层执行框架外壳

而不像 `X-Ladon` 值本身的直接计算点。

### 5.17 当前结构体建模建议（新增）

基于当前证据，建议在 Binary Ninja 中优先采用以下保守建模：

- `FxxProgramRecord`
  - `operand0`
  - `operand1`
  - `operand2`
  - `raw_04[0x24]`
  - `opcode_selector @ +0x28`

- `FxxBatchFrame`
  - `record_index @ +0x0c`
  - `runtime_record_ctx @ +0x10`
  - `slots[] @ +0x6070`
  - `aux_region_a @ +0x6170`
  - `aux_region_b @ +0x61f0`

当前不建议把 `operand0/1/2` 直接强命名为永久性的 `srcA/srcB/dst`，原因是：

- 在部分 handler 中它们确实表现为 `srcA/srcB/dst`
- 但在其他 handler 中，它们也可能承担对象索引、字段偏移或立即数编码语义
- 过早固化命名，反而会污染后续分析

因此更稳妥的策略是：

- 先把前三个字节统一命名为 `operand0/1/2`
- 等不同 handler 语义分组更稳定后，再做更细粒度拆分

---

## 6. 当前建议的后续 hook 方案

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

## 7. 当前阶段结论摘要

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

## 8. 后续维护要求

- 后续新的 hook 结果、Binary Ninja 重命名、结构体修复、偏移确认、参数生成推断，继续同步写入本文件。
- 如果已有结论被新的运行时证据修正，应直接更新对应章节，而不是另起一份分散记录。
