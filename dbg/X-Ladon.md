# X-Ladon

## 当前结论

- `X-Argus = base64(le32(X-Khronos))`
- `X-Ladon = base64(be32(new_tls32))`
- `sub_269b70(slot8)` 的 hash 输入不是 `X-Khronos`，而是另一段 10 位十进制串
- 当前设备日志里稳定看到：
  - `slot8_text = "1588093228"`
  - `hash = 0x934507fb6e509873`
- 当前设备日志里同一个 `X-Khronos` 可以对应多个不同 `X-Ladon`
  - 所以除了 `X-Khronos / X-Argus / slot8_text` 之外，还存在第三个变化输入
  - 这个变化输入最终体现为 `old_tls32 -> new_tls32` 的变化

## 重要修正：之前的 slot122 是误判

- 之前一度把 `0x7a` 解释成了 `srcSlot=122`
- 这个结论是错的，原因是取点太晚：
  - 在 `0x2cf178` 时，`w12/x12` 已经被 opcode selector 覆盖
  - `0x7a` 只是 opcode selector，十进制刚好是 `122`
- 后来把日志点前移到 `0x2cf174` 之后，真实链路已经明确：
  - `vm-lsl32-load ... srcSlot=6 ...`
  - `vm-lsl32-shift opcodeSel=0x7a ...`
- 所以这里必须分开看：
  - `srcSlot = 6`
  - `opcode selector = 0x7a`
- 也就是说：
  - 之前围绕“slot122”的那条推导应该整体废弃
  - `0xe4ff7f60` 上看到的大量原始写入，也不能再直接当成 Ladon 主链里的“语义槽位写回”

## 把 slot8 当常量后的收敛模型

- 这份设备日志里可以先把下面两项当常量：
  - `slot8_text = "1588093228"`
  - `H = sub_269b70(slot8) = 0x934507fb6e509873`
- 这样一来，当前真正变化的量只剩 4 组：
  - `X-Khronos`
  - `X-Argus`
  - `old_tls32`
  - `new_tls32`
- 其中：
  - `X-Argus` 仍然只是 `X-Khronos` 的 4 字节小端 base64
  - `X-Ladon` 仍然只是 `new_tls32` 的 4 字节大端 base64
  - 所以真正需要盯的是：
    - `delta = old_tls32 ^ new_tls32`
- `delta` 比 `old_tls32` 更关键，因为：
  - `old_tls32` 是线程当前状态，天然会漂移
  - `delta` 才是这次 Ladon 计算真正注入进去的“增量”
  - `new_tls32 = old_tls32 ^ delta`

## 当前日志里实际变化的参数

- 从 [dbg/X-Ladon.log](/Users/admin/Desktop/douyin/unidbg/dbg/X-Ladon.log) 抽出来的 33 个完整样本里：
  - `slot8_text` 只有一个值：`1588093228`
  - `hash` 只有一个值：`0x934507fb6e509873`
  - `X-Khronos` 有 17 个值：`1779950861` 到 `1779950877`
  - 同一个 `X-Khronos` 仍然可以对应多个不同：
    - `old_tls32`
    - `new_tls32`
    - `X-Ladon`
    - `delta`
- 例子：
  - `1779950862 / DuUXag==`
  - `old_tls32 -> new_tls32` 分别出现过：
    - `0xd417e1ee -> 0xb4237837`
    - `0x63710c8b -> 0x04fc0752`
    - `0x2d5571f4 -> 0x4adb582d`
    - `0x4d59a228 -> 0x2d2f3ef1`
  - 对应 `X-Ladon` 分别是：
    - `tCN4Nw==`
    - `BPwHUg==`
    - `SttYLQ==`
    - `LS8+8Q==`
- 这说明：
  - `Khronos/Argus` 相同
  - `slot8/hash` 相同
  - 但“第三输入”仍然在变

## delta 的结构特征

- 对当前日志定义：
  - `delta = old_tls32 ^ new_tls32`
- 观察到两个很强的特征：
  - 同一个 `X-Khronos` 下，`delta` 的最低字节固定
  - 所有样本的 `delta` 最低 4 bit 恒为 `0x9`
- 例如：
  - `1779950861` 时，`delta` 末字节总是 `0xe9`
  - `1779950862` 时，`delta` 末字节总是 `0xd9`
  - `1779950863` 时，`delta` 末字节总是 `0xc9`
  - `1779950864` 时，`delta` 末字节总是 `0x39`
  - `1779950871` 时，`delta` 末字节总是 `0x49`
- 在当前 `H = 0x934507fb6e509873` 的前提下，日志样本还能继续收敛到：
  - `delta_low8 = ((((Khronos & 0xf) ^ 0x3) & 0xf) << 4) | 0x9`
- 这等价于说：
  - `H` 的低 4 bit 是 `0x3`
  - 当前第三输入 `S` 的低 4 bit 推断为 `0x0`
- 这说明：
  - `delta` 不是纯随机值
  - 它至少有一部分位是被 `X-Khronos` 直接决定的
  - 而剩余高位则由“第三输入”决定

## 可反推出的隐藏变化量

- 如果沿用当前已经验证过的 VM 链：
  - `delta = low32(ror64(H ^ K ^ S, 60))`
  - 其中：
    - `H = 0x934507fb6e509873`
    - `K = uint32(X-Khronos)`
    - `S = 当前未直接打印出来的第三输入`
- 当 `H` 固定后，可以从日志直接反推 `S` 的低 28 位：
  - `S_low28 = ((delta >> 4) ^ (H & 0x0fffffff) ^ (K & 0x0fffffff)) & 0x0fffffff`
- 当前样本算出来的 `S_low28` 很有特征：
  - `0x241f210`
  - `0x242af70`
  - `0x24434e0`
  - `0x23fadc0`
  - `0x255b020`
  - `0x266ad30`
- 它们共同特点：
  - 最低 4 bit 全是 `0`
  - 更像某个 16 字节对齐的地址/偏移，而不像普通随机数
- 所以当前最值得继续追的是：
  - 第三输入 `S` 很可能不是“业务数值”
  - 而是某个对齐后的地址、槽位值、或结构体字段地址

## 最新设备日志样本

- 日志文件：
  - [dbg/X-Ladon.log](/Users/admin/Desktop/douyin/unidbg/dbg/X-Ladon.log)
- 当前这份日志里，关键链路都发生在同一线程上下文：
  - `ctx = 0x7b805ea430`
  - `mapCtx = 0x7b805f6a38`
  - `slot8_text = "1588093228"`
  - `hash = 0x934507fb6e509873`
- 已确认样本：
  - `X-Khronos = 1779950565`
  - `X-Argus = 5eMXag==`
  - `old_tls32 = 0x58937837`
  - `new_tls32 = 0x388db15e`
  - `X-Ladon = OI2xXg==`
- 同一个 `X-Khronos` 的第二次样本：
  - `X-Khronos = 1779950565`
  - `X-Argus = 5eMXag==`
  - `old_tls32 = 0xdda6b0a2`
  - `new_tls32 = 0xbda883cb`
  - `X-Ladon = vaiDyw==`
- 更强的重复样本：
  - `X-Khronos = 1779950570`
  - `X-Argus = 6uMXag==`
  - `X-Ladon` 至少出现过：
    - `OhDxlw==`
    - `iGpunw==`
    - `HA8BJg==`
- 因此已经可以确认：
  - `X-Khronos` 相同
  - `X-Argus` 相同
  - `slot8_text` 相同
  - 但 `old_tls32 / new_tls32 / X-Ladon` 仍然会变

## 最新设备日志直接结论

- `base64^-1("OI2xXg==") = 38 8d b1 5e = be32(0x388db15e)`
- `base64^-1("vaiDyw==") = bd a8 83 cb = be32(0xbda883cb)`
- `base64^-1("mglp6Q==") = 9a 09 69 e9 = be32(0x9a0969e9)`
- 所以当前设备日志继续验证：
  - `X-Ladon = base64(be32(new_tls32))`

## 与 X-Helios 的交叉点

- 旧样本中已经出现过：
  - `message26 = "1779160424-1611921764-3019"`
- 这说明 `slot8_text` 很可能不是孤立字段，而是另一条签名链里会被单独取出的十进制段
- 目前只能下到这个强度：
  - `slot8_text` 很像某个设备/会话相关的稳定十进制字段
  - 旧样本是 `1611921764`
  - 当前设备日志是 `1588093228`
  - 还没完全命名其业务语义

## 关键日志位置

- 当前设备日志重点看：
  - `X-Khronos / X-Argus / slot8Obj / old_tls32 / new_tls32 / X-Ladon` 的连续段
- 旧的 unidbg 交叉样本看：
  - `data.log:4063` 到 `data.log:4092`
  - `data.log:4075` 到 `data.log:4089`
  - `data.log:3932` 到 `data.log:4045`
  - `data.log:4161` 到 `data.log:4162`

## 三个参数的关系

1. `X-Khronos`
   - 十进制秒级时间戳
   - 当前样本是 `1779160424`
2. `X-Argus`
   - 先把 `X-Khronos` 当作 32 位整数：`0x6a0bd568`
   - 再按小端字节写成 `68 d5 0b 6a`
   - 最后 base64 得到 `aNULag==`
3. `X-Ladon`
   - 不是直接从 `X-Khronos` 做 base64
   - 它会把 `X-Argus/X-Khronos`、一个额外的 10 位字符串、以及 TLS 状态字混在一起
   - 最后产出 4 字节，再 base64 成 `PJTQZg==`

## 已确认的生成链

1. `sub_2be3dc` 在 `0x2be3ec` 调 `sub_269b70(slot8)`，返回值写入 `slot[6]`
2. `sub_269b70` 实际执行：
   - `return sub_25bfe0(*(slot8 + 0x10), *(slot8 + 0xc))`
3. `sub_25bfe0` 是表驱动的逐字节混合函数：
   - `result = table[((result & 0xff) ^ byte)] ^ (result >> 8)`
   - 当前看到的结果为 `0xe9c975f1c62f9107`
   - 当前样本被 hash 的输入不是 `X-Khronos`，而是另一段 10 位十进制串：`1611921764`
   - 该值还出现在字符串 `1779160424-1611921764-3019`
   - 这个 `slot8` 对象本身是 `sub_2b7f3c -> sub_2590ec` 先复制出来的 `len/data` 对象
4. `sub_2def20` 在 `0x2def3c` 把 `0x123573d8` 写入 `slot[5]`
5. `sub_2d15e8` 执行：
   - `slot[6] = slot[7] ^ slot[6]`
   - 这里 `slot[7] = 0x6a0bd568`
   - 它同时等于：
     - `X-Khronos` 的 32 位整数值
     - `X-Argus` base64 解码后的小端 32 位值
   - `0x6a0bd568 ^ 0xe9c975f1c62f9107 = 0xe9c975f1ac24446f`
6. `sub_304a24` 在 `0x304ae4` 执行：
   - `slot[5] = slot[6] ^ slot[5]`
   - `0xe9c975f1ac24446f ^ 0x123573d8 = 0xe9c975f1be1137b7`
7. `BN_CODE_start_0x2d2080_size_0x68` 在 `0x2d20a0` 执行：
   - `slot[20] = ror64(slot[5], 60)`
   - `ror64(0xe9c975f1be1137b7, 60) = 0x9c975f1be1137b7e`
8. `sub_29fb98` 读取全局 32 位字：
   - 先读到旧值 `0xdd87ab18`
   - 写入 `slot[6]`
9. `sub_2d15e8` 再执行：
   - `slot[9] = slot[20] ^ slot[6]`
   - `0x9c975f1be1137b7e ^ 0xdd87ab18 = 0x9c975f1b3c94d066`
10. `sub_291e3c` 把 `slot[9]` 低 32 位写回全局：
    - `*(global_0x516160) = 0x3c94d066`
11. `sub_29fb98` 再次读取：
    - 读回 `0x3c94d066`
    - 写入 `slot[6]`
12. `slot[6] -> slot[5]` 的最终 32 位变换：
    - `slot[5] = 0x3c94d066`
    - `rev16(slot[5]) = 0x943c66d0`
    - `ror32(..., 16) = 0x66d0943c`
13. `vm-store32 -> memcpy -> base64`
    - 写到 `0xe4ff7998`
    - `memcpy` 到 `0x12357410`
    - `base64(3c 94 d0 66) = PJTQZg==`

## 已确认的 helper 语义

- `sub_25bfe0`
  - 表驱动逐字节混合，输入为 `ptr + len`
- `sub_269b70`
  - `hash = sub_25bfe0(obj->data, obj->len)`
- `sub_2590ec`
  - 把源对象的 `len/data` 复制到新的缓冲区，并补 `\\0`
- `sub_2b7f3c`
  - `return sub_2590ec(get-value-from-address(arg1, 8), get-value-from-address(arg1, 9))`
- `sub_291e3c`
  - `*sub_4cff50(0x516160) = arg2_low32`
- `sub_29fb98`
  - `return *(uint32_t *)sub_4cff50(0x516160)`
- `sub_304a24`
  - `slot[dst] = slot[srcB] ^ slot[srcA]`
- `sub_2def20`
  - `slot[dst] = *(slot[srcBase] + off)`
- `sub_2e423c`
  - `slot[dst] = *(slot[srcBase] + off)`
- `0x2d2080` handler
  - `slot[dst] = ror64(slot[src], imm + 0x20)`

## 重要修正

- `0x516160` 不是普通“全局变量地址”
  - `sub_291e3c` / `sub_29fb98` 实际都先调 `sub_4cff50(0x516160)`
  - `sub_4cff50` 是一个 TLS 访问器，会返回当前线程的一块存储
  - 所以 `old raw32` 的本质是“线程局部状态字”
- `rev16 + ror32(16)` 可以合并理解成：
  - `bswap32(new_tls32)`
  - 因此 `X-Ladon` 本质上是 `base64(be32(new_tls32))`

## 公式化理解

先定义：

- `K = uint32(X-Khronos) = 0x6a0bd568`
- `A = le32(base64^-1(X-Argus)) = 0x6a0bd568`
- 当前样本里 `A == K`
- `H = sub_25bfe0(slot8_text, len)`，当前样本 `slot8_text = "1611921764"`
- `S = *(slot23 + 0x80)`，当前样本观察值是 `0x123573d8`
- `T_old = *(uint32_t *)sub_4cff50(0x516160)`

则当前链可写成：

1. `mix64 = H ^ A ^ S`
2. `rot64 = ror64(mix64, 60)`
3. `T_new = T_old ^ low32(rot64)`
4. `X-Ladon = base64(be32(T_new))`

旧样本代入（unidbg 交叉验证）：

- `H = 0xe9c975f1c62f9107`
- `A = 0x6a0bd568`
- `S = 0x123573d8`
- `mix64 = 0xe9c975f1be1137b7`
- `rot64 = 0x9c975f1be1137b7e`
- `T_old = 0xdd87ab18`
- `T_new = 0x3c94d066`
- `be32(T_new) = 3c 94 d0 66`
- `base64 = PJTQZg==`

## 目前最强的推断

- `data.log:4066` 先把 `0x1235f000` 写入 `slot[5]`
- `data.log:4070` 再把 `0x123573d8` 写入 `slot[5]`
- 两者差值：
  - `0x123573d8 - 0x1235f000 = 0x83d8`
- 所以第二次解引用很像：
  - `slot[5] = *(slot[5] + 0x83d8)`
- 这个需要新加的 `vm-deref-to-slot` 日志确认 `srcBaseSlot` 和 `off`

## 还没完全落地的点

- 当前设备日志里的 `slot8_text = 1588093228` 语义还没完全命名
  - 已确认它不是 `X-Khronos`
  - 已确认它明确参与 `sub_269b70` 的 hash
  - 旧样本里同类位置出现过 `1611921764`
- `S = *(slot23 + 0x80)` 这个字段的业务语义还没完全命名
  - 目前只确认它在当前样本里被当成 64 位值参与异或
  - 当前设备日志里它对应的“第三输入”仍在变，因为同一个 `X-Khronos` 会出现多个不同 `delta = old_tls32 ^ new_tls32`
- 本机当前不能直接复跑
  - `OpenJDK 21 + libunicorn.dylib` 在初始化时 `SIGILL`
  - 崩溃文件：`unidbg-android/hs_err_pid63317.log`

## 当前最短理解

- `X-Argus` 是 `X-Khronos` 的 4 字节 base64 形态
- `X-Ladon` 会取另一段 10 位字符串做 64 位混合
- 再把这个混合结果与 `X-Argus/X-Khronos` 和 TLS 状态字做异或
- 最后把新的 TLS 低 32 位按大端字节做 base64
