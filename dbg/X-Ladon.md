# X-Ladon

## 当前结论

- `X-Ladon = PJTQZg==`
- 对应 base64 输入 4 字节为 `3c 94 d0 66`
- 小端 32 位值为 `0x66d0943c`
- `X-Khronos = 1779160424`

## 关键日志位置

- `data.log:4063` 到 `data.log:4092`
- `data.log:4075` 到 `data.log:4089`

## 已确认的生成链

1. `sub_2be3dc` 在 `0x2be3ec` 调 `sub_269b70(slot8)`，返回值写入 `slot[6]`
2. `sub_269b70` 实际执行：
   - `return sub_25bfe0(*(slot8 + 0x10), *(slot8 + 0xc))`
3. `sub_25bfe0` 是表驱动的逐字节混合函数：
   - `result = table[((result & 0xff) ^ byte)] ^ (result >> 8)`
   - 当前看到的结果为 `0xe9c975f1c62f9107`
4. `sub_2def20` 在 `0x2def3c` 把 `0x123573d8` 写入 `slot[5]`
5. `sub_2d15e8` 执行：
   - `slot[6] = slot[7] ^ slot[6]`
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
- `sub_291e3c`
  - 写全局 32 位字到 `0x516160`
- `sub_29fb98`
  - 从 `0x516160` 读全局 32 位字
- `sub_304a24`
  - `slot[dst] = slot[srcB] ^ slot[srcA]`
- `sub_2def20`
  - `slot[dst] = *(slot[srcBase] + off)`
- `sub_2e423c`
  - `slot[dst] = *(slot[srcBase] + off)`
- `0x2d2080` handler
  - `slot[dst] = ror64(slot[src], imm + 0x20)`

## 目前最强的推断

- `data.log:4066` 先把 `0x1235f000` 写入 `slot[5]`
- `data.log:4070` 再把 `0x123573d8` 写入 `slot[5]`
- 两者差值：
  - `0x123573d8 - 0x1235f000 = 0x83d8`
- 所以第二次解引用很像：
  - `slot[5] = *(slot[5] + 0x83d8)`
- 这个需要新加的 `vm-deref-to-slot` 日志确认 `srcBaseSlot` 和 `off`

## 还没完全落地的点

- `sub_269b70` 到底 hash 了哪段原始字节
  - 已在 `MainActivity.java` 新增 `ladon-slot6-hash-precall`
  - 下一次运行会直接打印 `slot8Obj => obj/len/data/hex/text`
- `0x2e4258` 和 `0x2def3c` 的精确 `srcBaseSlot/off`
  - 代码里已补 `vm-deref-to-slot` 和 `vm-deref-to-slot2`
- 本机当前不能直接复跑
  - `OpenJDK 21 + libunicorn.dylib` 在初始化时 `SIGILL`
  - 崩溃文件：`unidbg-android/hs_err_pid63317.log`

## 当前最短理解

- Ladon 不是直接对请求做 base64
- 它先从 `slot8` 对象里取一段数据做 64 位哈希
- 再和另一段 VM 内部解引用得到的指针值混合
- 然后把结果旋转、异或、截成低 32 位
- 最后再做一轮 `rev16 + ror32 + base64`
