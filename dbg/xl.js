// 1. VM 先在 slot[9] 里放一个 64 位值。
//     关键样本里这个值是 0x9c975f1b3c94d066，真正后续用的是它的低 32 位 0x3c94d066。
//  2. sub_2be408 把 slot[9] 的低 32 位写进一个全局字。
//     这条链是：
//     get-value-from-address(ctx, 8) -> get-value-from-address(ctx, 9) -> sub_291e3c(slot8, slot9)
//     其中 sub_291e3c 本质就是 *global_word = arg2_low32。
//  3. sub_29fb98 再把这个全局字读出来，sub_2be444 把返回值写到 slot[6]。
//     所以这里已经确定：
//     slot[6] = 0x3c94d066
//  4. VM 后续对这个 32 位值做两步变换：
//     0x2cf174/0x2cf178：slot[6] -> slot[5]，本轮相当于不变
//     0x2d0f58：rev16(0x3c94d066) = 0x943c66d0
//     0x2cea04：ror32(0x943c66d0, 16) = 0x66d0943c
//  5. 0x2cead4 把 0x66d0943c 写到临时地址 0xe4ff7998，随后 sub_258f08 的 memcpy 把这 4 字节拷到 base64 的 arg4 缓
//     冲区 0x12357410。
//  6. 0x269dd8 调 base64，输入就是这 4 字节。
//     内存小端字节是 3c 94 d0 66，base64 后就是 PJTQZg==，也就是 X-Ladon

//0xdd87ab18 ^ 0x9c975f1be1137b7e