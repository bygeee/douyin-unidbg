# X-Helios

## 1. Final shape

`X-Helios` is a 48-char base64 string.

Recovered final layout:

```text
final_binary_36 = prefix4(4 bytes) || body32(32 bytes)
X-Helios       = base64(final_binary_36)
```

Because `36 % 3 == 0`, the final base64 has no `=` padding.

Runtime evidence:

- `key = X-Helios`
- `value len = 48`
- buffer write trace shows a 48-byte ASCII string plus trailing `0x00`

## 2. Recovered formula

Recovered equivalent logic is already implemented in:

- `dbg/X-Helios.js`

Core formula:

```text
key32  = md5(prefix4_bytes || ascii(aid))
body32 = SPECK128/256-ECB-PKCS7(message26_ascii, key32_ascii)
final  = base64(prefix4_bytes || body32)
```

Important:

- `key32` is a 32-char lowercase hex string.
- Native code uses that 32-char hex string as 32 ASCII bytes for the SPECK key.
- `message26` is the plaintext body before block padding.

## 3. Parameters actually used

### 3.1 `prefix4`

- Type: 4 raw bytes
- Role:
  - becomes `final_binary_36[0..3]`
  - also participates in `key32` derivation
- Sample:

```text
prefix4 = fa3b5647
```

### 3.2 `aid`

- Type: decimal ASCII string from request context
- Sample:

```text
aid = 1128
```

- Role:

```text
key32 = md5(prefix4_bytes || "1128")
```

### 3.3 `message26`

- Type: observed ASCII plaintext
- Observed sample:

```text
message26 = "1779160424-1611921764-3019"
```

- Length in sample: `26`
- Role:
  - plaintext input to the body encryption path
  - padded to block boundary, then encrypted into `body32`

### 3.4 `key32`

- Type: 32-char lowercase hex string
- Sample:

```text
key32 = 3745137dcdc6f2e91be76594309ccbbb
```

- Derived from:

```text
md5(fa 3b 56 47 || "1128")
```

### 3.5 `body32`

- Type: 32 raw bytes
- Sample:

```text
body32 = b610228b358bf65f83979bf0b9e369cf7a09eae8de283b16af0f728cd014beda
```

### 3.6 Final `X-Helios`

- Sample reconstructed from `dbg/X-Helios.js`:

```text
X-Helios = +jtWR7YQIos1i/Zfg5eb8Lnjac96Cero3ig7Fq8PcozQFL7a
```

Another observed runtime sample in `dbg/data1.log`:

```text
X-Helios = 6trBejr/mfx5ewR3Jnlp33gxeW6hAXL4DD1nEgcAofxf52Ew
```

## 4. Key native positions

### 4.1 Header insertion

`0x2b7724` `sub_2b7724`

- Direct role: insert header key/value into the map
- Approx params:

```text
arg1 = mapCtx
arg2 = keyRef
arg3 = valueRef
```

For `X-Helios`, this is the place where the already-built base64 value is inserted.

Related caller-side observation point:

- `0x2c615c` inside `sub_2c6030`: key/value ready before insertion
- `0x2c6160` inside `sub_2c6030`: actual call to `sub_2b7724`

### 4.2 Final base64 encoder

`0x2563b8` `base64`

Recovered signature:

```c
int base64(char* out, size_t out_cap, size_t* out_len, void* src, size_t src_len)
```

Behavior:

- first can be called with `out = NULL` to probe required size
- then encodes into output buffer
- output is NUL-terminated

### 4.3 Base64 wrapper used by X-Helios path

`0x269c14` `sub_269c14`

- Reads:

```text
input->len  at +0xc
input->data at +0x10
```

- Then:
  - calls `base64(NULL, cap, &need_len, input->data, input->len)`
  - allocates buffer
  - calls `base64(...)` again to produce the final string

`0x269ba4` `sub_269ba4`

- VM thunk / wrapper landing pad
- xrefs show it is used by:
  - `0x2c3120`
  - `0x2bf68c`

### 4.4 Body32 generation

`0x2c29a0` `sub_2c29a0`

- Role: build the 32-byte encrypted body used by `X-Helios`
- Observed behavior:
  - consumes message-like object and key-related input
  - eventually calls `sub_2c2b10`
  - copies the produced 32-byte block into the output object

`0x2c2b10` `sub_2c2b10`

- Role: body encryption core
- Important recovered behavior:
  - computes padded size as `ceil(len / 16) * 16`
  - computes `pad = padded_len - len`
  - appends `pad` repeated `pad` times
  - loops 16 bytes per block
  - final output buffer is allocated and copied out

This matches the JS reconstruction:

```text
SPECK128/256-ECB-PKCS7
```

### 4.5 Mid-level X-Helios chain nodes

`0x2c3084` `sub_2c3084`

- xref target of `0x2c31d8`
- calls `0x2c29a0`
- this is the body32 branch

`0x2c3120` `sub_2c3120`

- xref target of `0x2c31d8`
- calls `0x269ba4`
- this is the final base64 branch

`0x2bf68c` `sub_2bf68c`

- another path into `0x269ba4`

`0x2c3974` `sub_2c3974`

- upper entry point
- xref target of `0x2be470`

`0x2c004c` `sub_2c004c`

- upper entry point
- xref target of `0x2bdd94`

## 5. Recovered call chains

### 5.1 One observed base64 chain

```text
sub_2be470
  -> sub_2c3974
    -> sub_2c31d8
      -> sub_2c3120
        -> sub_269ba4
          -> sub_269c14
            -> base64
```

### 5.2 Another observed base64 chain

```text
sub_2ba1c0
  -> sub_2bdd94
    -> sub_2c004c
      -> sub_2bf700
        -> sub_2bf68c
          -> sub_269ba4
            -> sub_269c14
              -> base64
```

### 5.3 Body generation chain

```text
sub_2c3974
  -> sub_2c31d8
    -> sub_2c3084
      -> sub_2c29a0
        -> sub_2c2b10
```

### 5.4 Insert into header map

```text
... build X-Helios value ...
  -> sub_2c6030 + 0x2c615c   ; key/value already prepared
  -> sub_2c6030 + 0x2c6160   ; call sub_2b7724
  -> sub_2b7724              ; insert "X-Helios" into map
```

## 6. What is not X-Helios

Do not confuse `X-Helios` with the `X-Gorgon` path.

Especially:

- `0x2c20d4` `sub_2c20d4`

This one is the 20-byte mix/encrypt path used for `X-Gorgon`, not the final `X-Helios` base64 body builder.

## 7. Repro sample

Sample values from `dbg/X-Helios.js`:

```text
aid         = 1128
prefix4     = fa3b5647
message26   = 1779160424-1611921764-3019
key32       = 3745137dcdc6f2e91be76594309ccbbb
body32      = b610228b358bf65f83979bf0b9e369cf7a09eae8de283b16af0f728cd014beda
X-Helios    = +jtWR7YQIos1i/Zfg5eb8Lnjac96Cero3ig7Fq8PcozQFL7a
```

Run:

```bash
node dbg/X-Helios.js
```

## 8. Current certainty

High confidence:

- final format is `base64(prefix4 || body32)`
- `key32 = md5(prefix4 || aid)`
- body encryption matches `SPECK128/256-ECB-PKCS7`
- `0x2563b8` is the final base64 encoder
- `0x2b7724` is the header map insertion point

Still worth keeping as runtime-labeled, not business-labeled:

- exact business meaning of `prefix4`
- exact semantic source of each field inside `message26`

