# pkcs11-proxy: AES-CBC / AES-GCM mechanism support fix

## Root cause

`gck-rpc-util.c` has two whitelist functions that decide, per mechanism,
whether its `pParameter` (e.g. the IV for CBC, or the `CK_GCM_PARAMS`
struct for GCM) gets forwarded across the RPC link between the client
library (`libpkcs11-proxy.so`) and `pkcs11-daemon`:

- `gck_rpc_mechanism_has_no_parameters()` — mechanisms with **no**
  parameter (e.g. `CKM_AES_ECB`). These work today.
- `gck_rpc_mechanism_has_sane_parameters()` — mechanisms **with** a
  parameter that's safe to serialize as an opaque byte array. This
  list only contained `CKM_RSA_PKCS_OAEP` and `CKM_RSA_PKCS_PSS`, with
  a literal `/* This list is incomplete */` comment above it.

`CKM_AES_CBC`, `CKM_AES_CBC_PAD`, and `CKM_AES_GCM` were in **neither**
list. Effect, in `gck-rpc-module.c`'s `proto_write_mechanism()`:

```c
if (gck_rpc_mechanism_has_no_parameters(mech->mechanism))
    egg_buffer_add_byte_array(&msg->buffer, NULL, 0);
else if (gck_rpc_mechanism_has_sane_parameters(mech->mechanism))
    egg_buffer_add_byte_array(&msg->buffer, mech->pParameter, mech->ulParameterLen);
else
    return CKR_MECHANISM_INVALID;   /* <-- AES-CBC / AES-GCM hit this, client-side, before any network call */
```

Two visible symptoms, same root cause:

1. `C_GetMechanismList()` over the proxy silently drops AES-CBC/CBC-PAD/GCM
   from the list, because `gck_rpc_mechanism_list_purge()` (also gated by
   this whitelist) strips any mechanism it doesn't consider "sane" to
   transport.
2. Calling `C_EncryptInit`/`C_DecryptInit` with `CKM_AES_CBC` fails
   immediately with `CKR_MECHANISM_INVALID` — client-side, before the
   daemon or the underlying PKCS#11 module (e.g. SoftHSM2) is even
   contacted.

The server side (`proto_read_mechanism()` in `gck-rpc-dispatch.c`) was
already fully generic — it reads the mechanism type and parameter as a
plain byte array with no whitelist. Only the client-side whitelist was
the blocker.

## The fix

Add `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, and `CKM_AES_GCM` to
`gck_rpc_mechanism_has_sane_parameters()` in `gck-rpc-util.c`. Both the
CBC IV and the GCM params struct's IV/AAD fields are flat byte buffers,
so they're just as safe to forward opaquely as the existing RSA-OAEP/PSS
entries.

See `aes-cbc-gcm-mechanism-support.patch` for the exact diff, and
`gck-rpc-util.c` for the fully patched file.

## Applying to your fork

```bash
cd your-pkcs11-proxy-fork
git apply /path/to/aes-cbc-gcm-mechanism-support.patch
```

If `git apply` complains about context (e.g. your fork has diverged from
upstream `master`), just open `gck-rpc-util.c` and apply the same change
by hand to `gck_rpc_mechanism_has_sane_parameters()` — it's a single,
self-contained function.

## Build note: `CKM_AES_GCM` undeclared

If your build fails with:

```
error: 'CKM_AES_GCM' undeclared (first use in this function)
```

it's because the `pkcs11.h` bundled in this project (`pkcs11/pkcs11.h`)
implements **PKCS#11 v2.20** — `CKM_AES_GCM` was only added in **v2.40**
(2015), so the constant simply doesn't exist in the vendored header.
`CKM_AES_CBC`/`CKM_AES_CBC_PAD` are older (v2.11) and compile fine.

The patch adds a guarded fallback define in `gck-rpc-util.c` (value
`0x00001087`, taken from the official PKCS#11 v2.40 mechanism list) so
this compiles regardless of which `pkcs11.h` you're building against —
if you later switch to a v2.40+ header, the `#ifndef` means this
fallback is simply skipped.

## Building

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

This produces both `pkcs11-daemon` and `libpkcs11-proxy.so` — rebuild
and redeploy **both** sides, since the client-side whitelist is what's
being patched, but keeping daemon and client from the same build avoids
any other version drift.

## Testing after rebuild

```bash
# 1. Mechanism list should now include AES-CBC / AES-CBC-PAD / AES-GCM
PKCS11_PROXY_SOCKET=tls://127.0.0.1:2345 \
PKCS11_PROXY_TLS_PSK_FILE=/etc/pkcs11-daemon.psk \
pkcs11-tool --module ./libpkcs11-proxy.so --list-mechanisms | grep -E "AES-CBC|AES-GCM"

# 2. An actual encrypt operation should now succeed (adjust --label to your key)
PKCS11_PROXY_SOCKET=tls://127.0.0.1:2345 \
PKCS11_PROXY_TLS_PSK_FILE=/etc/pkcs11-daemon.psk \
pkcs11-tool --module ./libpkcs11-proxy.so \
  -p <PIN> --encrypt --mechanism AES-CBC \
  --label <your-key-label> -i /etc/hostname -o /tmp/test.enc
```

## Note on scope

This patch only whitelists the mechanisms actually needed here
(AES-CBC, AES-CBC-PAD, AES-GCM). The whitelist is still, by the
upstream authors' own admission, incomplete for other use cases (e.g.
other AEAD or wrap/unwrap-parameterized mechanisms) — extend the same
`switch` statement if you hit `CKR_MECHANISM_INVALID` on something else
that has a flat-byte-array parameter.
