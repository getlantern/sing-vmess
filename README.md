This repo is a fork of [sing-vmess](https://github.com/sagernet/sing-vmess) with the following changes:
1. No panics anywhere. All methods (excepet the allocator) that could panic before will now return errors
2. VMess/VLess Service now accepts Handler as part of NewConnection to allow synchronous handling of incoming connections

# sing-vmess

Some confusing protocol.

### Features

100% compatible with `v2ray-core`.

* Stream length chunk with padding and masking
* AEAD length chunk with padding
* Stream chunk
* AEAD chunk
* Legacy client
* AEAD client
* Legacy server
* AEAD server

Extra features:

* Mux server
* XUDP client
* VLESS client
