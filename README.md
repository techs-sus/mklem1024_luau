# mklem1024_luau

You can download the library by downloading the repository as a zip and taking the "library" folder.

If ran on Roblox, CSPRNG is seeded with 64 `HttpService:GenerateGuid()` calls on Roblox.

An example is provided in `test/server/init.server.luau`.

## Build steps

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release

# You need the roblox-rs cli for this
roblox-rs build -o out ./target/wasm32-unknown-unknown/release/kyber_wasm.wasm
```

You need to modify the output of runtime.luau to make `get_public_key`, `get_ciphertext`, and `get_shared_secret` to return buffers.

Then, make `encapsulate`, `decapsulate`, and `generate` accept buffers.

## Credits

Uses CSPRNG via [rbx-cryptography](https://github.com/daily3014/rbx-cryptography).
Uses a verified MLKEM1024 implementation via [libcrux](https://github.com/cryspen/libcrux).
