# WebAssembly Test Fixtures

This directory contains WebAssembly test fixtures in WebAssembly Text Format (WAT).

## Files

- `add.wat` / `add.wasm` - Simple addition function for basic functionality tests
- `infinite_loop.wat` / `infinite_loop.wasm` - Infinite loop for timeout/cancellation tests

## Rebuilding Fixtures

If you modify a `.wat` file, rebuild the corresponding `.wasm` binary using the `wat2wasm` tool from [WABT](https://github.com/WebAssembly/wabt) (WebAssembly Binary Toolkit).

### Prerequisites

Install WABT 1.0 or later:

```bash
# macOS
brew install wabt

# Linux (Ubuntu/Debian)
apt-get install wabt

# Or build from source
git clone https://github.com/WebAssembly/wabt.git
cd wabt
git submodule update --init
mkdir build && cd build
cmake ..
cmake --build .
```

### Rebuild Commands

```bash
# From this directory
wat2wasm add.wat -o add.wasm
wat2wasm infinite_loop.wat -o infinite_loop.wasm

# Or using the task (if available)
task wasm:fixtures
```

Verify the binaries are updated:

```bash
ls -la *.wasm
```
