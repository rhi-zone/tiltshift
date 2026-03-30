# decode

Decode instructions from a byte offset using a named opcode grammar.

`tiltshift decode` reads bytes starting at the given offset and displays decoded mnemonics and operand bytes using an installed opcode grammar. Unknown opcodes are shown as `UNKNOWN` and consume 1 byte. Use [`tiltshift opcodes`](./opcodes) to install grammar files.

## Usage

```
tiltshift decode <FILE> <OFFSET> <FORMAT> [--count <N>]
```

## Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Path to the binary file |
| `<OFFSET>` | Byte offset to start decoding (decimal or `0x` hex) |
| `<FORMAT>` | Grammar name (from `tiltshift opcodes list`) |

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--count <N>` | `64` | Maximum number of instructions to decode |

## Examples

Decode 64 instructions starting at offset 0x10 using the `my-vm` grammar:

```bash
tiltshift decode bytecode.bin 0x10 my-vm
```

Decode 128 instructions from a decimal offset:

```bash
tiltshift decode bytecode.bin 256 my-vm --count 128
```

## Workflow

The intended workflow is:

1. Run `tiltshift analyze` to detect a bytecode region (look for a `BytecodeStream` signal with high confidence).
2. Observe the signal's region offset and the inferred instruction width.
3. Write a grammar TOML file mapping opcode bytes to mnemonics (see [opcodes](./opcodes)).
4. Install the grammar: `tiltshift opcodes add my-vm /path/to/my-vm.toml`
5. Decode: `tiltshift decode bytecode.bin 0xOFFSET my-vm`

## Grammar file format

Grammar files are TOML with the following structure:

```toml
name = "my-vm"
description = "My custom bytecode VM"  # optional

[[opcodes]]
byte = 0x00
mnemonic = "NOP"
operand_bytes = 0

[[opcodes]]
byte = 0x01
mnemonic = "PUSH"
operand_bytes = 2

[[opcodes]]
byte = 0x02
mnemonic = "CALL"
operand_bytes = 4
```

- `byte` — the opcode value (0–255)
- `mnemonic` — the human-readable instruction name
- `operand_bytes` — number of bytes consumed by operands after the opcode byte

## See also

- [`opcodes`](./opcodes) — install and list opcode grammar files
- [Signal Reference: BytecodeStream](/signals#bytecodestream) — how bytecode regions are detected
