# opcodes

Manage opcode grammar files used by [`tiltshift decode`](./decode).

Grammar files map opcode bytes to mnemonics and operand widths. They are written by hand after identifying a bytecode format and enable `tiltshift decode` to display named instructions rather than raw hex.

## Subcommands

### opcodes add

Install an opcode grammar file from a TOML path.

The file is validated and copied to `~/.config/tiltshift/opcodes/<name>.toml`.

#### Usage

```
tiltshift opcodes add <NAME> <FILE>
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `<NAME>` | Short name to install the grammar under (e.g. `my-vm`) |
| `<FILE>` | Path to the TOML grammar file |

#### Example

```bash
tiltshift opcodes add my-vm /path/to/my-vm.toml
```

### opcodes list

List all installed opcode grammars.

Shows all grammars stored at `~/.config/tiltshift/opcodes/`.

#### Usage

```
tiltshift opcodes list
```

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
byte = 0xFF
mnemonic = "HALT"
operand_bytes = 0
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Human-readable grammar name |
| `description` | no | Optional longer description |
| `[[opcodes]]` | yes | One entry per known opcode |
| `byte` | yes | Opcode value (0–255) |
| `mnemonic` | yes | Instruction name (e.g. `PUSH`, `CALL`, `NOP`) |
| `operand_bytes` | yes | Number of bytes consumed by operands after the opcode byte |

Opcodes not listed in the grammar are shown as `UNKNOWN` during decode and consume 1 byte.

## See also

- [`decode`](./decode) — decode instructions using a grammar
- [Signal Reference: BytecodeStream](/signals#bytecodestream) — how bytecode regions are detected
