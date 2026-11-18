# secure-box

A command-line tool for making **encrypted backups of a directory** — one opaque file you can hand
to cloud storage or keep on an external disk, which cannot be read or silently modified without the
password.

Encryption is **AES-256-GCM**. The key is derived from an interactively-prompted password with
**Argon2id**, a memory-hard KDF chosen to make offline password guessing expensive. A fresh salt and
nonce are generated on every lock, so backing up the same directory twice produces different
ciphertext and never reuses a nonce under a key.

Each container records the Argon2 parameters it was written with and re-derives the key from them, so
archives survive a change to the program's defaults. Nothing is deleted unless you ask for it: every
command leaves its input in place by default.

> ### Read this before storing a backup you care about
>
> This is a working tool, not an audited one, and the container format is **not yet stable**.
>
> There is no format version field, and the Argon2 parameters are recovered by reading the last four
> underscore-separated fields of the metadata. That works today, but it means the format cannot grow:
> adding a fifth parameter would make every existing container parse against the wrong fields and
> fail with nothing more informative than an authentication error. Keep the revision of this tool
> that wrote an archive alongside the archive until a version field exists.

## Requirements

- Python 3.10+ (3.12 is pinned in `.python-version`)
- [`uv`](https://docs.astral.sh/uv/) for dependency management

```bash
uv sync
```

## Usage

### Lock a directory

```bash
uv run main.py lock --input ./Docs --output-dir . --name Docs
```

Prompts for a password, then writes `./Docs.zip.gcm`. The source directory is left in place, and the
intermediate archive is removed once encryption succeeds.

Add `-d` / `--delete` to also remove the source directory after a successful lock — for when the data
is going to cold storage and is no longer needed on this machine:

```bash
uv run main.py lock --input ./Docs --output-dir . --name Docs --delete
```

### Unlock a container

```bash
uv run main.py unlock --input ./Docs.zip.gcm --output-dir . --name Docs
```

Prompts for the password and restores the original contents into `./Docs/`. If the password is wrong,
or the file has been altered by even one byte, decryption fails and nothing is written.

The container is kept. Add `-d` / `--delete` to remove it once the contents have been extracted:

```bash
uv run main.py unlock --input ./Docs.zip.gcm --output-dir . --name Docs --delete
```

### Verify a container

```bash
uv run main.py verify --input ./Docs.zip.gcm
```

Prompts for the password, decrypts the container, and a successful decryption
indicates that the container hasn't been tampered with.

Note that this currently decrypts to a temporary '.zip' file, and the container itself is never modified.

### Arguments

| Argument | `lock` | `unlock` | `verify` | Meaning |
| --- | :-: | :-: | :-: | --- |
| `--input` | ✓ | ✓ | ✓ | Source directory (`lock`) or `.gcm` container (`unlock`, `verify`) |
| `--output-dir` | ✓ | ✓ | — | Existing directory the result is written into |
| `--name` | ✓ | ✓ | — | Base name for the output, without extension |
| `-d`, `--delete` | ✓ | ✓ | — | Delete the operation's own input on success — the source directory for `lock`, the container for `unlock` |

Every path argument shown is required. `--output-dir` must already exist.

## How it works

```
lock:    directory ──zip (LZMA)──> .zip ──AES-256-GCM──> .zip.gcm ──> delete .zip
unlock:  .zip.gcm ──AES-256-GCM──> .zip ──unzip──> directory ──> delete .zip
verify:  .zip.gcm ──AES-256-GCM──> .zip ──read every member──> delete .zip
```

The intermediate `.zip` is always removed on success; `--delete` controls only the operation's own
input.

### Container layout

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 12 | GCM nonce |
| 12 | 16 | Argon2 salt |
| 28 | 4 | Length of the associated data |
| 32 | *n* | Associated data (not encrypted, but authenticated) |
| 32+*n* | rest | Ciphertext + 16-byte GCM tag |

The associated data is an underscore-joined record of the version, source directory name, the lock timestamp,
and the three Argon2 parameters — for example `Docs_1794369440_65536_3_4`. It is stored in the clear
and covered by the GCM tag, so it cannot be tampered with undetected, but it is metadata, not a
secret.

Reading a container takes its parameters from this field, not from the program's defaults, which is
what lets an archive outlive a change to those defaults. Current defaults for new archives are 64 MiB
memory, 4 passes, 4 lanes, 32-byte key (cannot be modified).

## Limitations

Ordered by how much damage they can do to a backup:

- **Parameters are trusted before they are authenticated.** The key has to be derived before GCM can
  check the tag, so the cost values read out of a container are acted on first and validated never. A
  corrupt length field or mangled digits can make the tool attempt an absurd memory allocation before
  it discovers the file was damaged.
- **Corruption is all-or-nothing.** GCM authenticates the archive as a single unit, so one flipped bit
  from bit rot or a truncated upload makes the whole backup unrecoverable — there is no partial
  recovery and no built-in redundancy. Verify your copies and keep more than one.
- **Plaintext touches the disk.** Every command writes an intermediate `.zip` before deleting it, and
  the delete is an ordinary `unlink`, not a secure erase. Note that overwriting is unreliable on SSDs
  and copy-on-write filesystems anyway; full-disk encryption is the real mitigation.
- **Extraction is not hardened.** `unlock` extracts archive entries without validating their paths, so
  a container crafted by someone else could write outside the output directory. Only unlock containers
  you created.
- **`--name` is truncated at a dot.** A name like `my.archive` becomes `my.zip`.
- **No key rotation and no password change** — both require a full lock/unlock cycle.

## Planned changes

Decided, not yet implemented, in priority order:

1. **Bounds-checking the Argon2 parameters** read from a container, refusing anything outside an
   accepted range rather than allocating on it.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
