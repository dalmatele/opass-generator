# OMEN Generator

A C password-candidate generator that reads pcfg-go/OMEN `IP.level`,
`CP.level`, and `config.txt` model files and streams candidates to `stdout`.
Output can be redirected to a file or piped directly to another program.

[Read the Vietnamese documentation](README.vi.md).

> Use candidate generation and Hashcat only with data and hashes you are
> authorized to test or recover.

## Requirements

- A C11-compatible compiler (`cc`, GCC, or Clang).
- POSIX-compatible `make` (GNU Make or BSD Make).
- An OMEN model containing `IP.level`, `CP.level`, and a `config.txt` with an
  `ngram` setting.

The generator supports native Windows builds with MinGW-w64 as well as
POSIX-compatible environments such as MSYS2 MSYS and Cygwin.

### Windows build with MSYS2

1. Install MSYS2 from [msys2.org](https://www.msys2.org/).
2. Open the **MSYS2 MINGW64** terminal.
3. Update MSYS2:

   ```sh
   pacman -Syu
   ```

   Follow any instruction to close and reopen the terminal, then install GNU
   Make and the MINGW64 MinGW-w64 compiler:

   ```sh
   pacman -S --needed base-devel mingw-w64-x86_64-gcc
   ```

4. In the MINGW64 terminal, change to the project directory and build:

   ```sh
   cd /e/Projects/github/opass-generator
   make
   ```

   Replace the path with the location where you cloned the project. The build
   creates `omen-generator.exe` and `omen-level-check.exe`. With a
   MinGW-w64 compiler, these are native Windows executables and do not require
   the MSYS2 runtime. If MinGW and GNU Make are already on `PATH`, you can run
   `make` from that environment instead.

## Build

From the project directory:

```sh
make
```

This builds:

- `omen-generator`: reads the model and generates candidates.
- `omen-level-check`: checks the level files.

Choose another compiler or compiler flags if needed:

```sh
make CC=clang
make CC=gcc CFLAGS="-O2 -Wall -Wextra -Wpedantic -std=c11"
```

Remove built executables:

```sh
make clean
```

## Validate the model

Validate the model as parsed by the generator:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --check
```

The standalone checker is also available:

```sh
./omen-level-check \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt
```

The checker is a separate utility. For models with special characters such as
spaces in tokens, use `omen-generator --check` to validate the format consumed
by the generator.

## Generate candidates

Generate candidates from 8 through 16 characters and save them to a file:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  > candidates.txt
```

Options:

- `--min-len N`: minimum password length, measured in UTF-8 characters.
  Defaults to `ngram - 1`; smaller values are raised to the minimum prefix
  length.
- `--max-len N`: maximum password length. If omitted, generation continues
  to longer lengths until stopped.
- `--session FILE`: checkpoint path; defaults to `omen.session`.
- `--no-session`: disable checkpointing.
- `--check`: validate the model without generating candidates.
- `--help`: print usage information.

Candidates are written to `stdout`; progress and errors go to `stderr`.
Candidates are ordered by ascending total OMEN level within each password
length.

## Use with Hashcat

Pipe candidate output directly to Hashcat in stdin mode:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  --session omen.session |
hashcat -m <hash-mode> -a 0 hashes.txt
```

Replace `<hash-mode>` with the mode matching your hash format. Prefer piping
when you do not need a candidate file; this avoids storing the full wordlist
on disk.

## Sessions and resume

Sessions are enabled by default. The generator creates or updates
`omen.session`. A checkpoint stores model fingerprints, length limits, the
current password length, IP line, and total OMEN level. It is written to a
temporary file and replaces the previous checkpoint to reduce the risk of a
partial checkpoint.

Checkpoints are updated about every five seconds and when a new password
length starts. Stop the generator with `Ctrl+C` or `SIGTERM` to request a
checkpoint before exit. Restart with the same model, session, and length range:

```sh
./omen-generator \
  --ip data/IP.level \
  --cp data/CP.level \
  --config data/config.txt \
  --min-len 8 \
  --max-len 16 \
  --session omen.session \
  --resume
```

The generator verifies that model files match the saved fingerprints and
refuses to resume if they changed. `--min-len` and `--max-len` must match the
checkpoint. If `--max-len` was omitted, keep it omitted when resuming. A
completed session cannot be resumed; remove or rename it to start a new run.

### Resuming a Hashcat pipeline

`--resume` restores the **generator**, not Hashcat's stdin candidate stream.
If the pipeline stops, start both programs again as a new pipeline and pass
`--resume` to the generator. Do not use Hashcat's `--restore` to restore the
generator's candidate stream.

The checkpoint does not store an exact position inside a candidate branch, so
some candidates from the in-progress section may be emitted again after
resuming. To avoid duplicates across restarts, generate and persist a complete
wordlist and manage its offset separately; a stdin pipeline does not provide
that guarantee.

## Speed and memory

Reference throughput with Hashcat mode `32500`:

| Hardware | Throughput |
|---|---:|
| NVIDIA GeForce RTX 2060 6 GB | 250K candidates/second |
| MacBook Pro 15-inch (2019) | 30K candidates/second |

These are observed results on the listed systems; actual throughput may vary
with the model, settings, and system configuration.

The generator loads the model and its indexes into memory once, but does not
keep all generated candidates in RAM. Candidates are streamed as they are
generated. Temporary buffers scale with the current password length; set
`--max-len` to bound the search range and temporary memory. In a Hashcat pipe,
end-to-end throughput is limited by whichever side processes data more slowly.
