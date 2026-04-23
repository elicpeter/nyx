# Installation

## Install from crates.io

```bash
cargo install nyx-scanner
```

This installs the `nyx` binary into `~/.cargo/bin/`.

## Install from GitHub releases

1. Go to the [Releases](https://github.com/elicpeter/nyx/releases) page.
2. Download the binary for your platform:

   | Platform | Archive |
   |----------|---------|
   | Linux x86_64 | `nyx-x86_64-unknown-linux-gnu.zip` |
   | macOS Intel | `nyx-x86_64-apple-darwin.zip` |
   | macOS Apple Silicon | `nyx-aarch64-apple-darwin.zip` |
   | Windows x86_64 | `nyx-x86_64-pc-windows-msvc.zip` |

3. Extract and install:

   ```bash
   # Linux / macOS
   unzip nyx-*.zip
   chmod +x nyx
   sudo mv nyx /usr/local/bin/

   # Windows (PowerShell)
   Expand-Archive -Path nyx-*.zip -DestinationPath .
   Move-Item -Path .\nyx.exe -Destination "C:\Program Files\Nyx\"
   ```

4. Verify:
   ```bash
   nyx --version
   ```

## Build from source

```bash
git clone https://github.com/elicpeter/nyx.git
cd nyx
cargo build --release
cargo install --path .
```

Requires **Rust 1.88+** (edition 2024).

## CI Integration

### GitHub Actions

```yaml
- name: Install Nyx
  run: cargo install nyx-scanner

- name: Run security scan
  run: nyx scan . --format sarif --fail-on medium > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Generic CI

```bash
# Fail the build if any High or Medium finding is detected
nyx scan . --severity ">=MEDIUM" --fail-on medium --quiet --format json
```

The `--fail-on` flag causes Nyx to exit with code **1** if any finding meets or exceeds the given severity. Exit code **0** means no findings matched.
