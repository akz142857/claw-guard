# /release — Build and publish a new claw-guard release

## When to use
Use this skill when the user says "release", "publish", "deploy version", or `/release`. It handles version bump, cross-compilation, packaging, and GitHub release creation.

## Instructions

Follow these steps in order. All release notes and GitHub content MUST be in English only.

### Step 1: Determine version

- Read current version from `Cargo.toml`
- Ask the user what the new version should be (patch/minor/major), or accept it as an argument (e.g., `/release 0.3.1`)
- Update `version` in `Cargo.toml`

### Step 2: Build and verify

```bash
cargo build --release
cargo run --release -- --list-rules 2>/dev/null | tail -1  # verify rule count
cargo run --release -- --version  # verify version
```

### Step 3: Commit version bump (if not already committed)

- Stage `Cargo.toml` and any other changed files
- Commit with message: `chore: bump version to {VERSION}`
- Do NOT include AI co-authorship in commit messages
- Push to main

### Step 4: Cross-compile all platforms

Build these 5 targets (macOS native, Linux/Windows via Docker):

```bash
# macOS (native)
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

# Linux (Docker) — run in parallel
docker run --rm --platform linux/arm64 -v "$(pwd)":/app -w /app rust:latest \
  cargo build --release --target aarch64-unknown-linux-gnu

docker run --rm -v "$(pwd)":/app -w /app rust:latest \
  cargo build --release --target x86_64-unknown-linux-gnu

# Windows (Docker)
docker run --rm -v "$(pwd)":/app -w /app rust:latest bash -c \
  "apt-get update -qq && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null 2>&1 && \
   rustup target add x86_64-pc-windows-gnu && \
   cargo build --release --target x86_64-pc-windows-gnu"
```

Run Docker builds in background where possible for parallelism.

### Step 5: Package artifacts

Create a temporary directory and package each binary:

```bash
VERSION="{version}"  # e.g., 0.3.0
DIST="/tmp/claw-guard-release-v${VERSION}"
rm -rf "$DIST" && mkdir -p "$DIST"

# macOS ARM64
tar -czf "$DIST/claw-guard-v${VERSION}-darwin-arm64.tar.gz" \
  -C target/aarch64-apple-darwin/release claw-guard

# macOS x86_64
tar -czf "$DIST/claw-guard-v${VERSION}-darwin-amd64.tar.gz" \
  -C target/x86_64-apple-darwin/release claw-guard

# Linux ARM64
tar -czf "$DIST/claw-guard-v${VERSION}-linux-arm64.tar.gz" \
  -C target/aarch64-unknown-linux-gnu/release claw-guard

# Linux x86_64
tar -czf "$DIST/claw-guard-v${VERSION}-linux-amd64.tar.gz" \
  -C target/x86_64-unknown-linux-gnu/release claw-guard

# Windows x86_64
(cd target/x86_64-pc-windows-gnu/release && zip "$DIST/claw-guard-v${VERSION}-windows-amd64.zip" claw-guard.exe)
```

### Step 6: Create git tag and GitHub release

```bash
git tag "v${VERSION}"
git push origin "v${VERSION}"
```

Generate release notes in **English only**. Use this template:

```
gh release create "v${VERSION}" \
  "$DIST/claw-guard-v${VERSION}-darwin-arm64.tar.gz" \
  "$DIST/claw-guard-v${VERSION}-darwin-amd64.tar.gz" \
  "$DIST/claw-guard-v${VERSION}-linux-arm64.tar.gz" \
  "$DIST/claw-guard-v${VERSION}-linux-amd64.tar.gz" \
  "$DIST/claw-guard-v${VERSION}-windows-amd64.zip" \
  --title "v${VERSION}" --notes "$(cat <<'NOTES'
## What's New in v{VERSION}

{summarize changes from git log since last tag}

## Downloads

| File | Platform |
|------|----------|
| claw-guard-v{VERSION}-darwin-arm64.tar.gz | macOS Apple Silicon (M1/M2/M3/M4) |
| claw-guard-v{VERSION}-darwin-amd64.tar.gz | macOS Intel |
| claw-guard-v{VERSION}-linux-amd64.tar.gz | Linux x86_64 |
| claw-guard-v{VERSION}-linux-arm64.tar.gz | Linux ARM64 |
| claw-guard-v{VERSION}-windows-amd64.zip | Windows x86_64 |

## Quick Start

\`\`\`bash
# Download and extract (example: macOS Apple Silicon)
curl -LO https://github.com/akz142857/claw-guard/releases/download/v{VERSION}/claw-guard-v{VERSION}-darwin-arm64.tar.gz
tar xzf claw-guard-v{VERSION}-darwin-arm64.tar.gz
chmod +x claw-guard

# Run audit
./claw-guard --no-analyze

# Run with LLM analysis
CLAW_GUARD_API_KEY="your-key" ./claw-guard --provider openai --model gpt-4o

# List all providers
./claw-guard --list-providers

# List all rules
./claw-guard --list-rules
\`\`\`
NOTES
)"
```

### Step 7: Verify

```bash
gh release view "v${VERSION}"
```

Print the release URL for the user.

## Important rules

- ALL release notes, titles, and descriptions MUST be in English
- Do NOT include AI co-authorship in any commits
- Artifact naming: `claw-guard-v{VERSION}-{OS}-{ARCH}.tar.gz` (`.zip` for Windows)
- OS values: `darwin`, `linux`, `windows`
- ARCH values: `arm64`, `amd64`
- Always verify builds succeeded before packaging
- If a Docker build fails, report the error and continue with available platforms
