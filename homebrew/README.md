# Homebrew Distribution for Transducer

This directory contains templates for setting up Homebrew distribution.

## Setup Instructions

### 1. Create the Tap Repository

Create a new GitHub repository named `homebrew-transducer`:

```bash
# On GitHub, create: brandon-coproduct/homebrew-transducer
git clone https://github.com/brandon-coproduct/homebrew-transducer.git
cd homebrew-transducer
mkdir Formula
cp /path/to/transducer.rb Formula/
git add . && git commit -m "Add transducer formula"
git push origin main
```

### 2. Set Up Automatic Formula Updates (Optional)

To automatically update the formula when new releases are published:

1. Create a Personal Access Token (PAT) with `repo` scope
2. Add it as a secret `HOMEBREW_TAP_TOKEN` in the transducer-agent repo
3. Add this workflow to the tap repo (`.github/workflows/update-formula.yml`):

```yaml
name: Update Formula

on:
  repository_dispatch:
    types: [update-formula]

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Update formula
        run: |
          VERSION="${{ github.event.client_payload.version }}"
          SHA256="${{ github.event.client_payload.sha256 }}"
          URL="${{ github.event.client_payload.url }}"

          # Update version
          sed -i "s/version \".*\"/version \"$VERSION\"/" Formula/transducer.rb

          # Update SHA (for universal binary on macOS)
          # Note: For multi-platform, you'll need to fetch all SHAs

      - name: Commit and push
        run: |
          git config user.name "GitHub Actions"
          git config user.email "actions@github.com"
          git add Formula/transducer.rb
          git commit -m "Update transducer to ${{ github.event.client_payload.version }}"
          git push
```

### 3. User Installation

Once the tap is set up, users can install with:

```bash
# Add the tap
brew tap brandon-coproduct/transducer

# Install
brew install transducer

# Or in one command
brew install brandon-coproduct/transducer/transducer
```

### 4. Updating

Users update with:

```bash
brew update
brew upgrade transducer
```

## Release Workflow

The release workflow (`.github/workflows/release.yml`) in transducer-agent:

1. **Triggers** on version tags (`v*`)
2. **Builds** binaries for:
   - `x86_64-apple-darwin` (macOS Intel)
   - `aarch64-apple-darwin` (macOS Apple Silicon)
   - `x86_64-unknown-linux-gnu` (Linux x64)
   - `x86_64-unknown-linux-musl` (Linux x64 static)
   - `aarch64-unknown-linux-gnu` (Linux ARM64)
3. **Creates** a universal macOS binary using `lipo`
4. **Publishes** to GitHub Releases with SHA256 checksums
5. **Notifies** the tap repo to update the formula (if configured)

## Creating a Release

```bash
# Tag a release
git tag v0.1.0
git push origin v0.1.0

# The workflow will automatically:
# - Build all platform binaries
# - Create GitHub Release
# - Update Homebrew formula (if configured)
```

## Formula Variants

### Pre-compiled (Current)

The template `transducer.rb` downloads pre-compiled binaries. This is fast for users.

### Build from Source (Alternative)

If you prefer users to build from source:

```ruby
class Transducer < Formula
  desc "Distributed transducer agent for Claude Code workloads"
  homepage "https://github.com/brandon-coproduct/transducer-agent"
  url "https://github.com/brandon-coproduct/transducer-agent/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "SOURCE_TARBALL_SHA256"
  license "MIT"

  depends_on "rust" => :build
  depends_on "protobuf" => :build

  def install
    # Need to also fetch transducer-api and transducer-sandbox
    system "cargo", "install", *std_cargo_args
  end

  test do
    assert_match "transducer", shell_output("#{bin}/transducer --version")
  end
end
```

Note: Building from source requires handling the transducer-api and transducer-sandbox dependencies.
