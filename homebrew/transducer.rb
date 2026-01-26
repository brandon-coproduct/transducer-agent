# Homebrew formula for transducer
#
# This file should be placed in a separate repository:
#   github.com/brandon-coproduct/homebrew-transducer/Formula/transducer.rb
#
# Users install with:
#   brew tap brandon-coproduct/transducer
#   brew install transducer

class Transducer < Formula
  desc "Distributed transducer agent for Claude Code workloads"
  homepage "https://github.com/brandon-coproduct/transducer-agent"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/brandon-coproduct/transducer-agent/releases/download/v#{version}/transducer-aarch64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_AARCH64_SHA256"
    else
      url "https://github.com/brandon-coproduct/transducer-agent/releases/download/v#{version}/transducer-x86_64-apple-darwin.tar.gz"
      sha256 "REPLACE_WITH_X86_64_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/brandon-coproduct/transducer-agent/releases/download/v#{version}/transducer-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    else
      url "https://github.com/brandon-coproduct/transducer-agent/releases/download/v#{version}/transducer-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "REPLACE_WITH_LINUX_X86_64_SHA256"
    end
  end

  def install
    bin.install "transducer"
  end

  test do
    assert_match "transducer", shell_output("#{bin}/transducer --version")
  end
end
