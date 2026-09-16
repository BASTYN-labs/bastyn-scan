#!/usr/bin/env bash
# Renders Formula/bastyn.rb for the Homebrew tap from a release tag and the
# four *.sha256 checksum files GitHub Releases already publishes for it.
#
# Usage: render-homebrew-formula.sh <tag> <checksums-dir> <output-path>
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <tag> <checksums-dir> <output-path>" >&2
    exit 2
fi

tag="$1"
checksums_dir="$2"
output_path="$3"
repo="BASTYN-labs/bastyn-scan"

sha_for() {
    target="$1"
    file="$checksums_dir/bastyn-${tag}-${target}.sha256"
    if [ ! -f "$file" ]; then
        echo "missing checksum file: $file" >&2
        exit 1
    fi
    awk '{print $1}' "$file"
}

darwin_arm64=$(sha_for aarch64-apple-darwin)
darwin_x86_64=$(sha_for x86_64-apple-darwin)
linux_arm64=$(sha_for aarch64-unknown-linux-musl)
linux_x86_64=$(sha_for x86_64-unknown-linux-musl)

cat > "$output_path" <<EOF
class Bastyn < Formula
  desc "Single-binary static analysis for AI and agent code"
  homepage "https://bastyn.ai"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/${repo}/releases/download/${tag}/bastyn-${tag}-aarch64-apple-darwin.tar.gz"
      sha256 "${darwin_arm64}"
    end
    on_intel do
      url "https://github.com/${repo}/releases/download/${tag}/bastyn-${tag}-x86_64-apple-darwin.tar.gz"
      sha256 "${darwin_x86_64}"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/${repo}/releases/download/${tag}/bastyn-${tag}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "${linux_arm64}"
    end
    on_intel do
      url "https://github.com/${repo}/releases/download/${tag}/bastyn-${tag}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "${linux_x86_64}"
    end
  end

  def install
    bin.install "bastyn"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/bastyn --version")
  end
end
EOF

echo "Rendered formula to $output_path" >&2
