class Nomos < Formula
  desc "Zero-trust execution gateway for autonomous agents"
  homepage "https://github.com/safe-agentic-world/nomos"
  license "Apache-2.0"
  version "latest"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/safe-agentic-world/nomos/releases/latest/download/nomos-darwin-arm64.tar.gz"
    else
      url "https://github.com/safe-agentic-world/nomos/releases/latest/download/nomos-darwin-amd64.tar.gz"
    end
    sha256 :no_check
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/safe-agentic-world/nomos/releases/latest/download/nomos-linux-arm64.tar.gz"
    else
      url "https://github.com/safe-agentic-world/nomos/releases/latest/download/nomos-linux-amd64.tar.gz"
    end
    sha256 :no_check
  end

  def install
    bin.install "nomos"
  end

  test do
    assert_match "nomos", shell_output("#{bin}/nomos version 2>&1")
  end
end
