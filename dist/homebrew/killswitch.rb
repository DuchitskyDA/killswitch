# Шаблон cask для tap DuchitskyDA/homebrew-tap: brew install --cask duchitskyda/tap/killswitch.
# Значения @…@ подставляет ci/darwin/cask.sh (версия выпуска и sha256 zip из SHA256SUMS).
cask "killswitch" do
  arch arm: "arm64", intel: "amd64"

  version "@VERSION@"
  sha256 arm:   "@SHA256_ARM64@",
         intel: "@SHA256_AMD64@"

  url "@URL_BASE@/killswitch-darwin-#{arch}.zip"
  name "killswitch"
  desc "Kill switch: blocks traffic that bypasses the tunnel"
  homepage "https://github.com/DuchitskyDA/killswitch"

  depends_on macos: :monterey

  app "killswitch.app"

  # Без подписи Apple: Homebrew ставит пометку карантина на загрузку, снимаем её с установленной программы.
  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/killswitch.app"]
  end

  # Сначала LaunchDaemon, затем killswitch uninstall снимает якорь pf, токены и копию в Application Support.
  uninstall launchctl: "io.github.duchitskyda.killswitch",
            script:    {
              executable: "#{appdir}/killswitch.app/Contents/MacOS/killswitch",
              args:       ["uninstall"],
              sudo:       true,
            }

  zap trash: [
    "/Library/Application Support/killswitch",
    "/var/log/killswitch.log",
  ]
end
