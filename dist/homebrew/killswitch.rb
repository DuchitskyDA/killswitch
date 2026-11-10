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

  # brew upgrade и brew reinstall снимают прежнюю версию и ставят новую в одном процессе brew (uninstall_preflight
  # старой, её uninstall, затем postflight новой), а простой brew uninstall снятием и заканчивается. Поэтому режим
  # (on, repair, off) запоминается в памяти процесса до снятия и возвращается после установки: обновление режим
  # не меняет, а brew install после brew uninstall — как первая установка. Незавершённый переход (намерение)
  # возвращается его целью — так его довёл бы enforce.
  uninstall_preflight do
    state = command.run("/bin/cat", args: ["/Library/Application Support/killswitch/state.json"],
                                    sudo: true, print_stderr: false)
    mode = begin
      data = JSON.parse(state.stdout) if state.success?
      data.dig("intent", "target") || data["mode"]
    rescue
      nil
    end
    $killswitch_brew_mode = mode if ["on", "repair", "off"].include?(mode)
  end

  # Без подписи Apple: Homebrew ставит пометку карантина на загрузку, снимаем её с установленной программы.
  postflight do
    system_command "/usr/bin/xattr", args: ["-dr", "com.apple.quarantine", "#{appdir}/killswitch.app"]

    mode = $killswitch_brew_mode
    $killswitch_brew_mode = nil
    # После brew reinstall --zap настроек нет — это первая установка. Сбой не роняет brew: у reinstall прежняя
    # версия уже снята, откат оставил бы без программы.
    if mode && File.exist?("/Library/Application Support/killswitch/config.toml")
      restored = command.run("#{appdir}/killswitch.app/Contents/MacOS/killswitch", args: [mode], sudo: true)
      unless restored.success?
        warn "killswitch: режим #{mode} после обновления не восстановлен — откройте killswitch или выполните " \
             "sudo #{appdir}/killswitch.app/Contents/MacOS/killswitch #{mode}"
      end
    end
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
