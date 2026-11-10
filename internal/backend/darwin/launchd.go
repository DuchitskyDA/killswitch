package darwin

import (
	"fmt"
	"html"
)

// Plist — LaunchDaemon наблюдателя: запуск при загрузке (RunAtLoad) и перезапуск не позже чем через 10 с,
// если процесс завершился (StartInterval; пока enforce жив, launchd второй экземпляр не запускает).
func Plist(binary, log string) string {
	esc := html.EscapeString
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>enforce</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>10</integer>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, esc(Label), esc(binary), esc(log), esc(log))
}
