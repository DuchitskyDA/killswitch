package linux

// unit — systemd-юнит: имя, файл, ссылка включения и текст. Ставит Apply, снимает Remove.
type unit struct{ name, file, wants, text string }

// units: [0] — ранний набор до сети (рев. 2 A3), [1] — наблюдатель enforce.
var units = []unit{
	{
		name:  "killswitch-early.service",
		file:  "/etc/systemd/system/killswitch-early.service",
		wants: "/etc/systemd/system/sysinit.target.wants/killswitch-early.service",
		text: `# killswitch: правила до сети. Ставит "killswitch on", снимает "killswitch uninstall".
[Unit]
Description=killswitch: правила nftables до сети
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target
After=nftables.service
RequiresMountsFor=` + stateDir + `

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft -f ` + onFile + ` || nft -f ` + fallbackFile + `'

[Install]
WantedBy=sysinit.target
`,
	},
	{
		name:  "killswitch.service",
		file:  "/etc/systemd/system/killswitch.service",
		wants: "/etc/systemd/system/multi-user.target.wants/killswitch.service",
		text: `# killswitch: наблюдатель. Ставит "killswitch on", снимает "killswitch uninstall".
[Unit]
Description=killswitch: наблюдатель (enforce)
After=killswitch-early.service

[Service]
Type=simple
ExecStart=` + binFile + ` enforce
Restart=always
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
`,
	},
}
