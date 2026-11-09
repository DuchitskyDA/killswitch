//go:build linux

// Package wgset настраивает ключи и пиров WireGuard через wgctrl в текущем network namespace.
package wgset

import (
	"fmt"
	"net"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Peer struct {
	PublicKey string   `json:"public_key"`
	Endpoint  string   `json:"endpoint,omitempty"`
	Allowed   []string `json:"allowed"`
}

type Config struct {
	Iface      string `json:"iface"`
	PrivateKey string `json:"private_key"`
	ListenPort int    `json:"listen_port"`
	Peers      []Peer `json:"peers"`
}

func Apply(c Config) error {
	cl, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer cl.Close()
	key, err := wgtypes.ParseKey(c.PrivateKey)
	if err != nil {
		return err
	}
	cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &c.ListenPort, ReplacePeers: true}
	for _, p := range c.Peers {
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return err
		}
		pc := wgtypes.PeerConfig{PublicKey: pub, ReplaceAllowedIPs: true}
		if p.Endpoint != "" {
			if pc.Endpoint, err = net.ResolveUDPAddr("udp", p.Endpoint); err != nil {
				return err
			}
		}
		for _, a := range p.Allowed {
			_, n, err := net.ParseCIDR(a)
			if err != nil {
				return err
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *n)
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return cl.ConfigureDevice(c.Iface, cfg)
}

// Show — состояние устройства для отчёта: порт, рукопожатие, счётчики.
func Show(iface string) (string, error) {
	cl, err := wgctrl.New()
	if err != nil {
		return "", err
	}
	defer cl.Close()
	d, err := cl.Device(iface)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s listen=%d peers=%d", d.Name, d.ListenPort, len(d.Peers))
	for _, p := range d.Peers {
		hs := "никогда"
		if !p.LastHandshakeTime.IsZero() {
			hs = time.Since(p.LastHandshakeTime).Round(time.Second).String() + " назад"
		}
		fmt.Fprintf(&b, "; peer endpoint=%v handshake=%s rx=%d tx=%d", p.Endpoint, hs, p.ReceiveBytes, p.TransmitBytes)
	}
	return b.String(), nil
}

// GenerateKeys — пара ключей для лаборатории.
func GenerateKeys() (priv, pub string, err error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}
	return k.String(), k.PublicKey().String(), nil
}
