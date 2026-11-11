// gen собирает иконки killswitch из PNG, которые рисует ../render.sh (resvg):
//
//	../killswitch.ico                           — Windows, 16…256 (png/win-*.png)
//	../killswitch.icns                          — macOS, 16…1024 с @2x (png/mac-*.png)
//	../../../cmd/killswitch/rsrc_windows_amd64.syso — ресурс exe: только иконка, без манифеста
//	../../../web/src/favicon.ico                — вкладка окна, 16/32/48
//
// PNG кладутся в ICO и ICNS как есть, байт в байт; повторный запуск даёт те же файлы.
// Запуск: cd dist/icon/gen && go run .
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"os"
	"path/filepath"

	"github.com/tc-hib/winres"
)

const (
	pngDir  = "../png"
	icoPath = "../killswitch.ico"
	icnsOut = "../killswitch.icns"
	sysoOut = "../../../cmd/killswitch/rsrc_windows_amd64.syso"
	favOut  = "../../../web/src/favicon.ico"
)

// winSizes — размеры значка exe: Проводник, ярлык, «Приложения», панель задач при 100–200 % масштаба.
var winSizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

// favSizes — вкладка и заголовок окна браузера (1x и 2x) и плитка окна Edge --app.
var favSizes = []int{16, 32, 48}

// icnsTypes — записи ICNS как в iconset macOS: тип и сторона PNG в пикселях (@2x — вдвое больше точек).
var icnsTypes = []struct {
	kind string
	size int
}{
	{"icp4", 16}, {"ic11", 32}, // 16pt, 16pt@2x
	{"icp5", 32}, {"ic12", 64}, // 32pt, 32pt@2x
	{"ic07", 128}, {"ic13", 256}, // 128pt, 128pt@2x
	{"ic08", 256}, {"ic14", 512}, // 256pt, 256pt@2x
	{"ic09", 512}, {"ic10", 1024}, // 512pt, 512pt@2x
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	ico, err := buildICO("win", winSizes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(icoPath, ico, 0o644); err != nil {
		return err
	}
	syso, err := buildSyso(ico)
	if err != nil {
		return err
	}
	if err := os.WriteFile(sysoOut, syso, 0o644); err != nil {
		return err
	}
	fav, err := buildICO("win", favSizes)
	if err != nil {
		return err
	}
	if err := os.WriteFile(favOut, fav, 0o644); err != nil {
		return err
	}
	icns, err := buildICNS()
	if err != nil {
		return err
	}
	if err := os.WriteFile(icnsOut, icns, 0o644); err != nil {
		return err
	}
	for _, f := range []string{icoPath, sysoOut, favOut, icnsOut} {
		st, err := os.Stat(f)
		if err != nil {
			return err
		}
		fmt.Printf("%-50s %7d байт\n", filepath.Clean(f), st.Size())
	}
	return nil
}

// readPNG читает png/<prefix>-<size>.png и проверяет, что сторона — size.
func readPNG(prefix string, size int) ([]byte, error) {
	path := filepath.Join(pngDir, fmt.Sprintf("%s-%d.png", prefix, size))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.Width != size || cfg.Height != size {
		return nil, fmt.Errorf("%s: %dx%d, ожидалось %dx%d", path, cfg.Width, cfg.Height, size, size)
	}
	return data, nil
}

// buildICO — ICO с PNG-записями (Windows Vista+ читает PNG любого размера); 256 пишется как 0.
func buildICO(prefix string, sizes []int) ([]byte, error) {
	images := make([][]byte, len(sizes))
	for i, s := range sizes {
		data, err := readPNG(prefix, s)
		if err != nil {
			return nil, err
		}
		images[i] = data
	}
	var b bytes.Buffer
	le := func(v any) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le(uint16(0))          // reserved
	le(uint16(1))          // type: icon
	le(uint16(len(sizes))) // count
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		side := uint8(s)
		if s >= 256 {
			side = 0
		}
		b.WriteByte(side) // width
		b.WriteByte(side) // height
		b.WriteByte(0)    // colors in palette
		b.WriteByte(0)    // reserved
		le(uint16(1))     // planes
		le(uint16(32))    // bits per pixel
		le(uint32(len(images[i])))
		le(uint32(offset))
		offset += len(images[i])
	}
	for _, img := range images {
		b.Write(img)
	}
	return b.Bytes(), nil
}

// buildSyso — COFF-объект для windows/amd64 с одной группой иконок (ID 1, она же значок exe). Манифеста нет:
// запрос прав остаётся прежним — повышение делает сама программа.
func buildSyso(ico []byte) ([]byte, error) {
	icon, err := winres.LoadICO(bytes.NewReader(ico))
	if err != nil {
		return nil, err
	}
	rs := winres.ResourceSet{}
	if err := rs.SetIcon(winres.ID(1), icon); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := rs.WriteObject(&b, winres.ArchAMD64); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// buildICNS — контейнер ICNS: заголовок 'icns' + длина файла, затем записи «тип, длина с заголовком, PNG».
func buildICNS() ([]byte, error) {
	var body bytes.Buffer
	for _, t := range icnsTypes {
		data, err := readPNG("mac", t.size)
		if err != nil {
			return nil, err
		}
		body.WriteString(t.kind)
		_ = binary.Write(&body, binary.BigEndian, uint32(8+len(data)))
		body.Write(data)
	}
	var b bytes.Buffer
	b.WriteString("icns")
	_ = binary.Write(&b, binary.BigEndian, uint32(8+body.Len()))
	b.Write(body.Bytes())
	return b.Bytes(), nil
}
