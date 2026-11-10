// Package windows — backend WFP: свой persistent provider и sublayer (вес 0xFFFF), block по умолчанию на слоях
// ALE_AUTH_CONNECT/RECV_ACCEPT v4/v6 и permit-фильтры по политике.
//
// Файлы без суффикса _windows — модель фильтров, план и его текст: чистые, собираются и тестируются на любой ОС.
package windows

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/DuchitskyDA/killswitch/internal/policy"
)

// Layer — слой ALE, на котором стоит фильтр.
type Layer string

const (
	ConnectV4 Layer = "connect-v4"
	ConnectV6 Layer = "connect-v6"
	AcceptV4  Layer = "accept-v4"
	AcceptV6  Layer = "accept-v6"
)

// Layers — наши слои в порядке текста плана.
var Layers = []Layer{ConnectV4, ConnectV6, AcceptV4, AcceptV6}

// V4 — слой IPv4.
func (l Layer) V4() bool { return l == ConnectV4 || l == AcceptV4 }

// Connect — исходящий слой.
func (l Layer) Connect() bool { return l == ConnectV4 || l == ConnectV6 }

// Action — действие фильтра.
type Action string

const (
	Block  Action = "block"
	Permit Action = "permit"
)

// Веса фильтров внутри нашего sublayer: block-repair 30 → permit-all 20 → permit 10 → block 1.
const (
	WeightBlock       uint64 = 1
	WeightPermit      uint64 = 10
	WeightPermitAll   uint64 = 20
	WeightBlockRepair uint64 = 30
)

// Field — поле условия.
type Field string

const (
	FieldLoopback   Field = "loopback"    // FLAGS & IS_LOOPBACK
	FieldLocalIface Field = "local-iface" // IP_LOCAL_INTERFACE (LUID)
	FieldAppID      Field = "app-id"      // ALE_APP_ID
	FieldProto      Field = "proto"       // IP_PROTOCOL
	FieldLocalPort  Field = "local-port"  // IP_LOCAL_PORT
	FieldRemotePort Field = "remote-port" // IP_REMOTE_PORT
	FieldRemoteAddr Field = "remote-addr" // IP_REMOTE_ADDRESS
)

// Op — сравнение условия.
type Op string

const (
	OpEq  Op = "=="
	OpNeq Op = "!="
)

// Протоколы IP.
const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
)

// Cond — одно условие. Условия с одним полем WFP объединяет через ИЛИ, с разными — через И.
type Cond struct {
	Field  Field
	Op     Op
	LUID   uint64
	AppID  string
	Proto  uint8
	Port   uint16
	Prefix netip.Prefix
	Raw    string // условие, которого нет в модели (прочитано у чужого или испорченного фильтра)
}

func (c Cond) String() string {
	if c.Raw != "" {
		return "raw:" + c.Raw
	}
	op := string(c.Op)
	if op == "" {
		op = string(OpEq)
	}
	switch c.Field {
	case FieldLoopback:
		return "loopback"
	case FieldLocalIface:
		return fmt.Sprintf("local-iface%s%d", op, c.LUID)
	case FieldAppID:
		return fmt.Sprintf("app-id%s%q", op, c.AppID)
	case FieldProto:
		return fmt.Sprintf("proto%s%d", op, c.Proto)
	case FieldLocalPort, FieldRemotePort:
		return fmt.Sprintf("%s%s%d", c.Field, op, c.Port)
	case FieldRemoteAddr:
		return fmt.Sprintf("remote-addr%s%s", op, c.Prefix)
	}
	return fmt.Sprintf("%s?", c.Field)
}

// Filter — фильтр WFP в нашем sublayer.
type Filter struct {
	Name       string // подпись для человека; в текст плана и хеш не входит
	Layer      Layer
	Action     Action
	Weight     uint64
	Hard       bool // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
	Persistent bool
	BootTime   bool
	Conds      []Cond
}

// Line — каноническая строка фильтра: то, что хранит WFP и что Status читает обратно.
func (f Filter) Line() string {
	kind := "runtime"
	switch {
	case f.BootTime:
		kind = "boottime"
	case f.Persistent:
		kind = "persistent"
	}
	hard := "soft"
	if f.Hard {
		hard = "hard"
	}
	conds := make([]string, len(f.Conds))
	for i, c := range f.Conds {
		conds[i] = c.String()
	}
	sort.Strings(conds)
	line := fmt.Sprintf("%s %s %s w=%d %s", kind, f.Layer, f.Action, f.Weight, hard)
	if len(conds) > 0 {
		line += " " + strings.Join(conds, " ")
	}
	return line
}

// Key — детерминированный ключ фильтра (16 байт, вид GUID v5) из канонической строки.
func (f Filter) Key() [16]byte {
	sum := sha256.Sum256([]byte("killswitch/wfp/" + f.Line()))
	var k [16]byte
	copy(k[:], sum[:16])
	k[6] = k[6]&0x0f | 0x50
	k[8] = k[8]&0x3f | 0x80
	return k
}

// Ruleset — план WFP.
type Ruleset struct {
	Mode    policy.Mode
	Filters []Filter
}

// Render — канонические строки фильтров по порядку: слой, вид, вес по убыванию, текст.
// Одна функция для плана и для набора, прочитанного обратно (Status): так совпадают хеши.
func (r Ruleset) Render() string {
	lines := make([]string, len(r.Filters))
	for i, f := range r.Filters {
		lines[i] = f.Line()
	}
	sort.Slice(lines, func(i, j int) bool { return lineLess(lines[i], lines[j]) })
	var b strings.Builder
	fmt.Fprintf(&b, "# killswitch wfp: %d фильтров\n", len(lines))
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

func lineLess(a, b string) bool {
	ka, kb := sortKey(a), sortKey(b)
	if ka != kb {
		return ka < kb
	}
	return a < b
}

// sortKey: вид (persistent, boottime, runtime), слой по Layers, вес по убыванию.
func sortKey(line string) string {
	parts := strings.Fields(line)
	kind := map[string]int{"persistent": 0, "boottime": 1, "runtime": 2}[parts[0]]
	layer := 0
	for i, l := range Layers {
		if string(l) == parts[1] {
			layer = i
		}
	}
	var w uint64
	fmt.Sscanf(parts[3], "w=%d", &w)
	return fmt.Sprintf("%d %d %020d", kind, layer, ^w)
}

// ModeOf — режим по НЕ-persistent надстройке: block-repair → repair, permit-all → off, иначе on.
func ModeOf(filters []Filter) policy.Mode {
	mode := policy.ModeOn
	for _, f := range filters {
		if f.Persistent || f.BootTime {
			continue
		}
		switch {
		case f.Weight == WeightBlockRepair && f.Action == Block:
			return policy.ModeRepair
		case f.Weight == WeightPermitAll && f.Action == Permit:
			mode = policy.ModeOff
		}
	}
	return mode
}
