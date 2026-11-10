// Package backend — интерфейс backend ОС (WFP, nftables, pf). Реализации — internal/backend/{windows,linux,darwin}.
package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/health"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/probe"
)

// Ruleset — план правил; Render — детерминированный текст для эталонных тестов и хеша.
type Ruleset interface{ Render() string }

// HashOf — хеш плана: hex sha256(Render()).
//
// Правило хеша: после успешного Apply(r) без чужого вмешательства Status().Hash == HashOf(r),
// причём Status считает хеш из прочитанного обратно набора, а не из кеша. Пустой Hash — наших правил нет.
func HashOf(r Ruleset) string {
	sum := sha256.Sum256([]byte(r.Render()))
	return hex.EncodeToString(sum[:])
}

// ControlFunc привязывает сокет к интерфейсу.
type ControlFunc = health.ControlFunc

// Status — фактическое состояние наших правил.
//
// Active — наша установка есть (persistent-фильтры, on.nft, LaunchDaemon, файл якоря), даже если правила
// сейчас не загружены (macOS после загрузки до старта LaunchDaemon). По Active=true enforce без state.json
// включает on (fail-closed). Hash пуст только при полном отсутствии установки; в off (пустой якорь,
// принимающая таблица, permit-all) это хеш off-набора.
type Status struct {
	Active     bool
	Mode       policy.Mode
	Rules      int
	Hash       string // хеш фактического набора, см. HashOf
	Details    string
	Structural []probe.StructuralFinding // WFP-ничья, pf-сосед, quick выше якоря, якорь недостижим, pf disabled
	Token      string                    // macOS: enable-токен pf
	AnchorOK   bool                      // macOS: якорь достижим (канарейка)
}

// Backend — backend ОС.
type Backend interface {
	// Capabilities — что backend умеет исполнить (policy.CapabilitiesFor).
	Capabilities() policy.Capabilities
	// Snapshot собирает всё с побочными эффектами и сетью: интерфейсы, пути программ, разрешение имён Endpoints,
	// маршруты к Endpoints и dns.health, DHCP-резолверы, boot id. Health заполняет ядро.
	// Разрешает все glob политики (Trust, Repair.Programs) независимо от p.Mode.
	// BootID обязателен: пустой — on/off/repair/enforce отказывают с кодом 3.
	Snapshot(p policy.Policy) (env.Env, error)
	// Plan — чистая функция, без побочных эффектов. Ошибка, обёрнутая в ErrConfig, — код 2, иначе 3.
	Plan(p policy.Policy, e env.Env) (Ruleset, error)
	// Apply — атомарно, fail-closed: при ошибке остаётся прежний набор или блок всего.
	Apply(r Ruleset) error
	// Remove снимает всё наше без конфига и сети.
	Remove() error
	// Status читает фактическое состояние.
	Status() (Status, error)
	// Evidence: проба id отброшена нашим правилом после since. Если свидетельству нужна подготовка
	// до пробы (счётчик «до», сбор событий WFP), backend реализует probe.Preparer.
	Evidence(id probe.ProbeID, since time.Time) (dropped bool, err error)
	// BindControl — привязка сокета к интерфейсу для health и check.
	BindControl(iface env.Iface) ControlFunc
}

// Watcher — необязательно: события смены интерфейсов для enforce.
type Watcher interface {
	Changes() <-chan struct{}
}

// Program — программа: имя файла без пути и расширения .exe и полный путь исполняемого файла.
type Program struct{ Name, Path string }

// ProgramLister — необязательно (Windows): запущенные программы с известным путём — без дублей пути, по имени
// и пути. Из них пользователь выбирает имена для repair.names.
type ProgramLister interface {
	RunningPrograms() ([]Program, error)
}

// NameKey и NameFilesKey — ключи Env.Programs для найденного по имени из repair.names: идентификаторы программ
// для правил и пути тех же файлов для показа. С шаблоном пути не совпадают: имя диска — одна буква.
func NameKey(name string) string      { return "name:" + name }
func NameFilesKey(name string) string { return "files:" + name }

// ErrConfig — ошибка плана из-за конфига (код 2).
var ErrConfig = errors.New("ошибка конфига")

// ErrNotImplemented — backend для ОС ещё не реализован.
var ErrNotImplemented = errors.New("backend для этой ОС ещё не реализован")
