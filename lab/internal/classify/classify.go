// Package classify превращает наблюдения одной пробы в вердикт BLOCKED / LEAK / INCONCLUSIVE.
package classify

import "fmt"

type Verdict string

const (
	Blocked      Verdict = "BLOCKED"
	Leak         Verdict = "LEAK"
	Inconclusive Verdict = "INCONCLUSIVE"

	TunnelOK   Verdict = "OK"
	TunnelFail Verdict = "FAIL"
	PathLeak   Verdict = "PATH-LEAK"
)

// Evidence — три независимых свидетеля одной прямой пробы (мимо туннеля, через физический интерфейс).
type Evidence struct {
	Window   bool   // положительный контроль: захват на WAN жив в этом окне
	AppOK    bool   // проба получила правильный ответ сервера
	Captured int    // пакетов от физического адреса клиента к цели в захвате на WAN
	Received int    // записей получателя с физическим адресом клиента
	Err      string // ошибка пробы, для отчёта
}

// BaselineOK — без правил проба прошла и её видели все свидетели.
func (e Evidence) BaselineOK() bool {
	return e.Window && e.AppOK && e.Captured > 0 && e.Received > 0
}

// LeakSeen — хоть один свидетель видел выход мимо туннеля.
func (e Evidence) LeakSeen() bool { return e.AppOK || e.Captured > 0 || e.Received > 0 }

func (e Evidence) String() string {
	s := fmt.Sprintf("window=%t app=%t wan=%d recv=%d", e.Window, e.AppOK, e.Captured, e.Received)
	if e.Err != "" {
		s += " err=" + e.Err
	}
	return s
}

// Classify сравнивает пробу под правилами с той же пробой без правил.
// Baseline не прошёл — INCONCLUSIVE: стенд не доказал, что выход вообще возможен, и отсутствие ответа ничего не значит.
func Classify(base, under Evidence) (Verdict, string) {
	switch {
	case !base.BaselineOK():
		return Inconclusive, "baseline без правил не прошёл: " + base.String()
	case under.LeakSeen():
		return Leak, under.String()
	case !under.Window:
		return Inconclusive, "захват на WAN не подтвердил окно: " + under.String()
	default:
		return Blocked, under.String()
	}
}

// TunnelEvidence — наблюдения пробы через туннель.
type TunnelEvidence struct {
	Window    bool
	AppOK     bool   // ответ правильный по содержимому, а не по connect
	Via       int    // записей получателя с адресом не клиента (сервер туннеля или inner)
	Direct    int    // пакетов от физического адреса клиента к цели на WAN — трафик пошёл мимо туннеля
	Transport int    // пакетов транспорта туннеля от клиента к серверу на WAN
	Echo      string // адрес источника, который увидел сервер
	Err       string
}

func (e TunnelEvidence) String() string {
	s := fmt.Sprintf("window=%t app=%t via=%d direct=%d transport=%d", e.Window, e.AppOK, e.Via, e.Direct, e.Transport)
	if e.Echo != "" {
		s += " echo=" + e.Echo
	}
	if e.Err != "" {
		s += " err=" + e.Err
	}
	return s
}

// ClassifyTunnel: OK — ответ пришёл и сервер видел не физический адрес клиента; PATH-LEAK — пакеты к цели ушли мимо туннеля;
// INCONCLUSIVE — окно захвата не подтверждено, отсутствие прямой утечки не доказано.
func ClassifyTunnel(e TunnelEvidence) (Verdict, string) {
	switch {
	case e.Direct > 0:
		return PathLeak, e.String()
	case !e.Window:
		return Inconclusive, "захват на WAN не подтвердил окно: " + e.String()
	case e.AppOK && e.Via > 0:
		return TunnelOK, e.String()
	default:
		return TunnelFail, e.String()
	}
}
