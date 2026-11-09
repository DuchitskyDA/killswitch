package classify

import "testing"

var good = Evidence{Window: true, AppOK: true, Captured: 3, Received: 1}

func TestClassify(t *testing.T) {
	cases := []struct {
		name        string
		base, under Evidence
		want        Verdict
	}{
		{"правило держит", good, Evidence{Window: true, Err: "operation not permitted"}, Blocked},
		{"правило снято — ответ пришёл", good, good, Leak},
		{"ответа нет, но пакет на WAN", good, Evidence{Window: true, Captured: 1}, Leak},
		{"ответа нет, но получатель видел", good, Evidence{Window: true, Received: 1}, Leak},
		{"нет сервера: baseline без ответа", Evidence{Window: true, Captured: 2}, Evidence{Window: true}, Inconclusive},
		{"нет сервера и правила сняты", Evidence{Window: true, Captured: 2}, Evidence{Window: true, Captured: 2}, Inconclusive},
		{"baseline: захват мёртв", Evidence{AppOK: true, Received: 1}, Evidence{Window: true}, Inconclusive},
		{"baseline: получатель не видел", Evidence{Window: true, AppOK: true, Captured: 1}, Evidence{Window: true}, Inconclusive},
		{"под правилами захват мёртв", good, Evidence{}, Inconclusive},
		{"под правилами захват мёртв, но ответ есть", good, Evidence{AppOK: true}, Leak},
	}
	for _, c := range cases {
		if got, why := Classify(c.base, c.under); got != c.want {
			t.Errorf("%s: %s (%s), ждали %s", c.name, got, why, c.want)
		}
	}
}

func TestClassifyTunnel(t *testing.T) {
	cases := []struct {
		name string
		e    TunnelEvidence
		want Verdict
	}{
		{"через туннель", TunnelEvidence{Window: true, AppOK: true, Via: 1, Transport: 4}, TunnelOK},
		{"connect без ответа (SYN-ACK от TUN-стека)", TunnelEvidence{Window: true, Via: 0}, TunnelFail},
		{"ответ есть, но сервер видел физический адрес", TunnelEvidence{Window: true, AppOK: true, Direct: 2}, PathLeak},
		{"ответ без записи получателя", TunnelEvidence{Window: true, AppOK: true}, TunnelFail},
		{"один прямой пакет мимо туннеля", TunnelEvidence{Window: true, AppOK: true, Via: 1, Direct: 1}, PathLeak},
		{"окно захвата не подтверждено", TunnelEvidence{Window: false, AppOK: true, Via: 1}, Inconclusive},
	}
	for _, c := range cases {
		if got, why := ClassifyTunnel(c.e); got != c.want {
			t.Errorf("%s: %s (%s), ждали %s", c.name, got, why, c.want)
		}
	}
}
