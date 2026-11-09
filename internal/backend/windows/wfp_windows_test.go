package windows

import (
	"net/netip"
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

// Чистые преобразования без вызовов WFP: можно гонять на любой Windows.

func TestRuleRoundTripKeepsEveryFilterLine(t *testing.T) {
	r := plan(t, basePolicy(policy.ModeRepair), baseEnv())
	back := Ruleset{}
	for _, f := range r.Filters {
		back.Filters = append(back.Filters, fromRule(toRule(f)))
	}
	if back.Render() != r.Render() {
		t.Errorf("toRule→fromRule меняет фильтры:\n%s", back.Render())
	}
}

func TestToRuleBlockIsHard(t *testing.T) {
	f := Filter{Layer: ConnectV4, Action: Block, Weight: WeightBlock, Hard: true, Persistent: true}
	if !toRule(f).HardAction {
		t.Error("block должен уходить в WFP с CLEAR_ACTION_RIGHT")
	}
}

func TestSockaddrOfIPv6(t *testing.T) {
	_, ok := sockaddrOf(netip.MustParseAddr("2001:db8::5")).(*xwin.SockaddrInet6)
	if !ok {
		t.Error("IPv6-адрес должен давать SockaddrInet6 (без паники As4)")
	}
}

// Из WFP флаги приходят как uint32 (parse.go), а не wf.ConditionFlag.
func TestFromMatchLoopbackAsReadFromWFP(t *testing.T) {
	m := &wf.Match{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: uint32(wf.ConditionFlagIsLoopback)}
	if got := fromMatch(m); got.Field != FieldLoopback || got.Raw != "" {
		t.Errorf("loopback из WFP прочитан как %+v", got)
	}
}
