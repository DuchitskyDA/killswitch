//go:build windows

package wf

import "strconv"

// killswitch: строка флагов перечисления написана руками — значения стали битовыми.
func (i filterEnumFlags) String() string {
	names := []struct {
		f filterEnumFlags
		s string
	}{
		{filterEnumFlagsBestTerminatingMatch, "BestTerminatingMatch"},
		{filterEnumFlagsSorted, "Sorted"},
		{filterEnumFlagsBootTimeOnly, "BootTimeOnly"},
		{filterEnumFlagsIncludeBootTime, "IncludeBootTime"},
		{filterEnumFlagsIncludeDisabled, "IncludeDisabled"},
	}
	out := ""
	for _, n := range names {
		if i&n.f != 0 {
			if out != "" {
				out += "|"
			}
			out += n.s
			i &^= n.f
		}
	}
	if i != 0 || out == "" {
		if out != "" {
			out += "|"
		}
		out += "filterEnumFlags(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return out
}
