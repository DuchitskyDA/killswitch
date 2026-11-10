//go:build linux || darwin

package window

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// start запускает команду открытия адреса в своём сеансе (Ctrl+C в терминале её не задевает);
// с User — от имени этого пользователя и с его группами.
func start(c Command) error {
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env = c.Env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if c.User != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: c.User.UID, Gid: c.User.GID, Groups: groups(*c.User)}
	}
	return run(cmd)
}

// groups — группы пользователя; не узнать — только основная.
func groups(u User) []uint32 {
	out := []uint32{u.GID}
	account, err := user.LookupId(strconv.FormatUint(uint64(u.UID), 10))
	if err != nil {
		return out
	}
	ids, err := account.GroupIds()
	if err != nil {
		return out
	}
	for _, id := range ids {
		if n, err := strconv.ParseUint(id, 10, 32); err == nil && uint32(n) != u.GID {
			out = append(out, uint32(n))
		}
	}
	return out
}
