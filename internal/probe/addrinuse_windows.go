package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

// addrInUse — адрес и порт сокета заняты: Windows сообщает об этом при привязке или при соединении.
func addrInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }
