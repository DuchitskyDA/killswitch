package main

import "golang.org/x/sys/unix"

const termiosRequest = unix.TCGETS

// elevateFunc: повышения нет — меню и окно просят запустить через sudo.
var elevateFunc func(command string) error
