//go:build !linux

package main

import "errors"

func dispatch(string, []string) error {
	return errors.New("kslab работает только в Linux (network namespace)")
}
