//go:build !linux && !darwin && !windows

package window

import "errors"

func start(Command) error {
	return errors.New("окно на этой ОС не поддерживается")
}
