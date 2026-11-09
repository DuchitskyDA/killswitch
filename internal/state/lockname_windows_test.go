package state

import (
	"fmt"
	"os"
	"testing"
)

func testLockName(t *testing.T) string {
	return fmt.Sprintf(`Local\killswitch-test-%d-%s`, os.Getpid(), t.Name())
}
