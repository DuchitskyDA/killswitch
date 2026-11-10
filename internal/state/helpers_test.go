package state

import (
	"reflect"
	"testing"
)

func eq[T any](t *testing.T, got, want T) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("получено %#v, ожидалось %#v", got, want)
	}
}

func hasErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("ожидалась ошибка, получено nil")
	}
}

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
}
