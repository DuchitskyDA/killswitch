package health

import (
	"testing"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func TestHealthStartsUnknown(t *testing.T) {
	eq(t, NewMachine().State(), env.HealthUnknown)
}

func TestHealthTwoSuccessesFiveSecondsApartNotUp(t *testing.T) {
	m := NewMachine()
	m.Observe(at(0), true)
	eq(t, m.Observe(at(5), true), env.HealthUnknown)
}

func TestHealthUpAfterTenSecondsOfSuccess(t *testing.T) {
	m := NewMachine()
	m.Observe(at(0), true)
	m.Observe(at(5), true)
	eq(t, m.Observe(at(10), true), env.HealthUp)
}

func TestHealthFailureResetsSuccessStreak(t *testing.T) {
	m := NewMachine()
	m.Observe(at(0), true)
	m.Observe(at(5), false)
	m.Observe(at(10), true)
	eq(t, m.Observe(at(15), true), env.HealthUnknown)
}

func TestHealthTwoFailuresKeepUp(t *testing.T) {
	m := NewMachine()
	m.Observe(at(0), true)
	m.Observe(at(5), true)
	m.Observe(at(10), true)
	m.Observe(at(15), false)
	eq(t, m.Observe(at(20), false), env.HealthUp)
}

func TestHealthThreeFailuresDown(t *testing.T) {
	m := NewMachine()
	m.Observe(at(0), true)
	m.Observe(at(5), true)
	m.Observe(at(10), true)
	m.Observe(at(15), false)
	m.Observe(at(20), false)
	eq(t, m.Observe(at(25), false), env.HealthDown)
}
