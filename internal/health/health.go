// Package health — здоровье туннеля для DNS-режима tunnel-up (рев. 4 B1).
package health

import (
	"time"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

// Параметры B1.
const (
	Interval     = 5 * time.Second  // шаг проверки
	Timeout      = 3 * time.Second  // ответ HTTP/ не позже
	UpAfter      = 10 * time.Second // серия успехов не короче
	UpSuccesses  = 2                // и не меньше стольких подряд
	DownFailures = 3                // провалов подряд до down
)

// Machine — машина состояний unknown → up ↔ down. Время приходит снаружи.
type Machine struct {
	state      env.HealthState
	okStreak   int
	okSince    time.Time
	failStreak int
}

// NewMachine — начальное состояние unknown (действует как down).
func NewMachine() *Machine { return &Machine{state: env.HealthUnknown} }

// State — текущее состояние.
func (m *Machine) State() env.HealthState { return m.state }

// Observe учитывает итог одной проверки в момент now и возвращает новое состояние.
func (m *Machine) Observe(now time.Time, ok bool) env.HealthState {
	if !ok {
		m.okStreak = 0
		m.failStreak++
		if m.failStreak >= DownFailures {
			m.state = env.HealthDown
		}
		return m.state
	}
	m.failStreak = 0
	if m.okStreak == 0 {
		m.okSince = now
	}
	m.okStreak++
	if m.okStreak >= UpSuccesses && now.Sub(m.okSince) >= UpAfter {
		m.state = env.HealthUp
	}
	return m.state
}
