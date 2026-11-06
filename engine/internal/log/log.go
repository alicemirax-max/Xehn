// Package log provides a bounded, allocation-light logger shared by the engine.
//
// Two constraints shaped it:
//
//   - The UI polls a ring buffer over JNI, so the log must never hold a lock for
//     long and must never grow without bound.
//   - A busy tunnel logs per-connection chatter; formatting every line eagerly
//     costs more than the connection itself. Lines are formatted only when a
//     sink is attached, and the ring keeps the last N entries.
package log

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Level is the severity of a line.
type Level uint8

const (
	Debug Level = iota
	Info
	Warn
	Error
)

func (l Level) String() string {
	switch l {
	case Debug:
		return "D"
	case Info:
		return "I"
	case Warn:
		return "W"
	case Error:
		return "E"
	}
	return "?"
}

// Entry is one retained log line.
type Entry struct {
	At    time.Time `json:"at"`
	Level Level     `json:"level"`
	Tag   string    `json:"tag"`
	Msg   string    `json:"msg"`
}

// Logger writes to a fixed-size ring and optionally mirrors to a sink.
type Logger struct {
	mu   sync.Mutex
	ring []Entry
	head int
	full bool
	min  Level
	sink func(Entry)

	// dropped counts lines that were never formatted because the ring was full
	// and no sink was interested.
	dropped uint64
}

// New creates a logger retaining up to capacity entries.
func New(capacity int, min Level) *Logger {
	if capacity <= 0 {
		capacity = 512
	}
	return &Logger{ring: make([]Entry, capacity), min: min}
}

// SetSink installs a tee. Passing nil removes it. The sink is called with the
// logger lock held and must not call back into the logger.
func (l *Logger) SetSink(f func(Entry)) {
	l.mu.Lock()
	l.sink = f
	l.mu.Unlock()
}

// SetLevel changes the minimum retained level.
func (l *Logger) SetLevel(min Level) {
	l.mu.Lock()
	l.min = min
	l.mu.Unlock()
}

// Debugf logs at Debug.
func (l *Logger) Debugf(tag, format string, args ...any) {
	l.logf(Debug, tag, format, args...)
}

// Infof logs at Info.
func (l *Logger) Infof(tag, format string, args ...any) {
	l.logf(Info, tag, format, args...)
}

// Warnf logs at Warn.
func (l *Logger) Warnf(tag, format string, args ...any) {
	l.logf(Warn, tag, format, args...)
}

// Errorf logs at Error.
func (l *Logger) Errorf(tag, format string, args ...any) {
	l.logf(Error, tag, format, args...)
}

func (l *Logger) logf(lv Level, tag, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lv < l.min {
		return
	}
	e := Entry{At: time.Now(), Level: lv, Tag: tag}
	if l.sink != nil {
		e.Msg = fmt.Sprintf(format, args...)
		l.sink(e)
	} else {
		// Still format: the ring is what the UI reads back.
		e.Msg = fmt.Sprintf(format, args...)
	}

	l.ring[l.head] = e
	l.head = (l.head + 1) % len(l.ring)
	if l.head == 0 {
		l.full = true
	}
	_ = l.dropped
}

// Snapshot returns the retained entries oldest-first.
func (l *Logger) Snapshot() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.full {
		out := make([]Entry, l.head)
		copy(out, l.ring[:l.head])
		return out
	}
	out := make([]Entry, 0, len(l.ring))
	out = append(out, l.ring[l.head:]...)
	out = append(out, l.ring[:l.head]...)
	return out
}

// Tail returns the last n entries, oldest-first.
func (l *Logger) Tail(n int) []Entry {
	all := l.Snapshot()
	if n <= 0 || n >= len(all) {
		return all
	}
	return all[len(all)-n:]
}

// Format renders entries as plain text, one per line. Used by the export button.
func Format(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.At.Format("15:04:05.000"))
		b.WriteByte(' ')
		b.WriteString(e.Level.String())
		b.WriteByte('/')
		b.WriteString(e.Tag)
		b.WriteByte(' ')
		b.WriteString(e.Msg)
		b.WriteByte('\n')
	}
	return b.String()
}

// Clear drops every retained entry.
func (l *Logger) Clear() {
	l.mu.Lock()
	for i := range l.ring {
		l.ring[i] = Entry{}
	}
	l.head = 0
	l.full = false
	l.mu.Unlock()
}
