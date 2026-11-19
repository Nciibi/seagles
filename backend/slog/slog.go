package slog

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var levelNames = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
	LevelFatal: "FATAL",
}

var currentLevel Level = LevelInfo
var format string = "kv"
var mu sync.Mutex

// The stdlib logger prefixes every line with LstdFlags ("YYYY/MM/DD HH:MM:SS ")
// by default. In JSON mode that makes each line invalid JSON and breaks log
// shippers that parse one object per line. Timestamps are already emitted as
// the "timestamp" field in buildJSON / buildKV, so the prefix is redundant.
func init() {
	log.SetFlags(0)
}

func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	currentLevel = l
}

func SetFormat(f string) {
	mu.Lock()
	defer mu.Unlock()
	format = f
}

func logf(level Level, msg string, keysAndValues ...interface{}) {
	mu.Lock()
	lvl := currentLevel
	fmt := format
	mu.Unlock()

	if level < lvl {
		return
	}

	switch fmt {
	case "json":
		log.Println(buildJSON(level, msg, keysAndValues...))
	default:
		log.Println(buildKV(level, msg, keysAndValues...))
	}
}

func buildKV(level Level, msg string, keysAndValues ...interface{}) string {
	var b strings.Builder
	b.WriteString(time.Now().Format(time.RFC3339))
	b.WriteString(" [")
	b.WriteString(levelNames[level])
	b.WriteString("] ")
	b.WriteString(msg)

	for i := 0; i < len(keysAndValues); i += 2 {
		b.WriteString(" ")
		if i+1 < len(keysAndValues) {
			b.WriteString(fmt.Sprintf("%v=%v", keysAndValues[i], keysAndValues[i+1]))
		} else {
			b.WriteString(fmt.Sprintf("%v=<missing>", keysAndValues[i]))
		}
	}
	return b.String()
}

func buildJSON(level Level, msg string, keysAndValues ...interface{}) string {
	entry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     levelNames[level],
		"message":   msg,
	}
	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			entry[key] = keysAndValues[i+1]
		}
	}
	b, err := json.Marshal(entry)
	if err != nil {
		// An unsupported attribute value (channel, func, NaN, ...) must not
		// turn the log line into an empty string. Keep the record and explain
		// why the original fields could not be encoded.
		fallback := map[string]interface{}{
			"timestamp":        entry["timestamp"],
			"level":            entry["level"],
			"message":          msg,
			"log_encode_error": err.Error(),
		}
		b, _ = json.Marshal(fallback)
	}
	return string(b)
}

func Debug(msg string, keysAndValues ...interface{}) {
	logf(LevelDebug, msg, keysAndValues...)
}

func Info(msg string, keysAndValues ...interface{}) {
	logf(LevelInfo, msg, keysAndValues...)
}

func Warn(msg string, keysAndValues ...interface{}) {
	logf(LevelWarn, msg, keysAndValues...)
}

func Error(msg string, keysAndValues ...interface{}) {
	logf(LevelError, msg, keysAndValues...)
}

func Fatal(msg string, keysAndValues ...interface{}) {
	logf(LevelFatal, msg, keysAndValues...)
	os.Exit(1)
}

type Logger struct {
	prefix string
}

func New(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	Info(l.prefix+": "+msg, keysAndValues...)
}

func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	Error(l.prefix+": "+msg, keysAndValues...)
}

func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	Warn(l.prefix+": "+msg, keysAndValues...)
}

func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	Debug(l.prefix+": "+msg, keysAndValues...)
}
