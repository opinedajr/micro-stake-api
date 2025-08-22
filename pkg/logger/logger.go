package logger

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
)

type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, err error, fields ...Field)
}

type StructuredLogger struct {
	logger  *log.Logger
	level   Level
	service string
	version string
}

type LogEntry struct {
	Timestamp string      `json:"timestamp"`
	Level     Level       `json:"level"`
	Service   string      `json:"service"`
	Version   string      `json:"version"`
	Message   string      `json:"message"`
	Error     string      `json:"error,omitempty"`
	Fields    interface{} `json:"fields,omitempty"`
}

func New(service, version string, level Level) Logger {
	return &StructuredLogger{
		logger:  log.New(os.Stdout, "", 0),
		level:   level,
		service: service,
		version: version,
	}
}

func (l *StructuredLogger) Debug(msg string, fields ...Field) {
	if l.shouldLog(LevelDebug) {
		l.log(LevelDebug, msg, nil, fields)
	}
}

func (l *StructuredLogger) Info(msg string, fields ...Field) {
	if l.shouldLog(LevelInfo) {
		l.log(LevelInfo, msg, nil, fields)
	}
}

func (l *StructuredLogger) Warn(msg string, fields ...Field) {
	if l.shouldLog(LevelWarn) {
		l.log(LevelWarn, msg, nil, fields)
	}
}

func (l *StructuredLogger) Error(msg string, err error, fields ...Field) {
	if l.shouldLog(LevelError) {
		l.log(LevelError, msg, err, fields)
	}
}

func (l *StructuredLogger) log(level Level, msg string, err error, fields []Field) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Level:     level,
		Service:   l.service,
		Version:   l.version,
		Message:   msg,
	}

	if err != nil {
		entry.Error = err.Error()
	}

	if len(fields) > 0 {
		fieldMap := make(map[string]interface{})
		for _, field := range fields {
			fieldMap[field.Key] = field.Value
		}
		entry.Fields = fieldMap
	}

	jsonData, jsonErr := json.Marshal(entry)
	if jsonErr != nil {
		l.logger.Printf("Error marshaling log entry: %v", jsonErr)
		return
	}

	l.logger.Println(string(jsonData))
}

func (l *StructuredLogger) shouldLog(level Level) bool {
	levelPriority := map[Level]int{
		LevelDebug: 0,
		LevelInfo:  1,
		LevelWarn:  2,
		LevelError: 3,
	}

	currentPriority, exists := levelPriority[l.level]
	if !exists {
		currentPriority = levelPriority[LevelInfo]
	}

	logPriority, exists := levelPriority[level]
	if !exists {
		return false
	}

	return logPriority >= currentPriority
}

// Helper functions para criar fields facilmente
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value}
}

func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

func Any(key string, value interface{}) Field {
	return Field{Key: key, Value: value}
}

func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value.String()}
}

func Time(key string, value time.Time) Field {
	return Field{Key: key, Value: value.Format(time.RFC3339)}
}

func HTTPMethod(method string) Field {
	return Field{Key: "http_method", Value: method}
}

func HTTPPath(path string) Field {
	return Field{Key: "http_path", Value: path}
}

func HTTPStatus(status int) Field {
	return Field{Key: "http_status", Value: status}
}

func UserID(userID string) Field {
	return Field{Key: "user_id", Value: userID}
}

func RequestID(requestID string) Field {
	return Field{Key: "request_id", Value: requestID}
}
