package utils

import (
	"sync"

	"github.com/kataras/golog"
)

const (
	DebugLevel = golog.DebugLevel
	InfoLevel  = golog.InfoLevel
	WarnLevel  = golog.WarnLevel
	ErrorLevel = golog.ErrorLevel
	FatalLevel = golog.FatalLevel
)

type Logger struct {
	*golog.Logger
	name  string
	level string
}

func initLogger(name string) *Logger {
	lock := sync.Mutex{}
	loggers := make(map[string]*Logger)
	lock.Lock()
	defer lock.Unlock()
	logger, exists := loggers[name]
	if exists {
		return logger
	} else {
		logger = &Logger{
			Logger: golog.New(),
			name:   name,
		}

		logger.SetTimeFormat("[2006-01-02 15:04:05]")
		loggers[name] = logger
		return logger
	}
}

var GlobalLogger = initLogger("GlobalLogger")

func Debug(v ...interface{}) {
	GlobalLogger.Debug(v...)
}

func Debugf(format string, args ...interface{}) {
	GlobalLogger.Debugf(format, args...)
}

func Info(v ...interface{}) {
	GlobalLogger.Info(v...)
}

func Infof(format string, args ...interface{}) {
	GlobalLogger.Infof(format, args...)
}

func Warn(v ...interface{}) {
	GlobalLogger.Warn(v...)
}

func Warnf(format string, args ...interface{}) {
	GlobalLogger.Warnf(format, args...)
}

func Error(v ...interface{}) {
	GlobalLogger.Error(v...)
}

func Errorf(format string, args ...interface{}) {
	GlobalLogger.Errorf(format, args...)
}

func Fatal(v ...interface{}) {
	GlobalLogger.Fatal(v...)
}

func Fatalf(format string, args ...interface{}) {
	GlobalLogger.Fatalf(format, args...)
}
