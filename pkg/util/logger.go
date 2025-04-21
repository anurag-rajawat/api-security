package util

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

func InitLogger(logLevel string) {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	var debugMode bool
	if logLevel == "debug" {
		debugMode = true
	}
	if debugMode {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	cfg.Level, _ = zap.ParseAtomicLevel(logLevel)
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	coreLogger, _ := cfg.Build()
	logger = coreLogger.Sugar()
}

func GetLogger() *zap.SugaredLogger {
	if logger == nil {
		InitLogger("info")
	}
	return logger
}
