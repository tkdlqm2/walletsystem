package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// CustomJSONFormatter 레벨을 맨 앞에 표시하는 커스텀 포매터
type CustomJSONFormatter struct {
	TimestampFormat string
	PrettyPrint     bool
	SortKeys        bool
}

// Format 로그 엔트리를 포맷팅
func (f *CustomJSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// 데이터 복사 (원본 수정 방지)
	data := make(logrus.Fields)
	for k, v := range entry.Data {
		data[k] = v
	}

	// 완전히 순서를 제어하기 위한 정렬된 필드 배열
	var orderedKeys []string
	orderedFields := make(map[string]interface{})

	// 타임스탬프 포맷 설정
	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = "2006-01-02T15:04:05.000Z07:00"
	}

	// 1. 고정된 순서로 기본 필드들 추가
	fixedFields := []struct {
		key   string
		value interface{}
	}{
		{"timestamp", entry.Time.Format(timestampFormat)},
		{"level", strings.ToUpper(entry.Level.String())},
		{"request_id", nil}, // 나중에 data에서 찾아서 추가
		{"message", entry.Message},
		{"user_id", nil}, // 나중에 data에서 찾아서 추가
	}

	// 2. 고정 필드들을 순서대로 추가
	for _, field := range fixedFields {
		if field.value != nil {
			orderedKeys = append(orderedKeys, field.key)
			orderedFields[field.key] = field.value
		} else if value, exists := data[field.key]; exists {
			orderedKeys = append(orderedKeys, field.key)
			orderedFields[field.key] = value
			delete(data, field.key)
		}
	}

	// 3. 나머지 우선순위 필드들
	priorityFields := []string{
		"method",
		"path",
		"status",
		"duration_ms",
		"action",
		"component",
		"error",
	}

	// 4. 우선순위 필드들 추가
	for _, field := range priorityFields {
		if value, exists := data[field]; exists {
			orderedKeys = append(orderedKeys, field)
			orderedFields[field] = value
			delete(data, field) // 이미 추가한 필드는 제거
		}
	}

	// 5. 나머지 필드들 추가 (알파벳 순서로 정렬하거나 원래 순서 유지)
	if f.SortKeys {
		keys := make([]string, 0, len(data))
		for k := range data {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			orderedKeys = append(orderedKeys, k)
			orderedFields[k] = data[k]
		}
	} else {
		for k, v := range data {
			orderedKeys = append(orderedKeys, k)
			orderedFields[k] = v
		}
	}

	// JSON으로 직렬화 (순서 보장을 위해 커스텀 방식 사용)
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	// 순서를 보장하기 위해 수동으로 JSON 구성
	b.WriteString("{")

	if f.PrettyPrint {
		// Pretty print 형식
		for i, key := range orderedKeys {
			if i > 0 {
				b.WriteString(",\n  ")
			} else {
				b.WriteString("\n  ")
			}

			keyBytes, _ := json.Marshal(key)
			valueBytes, _ := json.Marshal(orderedFields[key])

			b.Write(keyBytes)
			b.WriteString(": ")
			b.Write(valueBytes)
		}
		b.WriteString("\n}")
	} else {
		// Compact 형식
		for i, key := range orderedKeys {
			if i > 0 {
				b.WriteString(",")
			}

			keyBytes, _ := json.Marshal(key)
			valueBytes, _ := json.Marshal(orderedFields[key])

			b.Write(keyBytes)
			b.WriteString(":")
			b.Write(valueBytes)
		}
		b.WriteString("}")
	}

	b.WriteString("\n")
	return b.Bytes(), nil
}

// ColoredTextFormatter 컬러 텍스트 포매터 (개발 환경용)
type ColoredTextFormatter struct {
	TimestampFormat string
	ShowCaller      bool
}

// ANSI 컬러 코드
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorWhite  = "\033[37m"
	ColorCyan   = "\033[36m"
)

// Format 컬러 텍스트 포맷팅
func (f *ColoredTextFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var levelColor string
	var levelText string

	switch entry.Level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = ColorRed
		levelText = "ERROR"
	case logrus.WarnLevel:
		levelColor = ColorYellow
		levelText = "WARN "
	case logrus.InfoLevel:
		levelColor = ColorGreen
		levelText = "INFO "
	case logrus.DebugLevel:
		levelColor = ColorBlue
		levelText = "DEBUG"
	default:
		levelColor = ColorWhite
		levelText = "TRACE"
	}

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = "2006-01-02 15:04:05"
	}

	timestamp := entry.Time.Format(timestampFormat)

	// 기본 포맷: [LEVEL] timestamp message
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s[%s]%s %s%s %s%s%s",
		levelColor, levelText, ColorReset,
		ColorCyan, timestamp, ColorReset,
		ColorWhite, entry.Message, ColorReset,
	))

	// 필드들 추가
	if len(entry.Data) > 0 {
		buf.WriteString(" ")
		for k, v := range entry.Data {
			buf.WriteString(fmt.Sprintf("%s%s%s=%v ", ColorBlue, k, ColorReset, v))
		}
	}

	buf.WriteString("\n")
	return buf.Bytes(), nil
}

var (
	appLogger     *logrus.Logger
	appLoggerOnce sync.Once
	currentDate   string
	logFile       io.WriteCloser
	logMutex      sync.RWMutex
)

// LogConfig 로그 설정 구조체
type LogConfig struct {
	BaseDir         string `json:"base_dir"`
	MaxSize         int    `json:"max_size"`
	MaxBackups      int    `json:"max_backups"`
	MaxAge          int    `json:"max_age"`
	Compress        bool   `json:"compress"`
	Level           string `json:"level"`
	Format          string `json:"format"`           // json, text, colored
	PrettyPrint     bool   `json:"pretty_print"`     // JSON 예쁘게 출력
	SortKeys        bool   `json:"sort_keys"`        // 키 정렬
	TimestampFormat string `json:"timestamp_format"` // 타임스탬프 형식
}

// DefaultLogConfig 기본 로그 설정
func DefaultLogConfig() LogConfig {
	return LogConfig{
		BaseDir:         "./logs",
		MaxSize:         100,
		MaxBackups:      30,
		MaxAge:          90,
		Compress:        true,
		Level:           "info",
		Format:          "json", // json, text, colored
		PrettyPrint:     false,  // 프로덕션에서는 false
		SortKeys:        false,  // 성능상 false 권장
		TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
	}
}

// GetLogger returns a singleton logrus.Logger with hierarchical file structure
func GetLogger() *logrus.Logger {
	appLoggerOnce.Do(func() {
		config := DefaultLogConfig()

		// 환경변수에서 설정 읽기
		if format := os.Getenv("LOG_FORMAT"); format != "" {
			config.Format = format
		}
		if level := os.Getenv("LOG_LEVEL"); level != "" {
			config.Level = level
		}
		if dir := os.Getenv("LOG_DIR"); dir != "" {
			config.BaseDir = dir
		}

		appLogger = initLoggerWithConfig(config)
	})
	return appLogger
}

// initLoggerWithConfig 설정으로 로거 초기화
func initLoggerWithConfig(config LogConfig) *logrus.Logger {
	logger := logrus.New()

	// 로그 레벨 설정
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// 포매터 설정
	switch config.Format {
	case "json":
		logger.SetFormatter(&CustomJSONFormatter{
			TimestampFormat: config.TimestampFormat,
			PrettyPrint:     config.PrettyPrint,
			SortKeys:        config.SortKeys,
		})
	case "colored", "color":
		logger.SetFormatter(&ColoredTextFormatter{
			TimestampFormat: config.TimestampFormat,
			ShowCaller:      true,
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: config.TimestampFormat,
		})
	default:
		// 기본값은 커스텀 JSON
		logger.SetFormatter(&CustomJSONFormatter{
			TimestampFormat: config.TimestampFormat,
			PrettyPrint:     config.PrettyPrint,
			SortKeys:        config.SortKeys,
		})
	}

	// 파일 출력 설정 (프로덕션 환경)
	if config.BaseDir != "" {
		setupDailyLogFile(logger, config)
		go dailyLogRotation(logger, config)
	} else {
		// 파일 출력 없이 stdout만 사용
		logger.SetOutput(os.Stdout)
	}

	return logger
}

// setupDailyLogFile 일별 로그 파일 설정 (기존과 동일)
func setupDailyLogFile(logger *logrus.Logger, config LogConfig) {
	logMutex.Lock()
	defer logMutex.Unlock()

	now := time.Now()
	dateStr := now.Format("2006/01/02")
	currentDate = now.Format("2006-01-02")

	logDir := filepath.Join(config.BaseDir, dateStr)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.WithError(err).Error("Failed to create log directory")
		logger.SetOutput(os.Stdout)
		return
	}

	if logFile != nil {
		logFile.Close()
	}

	logPath := filepath.Join(logDir, "app.log")
	lumber := &lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}

	logFile = lumber
	multiWriter := io.MultiWriter(lumber, os.Stdout)
	logger.SetOutput(multiWriter)

	logger.WithFields(logrus.Fields{
		"log_path": logPath,
		"date":     currentDate,
	}).Info("Log file rotated")
}

// dailyLogRotation 매일 로그 로테이션 (기존과 동일)
func dailyLogRotation(logger *logrus.Logger, config LogConfig) {
	for {
		now := time.Now()
		tomorrow := now.AddDate(0, 0, 1)
		midnight := time.Date(tomorrow.Year(), tomorrow.Month(), tomorrow.Day(), 0, 0, 0, 0, now.Location())
		time.Sleep(time.Until(midnight))
		setupDailyLogFile(logger, config)
	}
}

// LoggingMiddleware Echo 미들웨어 (개선된 버전)
func LoggingMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		start := time.Now()
		req := c.Request()
		res := c.Response()
		log := GetLogger()

		requestID := generateRequestID()
		c.Set("request_id", requestID)

		// 요청 로그
		log.WithFields(logrus.Fields{
			"request_id":     requestID,
			"method":         req.Method,
			"path":           req.URL.Path,
			"query":          req.URL.RawQuery,
			"remote_addr":    req.RemoteAddr,
			"user_agent":     req.UserAgent(),
			"content_length": req.ContentLength,
		}).Info("Request started")

		err := next(c)
		duration := time.Since(start)

		// 응답 로그
		logFields := logrus.Fields{
			"request_id":  requestID,
			"method":      req.Method,
			"path":        req.URL.Path,
			"status":      res.Status,
			"duration_ms": duration.Milliseconds(),
			"duration_ns": duration.Nanoseconds(),
			"size":        res.Size,
		}

		switch {
		case res.Status >= 500:
			log.WithFields(logFields).Error("Request completed")
		case res.Status >= 400:
			log.WithFields(logFields).Warn("Request completed")
		default:
			log.WithFields(logFields).Info("Request completed")
		}

		if err != nil {
			log.WithFields(logrus.Fields{
				"request_id": requestID,
				"error":      err.Error(),
			}).Error("Request error occurred")
		}

		return err
	}
}

// generateRequestID 간단한 요청 ID 생성
func generateRequestID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// RequestLogger 요청별 로거 반환
func RequestLogger(c echo.Context) *logrus.Entry {
	log := GetLogger()
	requestID, exists := c.Get("request_id").(string)
	if !exists {
		requestID = "unknown"
	}

	return log.WithFields(logrus.Fields{
		"request_id": requestID,
		"method":     c.Request().Method,
		"path":       c.Request().URL.Path,
	})
}

func InitGlobalLogger() {
	// 기존 GetLogger() 사용
	appLogger := GetLogger()

	// 전역 logrus를 같은 설정으로 맞춤
	logrus.SetFormatter(appLogger.Formatter)
	logrus.SetOutput(appLogger.Out)
	logrus.SetLevel(appLogger.Level)

	fmt.Printf("✅ Global logger initialized\n")
}
