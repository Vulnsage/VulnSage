package logcenter

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/sirupsen/logrus"
)

var GlobalNoColorOutput = false

type StcgoFormatter struct {
	logrus.TextFormatter
	disableColors bool
	stepTag       string
	loggerName    string
}

const (
	Green  = "\033[32m"
	White  = "\033[38m"
	Yellow = "\033[33m"
	Red    = "\033[31m"
	BgRed  = "\033[41m\033[37m"
	Tail   = "\033[0m"
)

func (f *StcgoFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var levelColorHeader string
	var levelColorTail string
	if !f.disableColors {
		switch entry.Level {
		case logrus.DebugLevel:
			levelColorHeader = Green
		case logrus.InfoLevel:
			levelColorHeader = White
		case logrus.WarnLevel:
			levelColorHeader = Yellow
		case logrus.ErrorLevel:
			levelColorHeader = Red
		case logrus.FatalLevel, logrus.PanicLevel:
			levelColorHeader = BgRed
		default:
			levelColorHeader = White
		}
		levelColorTail = Tail
	}

	timestamp := entry.Time.Format("2006-01-02 15:04:05.000")
	var logBuilder strings.Builder
	for i, line := range strings.Split(entry.Message, "\n") {
		if i == 0 {
			logBuilder.WriteString(fmt.Sprintf("%s%s %s %s --- [%s] %s%s", levelColorHeader, timestamp, strings.ToUpper(entry.Level.String()), f.stepTag, f.loggerName, line, levelColorTail))
		} else {
			logBuilder.WriteString(fmt.Sprintf("%s%s%s", levelColorHeader, line, levelColorTail))
		}
		logBuilder.WriteString("\n")
	}
	return []byte(logBuilder.String()), nil
}

func NewLogger(loggerName string) *logrus.Logger {
	logger := logrus.New()

	formatter := &StcgoFormatter{
		disableColors: GlobalNoColorOutput,
		stepTag:       "cp",
		loggerName:    loggerName,
	}

	logger.SetFormatter(formatter)
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.DebugLevel)
	return logger
}

func NewNoColorLogger(loggerName string) *logrus.Logger {
	logger := logrus.New()

	formatter := &StcgoFormatter{
		disableColors: true,
		stepTag:       "cp",
		loggerName:    loggerName,
	}

	logger.SetFormatter(formatter)
	logger.SetOutput(os.Stdout)
	if GlobalNoColorOutput == false {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}
	return logger
}

func NewLoggerWithStepTag(loggerName string, scriptId string) *logrus.Logger {
	logger := logrus.New()

	formatter := &StcgoFormatter{
		disableColors: GlobalNoColorOutput,
		stepTag:       "c-" + scriptId,
		loggerName:    loggerName,
	}

	logger.SetFormatter(formatter)
	logger.SetOutput(os.Stdout)

	return logger
}

func NewProcessBar(count int) *pb.ProgressBar {
	bar := pb.StartNew(count)
	logger := NewLogger("pb")
	bar.SetWriter(logger.Writer())
	bar.SetRefreshRate(time.Hour * 24)
	return bar
}
