package sage4j

import (
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
	"os"
	"path/filepath"
	"strings"
)

var ConfigUseCommandInjectionOldValidator = false

func cleanLastExecutionResult(taskId, sessionId string) {
	taskType := cache.GetInterDataCache().GetFeeder(taskId).TaskType
	switch taskType {
	case entity.VULN_TYPE_COMMAND_INJECTION:
		flagFilePath := filepath.Join(GetJavaEnvDir(taskId, sessionId), "flag")
		if _, err := os.Stat(flagFilePath); err == nil {
			os.Remove(flagFilePath)
		}
	case entity.VULN_TYPE_STACK_OVER_FLOW_ERROR:

		executionPath := GetJavaEnvDir(taskId, sessionId)
		hsErrPattern := "hs_err_pid*.log"
		files, _ := filepath.Glob(filepath.Join(executionPath, hsErrPattern))
		for _, file := range files {
			os.Remove(file)
		}
	}
}

func validateJavaResult(taskId, sessionId, log string) (string, bool) {
	taskType := cache.GetInterDataCache().GetFeeder(taskId).TaskType

	switch taskType {
	case entity.VULN_TYPE_COMMAND_INJECTION:
		return validateCommandExecutionResult(taskId, sessionId)
	case entity.VULN_TYPE_JNDI:
		return validateJNDICommandExecutionResult(taskId, sessionId)
	case entity.VULN_TYPE_STACK_OVER_FLOW_ERROR:
		return validateStackOverflowResult(taskId, sessionId, log)
	case entity.VULN_TYPE_STRING_INDEX_OUT_OF_BOUNDS_EXCEPTION:
		return validateStringIndexOutOfBoundsExceptionResult(taskId, sessionId, log)
	case entity.VULN_TYPE_NUMBER_FORMAT_EXCEPTION:
		return validateNumberFormatExceptionResult(taskId, sessionId, log)
	case entity.VULN_TYPE_URL_REDIRECT:
		return validateURLRedirectResult(taskId, sessionId, log)
	}
	logger.Infof("taskType: %s is not supported", taskType)
	return "", false
}

func validateURLRedirectResult(taskId, sessionId, log string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortJNDI) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke attach urlRedirect vulnerability, please regenerate your script.", false
	}
}

func validateJNDICommandExecutionResult(taskId, sessionId string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortJNDI) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke attach jndi vulnerability, please regenerate your script.", false
	}
}

func validateCommandExecutionResult(taskId, sessionId string) (string, bool) {
	if ConfigUseCommandInjectionOldValidator {
		flagFilePath := filepath.Join(GetJavaEnvDir(taskId, sessionId), "flag")
		if _, err := os.Stat(flagFilePath); err == nil {
			return entity.SuccessMessage, true
		} else {
			return "the result didn't invoke system command, please regenerate your script.", false
		}
	} else {
		if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortCommandInjection) {
			return entity.SuccessMessage, true
		} else {
			return "the result didn't invoke system command, please regenerate your script.", false
		}
	}
}

func validateNumberFormatExceptionResult(taskId, sessionId, log string) (string, bool) {
	if strings.Contains(log, "Trigger NumberFormatException") {
		return entity.SuccessMessage, true
	}
	return "the result didn't trigger NumberFormatException vulnerability, please regenerate your script.", false
}

func validateStringIndexOutOfBoundsExceptionResult(taskId, sessionId, log string) (string, bool) {
	if strings.Contains(log, "Trigger StringIndexOutOfBoundsException") {
		return entity.SuccessMessage, true
	}
	return "the result didn't trigger StringIndexOutOfBoundsException vulnerability, please regenerate your script.", false
}

func validateStackOverflowResult(taskId, sessionId, log string) (string, bool) {
	logger.Infof("validateStackOverflowResult log: %s", log)
	if strings.Contains(log, "Trigger StackOverflowError") {
		return entity.SuccessMessage, true
	}
	executionPath := GetJavaEnvDir(taskId, sessionId)
	hsErrPattern := "hs_err_pid*.log"
	files, _ := filepath.Glob(filepath.Join(executionPath, hsErrPattern))
	if len(files) > 0 {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't trigger stack overflow vulnerability, please regenerate your script.", false
	}
}
