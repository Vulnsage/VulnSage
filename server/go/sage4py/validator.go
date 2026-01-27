package sage4py

import (
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
)

func validatePyResult(taskId string, sessionId, log string) (string, bool) {
	taskType := cache.GetInterDataCache().GetFeeder(taskId).TaskType
	switch taskType {
	case entity.VULN_TYPE_COMMAND_INJECTION:
		return validateCommandExecutionResult(taskId, sessionId)
	case entity.VULN_TYPE_PICKLE_INJECTION:
		return validatePickleInjectionResult(taskId, sessionId, log)
	}
	logger.Infof("taskType: %s is not supported", taskType)
	return "", false
}

func validateCommandExecutionResult(taskId, sessionId string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortCommandInjection) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke system command, please regenerate your script.", false
	}
}

func validatePickleInjectionResult(taskId, sessionId, log string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortCommandInjection) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke system command, please regenerate your script.", false
	}
}
