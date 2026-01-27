package sage4js

import (
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
	"strings"
)

func validateProtoTypePollutionResult(taskId, sessionId, log string) (string, bool) {
	if strings.Contains(log, "[POLLUTION_TRIGGERED]") || strings.Contains(log, "[DELETE_TRIGGERED]") {
		return entity.SuccessMessage, true
	} else {
		message := ""
		message += "the result didn't affect Object.prototype, please regenerate your script. \n"
		message += "Note1: you must use `console.log(({} as any).<propName> !== undefined ? '[POLLUTION_TRIGGERED]':'')` or `console.log(({} as any).toString ? '':'[DELETE_TRIGGERED]')`to verify the script. \n"
		message += "Note2: direct assignments to Object.prototype is not allowed.\n"
		message += "Note3: For the other arguments, you can specify their type without being restricted by the original function logic. example: making `arr` as an object instead of an array."
		return message, false
	}
}

func validateCodeInjectionResult(taskId, sessionId, log string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortCommandInjection) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke system command, please regenerate your script.", false
	}
}

func validateCommandExecutionResult(taskId, sessionId string) (string, bool) {
	if cache.GetInterDataCache().HasMessage(entity.MessageQueuePortCommandInjection) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't invoke system command, please regenerate your script.", false
	}
}

func validatePathTraversalResult(taskId, sessionId, log string) (string, bool) {
	if strings.Contains(log, entity.SuccessMessage) {
		return entity.SuccessMessage, true
	} else {
		return "the result didn't read the flag, please regenerate your script.", false
	}
}

func validateJsResult(taskId string, sessionId, log string) (string, bool) {
	taskType := cache.GetInterDataCache().GetFeeder(taskId).TaskType
	switch taskType {
	case entity.VULN_TYPE_COMMAND_INJECTION:
		return validateCommandExecutionResult(taskId, sessionId)
	case entity.VULN_TYPE_PROTOTYPE_POLLUTION:
		return validateProtoTypePollutionResult(taskId, sessionId, log)
	case entity.VULN_TYPE_CODE_INJECTION:
		return validateCodeInjectionResult(taskId, sessionId, log)
	case entity.VULN_TYPE_PATH_TRAVERSAL:
		return validatePathTraversalResult(taskId, sessionId, log)
	}
	logger.Infof("taskType: %s is not supported", taskType)
	return "", false
}
