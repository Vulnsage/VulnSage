package sage4js

import (
	"bytes"
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/sage4js/model"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var JsTempFileName = "tmp.ts"

func ExecuteJsCodeFile(filePath, taskId string, sessionId string) (string, bool) {
	tsNodeCmd := filepath.Join("node_modules", ".bin", "ts-node")

	fullFilePath := filepath.Join(GetJsEnvDir(taskId, sessionId), filePath)
	originalData, _ := os.ReadFile(fullFilePath)
	injectedContent := []byte("require('./hooker-sage4js');\n")
	newContent := append(injectedContent, originalData...)
	_ = os.Remove(fullFilePath)
	_ = os.WriteFile(fullFilePath, newContent, 0644)
	fmt.Printf("[Injected] require('./hooker-sage4js') into %s\n", fullFilePath)

	cmd := exec.Command("timeout", model.ScriptExecutionTimeoutString, tsNodeCmd, filePath)
	cmd.Dir = GetJsEnvDir(taskId, sessionId)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	currentTime := time.Now()
	cmd.Run()
	execTime := time.Since(currentTime)
	validateMessage, ok := validateJsResult(taskId, sessionId, out.String())
	if ok {
		return entity.SuccessMessage, true
	}

	errStr := ""
	outStr := out.String()

	if len(stderr.String()) > 0 {
		errorMsg := stderr.String()
		cleanedError := cleanJsErrorMsg(errorMsg)
		if len(cleanedError) > 0 {
			errStr = stderr.String()
		} else {
			errStr = errorMsg
		}
	}

	message := fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", outStr, errStr)
	message += validateMessage
	if execTime.Seconds() > (model.ScriptExecutionTimeout - 1) {
		message += "execution timeout over " + model.ScriptExecutionTimeoutString + " , please recheck your code."
	}

	return message, true
}

func ExecuteJsCodeFileNoTrace(filePath, taskId string, sessionId string) (string, bool) {
	tsNodeCmd := filepath.Join("node_modules", ".bin", "ts-node")
	fullFilePath := filepath.Join(GetJsEnvDir(taskId, sessionId), filePath)
	originalData, _ := os.ReadFile(fullFilePath)
	injectedContent := []byte("require('./hooker-sage4js-notrace');\n")
	newContent := append(injectedContent, originalData...)
	_ = os.Remove(fullFilePath)
	_ = os.WriteFile(fullFilePath, newContent, 0644)
	fmt.Printf("[Injected] require('./hooker-sage4js-notrace') into %s\n", fullFilePath)

	cmd := exec.Command("timeout", model.ScriptExecutionTimeoutString, tsNodeCmd, filePath)
	cmd.Dir = GetJsEnvDir(taskId, sessionId)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	currentTime := time.Now()
	cmd.Run()
	execTime := time.Since(currentTime)
	validateMessage, ok := validateJsResult(taskId, sessionId, out.String())
	if ok {
		return entity.SuccessMessage, true
	}

	errStr := ""
	outStr := out.String()

	if len(stderr.String()) > 0 {
		errorMsg := stderr.String()
		cleanedError := cleanJsErrorMsg(errorMsg)
		if len(cleanedError) > 0 {
			errStr = stderr.String()
		} else {
			errStr = errorMsg
		}
	}

	message := fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", outStr, errStr)
	message += validateMessage
	if execTime.Seconds() > (model.ScriptExecutionTimeout - 1) {
		message += "execution timeout over " + model.ScriptExecutionTimeoutString + " , please recheck your code."
	}

	return message, true
}

func cleanJsErrorMsg(errorMsg string) string {
	stack := strings.Split(errorMsg, "\n")
	var result []string
	for idx, content := range stack {
		contentTrimmed := strings.TrimSpace(content)
		if strings.HasPrefix(contentTrimmed, JsTempFileName) || strings.HasPrefix(contentTrimmed, "Error:") ||
			strings.HasPrefix(contentTrimmed, "An error occurred:") || strings.HasPrefix(contentTrimmed, "TypeError:") ||
			strings.Contains(contentTrimmed, "Unable to compile TypeScript") {
			startIdx := idx - 3
			endIdx := idx + 2
			if startIdx < 0 {
				startIdx = 0
			}
			if endIdx >= len(stack) {
				endIdx = len(stack) - 1
			}
			for i := startIdx; i <= endIdx; i++ {
				result = append(result, stack[i])
			}
			break
		}
	}
	if len(result) == 0 {
		return ""
	} else {
		return strings.Join(result, "\n")
	}
}
