package sage4py

import (
	"bytes"
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func ExecutePythonScript(filePath, taskId string, sessionId string) (string, bool) {
	pyEnvDir := GetPyEnvDir(taskId, sessionId)
	fullFilePath := filepath.Join(pyEnvDir, filePath)

	originalData, err := os.ReadFile(fullFilePath)
	if err != nil {
		return fmt.Sprintf("failed to read script file: %v", err), false
	}

	injectedContent := []byte("from hooker_sage4py import install_comprehensive_hook\ninstall_comprehensive_hook()\n")
	newContent := append(injectedContent, originalData...)

	err = os.WriteFile(fullFilePath, newContent, 0644)
	if err != nil {
		return fmt.Sprintf("failed to write injected script: %v", err), false
	}

	fmt.Printf("[Injected] import tracer into %s\n", fullFilePath)

	pyCmd := filepath.Join(pyEnvDir, "venv", "bin", "python")
	if _, err := os.Stat(pyCmd); err != nil {
		return fmt.Sprintf("python executable not found at %s", pyCmd), false
	}

	cmd := exec.Command("timeout", "10s", pyCmd, filePath)
	cmd.Dir = pyEnvDir

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	currentTime := time.Now()
	err = cmd.Run()
	execTime := time.Since(currentTime)
	validateMessage, ok := validatePyResult(taskId, sessionId, out.String())
	if ok {
		return entity.SuccessMessage, true
	}

	errStr := ""
	outStr := out.String()

	if len(stderr.String()) > 0 {
		errorMsg := stderr.String()
		cleanedError := cleanPyErrorMsg(errorMsg)
		if len(cleanedError) > 0 {
			errStr = stderr.String()
		} else {
			errStr = errorMsg
		}
	}

	message := fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", outStr, errStr)
	message += validateMessage
	if execTime.Seconds() > 9 {
		message += "execution timeout over 10s , please recheck your code."
	}
	return message, true
}

func cleanPyErrorMsg(errorMsg string) string {
	return errorMsg
}
