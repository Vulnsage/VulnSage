package sage4j

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/sage4j/model"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

func ExecuteJavaProjectJunitMode(taskId, sessionId string) (string, bool) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	var libtracePath string
	var isFound bool

	if libtracePath, isFound = os.LookupEnv(entity.VulnSageLibTracePath); !isFound {
		return "Could not find libtrace library in system environment", false
	}
	if _, err := os.Stat(libtracePath); err != nil {
		return "Could not find agent library " + libtracePath + " in absolute path", false
	}
	//argLine := "-agentpath:" + libtracePath + "=\\\"-packages=*\\\""

	cleanLastExecutionResult(taskId, sessionId)
	currentTime := time.Now()
	cmd := exec.Command("timeout", model.ScriptExecutionTimeoutString, "mvn", "test", "-Dtest=org.example.App" /*"-DargLine=\""+argLine+"\""*/)
	cmd.Dir = GetJavaEnvDir(taskId, sessionId)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Run()
	execTime := time.Since(currentTime)

	errStr := ""
	outStr := stdout.String()
	lines := strings.Split(outStr, "\n")
	var filteredLines []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "[INFO] ") {
			filteredLines = append(filteredLines, line)
		}
	}
	outStr = strings.Join(filteredLines, "\n")
	if len(stderr.String()) > 0 {
		errorMsg := stderr.String()
		cleanedError := make([]string, 0)
		if len(cleanedError) > 0 {
			errStr = stderr.String()
		} else {
			errStr = errorMsg
		}
	}
	if len(outStr) > 500 {
		outStr = outStr[len(outStr)-500:]
	}
	outErrStr := fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s\n", outStr, errStr)
	message := fmt.Sprintf("%sEXECUTION_TRACE:\n%s\n", outErrStr, generateExecutionTrace(taskId, sessionId))
	if execTime.Seconds() > (model.ScriptExecutionTimeout - 1.00) {
		message += "execution timeout over " + model.ScriptExecutionTimeoutString + " , please recheck your code."
	}
	if _errorHint, ok := validateJavaResult(taskId, sessionId, outErrStr); ok {
		message += entity.SuccessMessage
		return message, true
	} else {
		message += _errorHint
		return message, true
	}
}

func ExecuteJavaProject(taskId, sessionId string) (string, bool) {
	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("timeout", model.ScriptExecutionTimeoutString, "mvn", "clean", "compile", "package", "-DskipTests")
	cmd.Dir = GetJavaEnvDir(taskId, sessionId)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	message := fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", out.String(), stderr.String())
	if err != nil {
		if strings.Contains(message, "COMPILATION ERROR") {
			return extractMessageWithErrorTag(message), true
		}
		return message, false
	}
	var libtracePath string
	var isFound bool

	if libtracePath, isFound = os.LookupEnv(entity.VulnSageLibTracePath); !isFound {
		return "Could not find libtrace library in system environment", false
	}
	if _, err := os.Stat(libtracePath); err != nil {
		return "Could not find agent library " + libtracePath + " in absolute path", false
	}

	cleanLastExecutionResult(taskId, sessionId)

	cmd = exec.Command("timeout", model.ScriptExecutionTimeoutString, "java", "-jar", "-agentpath:"+libtracePath+"=\"-packages=*\"", "target/app-1.0-SNAPSHOT-jar-with-dependencies.jar")
	cmd.Dir = GetJavaEnvDir(taskId, sessionId)
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	cmd.Run()

	errStr := ""
	outStr := out.String()
	lines := strings.Split(outStr, "\n")
	var filteredLines []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "[INFO] ") {
			filteredLines = append(filteredLines, line)
		}
	}
	outStr = strings.Join(filteredLines, "\n")
	if len(stderr.String()) > 0 {
		errorMsg := stderr.String()
		cleanedError := make([]string, 0)
		if len(cleanedError) > 0 {
			errStr = stderr.String()
		} else {
			errStr = errorMsg
		}
	}
	if len(outStr) > 500 {
		outStr = outStr[len(outStr)-500:]
	}
	message = fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s\nEXECUTION_TRACE:\n%s\n", outStr, errStr, generateExecutionTrace(taskId, sessionId))
	if _errorHint, ok := validateJavaResult(taskId, sessionId, ""); ok {
		message += entity.SuccessMessage
		return message, true
	} else {
		message += _errorHint
		return message, true
	}
}

func generateExecutionTrace(taskId, sessionId string) string {

	traceInfoFile := path.Join(GetJavaEnvDir(taskId, sessionId), "trace.json")
	if _, err := os.Stat(traceInfoFile); err != nil {
		logger.Errorf("traceInfoFile not exists")
		return ""
	}

	var traceInfoList []*entity.JNIAgentTrace
	jsonContent, _ := os.ReadFile(traceInfoFile)
	if err := json.Unmarshal(jsonContent, &traceInfoList); err != nil {
		logger.Errorf("json.Unmarshal error: %v", err)
		return ""
	}

	if err := ParseJNIAgentTrace([]string{
		path.Join(GetJavaEnvDir(taskId, sessionId), "src", "main", "java"),
	}, traceInfoList, entity.JavaDependencyClassifierSources,
	); err != nil {
		return ""
	}
	if err := ParseJNIAgentTrace(
		[]string{
			GetDecompileEnvDir(cache.GetInterDataCache().GetFeeder(taskId).PackageName),
		},
		traceInfoList,
		cache.GetInterDataCache().GetJavaIdentifierClassifier(cache.GetInterDataCache().GetFeeder(taskId).PackageName),
	); err != nil {
		return ""
	}

	sb := ""
	for _, traceInfo := range traceInfoList {
		sb += traceInfo.String()
	}
	return sb
}

func extractMessageWithErrorTag(buffer string) string {
	result := ""
	for _, line := range strings.Split(buffer, "\n") {
		if strings.HasPrefix(line, "[ERROR]") {
			result += line + "\n"
		}
	}
	return result
}
