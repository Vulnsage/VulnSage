package openapi

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/sage4js"
	"github.com/vulnsage/vulnsage/go/sage4js/model"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (api *DefaultAPI) InstallJsModule(c *gin.Context) {
	var param model.InstallJsModuleRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		return
	}
	if param.TaskId == "" || param.ModuleName == "" || param.SessionId == "" {
		c.JSON(http.StatusOK, gin.H{"result": "taskId or moduleName or sessionId is empty"})
		return
	}
	if obj := cache.GetInterDataCache().GetFeeder(param.TaskId); obj == nil {
		c.JSON(http.StatusOK, gin.H{"result": "The given taskId is not found, please recheck the taskId given in task description."})
		return
	}
	if flag, err := sage4js.IsJsEnvInit(param.TaskId, param.SessionId); flag == false && err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "js env not init " + err.Error()})
		return
	}
	tsEnvDir := sage4js.GetJsEnvDir(param.TaskId, param.SessionId)
	if err := sage4js.InstallNpmDependency(tsEnvDir, param.ModuleName); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "install js module success"})
	return
}

func cleanCheckCode(code string) string {
	code = strings.ReplaceAll(code, "\"", "'")
	code = strings.ReplaceAll(code, "\n", "")
	code = strings.ReplaceAll(code, "\r", "")
	code = strings.ReplaceAll(code, "\t", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
}

func (api *DefaultAPI) InitJsEnvironment(c *gin.Context) {
	var param model.InitJsEnvironmentRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		return
	}
	if param.TaskId == "" || param.SessionId == "" {
		c.JSON(http.StatusOK, gin.H{"result": "taskId or moduleName or sessionId is empty"})
		return
	}
	if obj := cache.GetInterDataCache().GetFeeder(param.TaskId); obj == nil {
		c.JSON(http.StatusOK, gin.H{"result": "The given taskId is not found, please recheck the taskId given in task description."})
		return
	} else if obj.InstallModuleMode == "local" {
		//if err := sage4js.InitJsEnvLocal(param.TaskId, param.SessionId); err != nil {
		//	c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		//} else {
		//	c.JSON(http.StatusOK, gin.H{"result": "js env with local resource init success"})
		//}
		//return
	}
	if err := sage4js.InitJsEnv(param.TaskId, param.SessionId); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		logger.Info("Js env init failed, %s", err.Error())
		return
	}
	logger.Info("Js env init success")
	c.JSON(http.StatusOK, gin.H{"result": "Js env init success"})
}

func (api *DefaultAPI) ExecuteJsCodeNoTrace(c *gin.Context) {
	executeJsCode(c, false)
}

func (api *DefaultAPI) ExecuteJsCode(c *gin.Context) {
	executeJsCode(c, true)
}

func executeJsCode(c *gin.Context, useTrace bool) {
	var param model.ExecuteJsCodeRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
		return
	}
	if param.TaskId == "" || param.Code == "" || param.SessionId == "" {
		c.JSON(http.StatusOK, joinResult(param.Code, "taskId or code or sessionId is empty"))
		return
	}
	if ok, _ := sage4js.IsJsEnvInit(param.TaskId, param.SessionId); !ok {
		c.JSON(http.StatusOK, joinResult(param.Code, "js env not init, please install module first"))
		return
	}
	traceInfo := cache.GetInterDataCache().GetFeeder(param.TaskId)
	if traceInfo == nil {
		c.JSON(http.StatusOK,
			joinResult(param.Code, fmt.Sprintf("the given taskId %s is not found, please recheck the taskId given in task description.", param.TaskId)),
		)
		return
	}

	for _, codeCheck := range traceInfo.CodeCheckList {
		codeCheckClean := cleanCheckCode(codeCheck)
		paramCodeClean := cleanCheckCode(param.Code)
		if !strings.Contains(paramCodeClean, codeCheckClean) {
			c.JSON(http.StatusOK,
				joinResult(param.Code, fmt.Sprintf("the code didn't follow given template, missing %s, please check the code.", codeCheck)),
			)
			return
		}
	}

	filePath := filepath.Join(sage4js.GetJsEnvDir(param.TaskId, param.SessionId), "tmp.ts")
	if _, err := os.Stat(filePath); err == nil {
		err := os.Remove(filePath)
		if err != nil {
			c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
			return
		}
	}

	code := strings.ReplaceAll(param.Code, "\\n", "")

	err := os.WriteFile(filePath, []byte(code), 0644)
	if err != nil {
		c.JSON(http.StatusOK, joinResult(code, err.Error()))
		return
	}
	result := ""
	if useTrace {
		result, _ = sage4js.ExecuteJsCodeFile("tmp.ts", param.TaskId, param.SessionId)
	} else {
		result, _ = sage4js.ExecuteJsCodeFileNoTrace("tmp.ts", param.TaskId, param.SessionId)
	}
	c.JSON(http.StatusOK, joinResult(code, result))
	return
}
