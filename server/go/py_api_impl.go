package openapi

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/sage4py"
	"github.com/vulnsage/vulnsage/go/sage4py/model"
)

func (api *DefaultAPI) InstallPythonModule(c *gin.Context) {
	var param model.InstallPythonModuleRequest
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
	if flag, err := sage4py.IsPyEnvInit(param.TaskId, param.SessionId); flag == false && err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "python env not init " + err.Error()})
		return
	}
	pyEnvDir := sage4py.GetPyEnvDir(param.TaskId, param.SessionId)
	if err := sage4py.InstallPypiDependency(pyEnvDir, param.ModuleName); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "install pypi dependency failed " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "install pypi dependency success"})
	return
}

func (api *DefaultAPI) InitPythonEnvironment(c *gin.Context) {
	var param model.InitPythonEnvironmentRequest
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
	}
	if err := sage4py.InitPyEnv(param.TaskId, param.SessionId); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "Python env init success"})
}

func (api *DefaultAPI) ExecutePythonCode(c *gin.Context) {
	var param model.ExecutePythonCodeRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
		return
	}
	if param.TaskId == "" || param.Code == "" || param.SessionId == "" {
		c.JSON(http.StatusOK, joinResult(param.Code, "taskId or code or sessionId is empty"))
		return
	}
	if flag, err := sage4py.IsPyEnvInit(param.TaskId, param.SessionId); flag == false && err != nil {
		c.JSON(http.StatusOK, joinResult(param.Code, "python env not init "+err.Error()))
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

	filePath := filepath.Join(sage4py.GetPyEnvDir(param.TaskId, param.SessionId), "tmp.py")
	if err := os.WriteFile(filePath, []byte(param.Code), 0644); err != nil {
		c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
		return
	}

	result, _ := sage4py.ExecutePythonScript("tmp.py", param.TaskId, param.SessionId)
	c.JSON(http.StatusOK, joinResult(param.Code, result))
	return
}
