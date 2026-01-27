package openapi

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/sage4j"
	"github.com/vulnsage/vulnsage/go/sage4j/model"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func (api *DefaultAPI) ExecuteJavaCode(c *gin.Context) {
	var param model.ExecuteJavaCodeRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
		return
	}
	if param.TaskId == "" || param.Code == "" || param.SessionId == "" {
		c.JSON(http.StatusOK, joinResult(param.Code, "taskId or code or sessionId is empty"))
		return
	}
	if ok := sage4j.IsJavaEnvDirExists(param.TaskId, param.SessionId); !ok {
		c.JSON(http.StatusOK, joinResult(param.Code, "java env not init, please install module first"))
		return
	}

	traceInfo := cache.GetInterDataCache().GetFeeder(param.TaskId)
	if traceInfo == nil {
		c.JSON(http.StatusOK,
			joinResult(param.Code, fmt.Sprintf("the given taskId %s is not found, please recheck the taskId given in task description.", param.TaskId)),
		)
		return
	}

	var extraCodeCheckList []string
	var targetFileRelativePath string
	if traceInfo.ExecutionMode == "junit" {
		extraCodeCheckList = []string{"package org.example;", "public class App", "public void test"}
		targetFileRelativePath = path.Join("src", "test", "java", "org", "example", "App.java")
	} else {
		extraCodeCheckList = []string{"package org.example;", "public class App", "public static void main"}
		targetFileRelativePath = path.Join("src", "main", "java", "org", "example", "App.java")
	}

	extraCodeCheckList = append(extraCodeCheckList, traceInfo.CodeCheckList...)
	for _, codeCheck := range extraCodeCheckList {
		codeCheckClean := cleanCheckCode(codeCheck)
		paramCodeClean := cleanCheckCode(param.Code)
		if !strings.Contains(paramCodeClean, codeCheckClean) {
			c.JSON(http.StatusOK,
				joinResult(param.Code, fmt.Sprintf("the code didn't follow given template, missing %s, please check the code.", codeCheck)),
			)
			return
		}
	}

	filePath := filepath.Join(sage4j.GetJavaEnvDir(param.TaskId, param.SessionId), targetFileRelativePath)
	if _, err := os.Stat(filePath); err == nil {
		err := os.Remove(filePath)
		if err != nil {
			c.JSON(http.StatusOK, joinResult(param.Code, err.Error()))
			return
		}
	}

	code := param.Code

	err := os.WriteFile(filePath, []byte(param.Code), 0644)
	if err != nil {
		c.JSON(http.StatusOK, joinResult(code, err.Error()))
		return
	}

	var result string
	if traceInfo.ExecutionMode == "junit" {
		result, _ = sage4j.ExecuteJavaProjectJunitMode(param.TaskId, param.SessionId)
	} else {
		result, _ = sage4j.ExecuteJavaProject(param.TaskId, param.SessionId)
	}
	c.JSON(http.StatusOK, joinResult(code, result))
	return
}

func (api *DefaultAPI) InitJavaEnvironment(c *gin.Context) {
	var param model.InitJavaEnvironmentRequest
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
		if err := sage4j.InitJavaEnvLocal(param.TaskId, param.SessionId); err != nil {
			c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		} else {
			c.JSON(http.StatusOK, gin.H{"result": "Java env with local resource init success"})
		}
		return
	}
	if err := sage4j.InitJavaEnv(param.TaskId, param.SessionId); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "Java env init success"})
}

func (api *DefaultAPI) InstallJavaPackage(c *gin.Context) {
	var param model.InstallJavaModuleRequest
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
	} else if obj.InstallModuleMode == "local" {
		logger.Infof("InstallJavaPackage local mode")
		c.JSON(http.StatusOK, gin.H{"result": "Package install success"})
		return
	}
	if flag, err := sage4j.IsJavaEnvInit(param.TaskId, param.SessionId); flag == false && err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "Java env not init " + err.Error()})
		return
	}
	javaEnvDir := sage4j.GetJavaEnvDir(param.TaskId, param.SessionId)
	parts := strings.Split(param.ModuleName, ":")
	dependency := entity.Dependency{
		GroupId:    parts[0],
		ArtifactId: parts[1],
		Version:    parts[2],
	}
	if err := sage4j.AddMavenDependency(javaEnvDir, dependency); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "AddMavenDependency error " + err.Error()})
		return
	}

	if err := sage4j.InstallMavenDependency(javaEnvDir, dependency); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "InstallMavenDependency error " + err.Error()})
		return
	}

	if err := sage4j.RecordDependency(javaEnvDir, dependency); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "RecordDependency " + err.Error()})
		return
	}
	if err := sage4j.DecompileJar(param.ModuleName, cache.GetInterDataCache().GetJavaIdentifierToRealLocation(param.ModuleName)); err != nil {
		c.JSON(http.StatusOK, gin.H{"result": "DecompileJar " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "Package install success"})
	return
}
