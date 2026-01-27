package openapi

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/common/model"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/logcenter"
	"github.com/vulnsage/vulnsage/go/sage4j"
	"github.com/vulnsage/vulnsage/go/sage4js"
	"github.com/vulnsage/vulnsage/go/sage4py"
)

type DefaultAPI struct{}

var logger = logcenter.NewLogger("server")

func checkVulnSageEnv() error {
	if result, ok := os.LookupEnv(entity.VulnSageRootPath); !ok {
		return fmt.Errorf("VulnSageRootPath not set")
	} else {
		logger.Infof("Confirm VulnSageBackend Setting: VulnSageRootPath=%s", result)
	}
	if result, ok := os.LookupEnv(entity.VulnSageLibTracePath); !ok {
		return fmt.Errorf("VulnSageLibTracePath not set")
	} else {
		logger.Infof("Confirm VulnSageBackend Setting: VulnSageLibTracePath=%s", result)
	}
	if result, ok := os.LookupEnv(entity.VulnSageFernflowerPath); !ok {
		return fmt.Errorf("VulnSageFernflowerPath not set")
	} else {
		logger.Infof("Confirm VulnSageBackend Setting: VulnSageFernflowerPath=%s", result)
	}
	if result, ok := os.LookupEnv(entity.VulnSageLocalResourcePath); !ok {
		return fmt.Errorf("VulnSageLocalResourcePath not set")
	} else {
		logger.Infof("Confirm VulnSageLocalResourcePath Setting: VulnSageLocalResourcePath=%s", result)
	}
	return nil
}

func init() {
	if err := checkVulnSageEnv(); err != nil {
		logger.Error(err)
	}
}

func (api *DefaultAPI) ViewAllScanFeederId(c *gin.Context) {

	var scanFeederIds = make([]string, 0)
	for key := range cache.GetInterDataCache().Feeder() {
		scanFeederIds = append(scanFeederIds, key)
	}
	c.JSON(http.StatusOK, scanFeederIds)
	return
}

func (api *DefaultAPI) DeleteWorkEnv(c *gin.Context) {
	var param model.DeleteWorkEnvironmentRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusNotFound, "error parsing json")
		return
	}
	if obj := cache.GetInterDataCache().GetFeeder(param.TaskId); obj == nil {
		c.JSON(http.StatusNotFound, "taskId not found")
	}
	if sage4js.IsJsEnvDirExists(param.TaskId, param.SessionId) {
		os.RemoveAll(sage4js.GetJsEnvDir(param.TaskId, param.SessionId))
	}
	if sage4j.IsJavaEnvDirExists(param.TaskId, param.SessionId) {
		os.RemoveAll(sage4j.GetJavaEnvDir(param.TaskId, param.SessionId))
	}
	if sage4py.IsPyEnvDirExists(param.TaskId, param.SessionId) {
		os.RemoveAll(sage4py.GetPyEnvDir(param.TaskId, param.SessionId))
	}
	c.JSON(http.StatusOK, "success")
}

func (api *DefaultAPI) ViewScanFeederWithId(c *gin.Context) {
	var param model.ViewScanFeederWithIdRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusNotFound, "error parsing json")
		return
	}
	if obj, ok := cache.GetInterDataCache().Feeder()[param.TaskId]; ok {
		c.JSON(http.StatusOK, obj)
		return
	} else {
		c.JSON(http.StatusNotFound, "taskId not found")
	}
}

func (api *DefaultAPI) UploadScanFeeder(c *gin.Context) {

	var param model.UploadScanFeederRequest
	if err := c.BindJSON(&param); err != nil {
		c.JSON(http.StatusNotFound, "error parsing json")
		return
	}
	updatedTaskIds := make([]string, 0)
	addedTaskIds := make([]string, 0)
	for _, traceInfo := range param.ScanFeeder {
		if cache.GetInterDataCache().Feeder()[traceInfo.TaskId] != nil {
			updatedTaskIds = append(updatedTaskIds, traceInfo.TaskId)
		} else {
			addedTaskIds = append(addedTaskIds, traceInfo.TaskId)
		}
		cache.GetInterDataCache().AddFeeders(traceInfo)
	}
	var result = model.UploadScanFeederResponse{AddedTaskIds: addedTaskIds, UpdatedTaskIds: updatedTaskIds}
	c.JSON(http.StatusOK, result)
}

func (api *DefaultAPI) CheckHeartBeat(c *gin.Context) {
	c.JSON(http.StatusOK, "success")
}

func joinResult(script string, result string) model.ExecuteCodeResponse {
	return model.ExecuteCodeResponse{
		Result: model.ExecuteCodeResponseResult{
			LastReason: result,
			LastScript: script,
		},
	}
}
