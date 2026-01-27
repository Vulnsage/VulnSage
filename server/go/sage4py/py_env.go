package sage4py

import (
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/logcenter"
	"github.com/vulnsage/vulnsage/go/staticdata"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

var pythonVenvDirName = "venv"

var logger = logcenter.NewLogger("sage4py")

func GetPyEnvDir(taskId string, sessionId string) string {
	if _, err := os.Stat(path.Join(os.Getenv(entity.VulnSageRootPath), "env")); err != nil {
		os.Mkdir(path.Join(os.Getenv(entity.VulnSageRootPath), "env"), 0755)
	}
	return path.Join(os.Getenv(entity.VulnSageRootPath), "env", "py-env-"+taskId+"-"+sessionId)
}

func CleanAllPyEnvDir() error {
	var envDir = path.Join(os.Getenv(entity.VulnSageRootPath), "env")
	if _, err := os.Stat(envDir); err == nil {
		err := os.RemoveAll(envDir)
		if err != nil {
			return err
		}
	}
	return nil
}

func IsPyEnvInit(taskId string, sessionId string) (bool, error) {
	var jsEnvDir = GetPyEnvDir(taskId, sessionId)
	if _, err := os.Stat(jsEnvDir); err == nil {
		return true, nil
	} else {
		return false, fmt.Errorf("python env is not initialized")
	}
}

func IsPyEnvDirExists(taskId string, sessionId string) bool {
	var tsEnvDir = GetPyEnvDir(taskId, sessionId)
	if _, err := os.Stat(tsEnvDir); err == nil {
		return true
	}
	return false
}

func InitPyEnv(taskId string, sessionId string) error {
	var pyEnvDir = GetPyEnvDir(taskId, sessionId)

	if _, err := os.Stat(pyEnvDir); err == nil {
		if err := os.RemoveAll(pyEnvDir); err != nil {
			logger.Error("failed to remove existing env dir", "path", pyEnvDir, "error", err)
			return fmt.Errorf("failed to clean existing env: %w", err)
		}
	}

	if err := os.MkdirAll(pyEnvDir, os.ModePerm); err != nil {
		logger.Error("failed to create env dir", "path", pyEnvDir, "error", err)
		return fmt.Errorf("failed to create env directory: %w", err)
	}

	cmd := exec.Command("uv", "venv",
		"--python", "python3",
		pythonVenvDirName,
	)
	cmd.Dir = pyEnvDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("uv venv creation failed",
			"command", cmd.String(),
			"output", string(output),
			"error", err)
		return fmt.Errorf("uv venv creation failed: %v. Output: %s", err, string(output))
	}

	hookExecPath := filepath.Join(pyEnvDir, "hooker_sage4py.py")
	hookerExec, _ := staticdata.Asset("go/staticdata/hooker_sage4py.py")
	err = os.WriteFile(hookExecPath, hookerExec, 0644)

	logger.Info("successfully created uv virtualenv",
		"task_id", taskId,
		"session_id", sessionId,
		"path", path.Join(pyEnvDir, pythonVenvDirName))
	return nil
}
