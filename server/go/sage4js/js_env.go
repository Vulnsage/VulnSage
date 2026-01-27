package sage4js

import (
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/staticdata"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

func GetJsEnvDir(taskId string, sessionId string) string {
	if _, err := os.Stat(path.Join(os.Getenv(entity.VulnSageRootPath), "env")); err != nil {
		os.Mkdir(path.Join(os.Getenv(entity.VulnSageRootPath), "env"), 0755)
	}
	return path.Join(os.Getenv(entity.VulnSageRootPath), "env", "js-env-"+taskId+"-"+sessionId)
}

func IsJsEnvInit(taskId string, sessionId string) (bool, error) {
	var jsEnvDir = GetJsEnvDir(taskId, sessionId)

	if _, err := os.Stat(jsEnvDir); err == nil {
		return true, nil
	} else {
		return false, fmt.Errorf("js env is not initialized")
	}
}

func IsJsEnvDirExists(taskId string, sessionId string) bool {
	var tsEnvDir = GetJsEnvDir(taskId, sessionId)
	if _, err := os.Stat(tsEnvDir); err == nil {
		return true
	}
	return false
}

func InitJsEnv(taskId string, sessionId string) error {
	var tsEnvDir = GetJsEnvDir(taskId, sessionId)

	if _, err := os.Stat(tsEnvDir); err == nil {
		err := os.RemoveAll(tsEnvDir)
		if err != nil {
			return err
		}
	}

	err := os.MkdirAll(tsEnvDir, os.ModePerm)
	if err != nil {
		return err
	}

	pkgJsonPath := filepath.Join(tsEnvDir, "package.json")
	err = os.WriteFile(pkgJsonPath, []byte(`{}`), 0644)
	if err != nil {
		return err
	}

	tsConfigPath := filepath.Join(tsEnvDir, "tsconfig.json")
	err = os.WriteFile(tsConfigPath, []byte(`{
  "compilerOptions": {
    "target": "ESNext",
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "strict": false,
    "esModuleInterop": true
  }
}`), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("npm", "install", "ts-node", "typescript")
	cmd.Dir = tsEnvDir
	err = cmd.Run()
	if err != nil {
		return err
	}
	hookExecPath := filepath.Join(tsEnvDir, "hooker-sage4js.ts")
	logger.Info("hookerExecPath: %s", hookExecPath)
	hookerExec, _ := staticdata.Asset("go/staticdata/hooker-sage4js.ts")
	err = os.WriteFile(hookExecPath, hookerExec, 0644)

	hookExecNoTracePath := filepath.Join(tsEnvDir, "hooker-sage4js-notrace.ts")
	logger.Info("hookExecNoTracePath: %s", hookExecNoTracePath)
	hookerExecNoTrace, _ := staticdata.Asset("go/staticdata/hooker-sage4js-notrace.ts")
	err = os.WriteFile(hookExecNoTracePath, hookerExecNoTrace, 0644)
	return nil
}
