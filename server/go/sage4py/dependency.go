package sage4py

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
)

func InstallPypiDependency(root, ModuleName string) error {
	logger.Infof("install pypi dependency %s", ModuleName)

	venvPath := path.Join(root, "venv")
	cmd := exec.Command("uv", "pip", "install",
		"--python", path.Join(venvPath, "bin", "python"),
		ModuleName,
	)
	cmd.Dir = root

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.Errorf("uv install failed: %s", stderr.String())
		return fmt.Errorf("uv install failed for %s: %w\nOutput: %s",
			ModuleName, err, stderr.String())
	}

	logger.Debugf("Successfully installed %s: %s", ModuleName, out.String())
	return nil
}
