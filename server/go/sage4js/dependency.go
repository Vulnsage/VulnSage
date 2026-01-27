package sage4js

import (
	"bytes"
	"os/exec"
)

func InstallNpmDependency(root, ModuleName string) error {
	cmd := exec.Command("npm", "install", ModuleName)
	cmd.Dir = root

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	return cmd.Run()
}
