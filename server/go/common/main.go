package common

import (
	"os"
	"path"

	"github.com/vulnsage/vulnsage/go/entity"
)

func init() {

}

func CleanAllEnvDir() error {
	var envDir = path.Join(os.Getenv(entity.VulnSageRootPath), "env")
	if _, err := os.Stat(envDir); err == nil {
		err := os.RemoveAll(envDir)
		if err != nil {
			return err
		}
	}
	return nil
}
