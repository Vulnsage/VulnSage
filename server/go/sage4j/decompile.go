package sage4j

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
)

func GetDecompileEnvDir(identifier string) string {
	if _, err := os.Stat(path.Join(os.Getenv(entity.VulnSageRootPath), "decompile")); err != nil {
		os.Mkdir(path.Join(os.Getenv(entity.VulnSageRootPath), "decompile"), 0755)
	}
	return path.Join(os.Getenv(entity.VulnSageRootPath), "decompile", filepath.Clean(identifier))
}

func DecompileJar(identifier, inputPath string) error {
	var outputDir = GetDecompileEnvDir(identifier)
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := decompileJar(identifier, inputPath, outputDir); err != nil {
			logger.Warnf("decompiled from %s to %s failed: %v", inputPath, outputDir, err)
			return err
		}
		os.Mkdir(outputDir, 0755)
		logger.Infof("decompiled from %s to %s", inputPath, outputDir)
	} else {
		logger.Infof("outputDir exists, skip decompile, get decompiled from %s to %s", inputPath, outputDir)
	}
	cache.GetInterDataCache().AddJavaIdentifierToDecompiledLocation(identifier, outputDir)
	return nil
}

func decompileJar(identifier, inputPath, outputDir string) error {
	var out bytes.Buffer
	var stderr bytes.Buffer

	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		if err := os.Mkdir(outputDir, 0755); err != nil {
			return fmt.Errorf("create dir failed: %v", err)
		}
	}

	var fernflowerPath string
	var isFound bool
	if fernflowerPath, isFound = os.LookupEnv(entity.VulnSageFernflowerPath); !isFound {
		return fmt.Errorf("could not find fernflower library in system environment")
	}
	args := make([]string, 0)
	args = append(args, "-jar", fernflowerPath)
	args = append(args, entity.VulnSageFernflowerOptions...)
	args = append(args, inputPath, outputDir)
	cmd := exec.Command("java", args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("decompiled failed: %v, stderr: %s", err, stderr.String())
	}

	if err := unzipJarFiles(outputDir); err != nil {
		return err
	}

	return nil
}

func unzipJarFiles(outputDir string) error {
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return err
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".jar") {
			jarPath := filepath.Join(outputDir, file.Name())
			if err := unzipFile(jarPath, outputDir); err != nil {

				logger.Errorf("decompiled %s failed: %v", jarPath, err)
			}
		}
	}
	return nil
}

func unzipFile(jarPath, destDir string) error {
	r, err := zip.OpenReader(jarPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		if !strings.HasPrefix(fpath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer func(rc io.ReadCloser) {
			err := rc.Close()
			if err != nil {
				logger.Errorf("close rc failed: %v", err)
			}
		}(rc)

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}
		defer func(outFile *os.File) {
			err := outFile.Close()
			if err != nil {
				logger.Errorf("close outFile failed: %v", err)
			}
		}(outFile)

		_, err = io.Copy(outFile, rc)
		if err != nil {
			return err
		}
	}
	return nil
}
