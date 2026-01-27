package sage4j

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/vulnsage/vulnsage/go/cache"
	"github.com/vulnsage/vulnsage/go/entity"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func InstallMavenDependency(root string, dependency entity.Dependency) error {
	var cmd *exec.Cmd
	if dependency.ToIdentifier() == entity.BenchmarkJavaJuliet {
		if benchmarkJavaJulietPath, isFound := os.LookupEnv(entity.VulnSageBenchmarkJavaJulietPath); !isFound {
			return fmt.Errorf("could not find benchmarkJavaJulietPath library in system environment")
		} else {
			cmd = exec.Command("mvn",
				"install:install-file",
				"-Dfile="+benchmarkJavaJulietPath,
				"-DgroudId=com.taobao.stc",
				"-DartifactId=juliet-benchmark",
				"-Dversion=1.0.0",
				"-Dpackaging=jar",
			)
			cmd.Dir = root
		}
	} else {
		cmd = exec.Command("mvn", "install")
		cmd.Dir = root
	}
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	return cmd.Run()
}

func RecordDependency(root string, dependency entity.Dependency) error {
	cmd := exec.Command("mvn",
		"org.jiunie:maven-path-resolver-plugin:1.0.0:resolve-path",
		"-DgroupId="+dependency.GroupId, "-DartifactId="+dependency.ArtifactId,
		"-Dversion="+dependency.Version, "-Dclassifier=sources",
		"-DfallbackToMainArtifact=true")
	cmd.Dir = root
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	outStr := out.String()
	classifier := entity.JavaDependencyClassifierSources
	for _, line := range strings.Split(outStr, "\n") {
		if ok := strings.Contains(line, "Classifier artifact not found"); ok {
			classifier = entity.JavaDependencyClassifierEmpty
		}
		if ok := strings.Contains(line, "Resolved path: "); ok {
			resolvedPath := line[strings.Index(line, "Resolved path: ")+len("Resolved path: "):]
			resolvedPath = strings.TrimSpace(resolvedPath)
			logger.Infof("resolved identifier %s as path: %s ", dependency.ToIdentifier(), resolvedPath)
			cache.GetInterDataCache().AddJavaIdentifierToRealLocation(dependency.ToIdentifier(), resolvedPath)
			cache.GetInterDataCache().AddJavaIdentifierClassifier(dependency.ToIdentifier(), classifier)
		}
	}
	if cache.GetInterDataCache().GetJavaIdentifierToRealLocation(dependency.ToIdentifier()) == "" {
		logger.Infof("Failed to location sources for %s, the trace function will get error", dependency.ToIdentifier())
	}
	return nil
}

func AddMavenDependency(mavenRoot string, dependency entity.Dependency) error {

	data, err := os.ReadFile(filepath.Join(mavenRoot, "pom.xml"))
	if err != nil {
		return fmt.Errorf("error reading pom.xml: %v\n", err)
	}

	var project entity.Project
	err = xml.Unmarshal(data, &project)
	if err != nil {
		return fmt.Errorf("error unmarshalling XML: %v\n", err)
	}

	project.Dependencies.Dependency = append(project.Dependencies.Dependency, dependency)

	output, err := xml.MarshalIndent(project, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling XML: %v\n", err)
	}

	err = os.WriteFile(filepath.Join(mavenRoot, "pom.xml"), append([]byte(xml.Header), output...), os.ModePerm)
	if err != nil {
		return fmt.Errorf("error writing pom.xml: %v\n", err)
	}
	logger.Println("Dependency added and pom.xml updated successfully.")

	return nil
}
