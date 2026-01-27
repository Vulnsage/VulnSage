package sage4j

import (
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

func GetJavaEnvDir(taskId string, sessionId string) string {
	if _, err := os.Stat(path.Join(os.Getenv(entity.VulnSageRootPath), "env")); err != nil {
		os.Mkdir(path.Join(os.Getenv(entity.VulnSageRootPath), "env"), 0755)
	}
	return path.Join(os.Getenv(entity.VulnSageRootPath), "env", "java-env-"+taskId+"-"+sessionId)
}

func IsJavaEnvDirExists(taskId string, sessionId string) bool {
	var javaEnvDir = GetJavaEnvDir(taskId, sessionId)
	if _, err := os.Stat(javaEnvDir); err == nil {
		return true
	}
	return false
}

func InitJavaEnvLocal(taskId, sessionId string) error {
	if _, isFound := os.LookupEnv(entity.VulnSageLocalResourcePath); !isFound {
		return fmt.Errorf("could not find local resource path in system environment")
	}
	localResourceTarPath := path.Join(os.Getenv(entity.VulnSageLocalResourcePath), "java-env-"+taskId+"-"+sessionId+".tar")
	if _, err := os.Stat(localResourceTarPath); err != nil {
		return fmt.Errorf("could not find local resource tar %s in system environment", localResourceTarPath)
	}
	var javaEnvDir = GetJavaEnvDir(taskId, sessionId)

	if _, err := os.Stat(javaEnvDir); err == nil {
		err := os.RemoveAll(javaEnvDir)
		if err != nil {
			return err
		}
	}

	if err := os.MkdirAll(javaEnvDir, 0755); err != nil {
		return err
	}

	logger.Infof(exec.Command("tar", "-xvf", localResourceTarPath, "-C", javaEnvDir).String())
	if err := exec.Command("tar", "-xvf", localResourceTarPath, "-C", javaEnvDir).Run(); err != nil {
		return fmt.Errorf("tar -xvf %s -C %s error: %v", localResourceTarPath, javaEnvDir, err)
	}
	return nil
}

func InitJavaEnv(taskId string, sessionId string) error {
	if strings.HasPrefix(taskId, entity.BenchmarkJavaXAST) {
		return initJavaEnvXASTBenchmark(taskId, sessionId)
	} else {
		return initJavaEnv(taskId, sessionId)
	}
}

func IsJavaEnvInit(taskId string, sessionId string) (bool, error) {
	if strings.HasPrefix(taskId, entity.BenchmarkJavaXAST) {
		return false, fmt.Errorf("java env is not initialized for benchmark java-xast")
	} else {
		var javaEnvDir = GetJavaEnvDir(taskId, sessionId)

		if _, err := os.Stat(javaEnvDir); err == nil {
			return true, nil
		} else {
			return false, fmt.Errorf("java env is not initialized")
		}
	}
}

func initJavaEnvXASTBenchmark(taskId string, sessionId string) error {
	var javaEnvDir = GetJavaEnvDir(taskId, sessionId)

	if _, err := os.Stat(javaEnvDir); err == nil {
		err := os.RemoveAll(javaEnvDir)
		if err != nil {
			return err
		}
	}
	exec.Command("git", "clone", "https://github.com/SasanLabs/OWASP-Benchmark-vulnSage.git", javaEnvDir)
	buildGradleKtsPath := javaEnvDir + "/pom.xml"
	if _, err := os.Stat(buildGradleKtsPath); err == nil {
		err := os.WriteFile(buildGradleKtsPath, []byte(iniMavenPom), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

func initJavaEnv(taskId string, sessionId string) error {
	var javaEnvDir = GetJavaEnvDir(taskId, sessionId)

	if _, err := os.Stat(javaEnvDir); err == nil {
		err := os.RemoveAll(javaEnvDir)
		if err != nil {
			return err
		}
	}
	mavenInit(javaEnvDir)
	buildGradleKtsPath := javaEnvDir + "/pom.xml"
	if _, err := os.Stat(buildGradleKtsPath); err == nil {
		err := os.WriteFile(buildGradleKtsPath, []byte(iniMavenPom), 0644)
		if err != nil {
			return err
		}
	}

	if err := os.RemoveAll(path.Join(javaEnvDir, "src", "test")); err != nil {
		return err
	}
	return nil
}

const iniMavenPom = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>org.example</groupId>\n  <artifactId>app</artifactId>\n  <packaging>jar</packaging>\n  <version>1.0-SNAPSHOT</version>\n  <name>app</name>\n  <url>http://maven.apache.org</url>\n  <properties>\n    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>\n    <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>\n  </properties>\n  <dependencies>\n        <dependency>\n            <groupId>org.slf4j</groupId>\n            <artifactId>slf4j-log4j12</artifactId>\n            <version>1.7.21</version>\n        </dependency>\n        <dependency>\n            <groupId>log4j</groupId>\n            <artifactId>log4j</artifactId>\n            <version>1.2.17</version>\n        </dependency>\n       <dependency>\n           <groupId>javax.jms</groupId>\n           <artifactId>javax.jms-api</artifactId>\n           <version>2.0.1</version>\n        </dependency>\n  </dependencies>\n  <build>\n    <plugins>\n      <plugin>\n        <groupId>org.apache.maven.plugins</groupId>\n        <artifactId>maven-assembly-plugin</artifactId>\n        <version>3.6.0</version>\n        <executions>\n          <execution>\n            <phase>package</phase>\n            <goals>\n              <goal>single</goal>\n            </goals>\n          </execution>\n        </executions>\n        <configuration>\n          <descriptorRefs>\n            <descriptorRef>jar-with-dependencies</descriptorRef>\n          </descriptorRefs>\n          <archive>\n            <manifest>\n              <mainClass>org.example.App</mainClass>\n            </manifest>\n          </archive>\n        </configuration>\n      </plugin>\n      <plugin>\n        <groupId>org.jiunie</groupId>\n        <artifactId>maven-path-resolver-plugin</artifactId>\n        <version>1.0.0</version>\n      </plugin>\n    </plugins>\n  </build>\n</project>"

var mavenLock sync.Mutex

func mavenInit(javaEnvDir string) {
	mavenLock.Lock()
	defer mavenLock.Unlock()
	if _, err := os.Stat(path.Join(os.Getenv(entity.VulnSageRootPath), "env", "app")); err == nil {
		os.RemoveAll(path.Join(os.Getenv(entity.VulnSageRootPath), "env", "app"))
	}
	cmd := exec.Command("mvn", "archetype:generate",
		"-DgroupId=org.example",
		"-DartifactId=app",
		"-DarchetypeArtifactId=maven-archetype-quickstart",
		"-DinteractiveMode=false")
	cmd.Dir = filepath.Dir(javaEnvDir)
	err := cmd.Run()
	if err != nil {
		return
	}
	if err := os.Rename(path.Join(os.Getenv(entity.VulnSageRootPath), "env", "app"), javaEnvDir); err != nil {
		return
	}
}
