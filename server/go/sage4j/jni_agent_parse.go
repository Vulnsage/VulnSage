package sage4j

import (
	"bufio"
	"fmt"
	"github.com/vulnsage/vulnsage/go/entity"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func ParseJNIAgentTrace(baseDirs []string, items []*entity.JNIAgentTrace, classifierType string) error {
	switch classifierType {
	case entity.JavaDependencyClassifierEmpty:
		return parseJNIAgentTraceWithDecompiledFile(baseDirs, items)
	case entity.JavaDependencyClassifierSources:
		return parseJNIAgentTraceWithSourcesFile(baseDirs, items)
	default:
		return fmt.Errorf("unsupported classifier type: %s", classifierType)
	}
}

func parseJNIAgentTraceWithDecompiledFile(baseDirs []string, items []*entity.JNIAgentTrace) error {
	contentCache := make(map[string]string)
	for _, item := range items {
		className := item.ClassName
		fileName := item.FileName
		lineNumber := item.LineNumber
		if item.LineContent != "" {
			continue
		}
		fileContent := ""
		pathParts := make([]string, 0)
		if strings.Contains(className, ".") {
			pathParts = strings.Split(className[:strings.LastIndex(className, ".")], ".")
		} else {
			pathParts = append(pathParts, className)
		}
		for _, baseDir := range baseDirs {
			possibleRealPath := filepath.Join(baseDir, filepath.Join(pathParts...), fileName)
			if _, ok := contentCache[possibleRealPath]; ok {
				fileContent = contentCache[possibleRealPath]
				break
			}
			if _, err := os.Stat(possibleRealPath); err == nil {
				if contents, err := os.ReadFile(possibleRealPath); err == nil {
					contentCache[possibleRealPath] = string(contents)
					fileContent = contentCache[possibleRealPath]
					break
				}
			} else {
				//logger.Printf("filed %s not exist\n", possibleRealPath)
			}
		}
		if fileContent == "" {
			//logger.Printf("file %s not exist\n", fileName)
			continue
		}
		for _, lineContent := range strings.Split(fileContent, "\n") {
			realLineNumbers := make([]int, 0)
			lastCommentIdx := strings.LastIndex(lineContent, "//")
			if lastCommentIdx != -1 && lastCommentIdx < len(lineContent)-2 {
				parts := strings.Split(strings.TrimSpace(lineContent[lastCommentIdx+2:]), ",")
				for _, part := range parts {
					if num, err := strconv.Atoi(part); err == nil {
						realLineNumbers = append(realLineNumbers, num)
					}
				}
			}
			for _, realLineNumber := range realLineNumbers {
				if realLineNumber == lineNumber {
					item.LineContent = lineContent[:lastCommentIdx]
					//logger.Printf(item.String())
					break
				}
			}
		}
	}
	return nil
}

func parseJNIAgentTraceWithSourcesFile(baseDirs []string, items []*entity.JNIAgentTrace) error {
	for _, item := range items {
		className := item.ClassName
		fileName := item.FileName
		lineNumber := item.LineNumber
		pathParts := make([]string, 0)
		if strings.Contains(className, ".") {
			pathParts = strings.Split(className[:strings.LastIndex(className, ".")], ".")
		} else {
			pathParts = append(pathParts, className)
		}
		for _, baseDir := range baseDirs {
			possibleRealPath := filepath.Join(baseDir, filepath.Join(pathParts...), fileName)

			if _, err := os.Stat(possibleRealPath); err == nil {
				lineContent, err := ReadLine(possibleRealPath, lineNumber)
				if err != nil {
					//logger.Printf("read line %d error: %v\n", lineNumber, err)
					continue
				}
				item.LineContent = strings.TrimSpace(lineContent)
				//logger.Printf(item.String())
				break
			} else {
				//logger.Printf("filed %s not exist\n", possibleRealPath)
			}
		}
	}
	return nil
}

func ReadLine(filePath string, lineNumber int) (string, error) {
	currentLine := 1
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open file %s failed: %v", filePath, err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			logger.Errorf("close file %s failed: %v", filePath, err)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if currentLine == lineNumber {
			return strings.TrimSpace(scanner.Text()), nil
		}
		currentLine++
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error when scanning file: %v", err)
	}

	return "", fmt.Errorf("line %d not exists", lineNumber)
}
