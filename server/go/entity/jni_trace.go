package entity

import "fmt"

type JNIAgentTrace struct {
	FuncName    string `json:"funcName"`
	FileName    string `json:"fileName"`
	LineNumber  int    `json:"lineNumber"`
	ClassName   string `json:"className"`
	ThreadName  string `json:"threadName"`
	Timestamp   int    `json:"timestamp"`
	LineContent string `json:"lineContent,omitempty"`
}

func (t JNIAgentTrace) String() string {
	return fmt.Sprintf("%s[%s:%d] @ %s @ %s\n", t.ClassName, t.FileName, t.LineNumber, t.FuncName, t.LineContent)
}
