package entity

type FeederTrace struct {
	VulnerableFunction string   `json:"vulnerable_function"`
	UserInput          string   `json:"user_input"`
	CallChain          []string `json:"call_chain"`
}

type FeederInfo struct {
	TaskId            string            `json:"task_id"`
	InstallModuleMode string            `json:"install_module_mode"`
	ExecutionMode     string            `json:"execution_mode,omitempty" default:"junit" `
	TaskType          TaskType          `json:"task_type"`
	CodeTemplate      string            `json:"template"`
	PackageName       string            `json:"package_name"`
	CodeCheckList     []string          `json:"code_check_list"`
	Trace             *FeederTrace      `json:"trace"`
	DetailedTrace     map[string]string `json:"detailed_trace"`
	ClassConstructors map[string]string `json:"class_constructors"`
}
