package entity

var MessageQueuePortJNDI = 59876
var MessageQueuePortCommandInjection = 59875

type TaskType string

const (
	BenchmarkJavaXAST   = "com.sast.astbenchmark"
	BenchmarkJavaJuliet = "com.taobao.stc:juliet-benchmark:1.0.0"

	VulnSageFernflowerPath          string = "VULN_SAGE_FERNFLOWER_PATH"
	VulnSageLibTracePath            string = "VULN_SAGE_LIB_TRACE_PATH"
	VulnSageRootPath                string = "VULN_SAGE_ROOT_PATH"
	VulnSageEZJNDIPath              string = "VULN_SAGE_EZJNDI_PATH"
	VulnSageBenchmarkJavaJulietPath string = "VULN_SAGE_BENCHMARK_JAVA_JULIET_PATH"
	VulnSageLocalResourcePath       string = "VULN_SAGE_LOCAL_RESOURCE_PATH"
	SuccessMessage                  string = "well done! the vulnerable has been proved , please finish the task!"
)

const (
	VULN_TYPE_COMMAND_INJECTION                    TaskType = "command_injection"
	VULN_TYPE_PICKLE_INJECTION                     TaskType = "pickle_injection"
	VULN_TYPE_SSRF                                 TaskType = "ssrf"
	VULN_TYPE_PROTOTYPE_POLLUTION                  TaskType = "prototype_pollution"
	VULN_TYPE_JNDI                                 TaskType = "jndi"
	VULN_TYPE_CODE_INJECTION                       TaskType = "code_injection"
	VULN_TYPE_PATH_TRAVERSAL                       TaskType = "path_traversal"
	VULN_TYPE_COMMON                               TaskType = "common"
	VULN_TYPE_STACK_OVER_FLOW_ERROR                TaskType = "StackOverflowError"
	VULN_TYPE_STRING_INDEX_OUT_OF_BOUNDS_EXCEPTION TaskType = "StringIndexOutOfBoundsException"
	VULN_TYPE_NUMBER_FORMAT_EXCEPTION              TaskType = "NumberFormatException"
	VULN_TYPE_URL_REDIRECT                         TaskType = "UrlRedirect"
)

var VulnSageFernflowerOptions []string = []string{"-dgs=1", "-ren=0", "-rsy=0", "-asc=1", "-bsm=1"}
