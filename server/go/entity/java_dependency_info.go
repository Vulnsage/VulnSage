package entity

const JavaDependencyClassifierInit = "init"
const JavaDependencyClassifierEmpty = ""
const JavaDependencyClassifierSources = "sources"

type JavaDependencyInfo struct {
	Dependency
	Classifier         string
	RealLocation       string
	DecompiledLocation string
}
