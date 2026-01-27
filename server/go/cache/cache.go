package cache

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/vulnsage/vulnsage/go/entity"
	"github.com/vulnsage/vulnsage/go/logcenter"
	"github.com/vulnsage/vulnsage/go/staticdata"
)

var logger = logcenter.NewLogger("cache")

type InterDataCache struct {
	sync.RWMutex

	port2MessageQueue              map[int]chan string
	vulnSageBackendRoot            string
	feederInfo                     map[string]*entity.FeederInfo
	javaIdentifierToDependencyInfo map[string]*entity.JavaDependencyInfo
}

func (pc *InterDataCache) HasMessage(port int) bool {
	hasMessage := false
	queue := pc.port2MessageQueue[port]
	for {
		select {
		case msg := <-queue:
			logger.Printf("Processed: %s\n", msg)
			hasMessage = true
		default:
			return hasMessage
		}
	}
}

func (pc *InterDataCache) setPort2messageQueue(port2messageQueue map[int]chan string) {
	pc.port2MessageQueue = port2messageQueue
}

func (pc *InterDataCache) VulnSageBackendRoot() string {
	return pc.vulnSageBackendRoot
}

func (pc *InterDataCache) SetVulnSageBackendRoot(vulnSageBackendRoot string) {
	pc.vulnSageBackendRoot = vulnSageBackendRoot
}

func (pc *InterDataCache) GetJavaIdentifierClassifier(classifier string) string {
	pc.RLock()
	defer pc.RUnlock()
	if pc.javaIdentifierToDependencyInfo[classifier] == nil {
		return ""
	} else {
		return pc.javaIdentifierToDependencyInfo[classifier].Classifier
	}
}

func (pc *InterDataCache) GetJavaIdentifierToRealLocation(identifier string) string {
	pc.RLock()
	defer pc.RUnlock()
	if pc.javaIdentifierToDependencyInfo[identifier] == nil {
		return ""
	} else {
		return pc.javaIdentifierToDependencyInfo[identifier].RealLocation
	}
}

func (pc *InterDataCache) GetJavaIdentifierToDecompliedLocation(identifier string) string {
	pc.RLock()
	defer pc.RUnlock()
	if pc.javaIdentifierToDependencyInfo[identifier] == nil {
		return ""
	} else {
		return pc.javaIdentifierToDependencyInfo[identifier].DecompiledLocation
	}
}

func (pc *InterDataCache) AddJavaIdentifierClassifier(identifier string, classifier string) {
	pc.Lock()
	defer pc.Unlock()
	if pc.javaIdentifierToDependencyInfo[identifier] == nil {
		pc.javaIdentifierToDependencyInfo[identifier] = &entity.JavaDependencyInfo{
			Dependency: entity.IdentifierToDependency(identifier),
			Classifier: classifier,
		}
	} else {
		pc.javaIdentifierToDependencyInfo[identifier].Classifier = classifier
	}
}

func (pc *InterDataCache) AddJavaIdentifierToRealLocation(identifier string, location string) {
	pc.Lock()
	defer pc.Unlock()
	if pc.javaIdentifierToDependencyInfo[identifier] == nil {
		pc.javaIdentifierToDependencyInfo[identifier] = &entity.JavaDependencyInfo{
			Dependency:   entity.IdentifierToDependency(identifier),
			RealLocation: location,
		}
	} else {
		pc.javaIdentifierToDependencyInfo[identifier].RealLocation = location
	}
}

func (pc *InterDataCache) AddJavaIdentifierToDecompiledLocation(identifier string, location string) {
	pc.Lock()
	defer pc.Unlock()
	if pc.javaIdentifierToDependencyInfo[identifier] == nil {
		pc.javaIdentifierToDependencyInfo[identifier] = &entity.JavaDependencyInfo{
			Dependency:         entity.IdentifierToDependency(identifier),
			DecompiledLocation: location,
		}
	} else {
		pc.javaIdentifierToDependencyInfo[identifier].DecompiledLocation = location
	}
}

func (pc *InterDataCache) Feeder() map[string]*entity.FeederInfo {
	pc.RLock()
	defer pc.RUnlock()
	return pc.feederInfo
}

func (pc *InterDataCache) GetFeeder(taskId string) *entity.FeederInfo {
	pc.RLock()
	defer pc.RUnlock()
	if pc.feederInfo[taskId] != nil {
		return pc.feederInfo[taskId]
	} else {
		return nil
	}
}

func (pc *InterDataCache) SetFeeder(feederInfo map[string]*entity.FeederInfo) {
	pc.Lock()
	defer pc.Unlock()
	pc.feederInfo = feederInfo
}

func (pc *InterDataCache) AddFeeder(feederInfo *entity.FeederInfo) {
	pc.Lock()
	defer pc.Unlock()
	pc.feederInfo[feederInfo.TaskId] = feederInfo
}

func (pc *InterDataCache) AddFeeders(feederInfos ...*entity.FeederInfo) {
	pc.Lock()
	defer pc.Unlock()
	for _, feederInfo := range feederInfos {
		pc.feederInfo[feederInfo.TaskId] = feederInfo
	}
}

var instance *InterDataCache
var once sync.Once

func GetInterDataCache() *InterDataCache {
	once.Do(func() {
		instance = &InterDataCache{
			feederInfo:                     make(map[string]*entity.FeederInfo),
			javaIdentifierToDependencyInfo: make(map[string]*entity.JavaDependencyInfo),
		}
	})
	return instance
}

func init() {
	var trace map[string]*entity.FeederInfo = make(map[string]*entity.FeederInfo)
	jsonContent, _ := staticdata.Asset("go/staticdata/scanFeeder.json")
	var traceInfoList []*entity.FeederInfo
	err := json.Unmarshal(jsonContent, &traceInfoList)
	if err != nil {
		return
	}
	for _, traceInfo := range traceInfoList {
		trace[traceInfo.TaskId] = traceInfo
	}
	GetInterDataCache().SetFeeder(trace)

	messageQueue := make(chan string, 100)
	go startServer(fmt.Sprintf(":%d", entity.MessageQueuePortJNDI), messageQueue)

	messageQueue2 := make(chan string, 100)
	go startServer(fmt.Sprintf(":%d", entity.MessageQueuePortCommandInjection), messageQueue2)

	port2messageQueue := make(map[int]chan string)
	port2messageQueue[entity.MessageQueuePortJNDI] = messageQueue
	port2messageQueue[entity.MessageQueuePortCommandInjection] = messageQueue2

	GetInterDataCache().setPort2messageQueue(port2messageQueue)
}
