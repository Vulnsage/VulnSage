package entity

import (
	"encoding/xml"
	"strings"
)

type Project struct {
	XMLName           xml.Name     `xml:"project"`
	Xmlns             string       `xml:"xmlns,attr,omitempty"`
	XmlnsXsi          string       `xml:"xmlns:xsi,attr,omitempty"`
	XsiSchemaLocation string       `xml:"xsi:schemaLocation,attr,omitempty"`
	ModelVersion      string       `xml:"modelVersion"`
	GroupId           string       `xml:"groupId"`
	ArtifactId        string       `xml:"artifactId"`
	Packaging         string       `xml:"packaging"`
	Version           string       `xml:"version"`
	Name              string       `xml:"name"`
	Url               string       `xml:"url"`
	Properties        Properties   `xml:"properties"`
	Dependencies      Dependencies `xml:"dependencies"`
	Build             Build        `xml:"build"`
}

type Dependencies struct {
	Dependency []Dependency `xml:"dependency"`
}

type IDependency interface {
	ToIdentifier() string
}

type Dependency struct {
	IDependency
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

func IdentifierToDependency(identifier string) Dependency {
	parts := strings.Split(identifier, ":")
	if len(parts) == 3 {
		return Dependency{
			GroupId:    parts[0],
			ArtifactId: parts[1],
			Version:    parts[2],
		}
	} else {
		return Dependency{}
	}
}

func (d Dependency) ToIdentifier() string {
	return d.GroupId + ":" + d.ArtifactId + ":" + d.Version
}

type Build struct {
	Plugins []Plugin `xml:"plugins>plugin"`
}

type Plugin struct {
	GroupId       string        `xml:"groupId"`
	ArtifactId    string        `xml:"artifactId"`
	Version       string        `xml:"version"`
	Executions    Executions    `xml:"executions"`
	Configuration Configuration `xml:"configuration"`
}

type Executions struct {
	Execution []Execution `xml:"execution"`
}

type Execution struct {
	Phase string `xml:"phase"`
	Goals Goals  `xml:"goals"`
}

type Goals struct {
	Goal []Goal `xml:"goal"`
}

type Goal struct {
	Value string `xml:",chardata"`
}

type Configuration struct {
	DescriptorRefs DescriptorRefs `xml:"descriptorRefs"`
	Archive        Archive        `xml:"archive"`
}

type DescriptorRefs struct {
	DescriptorRef []string `xml:"descriptorRef"`
}

type Archive struct {
	Manifest Manifest `xml:"manifest"`
}

type Manifest struct {
	MainClass string `xml:"mainClass"`
}

type Properties struct {
	SourceEncoding string `xml:"project.build.sourceEncoding"`
	OutputEncoding string `xml:"project.reporting.outputEncoding"`
}
