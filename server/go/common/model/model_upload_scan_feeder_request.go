package model

import "github.com/vulnsage/vulnsage/go/entity"

type UploadScanFeederRequest struct {
	ScanFeeder []*entity.FeederInfo `json:"scanFeeder,omitempty"`
}
