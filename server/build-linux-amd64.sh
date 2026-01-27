rm ./go/staticdata/scan_feeder.go
go-bindata -fs -o=./go/staticdata/scan_feeder.go -pkg=staticdata ./go/staticdata

export CC=x86_64-linux-musl-gcc
export CXX=x86_64-linux-musl-g++
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=0
GOOS=linux GOARCH=amd64  go build -a -installsuffix cgo -o vulnSageBackend .