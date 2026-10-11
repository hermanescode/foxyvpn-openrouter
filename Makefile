BINARY_NAME=foxyvpn
DIST_DIR=dist
LDFLAGS=-s -w

.PHONY: all build clean build-all build-linux-armv7 build-linux-arm64 build-linux-amd64 build-linux-mipsle

all: build

build:
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/foxyvpn

build-all: build-linux-armv7 build-linux-arm64 build-linux-amd64 build-linux-mipsle

# Google Wifi AC1304 (Qualcomm IPQ4019, Cortex-A7 ARMv7-A)
build-linux-armv7:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-armv7 ./cmd/foxyvpn

build-linux-arm64:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/foxyvpn

build-linux-amd64:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/foxyvpn

build-linux-mipsle:
	mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-mipsle ./cmd/foxyvpn

clean:
	rm -rf $(DIST_DIR) $(BINARY_NAME)
