VERSION ?= 1.0.4
PKG_NAME = wifibridge
BIN_DIR = bin
DIST_DIR = dist
ARCH ?= amd64

.PHONY: all build build-arm64 test package package-arm64 clean

all: build

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BIN_DIR)/wifibridge ./cmd/wifibridge

build-arm64:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOARCH=arm64 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BIN_DIR)/wifibridge-arm64 ./cmd/wifibridge

test:
	go test -v ./...

package: build
	@echo "Packaging $(PKG_NAME) $(VERSION) ($(ARCH))..."
	mkdir -p $(DIST_DIR)/pkg_$(ARCH)/DEBIAN
	mkdir -p $(DIST_DIR)/pkg_$(ARCH)/usr/bin
	mkdir -p $(DIST_DIR)/pkg_$(ARCH)/lib/systemd/system
	cp -r packaging/DEBIAN/* $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/
	chmod 0755 $(DIST_DIR)/pkg_$(ARCH)/DEBIAN
	sed -i 's/^Architecture:.*/Architecture: $(ARCH)/' $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/control
	sed -i 's/^Version:.*/Version: $(VERSION)/' $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/control
	chmod 0755 $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/postinst $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/prerm
	chmod 0644 $(DIST_DIR)/pkg_$(ARCH)/DEBIAN/control
	cp packaging/lib/systemd/system/wifibridge.service $(DIST_DIR)/pkg_$(ARCH)/lib/systemd/system/
	chmod 0644 $(DIST_DIR)/pkg_$(ARCH)/lib/systemd/system/wifibridge.service
	cp $(BIN_DIR)/wifibridge $(DIST_DIR)/pkg_$(ARCH)/usr/bin/
	chmod 0755 $(DIST_DIR)/pkg_$(ARCH)/usr/bin/wifibridge
	dpkg-deb --root-owner-group --build $(DIST_DIR)/pkg_$(ARCH) $(DIST_DIR)/$(PKG_NAME)_$(VERSION)_$(ARCH).deb
	@echo "Package created at $(DIST_DIR)/$(PKG_NAME)_$(VERSION)_$(ARCH).deb"

package-arm64: build-arm64
	@echo "Packaging $(PKG_NAME) $(VERSION) (arm64)..."
	mkdir -p $(DIST_DIR)/pkg_arm64/DEBIAN
	mkdir -p $(DIST_DIR)/pkg_arm64/usr/bin
	mkdir -p $(DIST_DIR)/pkg_arm64/lib/systemd/system
	cp -r packaging/DEBIAN/* $(DIST_DIR)/pkg_arm64/DEBIAN/
	chmod 0755 $(DIST_DIR)/pkg_arm64/DEBIAN
	sed -i 's/^Architecture:.*/Architecture: arm64/' $(DIST_DIR)/pkg_arm64/DEBIAN/control
	sed -i 's/^Version:.*/Version: $(VERSION)/' $(DIST_DIR)/pkg_arm64/DEBIAN/control
	chmod 0755 $(DIST_DIR)/pkg_arm64/DEBIAN/postinst $(DIST_DIR)/pkg_arm64/DEBIAN/prerm
	chmod 0644 $(DIST_DIR)/pkg_arm64/DEBIAN/control
	cp packaging/lib/systemd/system/wifibridge.service $(DIST_DIR)/pkg_arm64/lib/systemd/system/
	chmod 0644 $(DIST_DIR)/pkg_arm64/lib/systemd/system/wifibridge.service
	cp $(BIN_DIR)/wifibridge-arm64 $(DIST_DIR)/pkg_arm64/usr/bin/wifibridge
	chmod 0755 $(DIST_DIR)/pkg_arm64/usr/bin/wifibridge
	dpkg-deb --root-owner-group --build $(DIST_DIR)/pkg_arm64 $(DIST_DIR)/$(PKG_NAME)_$(VERSION)_arm64.deb
	@echo "Package created at $(DIST_DIR)/$(PKG_NAME)_$(VERSION)_arm64.deb"

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
