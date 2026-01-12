# Kohler Anthem - Development Tools
#
# Traffic capture and API analysis tools for development.
# Production setup is in the root Makefile.

SHELL := /bin/bash
.PHONY: help capture clean logs mitmproxy proxy-on proxy-off install-cert

# Paths
DEV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(DEV_DIR)/..
SCRIPTS_DIR := $(DEV_DIR)/scripts
OUTPUT_DIR := $(DEV_DIR)/output

HOST_IP := $(shell ipconfig getifaddr en0 2>/dev/null || echo "10.0.2.2")
MITMPROXY := ~/Library/Python/3.9/bin/mitmdump
ADB := /Applications/Genymotion.app/Contents/MacOS/tools/adb

help:
	@echo "Kohler Anthem - Development Tools"
	@echo ""
	@echo "Frida capture:"
	@echo "  make capture     Launch app with bypass + traffic capture"
	@echo "  make logs        Show recent capture logs"
	@echo "  make clean       Remove capture logs"
	@echo ""
	@echo "HTTP capture (mitmproxy):"
	@echo "  make mitmproxy   Start mitmproxy to capture HTTP traffic"
	@echo "  make proxy-on    Configure emulator to use proxy (HOST_IP=$(HOST_IP))"
	@echo "  make proxy-off   Disable proxy on emulator"
	@echo "  make install-cert Install mitmproxy CA cert on emulator"
	@echo ""
	@echo "Prerequisites:"
	@echo "  - Genymotion emulator running"
	@echo "  - frida-server running on emulator (see root 'make frida-start')"
	@echo "  - Kohler Konnect APK installed"

# Launch app with full bypass + traffic capture
capture:
	@python3 $(SCRIPTS_DIR)/frida_dev_capture.py

# Show recent capture logs
logs:
	@echo "Recent capture logs:"
	@echo ""
	@ls -lt $(OUTPUT_DIR)/capture_*.log 2>/dev/null | head -10 || echo "No capture logs found"

# View latest capture log
latest:
	@LATEST=$$(ls -t $(OUTPUT_DIR)/capture_*.log 2>/dev/null | head -1); \
	if [ -n "$$LATEST" ]; then \
		echo "Viewing: $$LATEST"; \
		less $$LATEST; \
	else \
		echo "No capture logs found"; \
	fi

# Clean capture logs
clean:
	@echo "Removing capture logs..."
	@rm -f $(OUTPUT_DIR)/capture_*.log
	@rm -f $(OUTPUT_DIR)/mitmproxy_*.log
	@rm -f $(OUTPUT_DIR)/mitmproxy_*.flow
	@echo "Done"

# Start mitmproxy to capture HTTP traffic
mitmproxy:
	@echo "Starting mitmproxy on port 8080..."
	@echo "Make sure proxy is configured: make proxy-on"
	@echo "Output: $(OUTPUT_DIR)/mitmproxy_http.log"
	@echo ""
	$(MITMPROXY) -s $(SCRIPTS_DIR)/mitmproxy_capture.py --set block_global=false

# Configure emulator to use proxy
proxy-on:
	@echo "Configuring proxy on emulator ($(HOST_IP):8080)..."
	@$(ADB) shell settings put global http_proxy $(HOST_IP):8080
	@echo "Proxy enabled. Run 'make mitmproxy' to start capturing."

# Disable proxy on emulator
proxy-off:
	@echo "Disabling proxy on emulator..."
	@$(ADB) shell settings put global http_proxy :0
	@echo "Proxy disabled."

# Install mitmproxy CA certificate on emulator
install-cert:
	@echo "Installing mitmproxy CA certificate..."
	@if [ ! -f ~/.mitmproxy/mitmproxy-ca-cert.cer ]; then \
		echo "CA cert not found. Run mitmproxy once first to generate it."; \
		exit 1; \
	fi
	@HASH=$$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.cer | head -1); \
	echo "Certificate hash: $$HASH"; \
	openssl x509 -inform PEM -in ~/.mitmproxy/mitmproxy-ca-cert.cer -out /tmp/$$HASH.0; \
	$(ADB) root; \
	sleep 1; \
	$(ADB) remount; \
	sleep 1; \
	$(ADB) push /tmp/$$HASH.0 /system/etc/security/cacerts/; \
	$(ADB) shell chmod 644 /system/etc/security/cacerts/$$HASH.0; \
	echo "Certificate installed. Reboot emulator for changes to take effect."
	@echo "Run: $(ADB) reboot"
