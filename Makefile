# Kohler Anthem HACS Integration - Setup Makefile
#
# Usage:
#   make install    - Install all required tools
#   make extract    - Extract secrets from APK
#   make proxy      - Start mitmproxy for traffic capture
#   make env        - Generate .env file from captured secrets
#   make test       - Test the configuration
#   make clean      - Remove generated files

SHELL := /bin/bash
.PHONY: install extract proxy env test clean help frida-start frida-stop frida-status bypass proxy-on proxy-off proxy-status capture mitm-cert-install

# Directories
SCRIPTS_DIR := scripts
BUILD_DIR := .build
APK_DIR := dev/apk
DECOMPILED_DIR := $(BUILD_DIR)/decompiled

# Files
ENV_FILE := .env
SECRETS_FILE := $(BUILD_DIR)/secrets.json

help:
	@echo "Kohler Anthem HACS Integration Setup"
	@echo ""
	@echo "Quick start:"
	@echo "  make extract        Extract secrets from APK (needs dev/apk/base.apk)"
	@echo "  make capture        Capture APIM key via mitmproxy (needs emulator)"
	@echo "  make env            Generate .env file"
	@echo "  make test           Test authentication"
	@echo ""
	@echo "Emulator tools:"
	@echo "  make mitm-cert-install   Install mitmproxy CA cert as system cert"
	@echo "  make frida-start    Start frida-server on emulator"
	@echo "  make frida-status   Check frida connection"
	@echo "  make bypass         Launch Kohler app with bypass"
	@echo "  make proxy-on       Set Android to use Mac as proxy"
	@echo "  make proxy-off      Remove Android proxy setting"
	@echo ""
	@echo "Other:"
	@echo "  make install        Install required tools"
	@echo "  make clean          Remove generated files"
	@echo ""
	@echo "See SETUP.md for detailed instructions."

# =============================================================================
# Step 1: Install Tools
# =============================================================================

install: install-brew install-python install-android install-apk-tools install-frida
	@echo ""
	@echo "=========================================="
	@echo "All tools installed successfully!"
	@echo "=========================================="
	@echo ""
	@echo "Next step: make extract"

install-brew:
	@echo "Checking Homebrew..."
	@which brew > /dev/null || (echo "Installing Homebrew..." && /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)")
	@echo "Homebrew OK"

install-python:
	@echo "Installing Python dependencies..."
	@brew list python@3.11 > /dev/null 2>&1 || brew install python@3.11
	@pip3 install --quiet mitmproxy frida-tools aiohttp msal
	@echo "Python OK"

install-android:
	@echo "Installing Android tools..."
	@brew list --cask android-platform-tools > /dev/null 2>&1 || brew install --cask android-platform-tools
	@echo "Android Platform Tools OK"
	@echo ""
	@echo "NOTE: You also need an Android emulator or device."
	@echo "      Recommended: Genymotion (https://www.genymotion.com/)"
	@echo "      Or use a physical Android device with USB debugging enabled."

install-frida:
	@echo "Installing Frida..."
	@pip3 install --quiet --upgrade frida-tools
	@echo "Frida OK"

install-apk-tools:
	@echo "Installing APK analysis tools..."
	@brew list jadx > /dev/null 2>&1 || brew install jadx
	@brew list jq > /dev/null 2>&1 || brew install jq
	@echo "APK tools OK"

# =============================================================================
# Step 2: Extract Secrets from APK
# =============================================================================

extract: $(BUILD_DIR) $(SECRETS_FILE)
	@echo ""
	@echo "=========================================="
	@echo "Secrets extracted!"
	@echo "=========================================="
	@cat $(SECRETS_FILE) | jq .
	@echo ""
	@echo "Next step: make proxy"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(SECRETS_FILE): $(BUILD_DIR)
	@echo ""
	@echo "=========================================="
	@echo "APK Extraction"
	@echo "=========================================="
	@echo ""
	@if [ ! -f "$(APK_DIR)/base.apk" ]; then \
		echo "ERROR: APK not found at $(APK_DIR)/base.apk"; \
		echo ""; \
		echo "Get the APK from your Android device or emulator:"; \
		echo "  1. Install 'Kohler Konnect' from Play Store"; \
		echo "  2. Run: adb shell pm path com.kohler.hermoth"; \
		echo "  3. Run: adb pull <path>/base.apk $(APK_DIR)/base.apk"; \
		echo ""; \
		exit 1; \
	fi
	@echo "Decompiling APK with jadx..."
	@jadx --quiet -d $(DECOMPILED_DIR) $(APK_DIR)/base.apk 2>/dev/null || true
	@echo "Searching for secrets..."
	@python3 $(SCRIPTS_DIR)/extract_secrets_from_apk.py $(DECOMPILED_DIR) > $(SECRETS_FILE)
	@echo "Done!"

# =============================================================================
# Step 3: Capture APIM Key via mitmproxy
# =============================================================================

capture:
	@echo ""
	@echo "=========================================="
	@echo "Capture APIM Key"
	@echo "=========================================="
	@echo ""
	@echo "This will capture the APIM key by running mitmproxy + Frida."
	@echo ""
	@echo "Prerequisites (one-time setup):"
	@echo "  1. Genymotion emulator running with Kohler app installed"
	@echo "  2. Frida server running: make frida-start"
	@echo "  3. Mitmproxy CA cert installed as system cert (see SETUP.md)"
	@echo ""
	@echo "Press ENTER to start, or Ctrl+C to cancel..."
	@read
	@echo ""
	@echo "Step 1: Setting Android proxy..."
	@$(ADB) shell settings put global http_proxy $$(ipconfig getifaddr en0):8080
	@echo ""
	@echo "Step 2: Starting mitmproxy (this terminal)..."
	@echo "Step 3: In ANOTHER terminal, run: make bypass"
	@echo "Step 4: Log in to the app and tap around"
	@echo ""
	@echo "When you see 'FOUND APIM KEY', press Ctrl+C here."
	@echo ""
	@mitmweb --listen-port 8080 --web-port 8081 -s $(SCRIPTS_DIR)/capture_apim_key.py || true
	@echo ""
	@echo "Cleaning up proxy..."
	@$(ADB) shell settings delete global http_proxy
	@echo "Done!"

proxy:
	@echo "Use 'make capture' instead - it handles proxy setup automatically."
	@echo ""
	@$(MAKE) capture

# =============================================================================
# Step 4: Generate .env File
# =============================================================================

env:
	@echo ""
	@echo "=========================================="
	@echo "Generate .env Configuration"
	@echo "=========================================="
	@python3 $(SCRIPTS_DIR)/generate_env.py

# =============================================================================
# Step 5: Test Configuration
# =============================================================================

test:
	@echo ""
	@echo "=========================================="
	@echo "Testing Configuration"
	@echo "=========================================="
	@if [ ! -f "$(ENV_FILE)" ]; then \
		echo "ERROR: .env file not found. Run 'make env' first."; \
		exit 1; \
	fi
	@echo "Loading .env and running test..."
	@bash -c 'source $(ENV_FILE) && python3 $(SCRIPTS_DIR)/test_quick_dirty.py'

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@echo "Cleaning up..."
	@rm -rf $(BUILD_DIR)
	@rm -f $(ENV_FILE)
	@echo "Done. Note: .env was removed. Run 'make env' to recreate."

# =============================================================================
# Frida Management (for Genymotion emulator)
# =============================================================================

frida-start:
	@echo "Starting frida-server on emulator..."
	@$(ADB) root >/dev/null 2>&1 || true
	@sleep 1
	@$(ADB) shell "pkill -9 frida-server 2>/dev/null; /data/local/tmp/frida-server &" &
	@sleep 2
	@echo "Checking frida connection..."
	@frida-ps -U >/dev/null 2>&1 && echo "Frida server running!" || echo "ERROR: Could not connect to frida-server"

frida-stop:
	@echo "Stopping frida-server..."
	@$(ADB) shell pkill -9 frida-server 2>/dev/null || true
	@echo "Done"

FRIDA := $(shell which frida 2>/dev/null || echo ~/Library/Python/3.9/bin/frida)
FRIDA_PS := $(shell which frida-ps 2>/dev/null || echo ~/Library/Python/3.9/bin/frida-ps)

frida-status:
	@echo "Checking frida connection..."
	@$(FRIDA_PS) -U 2>&1 | head -5 || echo "ERROR: Frida not connected"

bypass:
	@echo "Launching Kohler app with bypass script..."
	@echo "After the app launches, proceed through the location screen and log in."
	@echo ""
	@$(FRIDA) -U -f com.kohler.hermoth -l scripts/frida_bypass.js

# =============================================================================
# Android Proxy Management
# =============================================================================

MAC_IP := $(shell ipconfig getifaddr en0 2>/dev/null || echo "192.168.1.100")
ADB := $(shell which adb 2>/dev/null || echo /Applications/Genymotion.app/Contents/MacOS/tools/adb)

proxy-on:
	@echo "Setting Android proxy to $(MAC_IP):8080..."
	@$(ADB) shell settings put global http_proxy $(MAC_IP):8080
	@echo "Proxy enabled. Run 'make proxy-off' when done."

proxy-off:
	@echo "Removing Android proxy..."
	@$(ADB) shell settings delete global http_proxy
	@echo "Proxy disabled."

proxy-status:
	@echo "Current Android proxy setting:"
	@$(ADB) shell settings get global http_proxy || echo "(not set)"

# =============================================================================
# Mitmproxy CA Certificate Installation
# =============================================================================

MITMPROXY_CERT := $(HOME)/.mitmproxy/mitmproxy-ca-cert.cer

mitm-cert-install:
	@echo "Installing mitmproxy CA certificate as system cert..."
	@if [ ! -f "$(MITMPROXY_CERT)" ]; then \
		echo "ERROR: mitmproxy cert not found at $(MITMPROXY_CERT)"; \
		echo "Run mitmproxy once to generate the cert: mitmproxy --help"; \
		exit 1; \
	fi
	@HASH=$$(openssl x509 -inform PEM -subject_hash_old -in "$(MITMPROXY_CERT)" | head -1) && \
	echo "Cert hash: $$HASH" && \
	if $(ADB) shell "ls /system/etc/security/cacerts/$$HASH.0" >/dev/null 2>&1; then \
		echo "Certificate already installed!"; \
	else \
		echo "Pushing certificate..." && \
		cp "$(MITMPROXY_CERT)" "/tmp/$$HASH.0" && \
		$(ADB) push "/tmp/$$HASH.0" /sdcard/ && \
		$(ADB) shell "su 0 mount -o rw,remount /system 2>/dev/null || true" && \
		$(ADB) shell "su 0 cp /sdcard/$$HASH.0 /system/etc/security/cacerts/" && \
		$(ADB) shell "su 0 chmod 644 /system/etc/security/cacerts/$$HASH.0" && \
		$(ADB) shell "su 0 mount -o ro,remount /system 2>/dev/null || true" && \
		echo "Certificate installed successfully!"; \
	fi && \
	echo "Verified: $$($(ADB) shell ls -la /system/etc/security/cacerts/$$HASH.0)"
