# Kohler Anthem HACS Integration - Setup Makefile
#
# Usage:
#   make install    - Install all required tools
#   make extract    - Extract secrets from APK (client_id, api_resource)
#   make bypass     - Launch app with Frida bypass (captures APIM key automatically)
#   make env        - Generate .env file from captured secrets
#   make release    - Create GitHub release for HACS
#   make clean      - Remove generated files

SHELL := /bin/bash
.PHONY: install extract env clean help frida-start frida-stop frida-status bypass release

# Directories
SCRIPTS_DIR := scripts
BUILD_DIR := .build
APK_DIR := apk
DECOMPILED_DIR := $(BUILD_DIR)/decompiled

# Files
ENV_FILE := .env
SECRETS_FILE := $(BUILD_DIR)/secrets.json

help:
	@echo "Kohler Anthem HACS Integration Setup"
	@echo ""
	@echo "Setup workflow:"
	@echo "  make install        Install required tools"
	@echo "  make extract        Extract client_id/api_resource from APK"
	@echo "  make bypass         Launch app with Frida (captures APIM key)"
	@echo "  make env            Generate .env file"
	@echo ""
	@echo "Maintenance:"
	@echo "  make release        Create GitHub release for HACS"
	@echo "  make clean          Remove generated files"
	@echo ""
	@echo "See SETUP.md for detailed instructions."

# =============================================================================
# Install Tools
# =============================================================================

install: install-brew install-python install-android install-apk-tools install-frida
	@echo ""
	@echo "All tools installed. Next step: make extract"

install-brew:
	@which brew > /dev/null || /bin/bash -c "$$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

install-python:
	@brew list python@3.11 > /dev/null 2>&1 || brew install python@3.11
	@pip3 install --quiet frida-tools aiohttp

install-android:
	@brew list --cask android-platform-tools > /dev/null 2>&1 || brew install --cask android-platform-tools

install-frida:
	@pip3 install --quiet --upgrade frida-tools

install-apk-tools:
	@brew list jadx > /dev/null 2>&1 || brew install jadx
	@brew list jq > /dev/null 2>&1 || brew install jq

# =============================================================================
# Extract Secrets from APK
# =============================================================================

extract: $(BUILD_DIR) $(SECRETS_FILE)
	@echo "Secrets extracted:"
	@cat $(SECRETS_FILE) | jq .
	@echo ""
	@echo "Next step: make bypass"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

$(SECRETS_FILE): $(BUILD_DIR)
	@if [ ! -f "$(APK_DIR)/base.apk" ]; then \
		echo "ERROR: APK not found at $(APK_DIR)/base.apk"; \
		echo ""; \
		echo "Get the APK from your Android device:"; \
		echo "  1. Install 'Kohler Konnect' from Play Store"; \
		echo "  2. adb shell pm path com.kohler.hermoth"; \
		echo "  3. adb pull <path>/base.apk $(APK_DIR)/base.apk"; \
		exit 1; \
	fi
	@jadx --quiet -d $(DECOMPILED_DIR) $(APK_DIR)/base.apk 2>/dev/null || true
	@python3 $(SCRIPTS_DIR)/extract_secrets_from_apk.py $(DECOMPILED_DIR) > $(SECRETS_FILE)

# =============================================================================
# Capture APIM Key via Frida
# =============================================================================

bypass:
	@python3 $(SCRIPTS_DIR)/frida_capture_apim.py

# =============================================================================
# Generate .env File
# =============================================================================

env:
	@python3 $(SCRIPTS_DIR)/generate_env.py

# =============================================================================
# Cleanup
# =============================================================================

clean:
	@rm -rf $(BUILD_DIR)
	@rm -f $(ENV_FILE)
	@echo "Cleaned. Run 'make env' to regenerate .env"

# =============================================================================
# Frida Management
# =============================================================================

ADB := $(shell which adb 2>/dev/null || echo /Applications/Genymotion.app/Contents/MacOS/tools/adb)
FRIDA_PS := $(shell which frida-ps 2>/dev/null || echo ~/Library/Python/3.9/bin/frida-ps)

frida-start:
	@$(ADB) root >/dev/null 2>&1 || true
	@$(ADB) shell "pkill -9 frida-server 2>/dev/null; /data/local/tmp/frida-server &" &
	@sleep 2
	@frida-ps -U >/dev/null 2>&1 && echo "Frida server running" || echo "ERROR: Could not connect"

frida-stop:
	@$(ADB) shell pkill -9 frida-server 2>/dev/null || true

frida-status:
	@$(FRIDA_PS) -U 2>&1 | head -5 || echo "Frida not connected"

# =============================================================================
# GitHub Release for HACS
# =============================================================================

VERSION := $(shell python3 -c "import json; print(json.load(open('custom_components/kohler_anthem/manifest.json'))['version'])")

release:
ifndef COMMIT
	$(error Usage: make release COMMIT=<git-hash>)
endif
	@git cat-file -e $(COMMIT) 2>/dev/null || (echo "ERROR: commit $(COMMIT) not found" && exit 1)
	@if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "ERROR: tag v$(VERSION) already exists"; \
		exit 1; \
	fi
	@echo "Creating GitHub release v$(VERSION) at $(COMMIT)..."
	@git tag -a "v$(VERSION)" $(COMMIT) -m "Release v$(VERSION)"
	@git push origin "v$(VERSION)"
	@gh release create "v$(VERSION)" \
		--title "v$(VERSION)" \
		--notes "Kohler Anthem HACS Integration v$(VERSION)" \
		--latest
	@echo "Release: https://github.com/yon/kohler-anthem-hacs/releases/tag/v$(VERSION)"
