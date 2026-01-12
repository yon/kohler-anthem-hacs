# Kohler Anthem - Development Tools
#
# Traffic capture and API analysis tools for development.
# Production setup is in the root Makefile.

SHELL := /bin/bash
.PHONY: help capture clean logs

# Paths
DEV_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
PROJECT_DIR := $(DEV_DIR)/..
SCRIPTS_DIR := $(DEV_DIR)/scripts
OUTPUT_DIR := $(DEV_DIR)/output

help:
	@echo "Kohler Anthem - Development Tools"
	@echo ""
	@echo "Traffic capture:"
	@echo "  make capture     Launch app with bypass + traffic capture"
	@echo "  make logs        Show recent capture logs"
	@echo "  make clean       Remove capture logs"
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
	@echo "Done"
