SHELL := /usr/bin/env bash
SCRIPT := mailprobe.sh
BINNAME := mailprobe
PREFIX ?= /usr/local
PKGNAME := $(shell git describe --tags --always 2>/dev/null || echo "v1.0.0")

.PHONY: help lint format test install uninstall package clean

help:
	@printf 'Available targets:\n  make lint        Run shellcheck on the script\n  make format      Format the script if shfmt is installed\n  make test        Run the small test harness (tests/)\n  make install     Install the script to $(PREFIX)/bin\n  make uninstall   Remove installed script from $(PREFIX)/bin\n  make package     Create a release tarball\n  make clean       Remove generated files\n'

lint:
	@which shellcheck >/dev/null 2>&1 || { echo "shellcheck not found, please install it."; exit 2; }
	@echo "Running shellcheck..."
	@shellcheck -x $(SCRIPT)

format:
	@which shfmt >/dev/null 2>&1 || { echo "shfmt not found, skipping format."; exit 0; }
	@shfmt -w $(SCRIPT)

test:
	@./tests/run-tests.sh

install:
	@./install.sh --prefix $(PREFIX)

uninstall:
	@./install.sh --prefix $(PREFIX) --uninstall

package:
	@mkdir -p dist
	@tar -czf dist/$(PKGNAME)-mailprobe.tar.gz $(SCRIPT) README.md LICENSE CHANGELOG.md || true
	@sha256sum dist/$(PKGNAME)-mailprobe.tar.gz | awk '{print $$1}' > dist/$(PKGNAME)-mailprobe.sha256
	@echo "Created dist/$(PKGNAME)-mailprobe.tar.gz"

clean:
	@rm -rf dist
