PREFIX ?= $(HOME)/.local
BIN    := sec
SRC    := Sources/main.swift
BUILD_DIR := .build
BUILD_BIN := $(BUILD_DIR)/$(BIN)
SWIFTFLAGS ?= -O

# LocalAuthentication refuses to show the Touch ID dialog unless the process
# has a bundle identifier and a code signature. The identifier is embedded
# into the Mach-O at link time because there is no .app bundle to hold it.
LDFLAGS := -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist

# Ad-hoc by default. Override with a self-signed identity for a stable code
# identity across rebuilds:  make SIGN_IDENTITY="sec-signing"
SIGN_IDENTITY ?= -

.PHONY: all build sign install clean test

all: build

build: $(BUILD_BIN)

$(BUILD_BIN): $(SRC) Info.plist
	mkdir -p "$(BUILD_DIR)"
	swiftc $(SWIFTFLAGS) -o "$(BUILD_BIN)" $(SRC) \
		-framework LocalAuthentication -framework Security \
		$(LDFLAGS)
	codesign -s "$(SIGN_IDENTITY)" --force "$(BUILD_BIN)"
	codesign --verify --strict "$(BUILD_BIN)"

install: build
	install -d "$(PREFIX)/bin"
	install -m 755 "$(BUILD_BIN)" "$(PREFIX)/bin/$(BIN)"
	codesign --verify --strict "$(PREFIX)/bin/$(BIN)"
	@echo "installed $(PREFIX)/bin/$(BIN)"

test: build
	python3 Tests/test_cli.py
	python3 Tests/test_build.py

clean:
	rm -f "$(BUILD_BIN)"
