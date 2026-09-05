PREFIX ?= $(HOME)/.local
BIN    := sec
SRC    := $(wildcard Sources/*.swift)
BUILD_DIR := .build
BUILD_BIN := $(BUILD_DIR)/$(BIN)
SWIFTFLAGS ?= -O
ARCH ?= $(shell uname -m)
TARGET := $(ARCH)-apple-macos14.0

# LocalAuthentication refuses to show the Touch ID dialog unless the process
# has a bundle identifier and a code signature. The identifier is embedded
# into the Mach-O at link time because there is no .app bundle to hold it.
LDFLAGS := -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist

# Ad-hoc signing works with locally persisted CryptoKit Secure Enclave keys.
SIGN_IDENTITY ?= -

.PHONY: all build sign install clean test

all: build

build: sign

$(BUILD_BIN): $(SRC) Info.plist Makefile
	mkdir -p "$(BUILD_DIR)"
	swiftc -target $(TARGET) $(SWIFTFLAGS) -o "$(BUILD_BIN)" $(SRC) \
		-framework CryptoKit -framework LocalAuthentication -framework Security \
		$(LDFLAGS)

sign: $(BUILD_BIN)
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
