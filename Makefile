PREFIX ?= $(HOME)/.local
BIN    := sec
SRC    := Sources/main.swift

# LocalAuthentication refuses to show the Touch ID dialog unless the process
# has a bundle identifier and a code signature. The identifier is embedded
# into the Mach-O at link time because there is no .app bundle to hold it.
LDFLAGS := -Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker Info.plist

# Ad-hoc by default. Override with a self-signed identity for a stable code
# identity across rebuilds:  make SIGN_IDENTITY="sec-signing"
SIGN_IDENTITY ?= -

.PHONY: all build sign install clean test

all: build

build: $(BIN)

$(BIN): $(SRC) Info.plist
	swiftc -O -o $(BIN) $(SRC) \
		-framework LocalAuthentication -framework Security \
		$(LDFLAGS)
	codesign -s "$(SIGN_IDENTITY)" --force $(BIN)

install: build
	install -d $(PREFIX)/bin
	install -m 755 $(BIN) $(PREFIX)/bin/$(BIN)
	@echo "installed $(PREFIX)/bin/$(BIN)"

test: build
	python3 Tests/test_cli.py

clean:
	rm -f $(BIN)
