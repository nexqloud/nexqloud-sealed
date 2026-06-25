.PHONY: all wasm wasm_exec web clean

GO_ROOT := $(shell go env GOROOT)

all: wasm wasm_exec

wasm:
	GOOS=js GOARCH=wasm go build -o web/main.wasm ./web

wasm_exec:
	@for src in "$(GO_ROOT)/lib/wasm/wasm_exec.js" "$(GO_ROOT)/misc/wasm/wasm_exec.js"; do \
		if [ -f "$$src" ]; then \
			install -m 644 "$$src" web/wasm_exec.js; \
			exit 0; \
		fi; \
	done; \
	echo "wasm_exec.js not found in GOROOT"; exit 1

clean:
	rm -f web/main.wasm web/wasm_exec.js
