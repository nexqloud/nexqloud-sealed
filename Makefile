.PHONY: all wasm wasm_exec clean prod demo

GO_ROOT := $(shell go env GOROOT)

PROD_BINS := shim operator destruction-coordinator destruction-aggregator verify sealed-verify-deletion
DEMO_BINS := registry mock-idp bootstrap

all: wasm wasm_exec

wasm:
	GOOS=js GOARCH=wasm go build -o web/main.wasm ./web
	@date -u +%Y%m%d%H%M%S > web/wasm_build.txt

wasm_exec:
	@for src in "$(GO_ROOT)/lib/wasm/wasm_exec.js" "$(GO_ROOT)/misc/wasm/wasm_exec.js"; do \
		if [ -f "$$src" ]; then \
			install -m 644 "$$src" web/wasm_exec.js; \
			exit 0; \
		fi; \
	done; \
	echo "wasm_exec.js not found in GOROOT"; exit 1

prod:
	@for bin in $(PROD_BINS); do \
		echo "building $$bin"; \
		go build -o "bin/$$bin" "./cmd/$$bin"; \
	done

demo:
	@mkdir -p bin
	@for bin in $(DEMO_BINS); do \
		echo "building demo/$$bin"; \
		go build -o "bin/demo-$$bin" "./demo/$$bin"; \
	done

clean:
	rm -f web/main.wasm web/wasm_exec.js
	rm -rf bin

update-and-run:
	git pull && NEXQLOUD_DEV=1 go run ./cmd/shim/main.go --dev
