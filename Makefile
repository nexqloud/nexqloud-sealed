.PHONY: all wasm wasm_exec clean prod demo image-shim image-model-attest

GO_ROOT := $(shell go env GOROOT)
SHIM_IMAGE ?= sealed-shim:local
MODEL_ATTEST_IMAGE ?= sealed-model-attest:local

PROD_BINS := shim operator destruction-coordinator destruction-aggregator verify sealed-verify-deletion model-attest
DEMO_BINS := registry mock-idp bootstrap

all: wasm wasm_exec

# Workers Static Assets reject individual files over 25 MiB.
WASM_LDFLAGS := -s -w
WASM_MAX_BYTES := 26214400

wasm:
	GOOS=js GOARCH=wasm go build -ldflags="$(WASM_LDFLAGS)" -trimpath -o web/main.wasm ./web
	@bytes=$$(wc -c < web/main.wasm); \
	if [ "$$bytes" -gt $(WASM_MAX_BYTES) ]; then \
		echo "web/main.wasm is $$bytes bytes (limit $(WASM_MAX_BYTES) / 25 MiB)"; \
		exit 1; \
	fi
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

image-shim:
	docker build -t "$(SHIM_IMAGE)" -f deploy/shim/Dockerfile .

image-model-attest:
	docker build -t "$(MODEL_ATTEST_IMAGE)" -f deploy/model-attest/Dockerfile .

update-and-run:
	git pull && NEXQLOUD_DEV=1 go run ./cmd/shim/main.go --dev
