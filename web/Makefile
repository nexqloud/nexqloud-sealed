# Cloudflare Pages sometimes sets the project root to web/. Delegate to the repo Makefile.
.PHONY: all wasm wasm_exec clean

all wasm wasm_exec clean:
	@$(MAKE) -C .. $@
