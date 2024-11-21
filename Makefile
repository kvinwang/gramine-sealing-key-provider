# Makefile for Gramine Sealing Key Provider
ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
SELF_EXE = target/release/gramine-sealing-key-provider

.PHONY: all
all: $(SELF_EXE) gramine-sealing-key-provider.manifest
ifeq ($(SGX),1)
all: gramine-sealing-key-provider.manifest.sgx gramine-sealing-key-provider.sig
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

$(SELF_EXE): Cargo.toml
	cargo build --release

gramine-sealing-key-provider.manifest: gramine-sealing-key-provider.manifest.template
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

gramine-sealing-key-provider.manifest.sgx gramine-sealing-key-provider.sig: sgx_sign
	@:

.INTERMEDIATE: sgx_sign
sgx_sign: gramine-sealing-key-provider.manifest $(SELF_EXE)
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: run-provider
run-provider: all
	$(GRAMINE) gramine-sealing-key-provider $(QUOTE_PATH)

.PHONY: clean
clean:
	$(RM) -rf *.token *.sig *.manifest.sgx *.manifest OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock
