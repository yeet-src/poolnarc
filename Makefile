# poolnarc Makefile — compiles the BPF object to bin/poolnarc.bpf.o.

.DEFAULT_GOAL := all

# Resolve clang, bpftool and the libbpf headers from yeet's vendored toolchain
# cache (fetched on demand by the `toolchain` target) — no system BPF toolchain
# needed. A `make BPF_CLANG=…` / `BPFTOOL=…` override still wins.
include build/toolchain.mk

# PATH fallbacks, used only when toolchain.mk resolved nothing (off-Linux).
CLANG     ?= clang
BPF_CLANG ?= $(CLANG)
BPFTOOL   ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

# Prefer the vendored libbpf headers; fall back to system libbpf-dev on PATH.
LIBBPF_INCLUDE ?= $(if $(BPF_SYSINCLUDE),$(BPF_SYSINCLUDE),/usr/include)

INCLUDE_DIR := include
BIN_DIR     := bin
VMLINUX     := $(INCLUDE_DIR)/vmlinux.h
BPF_SRC     := poolnarc.bpf.c
BPF_OBJ     := $(BIN_DIR)/poolnarc.bpf.o

.PHONY: all clean distclean
all: $(BPF_OBJ)

$(VMLINUX): | $(INCLUDE_DIR) toolchain
	sh build/gen-vmlinux.sh $(BPFTOOL) $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX) | $(BIN_DIR) toolchain
	$(BPF_CLANG) -O2 -g -Wall -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I$(INCLUDE_DIR) -I$(LIBBPF_INCLUDE) \
		-c $< -o $@

$(INCLUDE_DIR) $(BIN_DIR):
	@mkdir -p $@

clean:
	rm -rf $(BIN_DIR)

distclean: clean
	rm -rf $(INCLUDE_DIR)
