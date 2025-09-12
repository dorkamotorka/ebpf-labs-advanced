# Path to the btfhub-archive repository (needs to be present)
BTFHUB_ARCHIVE ?= ./btfhub-archive

# Determine the architecture for the current machine
# Normalize common architecture names to match BTFHub naming convention
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

# Architecture naming is inconsistent across tools:
# - Golang uses: amd64, arm64
# - btfhub uses: x86_64, arm64
# - bpf2go uses: x86, arm64
# Normalize ARCH to match bpf2go's naming convention
ARCH_CLEANED = $(subst amd64,x86,$(ARCH))

# Output directory for BTF files
OUTPUT ?= btfs

# Find all eBPF C source files in the current directory
EBPF_SRC ?= $(wildcard *.c)

VMLINUX ?= vmlinux.h

# Default commands to run
.PHONY: all
all: vmlinux generate btfgen build

# Generate vmlinux.h file 
.PHONY: vmlinux
vmlinux: 
	@echo "Generating vmlinux.h file"
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile eBPF programs using `go generate`
.PHONY: generate
generate: 
	@echo "Compiling eBPF programs"
	@go generate

# Generate BTF files if your program is expected to run on non-BTF-enabled kernels.
.PHONY: btfgen
btfgen:
	@echo "Invoking Makefile.btfgen with BTFHUB_ARCHIVE=$(BTFHUB_ARCHIVE), ARCH=$(ARCH), OUTPUT=$(OUTPUT)"
	@$(MAKE) -f Makefile.btfgen BTFHUB_ARCHIVE=$(BTFHUB_ARCHIVE) ARCH=$(ARCH_CLEANED) OUTPUT=$(OUTPUT)

# Build the Go programs in the current directory
.PHONY: build
build: 
	@echo "Building Go programs"
	@go build

# Clean up generated BTF files and eBPF object files
.PHONY: clean
clean:
	@echo "Cleaning btfs directory ($(OUTPUT)), vmlinux file ($(VMLINUX)) and eBPF generated files ($()) "
	@find $(OUTPUT) -mindepth 1 ! -name '.gitkeep' -delete
	@rm -f $(VMLINUX)

