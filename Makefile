AX_ROOT ?= $(PWD)/arceos
AX_TESTCASE ?= junior
ARCH ?= riscv64
AX_TESTCASES_LIST=$(shell cat ./apps/$(AX_TESTCASE)/testcase_list | tr '\n' ',')
FEATURES ?= fp_simd
RUSTDOCFLAGS := -Z unstable-options --enable-index-page -D rustdoc::broken_intra_doc_links -D missing-docs

DIR := $(shell basename $(PWD))
OUT_ELF := $(DIR)_riscv64-qemu-virt.elf
OUT_BIN := $(DIR)_riscv64-qemu-virt.bin

ifneq ($(filter $(MAKECMDGOALS),doc_check_missing),) # make doc_check_missing
    export RUSTDOCFLAGS
else ifeq ($(filter $(MAKECMDGOALS),clean user_apps ax_root),) # Not make clean, user_apps, ax_root
    export AX_TESTCASES_LIST
endif

all: test_build

ax_root:
	@./scripts/set_ax_root.sh $(AX_ROOT)

user_apps:
	@make -C ./apps/$(AX_TESTCASE) ARCH=$(ARCH) build
	@./build_img.sh -a $(ARCH) -file ./apps/$(AX_TESTCASE)/build/$(ARCH)
	@mv ./disk.img $(AX_ROOT)/disk.img

test:
	@./scripts/app_test.sh

test_build: ax_root
	@rustup override set nightly-2024-02-03-x86_64-unknown-linux-gnu
	@make -C $(AX_ROOT) A=$(PWD) ARCH=$(ARCH) FEATURES=$(FEATURES) BLK=y NET=y BUS=mmio build
	@cp $(OUT_BIN) kernel-qemu

build run justrun debug disasm: ax_root user_apps
	@make -C $(AX_ROOT) A=$(PWD) ARCH=$(ARCH) FEATURES=$(FEATURES) BLK=y NET=y $@

clean: ax_root
	@make -C $(AX_ROOT) A=$(PWD) ARCH=$(ARCH) clean
	@cargo clean

doc_check_missing:
	@cargo doc --no-deps --all-features --workspace

.PHONY: all ax_root build run justrun debug disasm clean test_build
