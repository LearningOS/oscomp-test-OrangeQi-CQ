ARCH ?= riscv64

RV_TESTCASES := https://github.com/Starry-OS/testcases/releases/download/v0.2/riscv_syscall_testcases.tar.xz

ifeq ($(ARCH), riscv64)
	PLATFORM_NAME := riscv64-qemu-virt
else
	$(error "ARCH" must be "riscv64")
endif

build_dir := build/$(ARCH)

build:
	@mkdir -p $(build_dir)
	@if [ -z "$(wildcard $(build_dir)/*)" ]; then \
		wget $(RV_TESTCASES) -O $(build_dir)/riscv-syscall-testcases.tar.gz; \
		tar -xvf $(build_dir)/riscv-syscall-testcases.tar.gz -C $(build_dir); \
	fi

clean:
	@rm -rf $(build_dir)

.PHONY: build clean
