ARCH ?= x86_64

# Target
ifeq ($(ARCH), x86_64)
  TARGET := x86_64-unknown-none
else ifeq ($(ARCH), riscv64)
  TARGET := riscv64gc-unknown-none-elf
else ifeq ($(ARCH), aarch64)
  TARGET := aarch64-unknown-none
endif

RUSTDOCFLAGS := -Z unstable-options --enable-index-page -D rustdoc::broken_intra_doc_links -D missing-docs
clippy_args := -A clippy::new_without_default

export RUSTDOCFLAGS

clippy:
ifeq ($(origin ARCH), command line)
	@cargo clippy --all-features --target $(TARGET) -- $(clippy_args)
else
	@cargo clippy --all-features -- $(clippy_args)
endif

build:
ifeq ($(origin ARCH), command line)
	@cargo build --release --target $(TARGET)
else
	@cargo build --release
endif

doc:
	@cargo doc --no-deps --all-features --workspace