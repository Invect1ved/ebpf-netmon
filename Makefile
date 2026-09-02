# eBPF NetMon — Linux build (libbpf + clang CO-RE)
#
# Prerequisites: clang, llvm, libbpf, bpftool, linux headers / BTF
#   sudo ./scripts/setup_deps_ubuntu.sh
#   ./scripts/gen_vmlinux.sh

APP       := netmon
BPF_DIR   := bpf
SRC_DIR   := src
INC_DIR   := include
BUILD_DIR := build
BIN_DIR   := bin

BPF_SRC   := $(BPF_DIR)/netmon.bpf.c
BPF_OBJ   := $(BUILD_DIR)/netmon.bpf.o
BPF_SKEL  := $(BUILD_DIR)/netmon.skel.h

USER_SRCS := $(SRC_DIR)/main.c $(SRC_DIR)/agent.c
USER_OBJS := $(BUILD_DIR)/main.o $(BUILD_DIR)/agent.o
BIN       := $(BIN_DIR)/$(APP)

CLANG     ?= clang
CC        ?= gcc
BPFTOOL   ?= bpftool
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

LIBBPF_CFLAGS  := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS  := $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(LIBBPF_LDLIBS),)
  LIBBPF_LDLIBS := -lbpf -lelf -lz
endif

CFLAGS    := -O2 -g -Wall -Wextra -I$(INC_DIR) -I$(BUILD_DIR) $(LIBBPF_CFLAGS)
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) \
	-I$(INC_DIR) -I$(BPF_DIR) \
	-Wall -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

.PHONY: all clean dirs

all: dirs $(BIN)

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(BPF_DIR)/vmlinux.h:
	@echo "Missing bpf/vmlinux.h — run: ./scripts/gen_vmlinux.sh" >&2
	@exit 1

$(BPF_OBJ): $(BPF_SRC) $(INC_DIR)/netmon.h $(BPF_DIR)/vmlinux.h | dirs
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< name netmon > $@

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/agent.h $(INC_DIR)/netmon.h $(BPF_SKEL) | dirs
	$(CC) $(CFLAGS) -c $(SRC_DIR)/main.c -o $@

$(BUILD_DIR)/agent.o: $(SRC_DIR)/agent.c $(SRC_DIR)/agent.h $(INC_DIR)/netmon.h $(BPF_SKEL) | dirs
	$(CC) $(CFLAGS) -c $(SRC_DIR)/agent.c -o $@

$(BIN): $(USER_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBBPF_LDLIBS)

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
