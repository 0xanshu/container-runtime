# Makefile for libprocfs — static /proc + cgroup reading library
#
# Extracted from the process-inspector project as a standalone static library.
# Two consumers link it: process-inspector (the original CLI) and minicontainer
# (the container runtime's inspect/stats/top/netstat subcommands).
#
# ---------------------------------------------------------------------------
# Flag / hygiene policy
# ---------------------------------------------------------------------------
#   * CFLAGS mirror the donor exactly: -Wall -Wextra -Werror -pedantic -std=c11.
#     This keeps the extraction mechanical — a file that compiled clean in
#     process-inspector compiles clean here for the same reasons, so any new
#     warning is unambiguously something the extraction introduced.
#
#   * NO -D_GNU_SOURCE and NO -D_POSIX_C_SOURCE on the command line. The donated
#     sources that need POSIX.1-2008 interfaces (readlink, dirent traversal)
#     carry their own per-file `#define _POSIX_C_SOURCE 200809L`. Those defines
#     are source-level and travel with the .c files, so the library is
#     self-sufficient regardless of which Makefile compiles it. The donor uses
#     no `d_type`, so _GNU_SOURCE is genuinely not required.
#
#   * Sanitizers are SPLIT. The shipped `libprocfs.a` is built WITHOUT
#     sanitizers so it links cleanly into the (non-sanitized) minicontainer
#     binary — ASan is whole-program and an instrumented archive cannot link
#     into a non-instrumented consumer. ASan/UBSan live ONLY on the `test`
#     target, which compiles the library sources directly into each test binary
#     and never touches `libprocfs.a`. That keeps the shippable archive
#     provably sanitizer-free even when `make test` is run from clean.

CC      = gcc
AR      = ar
CFLAGS  = -Wall -Wextra -Werror -pedantic -std=c11
LDFLAGS =

SRC_DIR   = src
INC_DIR   = include
TEST_DIR  = tests
BUILD_DIR = build

INCLUDES  = -I$(INC_DIR)

# Auto-discovered library sources (none yet at scaffold time).
SRC_FILES = $(wildcard $(SRC_DIR)/*.c)
LIB_OBJS  = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC_FILES))

# One test binary per tests/test_*.c.
TEST_FILES = $(wildcard $(TEST_DIR)/test_*.c)
TEST_BINS  = $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/%,$(TEST_FILES))

LIBPROCFS = libprocfs.a

.PHONY: all clean test
all: $(LIBPROCFS)

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile library sources (no sanitizers — this feeds the shippable archive).
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Archive. `ar rcs` with zero members produces a valid empty archive at
# scaffold time; it fills in as src/*.c files land.
$(LIBPROCFS): $(LIB_OBJS)
	$(AR) rcs $@ $(LIB_OBJS)
	@echo "Built $(LIBPROCFS) ($(words $(LIB_OBJS)) object(s))"

# Tests: compile the library sources together with each test driver, WITH
# sanitizers. Deliberately does NOT depend on $(LIBPROCFS) — the shippable
# archive stays sanitizer-free no matter how tests are built.
test: CFLAGS  += -g -fsanitize=address,undefined
test: LDFLAGS += -fsanitize=address,undefined
test: $(TEST_BINS)
	@if [ -z "$(TEST_BINS)" ]; then echo "No tests yet."; else \
		for t in $(TEST_BINS); do echo "== $$t =="; ./$$t || exit 1; done; \
		echo "All libprocfs tests passed!"; fi

$(BUILD_DIR)/test_%: $(TEST_DIR)/test_%.c $(SRC_FILES) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(SRC_FILES) $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR) $(LIBPROCFS)