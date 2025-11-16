# Compiler and flags
CC = gcc
CFLAGS = -g -Wall -Wextra -D_GNU_SOURCE -fno-omit-frame-pointer -rdynamic
CFLAGS_EX = -g
SHARED_FLAGS = -shared -fPIC
LDFLAGS = -ldl -lpthread

# Directories
BUILD_DIR = build
DETECTOR_DIR = src/detector
OBJ_DIR = src/test

# Targets
TEST_PROGRAM = $(BUILD_DIR)/leak_test
LIB_DETECTOR = $(BUILD_DIR)/libleak_detector.so
LIB_DETECTOR_LINE = $(BUILD_DIR)/libleak_detector_line.so
LIB_DETECTOR_BASE = $(BUILD_DIR)/libleak_detector_base.so
TARGETS = $(TEST_PROGRAM) $(LIB_DETECTOR) $(LIB_DETECTOR_LINE) $(LIB_DETECTOR_BASE)
ANA_FILE = ./leak_analysis.txt

# Default target
all: $(BUILD_DIR) $(TARGETS)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build shared libraries
$(LIB_DETECTOR): $(DETECTOR_DIR)/leak_detector.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SHARED_FLAGS) $< -o $@ $(LDFLAGS)

$(LIB_DETECTOR_LINE): $(DETECTOR_DIR)/leak_detector_line.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SHARED_FLAGS) $< -o $@ $(LDFLAGS)

$(LIB_DETECTOR_BASE): $(DETECTOR_DIR)/leak_detector_base.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(SHARED_FLAGS) $< -o $@ $(LDFLAGS)

# Build test programs - 修正路径
$(BUILD_DIR)/test: $(OBJ_DIR)/test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS_EX) $< -o $@

$(BUILD_DIR)/leak_test: $(OBJ_DIR)/test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS_EX) $< -o $@

$(BUILD_DIR)/dlopen_test: $(OBJ_DIR)/dlopen_test.c | $(BUILD_DIR)
	$(CC) $(CFLAGS_EX) $< -o $@ -ldl -lpthread

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(ANA_FILE)
	rm -f heaptrack.*.*.gz

# Test targets
test_run: $(LIB_DETECTOR) $(TEST_PROGRAM)
	LD_PRELOAD="$(CURDIR)/$(LIB_DETECTOR)" $(CURDIR)/$(TEST_PROGRAM)

test_line_run: $(LIB_DETECTOR_LINE) $(TEST_PROGRAM)
	LD_PRELOAD="$(CURDIR)/$(LIB_DETECTOR_LINE)" $(CURDIR)/$(TEST_PROGRAM)

test_base_run: $(LIB_DETECTOR_BASE) $(TEST_PROGRAM)
	LD_PRELOAD="$(CURDIR)/$(LIB_DETECTOR_BASE)" $(CURDIR)/$(TEST_PROGRAM)

test_ana: $(ANA_FILE)
	./scripts/analyze_leaks.sh $(ANA_FILE)

test_val_run: $(TEST_PROGRAM)
	valgrind --leak-check=full --show-leak-kinds=all $(CURDIR)/$(TEST_PROGRAM)

test_heaptrack: $(TEST_PROGRAM)
	heaptrack $(CURDIR)/$(TEST_PROGRAM)

# Build all test programs
tests: $(BUILD_DIR)/test $(BUILD_DIR)/leak_test

tests-all: tests $(BUILD_DIR)/dlopen_test

# Help information
help:
	@echo "Available targets:"
	@echo "  all           - Build all targets (default)"
	@echo "  clean         - Clean build files"
	@echo "  test_run      - Run test with full detector"
	@echo "  test_line_run - Run test with line number detector"
	@echo "  test_base_run - Run test with base detector"
	@echo "  test_val_run  - Run test with valgrind"
	@echo "  test_heaptrack- Run test with heaptrack"
	@echo "  test_ana      - Analyze leak report"
	@echo "  tests         - Build all test programs"
	@echo "  help          - Show this help message"

.PHONY: all clean test_run test_line_run test_base_run test_val_run test_heaptrack test_ana tests help