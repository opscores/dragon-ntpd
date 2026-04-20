# ============================================
# Build Configuration
# ============================================

CC ?= cc
TARGET := dntpd
BUILD_TYPE ?= release

SRC := main.c config.c ntp_packet.c ntp_algorithms.c filter.c time_sync.c socket.c threads.c ido.c mode_handler.c network4.c network6.c leap_second.c ntpd.c
HDR := ntpd.h config.h main.h threads.h mode_handler.h network4.h network6.h ido.h socket.h ntp_packet.h ntp_algorithms.h time_sync.h filter.h leap_second.h
ALL_SRC := $(SRC) *.c
ALL_HDR := $(HDR) *.h

# Base flags
CSTD := -std=c11
WARN := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wundef
BASE_CFLAGS := $(CSTD) $(WARN)
BASE_LDFLAGS :=
LDLIBS := -lm -lpthread

# Security flags (only for release)
SECURITY_CFLAGS := -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
SECURITY_LDFLAGS := -Wl,-z,relro,-z,now

# Debug flags
DEBUG_CFLAGS := -g -O0

# Release flags
RELEASE_CFLAGS := -O2 -DNDEBUG

# ============================================
# Build type selection
# ============================================

# Set CFLAGS and LDFLAGS based on BUILD_TYPE
ifeq ($(BUILD_TYPE),debug)
    CFLAGS := $(BASE_CFLAGS) $(DEBUG_CFLAGS)
    LDFLAGS := $(BASE_LDFLAGS)
else
    CFLAGS := $(BASE_CFLAGS) $(RELEASE_CFLAGS) $(SECURITY_CFLAGS)
    LDFLAGS := $(BASE_LDFLAGS) $(SECURITY_LDFLAGS)
endif

# ============================================
# Targets
# ============================================

.PHONY: all debug release asan ubsan clean tidy format check lint lint-fix

all: release

debug:
	$(MAKE) BUILD_TYPE=debug $(TARGET)

release:
	$(MAKE) BUILD_TYPE=release $(TARGET)

asan: CFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=address
asan: $(TARGET)

ubsan: CFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=undefined -fno-omit-frame-pointer
ubsan: LDFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=undefined
ubsan: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

tidy:
	@for f in $(SRC); do \
		echo "Checking $$f..."; \
		clang-tidy -p . "$$f" -- $(CC) $(CFLAGS) -c "$$f" 2>/dev/null || true; \
	done

lint:
	@echo "=== Running clang-analyzer ===" && \
	clang-analyzer -analyze $(SRC) -- $(CC) $(CFLAGS) -c $(SRC) 2>&1 | grep -v "warning:" || true
	@echo "=== Running cppcheck ===" && \
	cppcheck --enable=all --suppress=*:*:*.h --inline-suppr $(SRC) 2>&1 || true

lint-fix:
	@echo "=== Formatting code ===" && \
	clang-format -i $(SRC) $(HDR) && \
	echo "=== Formatting complete ==="

format: lint-fix

check: release
	@echo "=== Testing dntpd ===" && \
	./$(TARGET) -h && \
	./$(TARGET) -v && \
	./$(TARGET) -h 2>&1 | head -1

clean:
	rm -f $(TARGET)
	rm -f *.o
