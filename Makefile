CC ?= cc

TARGET := ntpd
SRC := main.c config.c ntp_packet.c ntp_algorithms.c filter.c time_sync.c socket.c threads.c ido.c mode_handler.c
HDR := network.h ntpd.h ntp_packet.h threads.h socket.h time_sync.h filter.h config.h mode_handler.h ido.h

CSTD := -std=c11

WARN := -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -Wundef

BASE_CFLAGS := $(CSTD) $(WARN)
BASE_LDFLAGS :=
LDLIBS := -lm -lpthread

.PHONY: all debug release asan ubsan clean tidy format check

all: release

debug: CFLAGS := $(BASE_CFLAGS) -O0 -g3
debug: LDFLAGS := $(BASE_LDFLAGS)
debug: $(TARGET)

release: CFLAGS := $(BASE_CFLAGS) -O2 -DNDEBUG
release: LDFLAGS := $(BASE_LDFLAGS)
release: $(TARGET)

asan: CFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS := $(BASE_LDFLAGS) -fsanitize=address
asan: $(TARGET)

ubsan: CFLAGS := $(BASE_CFLAGS) -O1 -g3 -fsanitize=undefined -fno-omit-frame-pointer
ubsan: LDFLAGS := $(BASE_LDFLAGS) -fsanitize=undefined
ubsan: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

tidy:
	@for f in $(SRC); do \
		echo "Checking $$f..."; \
		clang-tidy -p . "$$f" -- $(CC) $(CFLAGS) -c "$$f" 2>/dev/null || true; \
	done

format:
	clang-format -i $(SRC) $(HDR)

check: release
	@echo "=== Testing ntpd ===" && \
	./$(TARGET) -h && \
	./$(TARGET) -v && \
	./$(TARGET) -h 2>&1 | head -1

clean:
	rm -f $(TARGET)
	rm -f *.o