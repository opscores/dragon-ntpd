# Makefile для тестирования threads.c

CC = cc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wformat=2 -O2 -DNDEBUG -fno-canonical-system-headers -fno-common
LDFLAGS = -lpthread -lm

# Файлы исходного кода
SRCS = threads.c threads_test.c
OBJS = threads.o threads_test.o

# Выходной файл
TARGET = threads_test

# Путь к заголовочным файлам
INCLUDES = -I. -I../

# Целевая директория
BINDIR = .

# Правила сборки
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c threads.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# Чистка
clean:
	rm -f $(OBJS) $(TARGET)

# Тестирование
test: $(TARGET)
	@echo "=== Тестирование threads ==="
	@./$(TARGET)
	@echo "=== Тестирование завершено ==="

# Установка
install: $(TARGET)
	install -m 755 $(TARGET) $(BINDIR)/

.PHONY: clean test install
