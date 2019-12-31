CC=gcc
CFLAGS=-std=c11 -Wall -O3
LDFLAGS=
OBJ=$(patsubst %.c, %.o, $(wildcard *.c))
TARGET=huff
.PHONY: all clean
all: $(TARGET)
$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) -o $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f $(OBJ) $(TARGET)
