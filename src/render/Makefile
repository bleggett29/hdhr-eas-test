# Makefile for the ATSC 3.0 LLS Parser with AC-4 Parser

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g -Ilibhdhomerun $(shell pkg-config --cflags libxml-2.0 libavcodec libavutil)
HDHR_LIB ?= -lhdhomerun
LDFLAGS = $(shell pkg-config --libs libxml-2.0 libavcodec libavutil) -lpcap -lz -lssl -lcrypto $(HDHR_LIB) -lm

# Source files
SRCS = a3render.c mmt.c input.c plp.c l1_detail_parser.c crypto.c esg.c bps.c egps.c utility.c direct_parsers.c eas.c

# Object files (automatically derived from SRCS)
OBJS = $(SRCS:.c=.o)

# Header files (for dependency tracking)
HEADERS = structures.h mmt.h input.h plp.h l1_detail_parser.h crypto.h esg.h bps.h egps.h utility.h direct_parsers.h eas.h

# Executable
TARGET = render

# Default target: build the executable
all: $(TARGET)

# Build the executable from object files
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Pattern rule for building object files from C source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Target to clean up the build directory
clean:
	rm -f $(TARGET) $(OBJS)

# Target to rebuild everything from scratch
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild
