CC = gcc
CFLAGS = -Wall -O2 -Isrc/core

# Directories
SRC_CORE = src/core
SRC_APPS = src/apps
SRC_TOOLS = src/tools
BIN_DIR = bin

# Core Protocol Files
CORE_SRC = $(SRC_CORE)/uavlink.c $(SRC_CORE)/uavlink_fast.c $(SRC_CORE)/uavlink_compress.c \
           $(SRC_CORE)/uavlink_hw_crypto.c $(SRC_CORE)/monocypher.c $(SRC_CORE)/uavlink_keymanager.c

# Platform-specific flags
ifeq ($(OS),Windows_NT)
    LDFLAGS = -lws2_32 -ladvapi32 -lm
    EXT = .exe
else
    LDFLAGS = -lm
    EXT =
endif

all: benchmark receiver simulator key_example

benchmark: $(SRC_TOOLS)/uavlink_benchmark.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/uavlink_benchmark$(EXT) $(SRC_TOOLS)/uavlink_benchmark.c $(CORE_SRC) $(LDFLAGS)

receiver: $(SRC_APPS)/gcs_receiver.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/gcs_receiver$(EXT) $(SRC_APPS)/gcs_receiver.c $(CORE_SRC) $(LDFLAGS)

simulator: $(SRC_APPS)/uav_simulator.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/uav_simulator$(EXT) $(SRC_APPS)/uav_simulator.c $(CORE_SRC) $(LDFLAGS)

key_example: $(SRC_TOOLS)/key_example.c $(CORE_SRC)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/key_example$(EXT) $(SRC_TOOLS)/key_example.c $(CORE_SRC) $(LDFLAGS)

clean:
	rm -f bin/* src/core/*.o src/apps/*.o src/tools/*.o

.PHONY: all benchmark receiver simulator key_example clean
