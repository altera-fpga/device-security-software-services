CC = g++
CC_ARM = aarch64-linux-gnu-g++
CFLAGS = -std=c++17 -Wall -Wextra -Werror -O3 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -Wformat-security -fno-strict-overflow -fno-delete-null-pointer-checks -static-libstdc++ -static-libgcc
CFLAGS_DEBUG = -std=c++17 -g -O0 -DDEBUG -static-libstdc++ -static-libgcc
UNIT_TEST_FLAG = -DLIB_FCS_MOCK
EXE_NAME = fcsServer
TEST_EXE_NAME = test.x86
BUILD_DIR = ./out
FCS_FILTER_INCLUDE_DIR = ./FCSFilter/include
FCS_FILTER_SOURCE_DIR = ./FCSFilter/src
FCS_SERVER_SOURCE_DIR = ./FCSServer/src
FCS_SERVER_INCLUDE_FLAGS = -I$(FCS_FILTER_INCLUDE_DIR) -I$(FCS_FILTER_SOURCE_DIR) -I$(FCS_SERVER_SOURCE_DIR)
FCS_SERVER_WITH_SIMULATOR_INCLUDE_FLAGS = $(FCS_SERVER_INCLUDE_FLAGS)  -I./FCSFilter/test/mocks
SRC_FILES := $(wildcard ./FCSFilter/test/mocks/*.cpp)
SRC_FILES := $(filter-out ./FCSFilter/test/mocks/fcsMock.cpp, $(SRC_FILES))
MOCK_FILES = ./FCSFilter/test/mocks/sys/*.cpp $(SRC_FILES)
SPDM_SIM = 1.5
OBJS := ./out/mock/fcsMock.o ./out/src/CommandHeader.o ./out/src/Logger.o ./out/mock/FcsSimulator.o
export LD_LIBRARY_PATH := $(LD_LIBRARY_PATH):./$(BUILD_DIR)

ifeq ($(DEBUG), 1)
        CFLAGS=$(CFLAGS_DEBUG)
endif

.PHONY: build all x86 x86sim x86sim1.2 x86sim1.5 aarch64 test clean

build: clean x86 aarch64

all: clean x86 aarch64 test

create_build_dir:
	mkdir -p $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/src
	mkdir -p $(BUILD_DIR)/mock

$(BUILD_DIR)/src/%.o: ./FCSFilter/src/%.cpp
	$(CC) -fPIC -Wall -Wextra -Werror -g $(FCS_SERVER_WITH_SIMULATOR_INCLUDE_FLAGS) -c $^ -o $@

$(BUILD_DIR)/mock/%.o: ./FCSFilter/test/mocks/%.cpp
	$(CC) -fPIC -Wall -Wextra -Werror -g $(FCS_SERVER_WITH_SIMULATOR_INCLUDE_FLAGS) -c $^ -o $@

$(BUILD_DIR)/mock/combined.o: $(OBJS)
	ld -r $^ -o $@

$(BUILD_DIR)/libFCSMock.so: $(BUILD_DIR)/mock/combined.o
	$(CC) -shared -o $(BUILD_DIR)/libFCSMock.so $^

x86: create_build_dir
	$(CC) $(CFLAGS) $(FCS_SERVER_INCLUDE_FLAGS) -o $(BUILD_DIR)/$(EXE_NAME).x86 $(FCS_FILTER_SOURCE_DIR)/*.cpp $(FCS_SERVER_SOURCE_DIR)/*.cpp -ldl

aarch64: create_build_dir
	$(CC_ARM) $(CFLAGS) $(FCS_SERVER_INCLUDE_FLAGS) -o $(BUILD_DIR)/$(EXE_NAME).aarch64 $(FCS_FILTER_SOURCE_DIR)/*.cpp $(FCS_SERVER_SOURCE_DIR)/*.cpp -ldl
	cp ./FCSServer/install.sh $(BUILD_DIR)/
	cp ./FCSServer/fcsServer.service $(BUILD_DIR)/
	cp $(BUILD_DIR)/$(EXE_NAME).aarch64 $(BUILD_DIR)/$(EXE_NAME)

test: create_build_dir $(BUILD_DIR)/libFCSMock.so
	./build_gtest.sh
	$(CC) $(CFLAGS) $(FCS_SERVER_WITH_SIMULATOR_INCLUDE_FLAGS) $(UNIT_TEST_FLAG) -I./gtest/include ./gtest/lib/libgtest_main.a ./gtest/lib/libgtest.a -o $(BUILD_DIR)/$(TEST_EXE_NAME) $(MOCK_FILES) $(FCS_FILTER_SOURCE_DIR)/*.cpp ./FCSFilter/test/*.cpp -pthread -ldl
	$(BUILD_DIR)/$(TEST_EXE_NAME)

clean:
	$(RM) -r ./out
