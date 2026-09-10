# Host tests for the portable DePIN codec (DepinCodec.cpp).
#
#   make run                      # build + run against ../fixtures/vectors.txt
#   make UNEURAI=/path/to/uNeurai # override the uNeurai checkout
#
# Needs: g++, OpenSSL dev headers (libssl-dev), a uNeurai checkout >= 0.0.10.
# The Arduino adapter (NeuraiDepinMsg.cpp, NeuraiDepinClient.cpp) is NOT built
# here: it depends on Arduino/mbedTLS and is compiled for the ESP32 target.

UNEURAI ?= ../../../../lib/uNeurai
LIB      = ../../src
BUILD    = build

CXX      = g++
CC       = gcc
CPPFLAGS = -I$(UNEURAI)/src -I$(LIB) -DUSE_STDONLY -DUXNA_TEST -g -O1 -Wall -Wextra -Wno-unused-parameter -Wno-write-strings
CFLAGS   = -I$(UNEURAI)/src -g -O1

UNEURAI_CPP = $(wildcard $(UNEURAI)/src/*.cpp)
UNEURAI_C   = $(wildcard $(UNEURAI)/src/utility/trezor/*.c) $(wildcard $(UNEURAI)/src/utility/*.c)
CODEC_CPP   = $(LIB)/DepinCodec.cpp
HOST_CPP    = DepinCryptoOpenSSL.cpp
TEST_CPP    = test_codec.cpp

OBJS = $(patsubst $(UNEURAI)/src/%.cpp,$(BUILD)/un/%.cpp.o,$(UNEURAI_CPP)) \
       $(patsubst $(UNEURAI)/src/%.c,$(BUILD)/un/%.c.o,$(UNEURAI_C)) \
       $(BUILD)/DepinCodec.cpp.o $(BUILD)/DepinCryptoOpenSSL.cpp.o

.PHONY: all run clean
all: $(BUILD)/test_codec

run: $(BUILD)/test_codec
	./$(BUILD)/test_codec ../fixtures/vectors.txt

$(BUILD)/un/%.cpp.o: $(UNEURAI)/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) -w $< -o $@

$(BUILD)/un/%.c.o: $(UNEURAI)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -w $< -o $@

$(BUILD)/DepinCodec.cpp.o: $(CODEC_CPP) $(LIB)/DepinCodec.h $(LIB)/DepinCrypto.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

$(BUILD)/DepinCryptoOpenSSL.cpp.o: $(HOST_CPP) $(LIB)/DepinCrypto.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

$(BUILD)/test_codec: $(TEST_CPP) $(OBJS) $(LIB)/DepinCodec.h
	$(CXX) $(CPPFLAGS) $(TEST_CPP) $(OBJS) -lcrypto -o $@

clean:
	rm -rf $(BUILD)
