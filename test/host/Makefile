# Host tests for the portable DePIN codec (DepinCodec.cpp).
#
#   make run                      # build + run against ../fixtures/vectors.txt
#   make UNEURAI=/path/to/uNeurai # override the uNeurai checkout
#
# Needs: g++, OpenSSL dev headers (libssl-dev), a uNeurai checkout >= 0.0.10.
# The Arduino adapter (NeuraiDepinMsg.cpp, NeuraiDepinClient.cpp) is NOT built
# here: it depends on Arduino/mbedTLS and is compiled for the ESP32 target.

UNEURAI ?= ../../../../lib/uNeurai
ARDUINOJSON ?= ../../../ESP32-testing/.pio/libdeps/lilygo-t-display-s3-dev/ArduinoJson
LIB      = ../../src
BUILD    = build

CXX      = g++
CC       = gcc
CPPFLAGS = -I$(UNEURAI)/src -I$(LIB) -I$(ARDUINOJSON)/src -DUSE_STDONLY -DUXNA_TEST -g -O1 -Wall -Wextra -Wno-unused-parameter -Wno-write-strings
CFLAGS   = -I$(UNEURAI)/src -g -O1

UNEURAI_CPP = $(wildcard $(UNEURAI)/src/*.cpp)
UNEURAI_C   = $(wildcard $(UNEURAI)/src/utility/trezor/*.c) $(wildcard $(UNEURAI)/src/utility/*.c)
LIB_CPP     = $(LIB)/DepinCodec.cpp $(LIB)/DepinAuth.cpp $(LIB)/DepinReply.cpp $(LIB)/DepinClient.cpp
HOST_CPP    = DepinCryptoOpenSSL.cpp
TESTS       = test_codec test_auth test_client

OBJS = $(patsubst $(UNEURAI)/src/%.cpp,$(BUILD)/un/%.cpp.o,$(UNEURAI_CPP)) \
       $(patsubst $(UNEURAI)/src/%.c,$(BUILD)/un/%.c.o,$(UNEURAI_C)) \
       $(patsubst $(LIB)/%.cpp,$(BUILD)/%.cpp.o,$(LIB_CPP)) $(BUILD)/DepinCryptoOpenSSL.cpp.o

.PHONY: all run clean
all: $(addprefix $(BUILD)/,$(TESTS))

run: all
	@for t in $(TESTS); do echo "== $$t"; ./$(BUILD)/$$t ../fixtures/vectors.txt || exit 1; done

$(BUILD)/un/%.cpp.o: $(UNEURAI)/src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) -w $< -o $@

$(BUILD)/un/%.c.o: $(UNEURAI)/src/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -w $< -o $@

$(BUILD)/%.cpp.o: $(LIB)/%.cpp $(LIB)/DepinCodec.h $(LIB)/DepinCrypto.h $(LIB)/DepinAuth.h $(LIB)/DepinReply.h $(LIB)/DepinClient.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

$(BUILD)/DepinCryptoOpenSSL.cpp.o: $(HOST_CPP) $(LIB)/DepinCrypto.h
	@mkdir -p $(dir $@)
	$(CXX) -c $(CPPFLAGS) $< -o $@

$(BUILD)/test_%: test_%.cpp $(OBJS) $(LIB)/DepinCodec.h $(LIB)/DepinAuth.h $(LIB)/DepinReply.h $(LIB)/DepinClient.h
	$(CXX) $(CPPFLAGS) $< $(OBJS) -lcrypto -o $@

clean:
	rm -rf $(BUILD)
