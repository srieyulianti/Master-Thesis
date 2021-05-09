BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
LIB_PATH := lib
INC_PATH := include
SCRIPT_PATH := scripts
SGX_SDK_INC_PATH := /opt/intel/sgxsdk/include
MBEDTLS_PATH := mbedtls/include
TFLOW_PATH := tensorflow_src
TENSORFLOW_PATH := tensorflow_src/bazel-bin/tensorflow/lite/c

CC := gcc
CCFLAGS := -I$(INC_PATH) -I$(SGX_SDK_INC_PATH) -I$(MBEDTLS_PATH) -I$(TFLOW_PATH) -fPIC
CCOBJFLAGS := $(CCFLAGS) -c

TARGET_NAME := ra-tls-server
TARGET := $(BIN_PATH)/$(TARGET_NAME)

CLEAN_LIST := $(BIN_PATH) $(OBJ_PATH) $(LIB_PATH) mbedtls ra_tls_instance mbedtls-2.26.0.tar.gz

.PHONY: all mkdir clean

default: mkdir all

mkdir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH) $(LIB_PATH)

all: mbedtls/.mbedtls_built $(LIB_PATH)/.mbedtls_libs_copied $(TARGET)


############################# MBEDTLS DEPENDENCY ##############################

MBEDTLS_VERSION ?= 2.26.0
MBEDTLS_SRC ?= mbedtls-$(MBEDTLS_VERSION).tar.gz
MBEDTLS_URI ?= \
	https://github.com/ARMmbed/mbedtls/archive \
	https://packages.grapheneproject.io/distfiles
MBEDTLS_CHECKSUM ?= 35d8d87509cd0d002bddbd5508b9d2b931c5e83747d087234cc7ad551d53fe05

ifeq ($(DEBUG),1)
MBED_BUILD_TYPE=Debug
else
MBED_BUILD_TYPE=Release
endif

$(MBEDTLS_SRC):
	$(SCRIPT_PATH)/download --output $@ $(foreach mirror,$(MBEDTLS_URI),--url $(mirror)/$(MBEDTLS_SRC)) --sha256 $(MBEDTLS_CHECKSUM)

mbedtls/.mbedtls_downloaded: $(MBEDTLS_SRC)
	tar --touch -xzf $(MBEDTLS_SRC)
	mv mbedtls-mbedtls-$(MBEDTLS_VERSION) mbedtls
	touch $@

mbedtls/.mbedtls_configured: mbedtls/.mbedtls_downloaded
	mkdir -p mbedtls/install
	cd mbedtls && ./scripts/config.pl set MBEDTLS_CMAC_C MBEDTLS_ERROR_C
	touch $@

mbedtls/.mbedtls_built: mbedtls/.mbedtls_configured
	$(MAKE) -C mbedtls SHARED=1 DESTDIR=install install .
	touch $@

$(LIB_PATH)/.mbedtls_libs_copied: mbedtls/.mbedtls_built
	cd $(LIB_PATH)					&& \
	cp ../mbedtls/install/lib/libmbedcrypto.so.* .	&& \
	ln -s libmbedcrypto.so.* libmbedcrypto.so	&& \
	cp ../mbedtls/install/lib/libmbedtls.so.* .	&& \
	ln -s libmbedtls.so.* libmbedtls.so		&& \
	cp ../mbedtls/install/lib/libmbedx509.so.* .	&& \
	ln -s libmbedx509.so.* libmbedx509.so

	touch $@

############################ RA-TLS-SERVER DEPENDENCY ###########################

LDFLAGS += -Lmbedtls/install/lib  
LFLAGS += -Wl,-ldl -lm -lpthread -ljpeg -lrt 

$(OBJ_PATH)/quote_generation.o: $(SRC_PATH)/quote_generation.c
	@echo $(CC) $(CCOBJFLAGS) $< -o $@
	$(CC) $(CCOBJFLAGS) $< -o $@
	@echo "CC <= $<"

$(OBJ_PATH)/ra_tls_attest.o: $(SRC_PATH)/ra_tls_attest.c $(OBJ_PATH)/quote_generation.o
	@echo $(CC) $(CCOBJFLAGS) $< -o $@
	$(CC) $(CCOBJFLAGS) $< -o $@
	@echo "CC <= $<"

$(LIB_PATH)/libra_tls_attest.so: $(OBJ_PATH)/ra_tls_attest.o $(OBJ_PATH)/quote_generation.o
	@echo $(CC) $^ $(LDFLAGS) -l:libmbedx509.a -l:libmbedcrypto.a -shared -o $@
	$(CC) $^ $(LDFLAGS) -l:libmbedx509.a -l:libmbedcrypto.a -shared -o $@
	@echo "CC <= $<"

$(LIB_PATH)/libtensorflowlite_c.so:
	cp -f $(TENSORFLOW_PATH)/libtensorflowlite_c.so $@
	@echo "Copy libtensorflowlite_c.so to lib directory"

$(OBJ_PATH)/ujpeg.o: $(SRC_PATH)/ujpeg.c 
	@echo $(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS)
	$(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS)
	@echo "CC <= $<"

$(OBJ_PATH)/object_detector.o: $(SRC_PATH)/object_detector.c $(LIB_PATH)/libtensorflowlite_c.so $(OBJ_PATH)/ujpeg.o
	@echo $(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS)
	$(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS)
	@echo "CC <= $<"

$(OBJ_PATH)/server.o: $(SRC_PATH)/server.c $(LIB_PATH)/libra_tls_attest.so $(OBJ_PATH)/object_detector.o $(OBJ_PATH)/ujpeg.o
	@echo $(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS) 
	$(CC) $(CCOBJFLAGS) $< -o $@ $(LFLAGS) 
	@echo "CC <= $<"

$(TARGET): $(OBJ_PATH)/server.o $(OBJ_PATH)/object_detector.o $(OBJ_PATH)/ujpeg.o $(LIB_PATH)/libmbedcrypto.so $(LIB_PATH)/libmbedtls.so $(LIB_PATH)/libmbedx509.so $(LIB_PATH)/libtensorflowlite_c.so	
	@echo $(CC) $^ -o $@ $(LFLAGS)
	$(CC) $^ -o $@ $(LFLAGS) 
	@echo "CC <= $^"


clean:
	@rm -rf $(CLEAN_LIST)


