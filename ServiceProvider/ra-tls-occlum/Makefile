BIN_PATH := bin
OBJ_PATH := obj
SRC_PATH := src
LIB_PATH := lib
INC_PATH := include
SCRIPT_PATH := Scripts
SGX_SDK_INC_PATH := /opt/intel/sgxsdk/include

CC := gcc
CCFLAGS := -I$(INC_PATH) -I$(SGX_SDK_INC_PATH)
CCOBJFLAGS := $(CCFLAGS) -c

TARGET_NAME := ra-tls-server
TARGET := $(BIN_PATH)/$(TARGET_NAME)

SRC := $(foreach x, $(SRC_PATH), $(wildcard $(addprefix $(x)/*,.c*)))
OBJ := $(addprefix $(OBJ_PATH)/, $(addsuffix .o, $(notdir $(basename $(SRC)))))

CLEAN_LIST := $(BIN_PATH)  $(OBJ_PATH) $(LIB_PATH)

.PHONY: all mkdir clean

default: mkdir all

mkdir:
	@mkdir -p $(BIN_PATH) $(OBJ_PATH) $(LIB_PATH)

all: $(TARGET)

$(TARGET) :=  $(OBJ) mbedtls/.mbedtls_built $(LIB_PATH)/libra_tls_attest.so
	$(CC) $(CCFLAGS) -o $@ $(OBJ)

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