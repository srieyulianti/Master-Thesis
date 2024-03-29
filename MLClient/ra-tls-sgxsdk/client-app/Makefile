######## Intel(R) SGX SDK Settings ########
TOPDIR ?= ../
LIBDIR ?= $(TOPDIR)/build/lib
SGX_SDK ?= /opt/intel/sgxsdk
SGX_LIB ?= /usr/lib/x86_64-linux-gnu
SGX_MODE ?= HW
SGX_DEBUG ?= 1
SGX_ARCH ?= x64
WOLFSSL_ROOT ?= $(shell readlink -f $(TOPDIR)/wolfssl)
SGX_WOLFSSL_LIB ?= $(shell readlink -f $(WOLFSSL_ROOT)/IDE/LINUX-SGX)
SGX_RA_TLS_ROOT ?= $(shell readlink -f $(TOPDIR)/sgx-ra-tls)

ifdef ECDSA
SGX_DCAP ?= SGXDataCenterAttestationPrimitives
SGX_DCAP_INC := -I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/ql/inc \
		-I$(SGX_DCAP)/QuoteGeneration/quote_wrapper/common/inc  \
	        -I$(SGX_DCAP)/QuoteGeneration/pce_wrapper/inc \
		-I$(SGX_DCAP)/QuoteVerification/QVL/Src/AttestationLibrary/include \
		-I$(SGX_DCAP)/QuoteVerification/dcap_quoteverify/inc \
		-I$(SGX_DCAP)/QuoteGeneration/qpl/inc \
		-I../build/include \
		-I/usr/x86_64-linux-gnu/include \
		-I/usr/include/x86_64-linux-gnu 
endif

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g -ggdb -DSGX_DEBUG
else
        SGX_COMMON_CFLAGS += -O2
endif

######## App Settings ########


DCAP_Library_Name := sgx_dcap_ql
Urts_Library_Name := sgx_urts
Uae_Library_Name := sgx_quote_ex

Wolfssl_C_Extra_Flags := -DWOLFSSL_SGX -DUSE_WOLFSSL
ifdef ECDSA
	Wolfssl_C_Extra_Flags += -DRATLS_ECDSA
endif
ifdef LA
	Wolfssl_C_Extra_Flags += -DLA_REPORT
endif

Wolfssl_Include_Paths := -I$(WOLFSSL_ROOT) \
	-I$(WOLFSSL_ROOT)/wolfcrypt \
	-I../../curl-wolfssl/include

ifeq ($(HAVE_WOLFSSL_TEST), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/test
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_TEST
endif

ifeq ($(HAVE_WOLFSSL_BENCHMARK), 1)
	Wolfssl_Include_Paths += -I$(WOLFSSL_ROOT)/wolfcrypt/benchmark
	Wolfssl_C_Extra_Flags += -DHAVE_WOLFSSL_BENCHMARK
endif

App_C_Files := App.c ra-tls-client.c sgxsdk-ra-attester_u.c
ifndef ECDSA
	App_C_Files += ias-ra.c
endif

App_Include_Paths := $(Wolfssl_Include_Paths) -I$(SGX_SDK)/include -I$(SGX_RA_TLS_ROOT) -I$(INCDIR) $(SGX_DCAP_INC) -I$(shell readlink -f .)
App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -shared -Wno-attributes -Wall -Wno-unused-const-variable $(App_Include_Paths) $(Wolfssl_C_Extra_Flags)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(DCAP_Library_Name) -l$(Uae_Library_Name)  -lpthread -lsgx_uae_service -ldl -lm -lsgx_dcap_ql 

App_C_Objects := $(App_C_Files:.c=.o)

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

.PHONY: all

all: libra-tls-client.a libsgxsdk-ra-attester_u.a App

ra-tls-client.o: ra-tls-client.c 
	@echo $(CC) $(App_C_FLags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $<"

libra-tls-client.a: ra-tls-client.o  
	$(AR) rcs $@ $(filter %.o, $^)
	@echo "LINK =>  $@"

sgxsdk-ra-attester_u.o: sgxsdk-ra-attester_u.c
	@echo $(CC) $(App_C_FLags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $<"

libsgxsdk-ra-attester_u.a: sgxsdk-ra-attester_u.o
	$(AR) rcs $@ $(filter %.o, $^)
	@echo "LINK =>  $@"

App.o: App.c 
	@echo $(CC) $(App_C_FLags) -c $< -o $@
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC <= $<"

App: App.o $(App_C_Objects) libra-tls-client.a libsgxsdk-ra-attester_u.a $(LIBDIR)/libra-challenger.a $(LIBDIR)/libwolfssl.a $(SGX_LIB)/libsgx_dcap_quoteverify.so.1
	@$(CC) $^ -o $@ $(App_Link_Flags)  
	@echo "LINK => $@"


.PHONY: clean

clean:
	@rm -f libra-tls-client.* $(App_C_Objects)  
	@rm -f libsgxsdk-ra-attester_u.a
	@rm -f App
