# Directories
BOAT_BASE_DIR  := $(CURDIR)
BOAT_LIB_DIR   := $(BOAT_BASE_DIR)/lib
BOAT_BUILD_DIR := $(BOAT_BASE_DIR)/build


# Blockchains:
BOAT_PROTOCOL_USE_ETHEREUM           ?= 1
BOAT_PROTOCOL_USE_PLATON             ?= 0
BOAT_PROTOCOL_USE_QUORUM             ?= 0


# Chain config check
ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM)_$(BOAT_PROTOCOL_USE_PLATON)_$(BOAT_PROTOCOL_USE_QUORUM), 0_0_0)
    $(error Select at least one chain)
endif

ifeq ($(BOAT_PROTOCOL_USE_CHAINMAKER_V1)_$(BOAT_PROTOCOL_USE_CHAINMAKER_V2), 1_1)
    $(error Select only one chainmaker version)
endif
# Platform target
# The valid option value of PLATFORM_TARGET list as below:
# - linux-default             : Default linux platform
PLATFORM_TARGET ?= linux-default

# Set the flag to no if the executable is cross-compiled for a Fibocom L718 board
# Set the flag to yes if the executable runs on a computer for testing
TEST_ON_COMPUTER = yes

# Environment-specific Settings
include $(BOAT_BASE_DIR)/BoAT-SupportLayer/platform/$(PLATFORM_TARGET)/external.env


# Check gcc version
ifneq (,$(CC))
    GCCVERSION := $(shell $(CC) -v 2>&1)
else
    GCCVERSION := "NONE"
endif

ifneq (,$(findstring arm,$(GCCVERSION)))         # Target: arm-oe-linux-gnueabi
    COMPILER_TYPE = "ARM"
else ifneq (,$(findstring linux,$(GCCVERSION)))  # Target: x86_64-redhat-linux
    COMPILER_TYPE = "LINUX"
else ifneq (,$(findstring cygwin,$(GCCVERSION))) # Target: x86_64-pc-cygwin
    COMPILER_TYPE = "CYGWIN"
else
    COMPILER_TYPE = "NOTSUPPORT"                 # Not supported
endif


# Environment Language
LANG := en_US  # zh_CN.UTF-8

# Compiling Flags

# Target-independent Flags
BOAT_INCLUDE := $(EXTERNAL_INC)

include $(BOAT_BASE_DIR)/BoAT-SupportLayer/include/BoAT-SupportLayer.conf
include $(BOAT_BASE_DIR)/BoAT-Engine/include/BoAT-Engine.conf
BOAT_LITE_HTTP2 = N
BOAT_LITE_CJSON = Y
BOAT_LITE_PROTOBUF_C = N
BOAT_LITE_PROTOS = N
BOAT_LITE_RLP = Y
BOAT_LITE_UTILITIES = Y
BOAT_LITE_RPC = Y
BOAT_CSTD_FLAGS := -std=gnu99
BOAT_OPTIMIZATION_FLAGS := -g #-Os 
#BOAT_OPTIMIZATION_FLAGS := -Os
BOAT_WARNING_FLAGS := -Wall
BOAT_DEFINED_MACROS := #-DDEBUG_LOG

# BOAT_COMMON_LINK_FLAGS := -Wl,-Map,$(BOAT_BUILD_DIR)/boat.map


# Target-specific Flags
ifeq ($(COMPILER_TYPE), "ARM")
    TARGET_SPEC_CFLAGS := -mthumb -ffunction-sections -fdata-sections
    TARGET_SPEC_LIBS := 
    TARGET_SPEC_LINK_FLAGS :=
else ifeq ($(COMPILER_TYPE), "LINUX")
    TARGET_SPEC_CFLAGS := -ffunction-sections -fdata-sections 
    TARGET_SPEC_LIBS := 
    TARGET_SPEC_LINK_FLAGS := -Wl,-gc-sections
else ifeq ($(COMPILER_TYPE), "CYGWIN")
    TARGET_SPEC_CFLAGS :=
    TARGET_SPEC_LIBS := 
    TARGET_SPEC_LINK_FLAGS :=
else
    TARGET_SPEC_CFLAGS :=
    TARGET_SPEC_LIBS :=
    TARGET_SPEC_LINK_FLAGS :=
endif

# Soft-crypto Dependencies
# The valid option value of SOFT_CRYPTO list as below:
# - CRYPTO_DEFAULT      : default soft crypto algorithm
# - CRYPTO_MBEDTLS      : mbedtls crypto algorithm
# SOFT_CRYPTO ?= CRYPTO_MBEDTLS
# cJSON Dependencies
#
# - CJSON_DEFAULT : default cJSON library
# - CJSON_OUTTER  : externally provided by users
ifeq ($(BOAT_TEST), TEST_MODE)
BOAT_TEST_FLAG = -fprofile-arcs\
                 -ftest-coverage

ifeq ($(BOAT_NODES_DISCOVER), OPEN)
BOAT_DISCOVERY_PEER_QUERY    = 1
else
BOAT_DISCOVERY_PEER_QUERY    = 0
endif
endif


# Combine FLAGS
BOAT_CFLAGS := $(TARGET_SPEC_CFLAGS) \
               $(BOAT_INCLUDE) \
               $(BOAT_CSTD_FLAGS) \
               $(BOAT_OPTIMIZATION_FLAGS) \
               $(BOAT_WARNING_FLAGS) \
               $(BOAT_DEFINED_MACROS) \
               $(EXTERNAL_CFLAGS) \
               $(BOAT_TEST_FLAG) \
               $(BOAT_CHAINMAKER_VERSION_CFLAGS)

BOAT_LFLAGS := $(BOAT_COMMON_LINK_FLAGS) $(TARGET_SPEC_LINK_FLAGS) $(EXTERNAL_LFLAGS)
LINK_LIBS := $(EXTERNAL_LIBS) $(TARGET_SPEC_LIBS)

SCRIPTS_PARAM += "BOAT_PROTOCOL_USE_ETHEREUM=$(BOAT_PROTOCOL_USE_ETHEREUM)" \
                 "BOAT_PROTOCOL_USE_PLATON=$(BOAT_PROTOCOL_USE_PLATON)" \
                 "BOAT_PROTOCOL_USE_QUORUM=$(BOAT_PROTOCOL_USE_QUORUM)"

export BOAT_PROTOCOL_USE_ETHEREUM
export BOAT_PROTOCOL_USE_PLATON
export BOAT_PROTOCOL_USE_QUORUM

export BOAT_DISCOVERY_PEER_QUERY
export BOAT_USE_DEFAULT_CJSON


export SOFT_CRYPTO
export CJSON_LIBRARY
export PLATFORM_TARGET
export BOAT_BASE_DIR
export BOAT_LIB_DIR
export BOAT_BUILD_DIR
export BOAT_CFLAGS
export BOAT_LFLAGS
export LINK_LIBS
export BOAT_LITE_HTTP2
export BOAT_LITE_CJSON
export BOAT_LITE_PROTOBUF_C
export BOAT_LITE_PROTOS
export BOAT_LITE_RLP
export BOAT_LITE_UTILITIES
export BOAT_LITE_RPC

.PHONY: all x402 BoAT-SupportLayer_obj cleanBoAT-SupportLayer BoAT-Engine_obj cleanBoAT-Engine clean_x402
all: x402


x402: createdir SupportLayer_obj Engine_obj
	make -C $(BOAT_BASE_DIR)/x402-demo all

SupportLayer_obj:
	make -C $(BOAT_BASE_DIR)/BoAT-SupportLayer all

Engine_obj:
	make -C $(BOAT_BASE_DIR)/BoAT-Engine all


createdir:
	@echo generate header file boatconfig.h...
	python3 ./BoAT-SupportLayer/platform/$(PLATFORM_TARGET)/scripts/gen.py $(PLATFORM_TARGET) $(SCRIPTS_PARAM)
	@echo generate done.
# boatconfig is using
	$(BOAT_MKDIR) -p $(BOAT_LIB_DIR)
	$(BOAT_MKDIR) -p $(BOAT_BUILD_DIR)



clean: cleanBoAT-SupportLayer cleanBoAT-Engine clean_x402
	-$(BOAT_RM) $(BOAT_BUILD_DIR) $(BOAT_LIB_DIR)

cleanBoAT-SupportLayer:
	make -C $(BOAT_BASE_DIR)/BoAT-SupportLayer clean

cleanBoAT-Engine:
	make -C $(BOAT_BASE_DIR)/BoAT-Engine clean

clean_x402:
	make -C $(BOAT_BASE_DIR)/x402-demo clean

