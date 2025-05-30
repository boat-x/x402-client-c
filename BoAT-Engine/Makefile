# BoAT SDK Library Objects

# Generate sub-directory list
ALLSUBDIRS := $(shell $(BOAT_FIND) . -maxdepth 1 -type d)
ALLSUBDIRS := $(basename $(patsubst ./%,%,$(ALLSUBDIRS)))

EXCLUDE_DIRS := include tests demo tools docs
SUBDIRS := $(filter-out $(EXCLUDE_DIRS),$(ALLSUBDIRS))
CLEANEXCLUDE_DIRS := include tools docs
CLEANSUBDIRS := $(filter-out $(CLEANEXCLUDE_DIRS),$(ALLSUBDIRS))

# Add _clean_ prefix to avoid clean subdir target names being confused with compile subdir targets
CLEAN_SUBDIRS := $(addprefix _clean_,$(CLEANSUBDIRS)	)

ifneq (,$(BOAT_LOG_LEVEL))
BOAT_CFLAGS +=  -DBOAT_LOG_LEVEL=$(BOAT_LOG_LEVEL)
endif

OBJECTS = $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/protocol/*.o) \
		  $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/wallet/*.o)

ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM),1)
	OBJECTS += $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/protocol/boatethereum/*.o) \
			   $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/network/ethereum/*.o)
endif
ifeq ($(BOAT_PROTOCOL_USE_PLATON),1)
	OBJECTS += $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/protocol/boatplaton/*.o) \
				$(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/network/platon/*.o)
endif
ifeq ($(BOAT_PROTOCOL_USE_QUORUM),1)
	OBJECTS += $(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/protocol/boatquorum/*.o) \
				$(wildcard $(BOAT_BUILD_DIR)/BoAT-Engine/network/quorum/*.o)
endif


# ifeq ($(CJSON_LIBRARY), CJSON_DEFAULT)
#     OBJECTS += $(wildcard $(BOAT_BUILD_DIR)/sdk/third-party/cJSON/*.o)
# endif

LIBNAME = $(BOAT_LIB_DIR)/libboatengine.a

.PHONY: all $(SUBDIRS) boatwallet_objs clean

all: $(LIBNAME)

demo: $(LIBNAME)
	make -C demo all

$(LIBNAME): boatwallet_objs
	$(AR) r $(LIBNAME) $(OBJECTS)


boatwallet_objs: $(SUBDIRS)

$(SUBDIRS):
	make -C $@ all

test: $(LIBNAME)
	make -C tests all
	
$(CLEAN_SUBDIRS):
	make -C $(patsubst _clean_%,%,$@) clean

clean: $(CLEAN_SUBDIRS)
	-$(BOAT_RM) $(LIBNAME)



