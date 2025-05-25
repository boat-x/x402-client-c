# Source and Objects

SOURCES = $(wildcard *.c)
OBJECTS_DIR = $(BOAT_BUILD_DIR)/BoAT-Engine/protocol
OBJECTS = $(patsubst %.c,$(OBJECTS_DIR)/%.o,$(SOURCES))

.PHONY: all protocol_common protocol_ethereum protocol_platon protocol_quorum

all: protocol_common protocol_ethereum protocol_platon protocol_quorum $(OBJECTS_DIR) $(OBJECTS)


protocol_common:
	make -C common all
	
protocol_ethereum:
ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM), 1)
	make -C  boatethereum all
endif

protocol_platon:
ifeq ($(BOAT_PROTOCOL_USE_PLATON), 1)
	make -C  boatplaton all
endif

protocol_quorum:
ifeq ($(BOAT_PROTOCOL_USE_QUORUM), 1)
	make -C  boatquorum all
endif


$(OBJECTS_DIR):
	$(BOAT_MKDIR) -p $(OBJECTS_DIR)

$(OBJECTS_DIR)/%.o:%.c
	$(CC) -c $(BOAT_CFLAGS) $< -o $@


clean:
	-$(BOAT_RM) $(OBJECTS)
	make -C common clean
ifeq ($(PROTOCOL_USE_ETHEREUM), 1)	
	make -C boatethereum  clean
endif
ifeq ($(PROTOCOL_USE_PLATON), 1)
	make -C boatplaton    clean
endif
ifeq ($(BOAT_PROTOCOL_USE_QUORUM), 1)
	make -C boatquorum clean
endif
