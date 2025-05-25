# Source and Objects

#SOURCES = $(wildcard *.c)
# SOURCES =  boatversion.c
SOURCES = $(wildcard *.c)
OBJECTS_DIR = $(BOAT_BUILD_DIR)/BoAT-Engine/network
OBJECTS = $(patsubst %.c,$(OBJECTS_DIR)/%.o,$(SOURCES))
		  
.PHONY: all  network_ethereum network_platon network_quorum 

all:  network_ethereum network_platon network_quorum $(OBJECTS_DIR) $(OBJECTS)

network_ethereum:
ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM), 1)
	make -C  ethereum all
endif

network_platon:
ifeq ($(BOAT_PROTOCOL_USE_PLATON),1)
	make -C platon all
endif

network_quorum:
ifeq ($(BOAT_PROTOCOL_USE_QUORUM),1)
	make -C quorum all
endif


$(OBJECTS_DIR):
	$(BOAT_MKDIR) -p $(OBJECTS_DIR)

$(OBJECTS_DIR)/%.o:%.c
	$(CC) -c $(BOAT_CFLAGS) $< -o $@


clean:
	-$(BOAT_RM) $(OBJECTS)
ifeq ($(PROTOCOL_USE_ETHEREUM), 1)	
	make -C ethereum  clean
endif
ifeq ($(BOAT_PROTOCOL_USE_PLATON),1)
	make -C platon clean
endif
ifeq ($(BOAT_PROTOCOL_USE_QUORUM),1)
	make -C quorum clean
endif
