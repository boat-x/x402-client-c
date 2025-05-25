# Source and Objects

#SOURCES = $(wildcard *.c)
SOURCES = boatversion.c
		  
ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM), 1)
	SOURCES += api_ethereum.c
endif
ifeq ($(BOAT_PROTOCOL_USE_PLATON), 1)
	SOURCES += api_platon.c
endif		  
ifeq ($(BOAT_PROTOCOL_USE_QUORUM), 1)
	SOURCES += api_quorum.c
endif


OBJECTS_DIR = $(BOAT_BUILD_DIR)/BoAT-Engine/wallet
OBJECTS = $(patsubst %.c,$(OBJECTS_DIR)/%.o,$(SOURCES))


all: $(OBJECTS_DIR) $(OBJECTS)

$(OBJECTS_DIR):
	$(BOAT_MKDIR) -p $(OBJECTS_DIR)

$(OBJECTS_DIR)/%.o:%.c
	$(CC) -c $(BOAT_CFLAGS) $< -o $@
	$(BOAT_COPY) $(SOURCES) $(OBJECTS_DIR)


clean:
	-$(BOAT_RM) $(OBJECTS)

