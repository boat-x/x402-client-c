# Source and Objects

SOURCES = $(wildcard *.c)
OBJECTS_DIR = $(BOAT_BUILD_DIR)/BoAT-SupportLayer/third-party/rlp
OBJECTS = $(patsubst %.c,$(OBJECTS_DIR)/%.o,$(SOURCES))



ifeq ($(BOAT_PROTOCOL_USE_ETHEREUM)_$(BOAT_PROTOCOL_USE_PLATON)_$(BOAT_PROTOCOL_USE_QUORUM), 0_0_0)
all:
else
all: $(OBJECTS_DIR) $(OBJECTS)

$(OBJECTS_DIR):
	$(BOAT_MKDIR) -p $(OBJECTS_DIR)

$(OBJECTS_DIR)/%.o:%.c
	$(CC) -c $(BOAT_CFLAGS) $< -o $@
	$(BOAT_COPY) $(SOURCES) $(OBJECTS_DIR)
endif

clean:
	-$(BOAT_RM) $(OBJECTS)
