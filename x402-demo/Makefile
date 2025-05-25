# Source and Objects

SOURCES = $(wildcard *.c)
OBJECTS_DIR = $(BOAT_BUILD_DIR)/x402-demo
OBJECTS = $(patsubst %.c,$(OBJECTS_DIR)/%.o,$(SOURCES))

DEPENDENCE_LIBS = $(BOAT_LIB_DIR)/libboatengine.a \
				  $(BOAT_LIB_DIR)/libboatvendor.a \
				  $(LINK_LIBS)

all: $(OBJECTS_DIR) $(OBJECTS)
	$(CC) $(BOAT_LFLAGS) -o $(BOAT_BUILD_DIR)/x402-demo-app $(OBJECTS) $(DEPENDENCE_LIBS)

$(OBJECTS_DIR):
	mkdir -p $(OBJECTS_DIR)

$(OBJECTS_DIR)/%.o:%.c
	$(CC) -c $(BOAT_CFLAGS) $< -o $@


clean:
	-rm -f $(OBJECTS)
	-rm -f $(BOAT_BUILD_DIR)/x402-demo-app
