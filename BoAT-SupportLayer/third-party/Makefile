# Source and Objects
# Crypto is not here make

all:
ifeq ($(BOAT_LITE_CJSON), Y)
	make -C cJSON all
endif
ifeq ($(BOAT_LITE_PROTOBUF_C), Y)
	make -C protobuf-c/src all
endif
ifeq ($(BOAT_LITE_PROTOS), Y)
	make -C protos all
endif
ifeq ($(BOAT_LITE_RLP), Y)
	make -C rlp all
endif
ifeq ($(BOAT_LITE_HTTP2), Y)
	make -C nghttp2/src all
endif

	
clean:
ifeq ($(BOAT_LITE_CJSON), Y)
	make -C cJSON clean
endif
ifeq ($(BOAT_LITE_PROTOBUF_C), Y)
	make -C protobuf-c/src clean
endif
ifeq ($(BOAT_LITE_PROTOS), Y)
	make -C protos clean
endif
ifeq ($(BOAT_LITE_RLP), Y)
	make -C rlp clean
endif
ifeq ($(BOAT_LITE_HTTP2), Y)
	make -C nghttp2/src clean
endif
