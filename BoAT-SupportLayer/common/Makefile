# Source and Objects


all:
ifeq ($(BOAT_LITE_HTTP2), Y)
	make -C http2intf all
endif
ifeq ($(BOAT_LITE_RPC), Y)
	make -C rpc all
endif
	make -C storage all
ifeq ($(BOAT_LITE_UTILITIES), Y)
	make -C utilities all
endif

	
clean:
ifeq ($(BOAT_LITE_HTTP2), Y)
	make -C http2intf clean
endif
ifeq ($(BOAT_LITE_RPC), Y)
	make -C rpc clean
endif
	make -C storage clean
ifeq ($(BOAT_LITE_UTILITIES), Y)
	make -C utilities clean
endif
