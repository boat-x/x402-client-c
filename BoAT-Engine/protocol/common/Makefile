# Source and Objects


all:
# If at least one of BOAT_PROTOCOL_USE_ETHEREUM, BOAT_PROTOCOL_USE_PLATON and BOAT_PROTOCOL_USE_QUORUM is set to 1, 
# then build web3intf
ifeq ($(findstring $(BOAT_PROTOCOL_USE_ETHEREUM)$(BOAT_PROTOCOL_USE_PLATON)$(BOAT_PROTOCOL_USE_QUORUM), 000),)
	make -C web3intf  all
endif	
	
clean:
	make -C web3intf  clean
