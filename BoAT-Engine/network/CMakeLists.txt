

if(BOAT_PROTOCOL_USE_ETHEREUM)
add_subdirectory(ethereum)
endif()

if(BOAT_PROTOCOL_USE_PLATON)
add_subdirectory(platon)
endif()

if(BOAT_PROTOCOL_USE_QUORUM)
add_subdirectory(quorum)
endif()
