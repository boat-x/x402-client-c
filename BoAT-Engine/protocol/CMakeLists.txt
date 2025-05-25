add_subdirectory(common)

if(BOAT_PROTOCOL_USE_ETHEREUM)
add_subdirectory(boatethereum)
set(PROTOS  ${PROTOS} $<TARGET_OBJECTS:boatethereum-obj>)
endif()

if(BOAT_PROTOCOL_USE_PLATON)
add_subdirectory(boatplaton)
set(PROTOS  ${PROTOS} $<TARGET_OBJECTS:boatplaton-obj>)
endif()

if(BOAT_PROTOCOL_USE_QUORUM)
add_subdirectory(boatquorum)
set(PROTOS  ${PROTOS} $<TARGET_OBJECTS:boatquorum-obj>)
endif()

add_library(protocol_obj    OBJECT  ${PROTOS})

# target_link_libraries(protocol_obj  ${PROTOS})
