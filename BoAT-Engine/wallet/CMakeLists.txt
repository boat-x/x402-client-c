set(SUB_MODULE_NAME         wallet_obj)

set(FILE_SRC    boatversion.c)

if(BOAT_PROTOCOL_USE_ETHEREUM)
set(FILE_SRC    ${FILE_SRC} api_ethereum.c)
endif()

if(BOAT_PROTOCOL_USE_PLATON)
set(FILE_SRC    ${FILE_SRC} api_platon.c)
endif()

if(BOAT_PROTOCOL_USE_QUORUM)
set(FILE_SRC    ${FILE_SRC} api_quorum.c)
endif()

add_library(${SUB_MODULE_NAME}  OBJECT  ${FILE_SRC})


# target_link_libraries(${SUB_MODULE_NAME}  boatvendor cjson-obj  protocol_obj protos-obj)

target_include_directories(${SUB_MODULE_NAME}
    PRIVATE
    ${PROJECT_SOURCE_DIR}/sdk/include
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/vendor/platform/include
    ${PROJECT_SOURCE_DIR}/sdk/protocol
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)


