include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XDEX/xdex.cmake)

set(SPECABSTRACT_SOURCES
    ${XFORMATS_SOURCES}
    ${XDEX_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.cpp
)
