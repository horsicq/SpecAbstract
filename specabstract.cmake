include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XDEX/xdex.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XPDF/xpdf.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XArchive/xarchives.cmake)

set(SPECABSTRACT_SOURCES
    ${XFORMATS_SOURCES}
    ${XDEX_SOURCES}
    ${XPDF_SOURCES}
    ${XARCHIVES_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.cpp
)
