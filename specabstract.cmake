include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../XScanEngine/xscanengine.cmake)
# TODO Check includes
set(SPECABSTRACT_SOURCES
    ${XSCANENGINE_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.cpp
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.h
)
