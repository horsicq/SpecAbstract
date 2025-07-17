include_directories(${CMAKE_CURRENT_LIST_DIR})
include_directories(${CMAKE_CURRENT_LIST_DIR}/modules)

if (NOT DEFINED XSCANENGINE_SOURCES)
    include(${CMAKE_CURRENT_LIST_DIR}/../XScanEngine/xscanengine.cmake)
    set(SPECABSTRACT_SOURCES ${SPECABSTRACT_SOURCES} ${XSCANENGINE_SOURCES})
endif()

# TODO Check includes
set(SPECABSTRACT_SOURCES
    ${SPECABSTRACT_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.cpp
    ${CMAKE_CURRENT_LIST_DIR}/specabstract.h
    ${CMAKE_CURRENT_LIST_DIR}/modules/nfd_binary.cpp
    ${CMAKE_CURRENT_LIST_DIR}/modules/nfd_binary.h
)
