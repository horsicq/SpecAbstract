INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD
INCLUDEPATH += $$PWD/modules
DEPENDPATH += $$PWD/modules

HEADERS += \
    $$PWD/specabstract.h \
    $$PWD/modules/nfd_binary.h

SOURCES += \
    $$PWD/signatures.cpp \
    $$PWD/specabstract.cpp \
    $$PWD/modules/nfd_binary.cpp

contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone_x86) {
        XCONFIG += xcapstone_x86
        include($$PWD/../XCapstone/xcapstone_x86.pri)
    }
}

!contains(XCONFIG, use_capstone_x86) {
    !contains(XCONFIG, xcapstone) {
        XCONFIG += xcapstone
        include($$PWD/../XCapstone/xcapstone.pri)
    }
}

!contains(XCONFIG, xscanengine) {
    XCONFIG += xscanengine
    include($$PWD/../XScanEngine/xscanengine.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/import_hashes.txt \
    $$PWD/specabstract.cmake
