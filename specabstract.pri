INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/specabstract.h

SOURCES += \
    $$PWD/signatures.cpp \
    $$PWD/specabstract.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

!contains(XCONFIG, xdex) {
    XCONFIG += xdex
    include($$PWD/../XDEX/xdex.pri)
}

!contains(XCONFIG, xarchive) {
    XCONFIG += xarchive
    include($$PWD/../XArchive/xarchive.pri)
}
