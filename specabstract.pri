INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/specabstract.h

SOURCES += \
    $$PWD/specabstract.cpp

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include(../Formats/xpe.pri)
}

!contains(XCONFIG, xmsdos) {
    XCONFIG += xmsdos
    include(../Formats/xmsdos.pri)
}

!contains(XCONFIG, xelf) {
    XCONFIG += xelf
    include(../Formats/xelf.pri)
}

!contains(XCONFIG, xmach) {
    XCONFIG += xmach
    include(../Formats/xmach.pri)
}

!contains(XCONFIG, xarchive) {
    XCONFIG += xarchive
    include(../XArchive/xarchive.pri)
}
