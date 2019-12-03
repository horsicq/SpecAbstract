INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/specabstract.h

SOURCES += \
    $$PWD/specabstract.cpp

!contains(XCONFIG, xmsdos) {
    XCONFIG += xmsdos
    include(../Formats/xmsdos.pri)
}

!contains(XCONFIG, xne) {
    XCONFIG += xne
    include(../Formats/xne.pri)
}

!contains(XCONFIG, xle) {
    XCONFIG += xle
    include(../Formats/xle.pri)
}

!contains(XCONFIG, xlx) {
    XCONFIG += xlx
    include(../Formats/xlx.pri)
}

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include(../Formats/xpe.pri)
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
