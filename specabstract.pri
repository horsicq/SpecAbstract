INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/specabstract.h

SOURCES += \
    $$PWD/signatures.cpp \
    $$PWD/specabstract.cpp

!contains(XCONFIG, xcom) {
    XCONFIG += xcom
    include($$PWD/../Formats/xcom.pri)
}

!contains(XCONFIG, xmsdos) {
    XCONFIG += xmsdos
    include($$PWD/../Formats/xmsdos.pri)
}

!contains(XCONFIG, xne) {
    XCONFIG += xne
    include($$PWD/../Formats/xne.pri)
}

!contains(XCONFIG, xle) {
    XCONFIG += xle
    include($$PWD/../Formats/xle.pri)
}

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include($$PWD/../Formats/xpe.pri)
}

!contains(XCONFIG, xelf) {
    XCONFIG += xelf
    include($$PWD/../Formats/xelf.pri)
}

!contains(XCONFIG, xmach) {
    XCONFIG += xmach
    include($$PWD/../Formats/xmach.pri)
}

!contains(XCONFIG, xarchive) {
    XCONFIG += xarchive
    include($$PWD/../XArchive/xarchive.pri)
}
