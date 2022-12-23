INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

!contains(XCONFIG, use_dex) {
    XCONFIG += use_dex
}

!contains(XCONFIG, use_pdf) {
    XCONFIG += use_pdf
}

!contains(XCONFIG, use_archive) {
    XCONFIG += use_archive
}

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

HEADERS += \
    $$PWD/specabstract.h

SOURCES += \
    $$PWD/signatures.cpp \
    $$PWD/specabstract.cpp

!contains(XCONFIG, xformats) {
    XCONFIG += xformats
    include($$PWD/../Formats/xformats.pri)
}

contains(XCONFIG, use_dex) {
    DEFINES += USE_DEX
    !contains(XCONFIG, xdex) {
        XCONFIG += xdex
        include($$PWD/../XDEX/xdex.pri)
    }
}

contains(XCONFIG, use_pdf) {
    DEFINES += USE_PDF
    !contains(XCONFIG, xpdf) {
        XCONFIG += xpdf
        include($$PWD/../XPDF/xpdf.pri)
    }
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/import_hashes.txt \
    $$PWD/specabstract.cmake
