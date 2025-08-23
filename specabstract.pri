INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD
INCLUDEPATH += $$PWD/modules
DEPENDPATH += $$PWD/modules

HEADERS += \
    $$PWD/specabstract.h \
    $$PWD/modules/nfd_binary.h \
    $$PWD/modules/nfd_msdos.h \
    $$PWD/modules/nfd_pe.h \
    $$PWD/modules/nfd_elf.h \
    $$PWD/modules/nfd_mach.h \
    $$PWD/modules/nfd_zip.h \
    $$PWD/modules/nfd_jar.h \
    $$PWD/modules/nfd_archive.h \
    $$PWD/modules/nfd_rar.h \
    $$PWD/modules/nfd_npm.h \
    $$PWD/modules/nfd_machofat.h \
    $$PWD/modules/nfd_dex.h \
    $$PWD/modules/nfd_cfbf.h \
    $$PWD/modules/nfd_com.h \
    $$PWD/modules/nfd_image.h \
    $$PWD/modules/nfd_jpeg.h \
    $$PWD/modules/nfd_png.h \
    $$PWD/modules/nfd_ne.h \
    $$PWD/modules/nfd_le.h \
    $$PWD/modules/nfd_lx.h \
    $$PWD/modules/nfd_amiga.h \
    $$PWD/modules/nfd_dos16m.h \
    $$PWD/modules/nfd_dos4g.h \
    $$PWD/modules/nfd_apk.h \
    $$PWD/modules/nfd_ipa.h \
    $$PWD/modules/nfd_pdf.h \
    $$PWD/modules/nfd_javaclass.h

SOURCES += \
    $$PWD/signatures.cpp \
    $$PWD/specabstract.cpp \
    $$PWD/modules/nfd_binary.cpp \
    $$PWD/modules/nfd_msdos.cpp \
    $$PWD/modules/nfd_pe.cpp \
    $$PWD/modules/nfd_elf.cpp \
    $$PWD/modules/nfd_mach.cpp \
    $$PWD/modules/nfd_zip.cpp \
    $$PWD/modules/nfd_jar.cpp \
    $$PWD/modules/nfd_archive.cpp \
    $$PWD/modules/nfd_rar.cpp \
    $$PWD/modules/nfd_npm.cpp \
    $$PWD/modules/nfd_machofat.cpp \
    $$PWD/modules/nfd_dex.cpp \
    $$PWD/modules/nfd_cfbf.cpp \
    $$PWD/modules/nfd_com.cpp \
    $$PWD/modules/nfd_image.cpp \
    $$PWD/modules/nfd_jpeg.cpp \
    $$PWD/modules/nfd_png.cpp \
    $$PWD/modules/nfd_ne.cpp \
    $$PWD/modules/nfd_le.cpp \
    $$PWD/modules/nfd_lx.cpp \
    $$PWD/modules/nfd_amiga.cpp \
    $$PWD/modules/nfd_dos16m.cpp \
    $$PWD/modules/nfd_dos4g.cpp \
    $$PWD/modules/nfd_apk.cpp \
    $$PWD/modules/nfd_ipa.cpp \
    $$PWD/modules/nfd_pdf.cpp \
    $$PWD/modules/nfd_javaclass.cpp

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
