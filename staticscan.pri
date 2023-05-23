INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/staticscan.h

SOURCES += \
    $$PWD/staticscan.cpp

!contains(XCONFIG, specabstract) {
    XCONFIG += specabstract
    include($$PWD/../SpecAbstract/specabstract.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/staticscan.cmake
