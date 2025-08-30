#ifndef NFD_MACH_H
#define NFD_MACH_H

#include "mach_script.h"
#include "nfd_binary.h"
#include "xmach.h"

class NFD_MACH : public MACH_Script {
    Q_OBJECT

public:
    explicit NFD_MACH(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct MACHOINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;
        QList<XMACH::COMMAND_RECORD> listCommandRecords;
        QList<XMACH::LIBRARY_RECORD> listLibraryRecords;
        QList<XMACH::SEGMENT_RECORD> listSegmentRecords;
        QList<XMACH::SECTION_RECORD> listSectionRecords;
    };
};

#endif  // NFD_MACH_H
