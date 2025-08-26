#ifndef NFD_AMIGA_H
#define NFD_AMIGA_H

#include "amiga_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_Amiga : public Amiga_Script {
    Q_OBJECT

public:
    explicit NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct AMIGAHUNKINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
    };

    static AMIGAHUNKINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                        XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_AMIGA_H
