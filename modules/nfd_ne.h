#ifndef NFD_NE_H
#define NFD_NE_H

#include "ne_script.h"
#include "nfd_binary.h"
#include "nfd_msdos.h"

class QIODevice;

class NFD_NE : public NE_Script {
    Q_OBJECT

public:
    explicit NFD_NE(XNE *pNE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct NEINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    static NEINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_NE_H
