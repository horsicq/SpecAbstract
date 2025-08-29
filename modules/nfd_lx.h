#ifndef NFD_LX_H
#define NFD_LX_H

#include "lx_script.h"
#include "nfd_binary.h"
#include "nfd_msdos.h"

class QIODevice;

class NFD_LX : public LX_Script {
    Q_OBJECT

public:
    explicit NFD_LX(XLE *pLX, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct LXINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
    };

    static LXINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                 XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_LX_H
