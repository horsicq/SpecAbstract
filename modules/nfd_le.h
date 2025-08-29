#ifndef NFD_LE_H
#define NFD_LE_H

#include "le_script.h"
#include "nfd_binary.h"
#include "nfd_msdos.h"

class QIODevice;

class NFD_LE : public LE_Script {
    Q_OBJECT

public:
    explicit NFD_LE(XLE *pLE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct LEINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
    };

    static LEINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                 XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_LE_H
