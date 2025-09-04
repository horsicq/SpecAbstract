#ifndef NFD_RAR_H
#define NFD_RAR_H

#include "rar_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_RAR : public RAR_Script {
    Q_OBJECT

public:
    explicit NFD_RAR(XRar *pRar, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct RARINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QList<XArchive::RECORD> listArchiveRecords;
    };

    static RARINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_RAR_H
