#ifndef NFD_JAR_H
#define NFD_JAR_H

#include "jar_script.h"
#include "nfd_binary.h"
#include "xarchive.h"

class QIODevice;

class NFD_JAR : public JAR_Script {
    Q_OBJECT

public:
    explicit NFD_JAR(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct JARINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJava;
        bool bIsKotlin;
    };

    static JARINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                  XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JAR_H
