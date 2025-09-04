#ifndef NFD_COM_H
#define NFD_COM_H

#include "com_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_COM : public COM_Script {
    Q_OBJECT

public:
    explicit NFD_COM(XCOM *pCOM, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct COMINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    static COMINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    // Handlers migrated from SpecAbstract
    static void handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct);

    // Accessors for COM signature arrays (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getHeaderRecords();
    static qint32 getHeaderRecordsSize();  // size in bytes
    static NFD_Binary::SIGNATURE_RECORD *getHeaderExpRecords();
    static qint32 getHeaderExpRecordsSize();  // size in bytes
};

#endif  // NFD_COM_H
