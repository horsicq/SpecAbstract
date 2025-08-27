#ifndef NFD_CFBF_H
#define NFD_CFBF_H

#include "cfbf_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_CFBF : public CFBF_Script {
    Q_OBJECT

public:
    explicit NFD_CFBF(XCFBF *pCFBF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct CFBFINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
    };

    static CFBFINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_CFBF_H
