#ifndef NFD_JPEG_H
#define NFD_JPEG_H

#include "jpeg_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_JPEG : public Jpeg_Script {
    Q_OBJECT
public:
    explicit NFD_JPEG(XJpeg *pJpeg, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct JPEGINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
    };

    static JPEGINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                   XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JPEG_H
