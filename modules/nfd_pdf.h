#ifndef NFD_PDF_H
#define NFD_PDF_H

#include "pdf_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_PDF : public PDF_Script {
    Q_OBJECT

public:
    explicit NFD_PDF(XPDF *pPDF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct PDFINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QList<XPDF::XPART> listObjects;
    };

    static PDFINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                  XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_PDF_H
