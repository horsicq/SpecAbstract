#ifndef NFD_PDF_H
#define NFD_PDF_H

#include "pdf_script.h"

class NFD_PDF : public PDF_Script {
    Q_OBJECT

public:
    explicit NFD_PDF(XPDF *pPDF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_PDF_H
