#include "nfd_pdf.h"

NFD_PDF::NFD_PDF(XPDF *pPDF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : PDF_Script(pPDF, filePart, pOptions, pPdStruct) {}
