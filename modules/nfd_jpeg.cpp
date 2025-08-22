#include "nfd_jpeg.h"

NFD_JPEG::NFD_JPEG(XJpeg *pJpeg, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Jpeg_Script(pJpeg, filePart, pOptions, pPdStruct) {}
