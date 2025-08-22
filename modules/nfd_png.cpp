#include "nfd_png.h"

NFD_PNG::NFD_PNG(XPNG *pPNG, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : PNG_Script(pPNG, filePart, pOptions, pPdStruct) {}
