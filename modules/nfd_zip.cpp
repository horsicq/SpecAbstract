#include "nfd_zip.h"

NFD_ZIP::NFD_ZIP(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : ZIP_Script(pZip, filePart, pOptions, pPdStruct) {}
