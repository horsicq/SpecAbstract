#include "nfd_rar.h"

NFD_RAR::NFD_RAR(XRar *pRar, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : RAR_Script(pRar, filePart, pOptions, pPdStruct) {}
