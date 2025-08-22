#include "nfd_ne.h"

NFD_NE::NFD_NE(XNE *pNE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : NE_Script(pNE, filePart, pOptions, pPdStruct) {}
