#include "nfd_pe.h"

NFD_PE::NFD_PE(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : PE_Script(pPE, filePart, pOptions, pPdStruct) {}
