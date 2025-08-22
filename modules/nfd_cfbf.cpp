#include "nfd_cfbf.h"

NFD_CFBF::NFD_CFBF(XCFBF *pCFBF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : CFBF_Script(pCFBF, filePart, pOptions, pPdStruct) {}
