#include "nfd_npm.h"

NFD_NPM::NFD_NPM(XNPM *pNpm, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : NPM_Script(pNpm, filePart, pOptions, pPdStruct) {}
