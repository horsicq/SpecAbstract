#include "nfd_ipa.h"

NFD_IPA::NFD_IPA(XIPA *pIPA, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : IPA_Script(pIPA, filePart, pOptions, pPdStruct) {}
