#include "nfd_apk.h"

NFD_APK::NFD_APK(XAPK *pAPK, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : APK_Script(pAPK, filePart, pOptions, pPdStruct) {}
