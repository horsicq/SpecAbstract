#include "nfd_jar.h"

NFD_JAR::NFD_JAR(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : JAR_Script(pZip, filePart, pOptions, pPdStruct) {}
