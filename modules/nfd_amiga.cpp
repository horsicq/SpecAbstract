#include "nfd_amiga.h"

NFD_Amiga::NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Amiga_Script(pAmiga, filePart, pOptions, pPdStruct) {}
