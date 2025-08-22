#include "nfd_dos16m.h"

NFD_DOS16M::NFD_DOS16M(XDOS16 *pXdos16, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : DOS16M_Script(pXdos16, filePart, pOptions, pPdStruct) {}
