#include "nfd_dos4g.h"

NFD_DOS4G::NFD_DOS4G(XDOS16 *pXdos16, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : DOS4G_Script(pXdos16, filePart, pOptions, pPdStruct) {}
