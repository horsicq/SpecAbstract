#include "nfd_elf.h"

NFD_ELF::NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : ELF_Script(pELF, filePart, pOptions, pPdStruct) {}
