#include "nfd_archive.h"

NFD_Archive::NFD_Archive(XArchive *pArchive, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Archive_Script(pArchive, filePart, pOptions, pPdStruct) {}
