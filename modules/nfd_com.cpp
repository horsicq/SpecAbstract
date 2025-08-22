#include "nfd_com.h"

NFD_COM::NFD_COM(XCOM *pCOM, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : COM_Script(pCOM, filePart, pOptions, pPdStruct) {}
