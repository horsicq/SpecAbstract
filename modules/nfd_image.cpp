#include "nfd_image.h"

NFD_IMAGE::NFD_IMAGE(XBinary *pImage, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Image_Script(pImage, filePart, pOptions, pPdStruct) {}
