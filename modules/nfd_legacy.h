/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * MIT License
 */
#ifndef NFD_LEGACY_H
#define NFD_LEGACY_H

#include "nfd_binary.h"

namespace NFDLegacy {
// Bounded outer-format recognition. Does not unpack members or use file names.
// On failure no result is added; the device position is restored on all paths.
bool detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct);
}

#endif
