/* SPDX-License-Identifier: MIT */
#ifndef NFD_COMPRESSION_H
#define NFD_COMPRESSION_H

#include "nfd_binary.h"

namespace NFDCompression {
// Confirm small standalone compression streams with a complete bounded decode.
bool detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct);
}

#endif
