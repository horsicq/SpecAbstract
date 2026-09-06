/* SPDX-License-Identifier: MIT */
#ifndef NFD_ARCHIVEHEADERS_H
#define NFD_ARCHIVEHEADERS_H

#include "nfd_binary.h"

namespace NFDArchiveHeaders {
// Recognize archive headers without requiring the payload codec to be supported.
bool detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct);
}

#endif
