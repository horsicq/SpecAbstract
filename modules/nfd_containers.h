#ifndef NFD_CONTAINERS_H
#define NFD_CONTAINERS_H

#include "nfd_binary.h"

namespace NFDContainers {
// Content-only, bounded recognition. Restores the device position.
bool detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo, XBinary::PDSTRUCT *pPdStruct);
}

#endif  // NFD_CONTAINERS_H
