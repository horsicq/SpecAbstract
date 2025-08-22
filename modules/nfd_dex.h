#ifndef NFD_DEX_H
#define NFD_DEX_H

#include "dex_script.h"

class NFD_DEX : public DEX_Script {
    Q_OBJECT

public:
    explicit NFD_DEX(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_DEX_H
