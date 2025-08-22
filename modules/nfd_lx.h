#ifndef NFD_LX_H
#define NFD_LX_H

#include "lx_script.h"

class NFD_LX : public LX_Script {
    Q_OBJECT

public:
    explicit NFD_LX(XLE *pLX, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_LX_H
