#ifndef NFD_NE_H
#define NFD_NE_H

#include "ne_script.h"

class NFD_NE : public NE_Script {
    Q_OBJECT

public:
    explicit NFD_NE(XNE *pNE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_NE_H
