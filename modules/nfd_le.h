#ifndef NFD_LE_H
#define NFD_LE_H

#include "le_script.h"

class NFD_LE : public LE_Script {
    Q_OBJECT

public:
    explicit NFD_LE(XLE *pLE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_LE_H
