#ifndef NFD_RAR_H
#define NFD_RAR_H

#include "rar_script.h"

class NFD_RAR : public RAR_Script {
    Q_OBJECT

public:
    explicit NFD_RAR(XRar *pRar, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_RAR_H
