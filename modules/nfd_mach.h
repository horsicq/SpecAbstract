#ifndef NFD_MACH_H
#define NFD_MACH_H

#include "mach_script.h"

class NFD_MACH : public MACH_Script {
    Q_OBJECT

public:
    explicit NFD_MACH(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_MACH_H
