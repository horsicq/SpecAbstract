#ifndef NFD_CFBF_H
#define NFD_CFBF_H

#include "cfbf_script.h"

class NFD_CFBF : public CFBF_Script {
    Q_OBJECT

public:
    explicit NFD_CFBF(XCFBF *pCFBF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_CFBF_H
