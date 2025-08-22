#ifndef NFD_NPM_H
#define NFD_NPM_H

#include "npm_script.h"

class NFD_NPM : public NPM_Script {
    Q_OBJECT

public:
    explicit NFD_NPM(XNPM *pNpm, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_NPM_H
