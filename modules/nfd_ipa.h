#ifndef NFD_IPA_H
#define NFD_IPA_H

#include "ipa_script.h"

class NFD_IPA : public IPA_Script {
    Q_OBJECT

public:
    explicit NFD_IPA(XIPA *pIPA, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_IPA_H
