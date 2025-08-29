#ifndef NFD_PE_H
#define NFD_PE_H

#include "pe_script.h"
#include "nfd_msdos.h"

class NFD_PE : public PE_Script {
    Q_OBJECT

public:
    explicit NFD_PE(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_PE_H
