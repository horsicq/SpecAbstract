#ifndef NFD_ELF_H
#define NFD_ELF_H

#include "elf_script.h"

class NFD_ELF : public ELF_Script {
    Q_OBJECT

public:
    explicit NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_ELF_H
