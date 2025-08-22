#ifndef NFD_AMIGA_H
#define NFD_AMIGA_H

#include "amiga_script.h"

class NFD_Amiga : public Amiga_Script {
    Q_OBJECT

public:
    explicit NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_AMIGA_H
