#ifndef NFD_AMIGA_H
#define NFD_AMIGA_H

#include "amiga_script.h"
#include "nfd_binary.h"

class NFD_Amiga : public Amiga_Script {
    Q_OBJECT

public:
    explicit NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    // Returns an Operation System scans struct for this Amiga binary
    NFD_Binary::SCANS_STRUCT detectOperationSystem(XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_AMIGA_H
