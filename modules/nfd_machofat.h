#ifndef NFD_MACHOFAT_H
#define NFD_MACHOFAT_H

#include "machofat_script.h"

class NFD_MACHOFAT : public MACHOFAT_Script {
    Q_OBJECT

public:
    explicit NFD_MACHOFAT(XMACHOFat *pMachofat, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_MACHOFAT_H
