#ifndef NFD_MACHOFAT_H
#define NFD_MACHOFAT_H

#include "machofat_script.h"
#include "nfd_binary.h"
#include "xarchive.h"

class NFD_MACHOFAT : public MACHOFAT_Script {
    Q_OBJECT

public:
    explicit NFD_MACHOFAT(XMACHOFat *pMachofat, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct MACHOFATINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QList<XArchive::RECORD> listArchiveRecords;
    };
};

#endif  // NFD_MACHOFAT_H
