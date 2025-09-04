#ifndef NFD_DEX_H
#define NFD_DEX_H

#include "dex_script.h"
#include "nfd_binary.h"

class NFD_DEX : public DEX_Script {
    Q_OBJECT

public:
    explicit NFD_DEX(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct DEXINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        XDEX_DEF::HEADER header;
        QList<XDEX_DEF::MAP_ITEM> mapItems;
        QList<QString> listStrings;
        QList<QString> listTypeItemStrings;
        QList<XDEX_DEF::FIELD_ITEM_ID> listFieldIDs;
        QList<XDEX_DEF::METHOD_ITEM_ID> listMethodIDs;
        bool bIsStringPoolSorted;
        bool bIsOverlayPresent;
    };

    // Accessors for DEX string/type signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::STRING_RECORD *getStringRecords();
    static qint32 getStringRecordsSize();
    static NFD_Binary::STRING_RECORD *getTypeRecords();
    static qint32 getTypeRecordsSize();
};

#endif  // NFD_DEX_H
