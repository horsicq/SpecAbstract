#ifndef NFD_TEXT_H
#define NFD_TEXT_H

#include "nfd_binary.h"

class NFD_TEXT {
public:
    // STRING_RECORD based tables (migrated from SpecAbstract/signatures.cpp)
    static NFD_Binary::STRING_RECORD *getTextExpRecords();
    static qint32 getTextExpRecordsSize();
};

#endif  // NFD_TEXT_H
