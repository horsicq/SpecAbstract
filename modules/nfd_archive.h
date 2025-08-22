#ifndef NFD_ARCHIVE_H
#define NFD_ARCHIVE_H

#include "archive_script.h"

class NFD_Archive : public Archive_Script {
    Q_OBJECT

public:
    explicit NFD_Archive(XArchive *pArchive, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_ARCHIVE_H
