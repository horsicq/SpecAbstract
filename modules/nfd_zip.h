#ifndef NFD_ZIP_H
#define NFD_ZIP_H

#include "zip_script.h"

class NFD_ZIP : public ZIP_Script {
    Q_OBJECT

public:
    explicit NFD_ZIP(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_ZIP_H
