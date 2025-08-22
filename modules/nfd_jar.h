#ifndef NFD_JAR_H
#define NFD_JAR_H

#include "jar_script.h"

class NFD_JAR : public JAR_Script {
    Q_OBJECT

public:
    explicit NFD_JAR(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JAR_H
