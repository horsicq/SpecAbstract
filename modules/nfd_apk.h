#ifndef NFD_APK_H
#define NFD_APK_H

#include "apk_script.h"

class NFD_APK : public APK_Script {
    Q_OBJECT

public:
    explicit NFD_APK(XAPK *pAPK, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_APK_H
