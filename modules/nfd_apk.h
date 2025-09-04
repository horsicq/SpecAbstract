#ifndef NFD_APK_H
#define NFD_APK_H

#include "apk_script.h"
#include "nfd_binary.h"
#include "xarchive.h"
#include "nfd_dex.h"

class NFD_APK : public APK_Script {
    Q_OBJECT

public:
    explicit NFD_APK(XAPK *pAPK, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct APKINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJava;
        bool bIsKotlin;

        NFD_DEX::DEXINFO_STRUCT dexInfoClasses;
    };
};

#endif  // NFD_APK_H
