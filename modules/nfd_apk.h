#ifndef NFD_APK_H
#define NFD_APK_H

#include "nfd_binary.h"
#include "apk_script.h"
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

    // STRING_RECORD based tables (migrated from SpecAbstract/signatures.cpp)
    static NFD_Binary::STRING_RECORD *getFileRecords();
    static qint32 getFileRecordsSize();
    static NFD_Binary::STRING_RECORD *getFileExpRecords();
    static qint32 getFileExpRecordsSize();
};

#endif  // NFD_APK_H
