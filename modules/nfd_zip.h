#ifndef NFD_ZIP_H
#define NFD_ZIP_H

#include "zip_script.h"
#include "nfd_binary.h"
#include "xarchive.h"

class NFD_ZIP : public ZIP_Script {
    Q_OBJECT

public:
    explicit NFD_ZIP(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct ZIPINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJAR;
        bool bIsIPA;
        bool bIsAPKS;
        bool bIsJava;
        bool bIsKotlin;
    };
};

#endif  // NFD_ZIP_H
