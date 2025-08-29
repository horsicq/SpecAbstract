#ifndef NFD_JAVACLASS_H
#define NFD_JAVACLASS_H

#include "javaclass_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_JavaClass : public JavaClass_Script {
    Q_OBJECT

public:
    explicit NFD_JavaClass(XJavaClass *pJavaClass, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct JAVACLASSINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        // Reserved for future JavaClass-specific fields
    };

    static JAVACLASSINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                        XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JAVACLASS_H
