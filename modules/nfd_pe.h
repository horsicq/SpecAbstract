#ifndef NFD_PE_H
#define NFD_PE_H

#include "pe_script.h"
#include "nfd_msdos.h"
#include "nfd_binary.h"
#include "xpe.h"
#include "xmsdos.h"

class NFD_PE : public PE_Script {
    Q_OBJECT

public:
    explicit NFD_PE(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct VCL_STRUCT {
        quint32 nValue;
        qint64 nOffset;
        bool bIs64;
    };

    struct VCL_PACKAGEINFO_MODULE {
        quint8 nFlags;
        quint8 nHashCode;
        QString sName;
    };

    struct VCL_PACKAGEINFO {
        quint32 nFlags;
        quint32 nUnknown;
        quint32 nRequiresCount;
        QList<VCL_PACKAGEINFO_MODULE> listModules;
    };

    struct PEINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
        XMSDOS_DEF::IMAGE_DOS_HEADEREX dosHeader;
        XPE_DEF::IMAGE_FILE_HEADER fileHeader;
        union OPTIONAL_HEADER {
            XPE_DEF::IMAGE_OPTIONAL_HEADER32 optionalHeader32;
            XPE_DEF::IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        } optional_header;
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSectionHeaders;
        QList<XPE::SECTION_RECORD> listSectionRecords;
        QList<QString> listSectionNames;
        QList<XPE::IMPORT_HEADER> listImports;
        QList<XPE::IMPORT_RECORD> listImportRecords;
        quint64 nImportHash64;
        quint32 nImportHash32;
        QList<quint32> listImportPositionHashes;
        XPE::EXPORT_HEADER exportHeader;
        QList<QString> listExportFunctionNames;
        QList<XPE::RESOURCE_RECORD> listResources;
        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
        QString sResourceManifest;
        XPE::RESOURCES_VERSION resVersion;
        XPE::CLI_INFO cliInfo;
        QList<QString> listAnsiStrings;
        QList<QString> listUnicodeStrings;

        qint32 nEntryPointSection;
        qint32 nResourcesSection;
        qint32 nImportSection;
        qint32 nCodeSection;
        qint32 nDataSection;
        qint32 nConstDataSection;
        qint32 nRelocsSection;
        qint32 nTLSSection;
        qint32 nIATSection;
        QString sEntryPointSectionName;
        XADDR nEntryPointAddress;
        XADDR nImageBaseAddress;
        quint8 nMinorLinkerVersion;
        quint8 nMajorLinkerVersion;
        quint16 nMinorImageVersion;
        quint16 nMajorImageVersion;
        bool bIs64;
        bool bIsNetPresent;
        bool bIsTLSPresent;

        XBinary::OFFSETSIZE osHeader;
        XBinary::OFFSETSIZE osEntryPointSection;
        XBinary::OFFSETSIZE osCodeSection;
        XBinary::OFFSETSIZE osDataSection;
        XBinary::OFFSETSIZE osConstDataSection;
        XBinary::OFFSETSIZE osImportSection;
        XBinary::OFFSETSIZE osResourcesSection;
    };
};

#endif  // NFD_PE_H
