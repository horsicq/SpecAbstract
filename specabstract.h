/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef SPECABSTRACT_H
#define SPECABSTRACT_H

#ifndef USE_ARCHIVE
#define USE_ARCHIVE
#endif
#ifndef USE_DEX
#define USE_DEX
#endif
#ifndef USE_PDF
#define USE_PDF
#endif

#include "xscanengine.h"
#include "nfd_binary.h"

class SpecAbstract : public XScanEngine {
    Q_OBJECT

public:
    // TODO flags(static scan/emul/heur) ? Check
    struct SCAN_STRUCT {
        bool bIsHeuristic;
        bool bIsUnknown;
        SCANID id;
        SCANID parentId;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    enum DETECTTYPE {
        DETECTTYPE_UNKNOWN = 0,
        DETECTTYPE_ARCHIVE,
        DETECTTYPE_CODESECTION,
        DETECTTYPE_DEXSTRING,
        DETECTTYPE_DEXTYPE,
        DETECTTYPE_ENTRYPOINT,
        DETECTTYPE_ENTRYPOINTSECTION,
        DETECTTYPE_HEADER,
        DETECTTYPE_IMPORTHASH,
        DETECTTYPE_NETANSISTRING,
        DETECTTYPE_NETUNICODESTRING,
        DETECTTYPE_OVERLAY,
        DETECTTYPE_DEBUGDATA,
        DETECTTYPE_RESOURCES,
        DETECTTYPE_RICH,
        DETECTTYPE_SECTIONNAME
    };

    struct DETECT_RECORD {
        qint64 nOffset;  // memory scan
        XBinary::FILEPART filepart;
        DETECTTYPE detectType;
        QString sValue;  // mb TODO variant
        quint32 nVariant;
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    struct SCAN_RESULT {
        qint64 nScanTime;
        QString sFileName;
        QList<SCAN_STRUCT> listRecords;
        QList<DETECT_RECORD> listHeurs;
    };

    struct _SCANS_STRUCT {
        qint64 nOffset;
        quint32 nVariant;
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        bool bIsHeuristic;
        bool bIsUnknown;
        QVariant varExtra;
    };

    struct SCAN_RECORD {
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    struct BASIC_INFO {
        qint64 nElapsedTime;
        XScanEngine::SCANID parentId;
        XScanEngine::SCANID id;
        QString sHeaderSignature;
        XBinary::_MEMORY_MAP memoryMap;
        QList<SCAN_STRUCT> listDetects;
        QList<DETECT_RECORD> listHeurs;
        SCAN_OPTIONS scanOptions;

        QMap<RECORD_NAME, _SCANS_STRUCT> mapHeaderDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapTextHeaderDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapStringDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapTypeDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapArchiveDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapMetainfosDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapEntryPointDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapCommentSectionDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapOverlayDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapImportDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapExportDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapDotAnsiStringsDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapDotUnicodeStringsDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapCodeSectionDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapEntryPointSectionDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapSectionNamesDetects;
        QMap<RECORD_NAME, _SCANS_STRUCT> mapResourcesDetects;

        QMap<RECORD_NAME, SCAN_STRUCT> mapResultTexts;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultTools;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultLanguages;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultArchives;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultCertificates;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultDebugData;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultInstallerData;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultSFXData;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultFormats;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultDatabases;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultImages;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultProtectorData;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultLibraryData;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultResources;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultOperationSystems;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultProtectors;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultSigntools;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultAPKProtectors;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultDosExtenders;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultPackers;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultSFX;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultJoiners;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultInstallers;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultNETObfuscators;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultNETCompressors;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultDongleProtection;
        QMap<RECORD_NAME, SCAN_STRUCT> mapResultPETools;
    };

    struct BINARYINFO_STRUCT {
        BASIC_INFO basic_info;
        bool bIsPlainText;
        bool bIsUTF8;
        XBinary::UNICODE_TYPE unicodeType;
        QString sHeaderText;
    };

    struct DEXINFO_STRUCT {
        BASIC_INFO basic_info;

        XDEX_DEF::HEADER header;
        QList<XDEX_DEF::MAP_ITEM> mapItems;
        QList<QString> listStrings;
        QList<QString> listTypeItemStrings;
        QList<XDEX_DEF::FIELD_ITEM_ID> listFieldIDs;
        QList<XDEX_DEF::METHOD_ITEM_ID> listMethodIDs;
        bool bIsStringPoolSorted;
        bool bIsOverlayPresent;
    };

    struct ZIPINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJAR;
        bool bIsIPA;
        bool bIsAPKS;
        bool bIsJava;
        bool bIsKotlin;
    };

    struct JARINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJava;
        bool bIsKotlin;
    };

    struct RARINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;
    };

    struct APKINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJava;
        bool bIsKotlin;

        DEXINFO_STRUCT dexInfoClasses;
    };

    struct AMIGAHUNKINFO_STRUCT {
        BASIC_INFO basic_info;
    };

    struct JPEGINFO_STRUCT {
        BASIC_INFO basic_info;
    };

    struct JAVACLASSINFO_STRUCT {
        BASIC_INFO basic_info;
    };

    struct PDFINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XPDF::XPART> listObjects;
    };

    struct MACHOFATINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;
    };

    struct COMINFO_STRUCT {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    struct MSDOSINFO_STRUCT {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    struct ELFINFO_STRUCT {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;  // TODO move to basic
        QList<XELF::TAG_STRUCT> listTags;
        QList<QString> listLibraries;
        QList<QString> listComments;
        QList<XELF_DEF::Elf_Shdr> listSectionHeaders;
        QList<XELF_DEF::Elf_Phdr> listProgramHeaders;
        QList<XELF::SECTION_RECORD> listSectionRecords;
        QList<XELF::NOTE> listNotes;
        qint32 nSymTabSection;
        qint64 nSymTabOffset;
        qint32 nDebugSection;
        qint64 nDWARFDebugOffset;
        qint64 nDWARFDebugSize;

        qint32 nCommentSection;
        qint32 nStringTableSection;
        QByteArray baStringTable;
        QString sRunPath;

        XBinary::OFFSETSIZE osCommentSection;
    };

    struct LEINFO_STRUCT {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;

        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
    };

    struct LXINFO_STRUCT {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;

        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
    };

    struct NEINFO_STRUCT {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    struct MACHOINFO_STRUCT {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;
        QList<XMACH::COMMAND_RECORD> listCommandRecords;
        QList<XMACH::LIBRARY_RECORD> listLibraryRecords;
        QList<XMACH::SEGMENT_RECORD> listSegmentRecords;
        QList<XMACH::SECTION_RECORD> listSectionRecords;
    };

    struct PEINFO_STRUCT {
        BASIC_INFO basic_info;
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

    struct _BASICINFO {
        quint32 nVariant;
        const XBinary::FT fileType;
        const RECORD_TYPE type;
        const RECORD_NAME name;
        const char *pszVersion;
        const char *pszInfo;
    };

    struct SIGNATURE_RECORD {
        _BASICINFO basicInfo;
        const char *pszSignature;
    };

    struct STRING_RECORD {
        _BASICINFO basicInfo;
        const char *pszString;
    };

    struct PE_RESOURCES_RECORD {
        _BASICINFO basicInfo;
        bool bIsString1;
        const char *pszName1;
        quint32 nID1;
        bool bIsString2;
        const char *pszName2;
        quint32 nID2;
    };

    struct CONST_RECORD {
        _BASICINFO basicInfo;
        quint64 nConst1;
        quint64 nConst2;
    };

    struct MSRICH_RECORD {
        _BASICINFO basicInfo;
        quint16 nID;
        quint32 nBuild;
    };

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

    struct VI_STRUCT {
        bool bIsValid;
        QString sVersion;
        QString sInfo;
        QVariant vValue;
    };

    explicit SpecAbstract(QObject *pParent = nullptr);

    static QString append(const QString &sResult, const QString &sString);  // Move

    static QString heurTypeIdToString(qint32 nId);

    static QString _SCANS_STRUCT_toString(const _SCANS_STRUCT *pScanStruct, bool bShowType = true);

    static BASIC_INFO _initBasicInfo(XBinary *pBinary, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    static BINARYINFO_STRUCT getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                           XBinary::PDSTRUCT *pPdStruct);
    static COMINFO_STRUCT getCOMInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static MSDOSINFO_STRUCT getMSDOSInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct);
    static ELFINFO_STRUCT getELFInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static MACHOINFO_STRUCT getMACHOInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct);
    static LEINFO_STRUCT getLEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static LXINFO_STRUCT getLXInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static NEINFO_STRUCT getNEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static PEINFO_STRUCT getPEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static DEXINFO_STRUCT getDEXInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static ZIPINFO_STRUCT getZIPInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static JARINFO_STRUCT getJARInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static RARINFO_STRUCT getRARInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static APKINFO_STRUCT getAPKInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static AMIGAHUNKINFO_STRUCT getAmigaHunkInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                 XBinary::PDSTRUCT *pPdStruct);
    static PDFINFO_STRUCT getPDFInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static JPEGINFO_STRUCT getJpegInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                       XBinary::PDSTRUCT *pPdStruct);
    static JAVACLASSINFO_STRUCT getJavaClassInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                 XBinary::PDSTRUCT *pPdStruct);

    static _SCANS_STRUCT getScansStruct(quint32 nVariant, XBinary::FT fileType, RECORD_TYPE type, RECORD_NAME name, const QString &sVersion, const QString &sInfo,
                                        qint64 nOffset);

    static void PE_handle_import(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);  // TODO remove !!!
    static void PE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_VMProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_VProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo,
                                   XBinary::PDSTRUCT *pPdStruct);  // TODO move to protection
    static void PE_handle_TTProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo,
                                    XBinary::PDSTRUCT *pPdStruct);  // TODO move to protection
    static void PE_handle_SafeengineShielden(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_tElock(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Armadillo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Obsidium(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Themida(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_StarForce(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Petite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_NETProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Watcom(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_PETools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_wxWidgets(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Signtools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_Installers(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_PolyMorph(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_DongleProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_NeoLite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_PrivateEXEProtector(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_VisualBasicCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_DelphiCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void PE_handle_Joiners(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void PE_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static bool PE_isProtectionPresent(PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PE_handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void PE_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void Binary_handle_Texts(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo, XBinary::PDSTRUCT *pPdStruct);
    static void COM_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct);
    static void COM_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Binary_handle_Archives(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Binary_handle_Certificates(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Binary_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Databases(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Images(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_InstallerData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_SFXData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_ProtectorData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_LibraryData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Resources(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);

    static void Binary_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo);

    static void MSDOS_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_handle_DosExtenders(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);

    static void ELF_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_CommentSection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void ELF_handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);

    static void ELF_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct);

    static void MACHO_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MACHO_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);
    static void MACHO_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);

    static void LE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LE_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LE_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void LX_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LX_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LX_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void LX_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct);

    static void NE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void NE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct);
    static void NE_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void DEX_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void DEX_handle_Dexguard(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void DEX_handle_Protection(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);

    static void Zip_handle_Microsoftoffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Zip_handle_OpenOffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Zip_handle_Metainfos(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BASIC_INFO *pBasicInfo, QList<XArchive::RECORD> *pListArchiveRecords,
                                     XBinary::PDSTRUCT *pPdStruct);
    static void Zip_handle_JAR(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct);
    static void APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Zip_handle_IPA(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct);
    static void Zip_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct);

    static void APK_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct);

    static void AmigaHunk_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, AMIGAHUNKINFO_STRUCT *pAmigaHunkInfo,
                                                 XBinary::PDSTRUCT *pPdStruct);

    static void PDF_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PDFINFO_STRUCT *pPDFInfo, XBinary::PDSTRUCT *pPdStruct);
    static void PDF_handle_Tags(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PDFINFO_STRUCT *pPDFInfo, XBinary::PDSTRUCT *pPdStruct);

    static void Jpeg_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, JPEGINFO_STRUCT *pJpegInfo, XBinary::PDSTRUCT *pPdStruct);

    static DEXINFO_STRUCT APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct,
                                       const QString &sFileName);

    static void updateVersion(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sVersion);
    static void updateInfo(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sInfo);
    static void updateVersionAndInfo(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sVersion, const QString &sInfo);

    static bool isScanStructPresent(QList<XScanEngine::SCANSTRUCT> *pListScanStructs, XBinary::FT fileType, RECORD_TYPE type = RECORD_TYPE_UNKNOWN,
                                    RECORD_NAME name = RECORD_NAME_UNKNOWN, const QString &sVersion = "", const QString &sInfo = "");

    static VI_STRUCT get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType,
                                XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT _get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType);
    static VI_STRUCT get_GCC_vi1(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_GCC_vi2(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Nim_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Zig_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Watcom_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_PyInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_DWRAF_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT _get_GCC_string(const QString &sString);
    static VI_STRUCT get_WindowsInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_gold_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_TurboLinker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions);
    static VI_STRUCT get_Enigma_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_DeepSea_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_SmartAssembly_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_R8_marker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Go_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Rust_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_ObfuscatorLLVM_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT _get_ObfuscatorLLVM_string(const QString &sString);
    static VI_STRUCT get_AndroidClang_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT _get_AndroidClang_string(const QString &sString);
    static VI_STRUCT _get_AlipayClang_string(const QString &sString);
    static VI_STRUCT _get_AlpineClang_string(const QString &sString);
    static VI_STRUCT _get_AlibabaClang_string(const QString &sString);
    static VI_STRUCT _get_PlexClang_string(const QString &sString);
    static VI_STRUCT _get_UbuntuClang_string(const QString &sString);
    static VI_STRUCT _get_DebianClang_string(const QString &sString);
    static VI_STRUCT _get_AlipayObfuscator_string(const QString &sString);
    static VI_STRUCT _get_wangzehuaLLVM_string(const QString &sString);
    static VI_STRUCT _get_ByteGuard_string(const QString &sString);
    static VI_STRUCT _get_TencentObfuscation_string(const QString &sString);
    static VI_STRUCT _get_AppImage_string(const QString &sString);
    static VI_STRUCT _get_HikariObfuscator_string(const QString &sString);
    static VI_STRUCT _get_SnapProtect_string(const QString &sString);
    static VI_STRUCT _get_ByteDanceSecCompiler_string(const QString &sString);
    static VI_STRUCT _get_DingbaozengNativeObfuscator_string(const QString &sString);
    static VI_STRUCT _get_SafeengineLLVM_string(const QString &sString);
    static VI_STRUCT _get_NagainLLVM_string(const QString &sString);
    static VI_STRUCT _get_iJiami_string(const QString &sString);
    static VI_STRUCT _get_AppleLLVM_string(const QString &sString);
    static VI_STRUCT _get_ApportableClang_string(const QString &sString);
    static VI_STRUCT _get_ARMAssembler_string(const QString &sString);
    static VI_STRUCT _get_ARMLinker_string(const QString &sString);
    static VI_STRUCT _get_ARMC_string(const QString &sString);
    static VI_STRUCT _get_ARMCCPP_string(const QString &sString);
    static VI_STRUCT _get_ARMNEONCCPP_string(const QString &sString);
    static VI_STRUCT _get_ARMThumbCCPP_string(const QString &sString);
    static VI_STRUCT _get_ARMThumbMacroAssembler_string(const QString &sString);
    static VI_STRUCT _get_ThumbC_string(const QString &sString);
    static VI_STRUCT _get_clang_string(const QString &sString);
    static VI_STRUCT _get_DynASM_string(const QString &sString);
    static VI_STRUCT _get_Delphi_string(const QString &sString);
    static VI_STRUCT _get_LLD_string(const QString &sString);
    static VI_STRUCT _get_mold_string(const QString &sString);
    static VI_STRUCT _get_OracleSolarisLinkEditors_string(const QString &sString);
    static VI_STRUCT _get_SunWorkShop_string(const QString &sString);
    static VI_STRUCT _get_SunWorkShopCompilers_string(const QString &sString);
    static VI_STRUCT _get_SnapdragonLLVMARM_string(const QString &sString);
    static VI_STRUCT _get_NASM_string(const QString &sString);
    static VI_STRUCT _get_TencentLegu_string(const QString &sString);
    static VI_STRUCT _get_OllvmTll_string(const QString &sString);
    static VI_STRUCT _get_DelphiVersionFromCompiler(const QString &sString);
    static VI_STRUCT _get_SourceryCodeBench_string(const QString &sString);
    static VI_STRUCT _get_Rust_string(const QString &sString);

    static void _handleResult(BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct);

    static bool PE_isValid_UPX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);
    static void PE_x86Emul(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static VI_STRUCT PE_get_PECompact_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);

    static QList<VCL_STRUCT> PE_getVCLstruct(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, bool bIs64,
                                             XBinary::PDSTRUCT *pPdStruct);
    static VCL_PACKAGEINFO PE_getVCLPackageInfo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, QList<XPE::RESOURCE_RECORD> *pListResources,
                                                XBinary::PDSTRUCT *pPdStruct);

    static SCAN_STRUCT scansToScan(BASIC_INFO *pBasicInfo, _SCANS_STRUCT *pScansStruct);

    static void memoryScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                           SpecAbstract::SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                           DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void signatureScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, const QString &sSignature, SIGNATURE_RECORD *pRecords, qint32 nRecordsSize,
                              XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void PE_resourcesScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, PE_RESOURCES_RECORD *pRecords,
                                 qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                 XBinary::PDSTRUCT *pPdStruct);
    static void stringScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, STRING_RECORD *pRecords, qint32 nRecordsSize,
                           XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void constScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, CONST_RECORD *pRecords, qint32 nRecordsSize,
                          XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void MSDOS_richScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, quint32 nCount, MSRICH_RECORD *pRecords, qint32 nRecordsSize,
                               XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void archiveScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords, qint32 nRecordsSize,
                            XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void archiveExpScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords, qint32 nRecordsSize,
                               XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);

    static void signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, qint64 nOffset,
                                 SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                                 DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);

    static QList<_SCANS_STRUCT> MSDOS_richScan(quint16 nID, quint32 nBuild, quint32 nCount, MSRICH_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1,
                                               XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);

    static QByteArray serializeScanStruct(const SCAN_STRUCT &scanStruct, bool bIsHeader = false);
    static SCAN_STRUCT deserializeScanStruct(const QByteArray &baData, bool *pbIsHeader = nullptr);

    static void getLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages, XBinary::PDSTRUCT *pPdStruct);
    static void fixLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages);

    static _SCANS_STRUCT getOperationSystemScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo);
    static _SCANS_STRUCT getFormatScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo);
    static QString getMsRichString(quint16 nId, quint16 nBuild, quint32 nCount, XBinary::PDSTRUCT *pPdStruct);

    static QList<XScanEngine::SCANSTRUCT> convert(QList<SCAN_STRUCT> *pListScanStructs);
    static QList<XScanEngine::DEBUG_RECORD> convertHeur(QList<DETECT_RECORD> *pListDetectRecords);

private:
    static bool MSDOS_compareRichRecord(_SCANS_STRUCT *pResult, MSRICH_RECORD *pRecord, quint16 nID, quint32 nBuild, quint32 nCount, XBinary::FT fileType1,
                                        XBinary::FT fileType2);
    static void filterResult(QList<SCAN_STRUCT> *pListRecords, const QSet<RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct);
    static void _fixRichSignatures(QList<_SCANS_STRUCT> *pListRichSignatures, qint32 nMajorLinkerVersion, qint32 nMinorLinkerVersion, XBinary::PDSTRUCT *pPdStruct);

protected:
    virtual void _processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // SPECABSTRACT_H
