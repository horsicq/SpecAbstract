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
#ifndef NFD_BINARY_H
#define NFD_BINARY_H

#include "binary_script.h"
#include "xscanengine.h"
#include <QtCore/QString>
#include <QtCore/QVariant>
#include <QtCore/QMap>
#include <QtCore/QList>

// Common detection type used across NFD and SpecAbstract
// Kept as unscoped enum so legacy DETECTTYPE_* constants remain available
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

// Forward declaration to use SpecAbstract::VI_STRUCT in prototypes without cyclic include
class NFD_Binary : public Binary_Script {
    Q_OBJECT

public:
    // Common detection/scan types used across NFD and SpecAbstract
    struct SCAN_STRUCT {
        bool bIsHeuristic;
        bool bIsUnknown;
        XScanEngine::SCANID id;
        XScanEngine::SCANID parentId;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    // Generic version/info result used by vi helpers (moved from SpecAbstract)
    struct VI_STRUCT {
        bool bIsValid;
        QString sVersion;
        QString sInfo;
        QVariant vValue;
    };

    struct DETECT_RECORD {
        qint64 nOffset;  // memory scan
        XBinary::FILEPART filepart;
        DETECTTYPE detectType;
        QString sValue;  // mb TODO variant
        quint32 nVariant;
        XBinary::FT fileType;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    // Unified scan record structure moved from SpecAbstract
    struct SCANS_STRUCT {
        qint64 nOffset;
        quint32 nVariant;
        XBinary::FT fileType;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        bool bIsHeuristic;
        bool bIsUnknown;
        QVariant varExtra;
    };

    // Core scanning context moved from SpecAbstract
    struct BASIC_INFO {
        qint64 nElapsedTime;
        XScanEngine::SCANID parentId;
        XScanEngine::SCANID id;
        QString sHeaderSignature;
        XBinary::_MEMORY_MAP memoryMap;
        QList<SCAN_STRUCT> listDetects;
        QList<DETECT_RECORD> listHeurs;
        XScanEngine::SCAN_OPTIONS scanOptions;

        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapHeaderDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapTextHeaderDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapStringDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapTypeDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapArchiveDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapMetainfosDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapEntryPointDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapCommentSectionDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapOverlayDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapImportDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapExportDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapDotAnsiStringsDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapDotUnicodeStringsDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapCodeSectionDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapEntryPointSectionDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapSectionNamesDetects;
        QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> mapResourcesDetects;

        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultTexts;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultTools;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultLanguages;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultLibraries;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultArchives;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultCertificates;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultDebugData;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultInstallerData;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultSFXData;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultFormats;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultDatabases;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultImages;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultProtectorData;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultLibraryData;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultResources;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultOperationSystems;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultLinkers;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultCompilers;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultProtectors;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultSigntools;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultAPKProtectors;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultDosExtenders;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultPackers;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultSFX;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultJoiners;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultInstallers;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultNETObfuscators;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultNETCompressors;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultDongleProtection;
        QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> mapResultPETools;
    };

    // Generic binary info container moved from SpecAbstract
    struct BINARYINFO_STRUCT {
        BASIC_INFO basic_info;
        bool bIsPlainText;
        bool bIsUTF8;
        XBinary::UNICODE_TYPE unicodeType;
        QString sHeaderText;
    };

    // Scan table descriptors (moved from SpecAbstract)
    struct _BASICINFO {
        quint32 nVariant;
        XBinary::FT fileType;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
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

    // Accessors for centralized signature tables used by Binary scans
    // These return pointers to the local g_* tables in nfd_binary.cpp and their byte sizes
    static SIGNATURE_RECORD *getBinaryRecords();
    static qint32 getBinaryRecordsSize();
    static SIGNATURE_RECORD *getDebugdataRecords();
    static qint32 getDebugdataRecordsSize();
    static SIGNATURE_RECORD *getArchiveRecords();
    static qint32 getArchiveRecordsSize();
    static SIGNATURE_RECORD *getPEOverlayRecords();
    static qint32 getPEOverlayRecordsSize();

    // Utility: stringify a scan struct (moved from SpecAbstract)
    static QString _SCANS_STRUCT_toString(const SCANS_STRUCT *pScanStruct, bool bShowType = true);

    // Utility: convert SCANS_STRUCT + BASIC_INFO into a concrete SCAN_STRUCT (moved from SpecAbstract)
    static SCAN_STRUCT scansToScan(BASIC_INFO *pBasicInfo, SCANS_STRUCT *pScansStruct);

    // Derive Operation System directly from a binary instance
    static SCANS_STRUCT detectOperationSystem(XBinary *pBinary, XBinary::PDSTRUCT *pPdStruct);

    // Language aggregation helpers (moved from SpecAbstract)
    static void getLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages,
                            XBinary::PDSTRUCT *pPdStruct);
    static void fixLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages);

    // Converters from FILEFORMATINFO to scan records (moved from SpecAbstract)
    static SCANS_STRUCT getFormatScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo);
    static SCANS_STRUCT getOperationSystemScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo);

    // Insert a header-detected record into result maps (packers/protectors) if present
    static void addHeaderDetectToResults(BASIC_INFO *pBasicInfo, XScanEngine::RECORD_NAME rn, bool toProtector);

    // Moved from NFD_BinaryUtils: basic scan context init and final result synthesis
    static BASIC_INFO _initBasicInfo(XBinary *pBinary, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static void _handleResult(BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct);

    // Utility: convert global scan options to Binary_Script options
    static Binary_Script::OPTIONS toOptions(const XScanEngine::SCAN_OPTIONS *pScanOptions);

    explicit NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, Binary_Script::OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    // Scanning helpers moved from SpecAbstract
    static void memoryScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                           qint64 nSize, SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                           DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void signatureScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, const QString &sSignature, SIGNATURE_RECORD *pRecords, qint32 nRecordsSize,
                              XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void PE_resourcesScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, PE_RESOURCES_RECORD *pRecords,
                                 qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                 XBinary::PDSTRUCT *pPdStruct);
    static void stringScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, STRING_RECORD *pRecords, qint32 nRecordsSize,
                           XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    static void constScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, CONST_RECORD *pRecords, qint32 nRecordsSize,
                          XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);
    // MSDOS Rich scan moved to NFD_MSDOS
    static void archiveScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords,
                            qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                            XBinary::PDSTRUCT *pPdStruct);
    static void archiveExpScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords,
                               qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                               XBinary::PDSTRUCT *pPdStruct);
    static void signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, qint64 nOffset,
                                 SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                                 DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);

    // Version-info helpers moved from SpecAbstract
    static VI_STRUCT get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType,
                                XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT _get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType);

    // Version-info helpers moved from SpecAbstract (delegated wrappers remain there)
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

    // Version-info helpers moved from SpecAbstract (GCC/Nim/Zig)
    static VI_STRUCT get_GCC_vi1(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_GCC_vi2(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Nim_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_Zig_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);

    // String parsers moved from SpecAbstract
    static VI_STRUCT _get_GCC_string(const QString &sString);
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

    // Additional VI helpers moved from SpecAbstract
    static VI_STRUCT get_Watcom_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_PyInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_DWRAF_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_WindowsInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_gold_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct);
    static VI_STRUCT get_TurboLinker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions);

signals:
};

#endif  // NFD_BINARY_H
