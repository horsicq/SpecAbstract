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

class NFD_Binary : public Binary_Script
{
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

    // Moved from NFD_BinaryUtils: basic scan context init and final result synthesis
    static BASIC_INFO _initBasicInfo(XBinary *pBinary, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                     XBinary::PDSTRUCT *pPdStruct);
    static void _handleResult(BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct);

    // Utility: convert global scan options to Binary_Script options
    static Binary_Script::OPTIONS toOptions(const XScanEngine::SCAN_OPTIONS *pScanOptions);

    explicit NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, Binary_Script::OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

signals:
};

#endif // NFD_BINARY_H
