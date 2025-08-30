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
#include "modules/nfd_binary.h"
#include "modules/nfd_amiga.h"
#include "modules/nfd_jpeg.h"
#include "modules/nfd_cfbf.h"
#include "modules/nfd_pdf.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_com.h"
#include "modules/nfd_msdos.h"
// Newly delegated NFD modules
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"

class SpecAbstract : public XScanEngine {
    Q_OBJECT

public:
    // TODO flags(static scan/emul/heur) ? Check
    using SCAN_STRUCT = NFD_Binary::SCAN_STRUCT;
    // DETECTTYPE is declared as a global unscoped enum in nfd_binary.h
    using DETECT_RECORD = NFD_Binary::DETECT_RECORD;
    using _SCANS_STRUCT = NFD_Binary::SCANS_STRUCT;
    using BASIC_INFO = NFD_Binary::BASIC_INFO;
    using BINARYINFO_STRUCT = NFD_Binary::BINARYINFO_STRUCT;
    using AMIGAHUNKINFO_STRUCT = NFD_Amiga::AMIGAHUNKINFO_STRUCT;
    using CFBFINFO_STRUCT = NFD_CFBF::CFBFINFO_STRUCT;
    using VI_STRUCT = NFD_Binary::VI_STRUCT;

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

    using RARINFO_STRUCT = NFD_RAR::RARINFO_STRUCT;

    struct APKINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJava;
        bool bIsKotlin;

        DEXINFO_STRUCT dexInfoClasses;
    };

    using JPEGINFO_STRUCT = NFD_JPEG::JPEGINFO_STRUCT;

    using JAVACLASSINFO_STRUCT = NFD_JavaClass::JAVACLASSINFO_STRUCT;

    using PDFINFO_STRUCT = NFD_PDF::PDFINFO_STRUCT;

    struct MACHOFATINFO_STRUCT {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;
    };

    using COMINFO_STRUCT = NFD_COM::COMINFO_STRUCT;

    using MSDOSINFO_STRUCT = NFD_MSDOS::MSDOSINFO_STRUCT;

    using ELFINFO_STRUCT = NFD_ELF::ELFINFO_STRUCT;

    using LEINFO_STRUCT = NFD_LE::LEINFO_STRUCT;

    using LXINFO_STRUCT = NFD_LX::LXINFO_STRUCT;

    using NEINFO_STRUCT = NFD_NE::NEINFO_STRUCT;

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

    using _BASICINFO = NFD_Binary::_BASICINFO;
    using SIGNATURE_RECORD = NFD_Binary::SIGNATURE_RECORD;
    using STRING_RECORD = NFD_Binary::STRING_RECORD;
    using PE_RESOURCES_RECORD = NFD_Binary::PE_RESOURCES_RECORD;
    using CONST_RECORD = NFD_Binary::CONST_RECORD;
    using MSRICH_RECORD = NFD_Binary::MSRICH_RECORD;

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


    explicit SpecAbstract(QObject *pParent = nullptr);

    static BINARYINFO_STRUCT getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                           XBinary::PDSTRUCT *pPdStruct);
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
    static CFBFINFO_STRUCT getCFBFInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
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

    // LE/LX Microsoft-specific handlers moved into NFD modules

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

    static DEXINFO_STRUCT APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct,
                                       const QString &sFileName);

    static void updateVersion(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sVersion);
    static void updateInfo(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sInfo);
    static void updateVersionAndInfo(QMap<RECORD_NAME, SCAN_STRUCT> *pMap, RECORD_NAME name, const QString &sVersion, const QString &sInfo);

    static bool isScanStructPresent(QList<XScanEngine::SCANSTRUCT> *pListScanStructs, XBinary::FT fileType, RECORD_TYPE type = RECORD_TYPE_UNKNOWN,
                                    RECORD_NAME name = RECORD_NAME_UNKNOWN, const QString &sVersion = "", const QString &sInfo = "");


    static bool PE_isValid_UPX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);
    static void PE_x86Emul(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static VI_STRUCT PE_get_PECompact_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);

    static QList<VCL_STRUCT> PE_getVCLstruct(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, bool bIs64,
                                             XBinary::PDSTRUCT *pPdStruct);
    static VCL_PACKAGEINFO PE_getVCLPackageInfo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, QList<XPE::RESOURCE_RECORD> *pListResources,
                                                XBinary::PDSTRUCT *pPdStruct);

    static QList<XScanEngine::SCANSTRUCT> convert(QList<SCAN_STRUCT> *pListScanStructs);
    static QList<XScanEngine::DEBUG_RECORD> convertHeur(QList<DETECT_RECORD> *pListDetectRecords);

private:
    // MSDOS_compareRichRecord moved into NFD_MSDOS
    static void filterResult(QList<SCAN_STRUCT> *pListRecords, const QSet<RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct);
    static void _fixRichSignatures(QList<_SCANS_STRUCT> *pListRichSignatures, qint32 nMajorLinkerVersion, qint32 nMinorLinkerVersion, XBinary::PDSTRUCT *pPdStruct);

protected:
    virtual void _processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // SPECABSTRACT_H
