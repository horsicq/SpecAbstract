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
#include "modules/nfd_dex.h"
#include "modules/nfd_zip.h"
#include "modules/nfd_jar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_machofat.h"
#include "modules/nfd_mach.h"
#include "modules/nfd_pe.h"

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
    using DEXINFO_STRUCT = NFD_DEX::DEXINFO_STRUCT;
    using ZIPINFO_STRUCT = NFD_ZIP::ZIPINFO_STRUCT;
    using JARINFO_STRUCT = NFD_JAR::JARINFO_STRUCT;
    using RARINFO_STRUCT = NFD_RAR::RARINFO_STRUCT;
    using APKINFO_STRUCT = NFD_APK::APKINFO_STRUCT;
    using JPEGINFO_STRUCT = NFD_JPEG::JPEGINFO_STRUCT;
    using JAVACLASSINFO_STRUCT = NFD_JavaClass::JAVACLASSINFO_STRUCT;
    using PDFINFO_STRUCT = NFD_PDF::PDFINFO_STRUCT;
    using MACHOFATINFO_STRUCT = NFD_MACHOFAT::MACHOFATINFO_STRUCT;
    using COMINFO_STRUCT = NFD_COM::COMINFO_STRUCT;
    using MSDOSINFO_STRUCT = NFD_MSDOS::MSDOSINFO_STRUCT;
    using ELFINFO_STRUCT = NFD_ELF::ELFINFO_STRUCT;
    using LEINFO_STRUCT = NFD_LE::LEINFO_STRUCT;
    using LXINFO_STRUCT = NFD_LX::LXINFO_STRUCT;
    using NEINFO_STRUCT = NFD_NE::NEINFO_STRUCT;
    using MACHOINFO_STRUCT = NFD_MACH::MACHOINFO_STRUCT;
    using PEINFO_STRUCT = NFD_PE::PEINFO_STRUCT;
    using _BASICINFO = NFD_Binary::_BASICINFO;
    using SIGNATURE_RECORD = NFD_Binary::SIGNATURE_RECORD;
    using STRING_RECORD = NFD_Binary::STRING_RECORD;
    using PE_RESOURCES_RECORD = NFD_Binary::PE_RESOURCES_RECORD;
    using CONST_RECORD = NFD_Binary::CONST_RECORD;
    using MSRICH_RECORD = NFD_Binary::MSRICH_RECORD;

    explicit SpecAbstract(QObject *pParent = nullptr);

    static BINARYINFO_STRUCT getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                           XBinary::PDSTRUCT *pPdStruct);

    static PEINFO_STRUCT getPEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    static ZIPINFO_STRUCT getZIPInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);
    // JAR delegated to NFD_JAR::getInfo
    // APK delegated to NFD_APK::getInfo



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
    
    static void PE_handle_Joiners(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static void PE_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

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

    static bool PE_isValid_UPX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);
    static void PE_x86Emul(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct);

    static VI_STRUCT PE_get_PECompact_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo);

    static QList<XScanEngine::SCANSTRUCT> convert(QList<SCAN_STRUCT> *pListScanStructs);
    static QList<XScanEngine::DEBUG_RECORD> convertHeur(QList<DETECT_RECORD> *pListDetectRecords);

private:
    // MSDOS_compareRichRecord moved into NFD_MSDOS
    static void filterResult(QList<SCAN_STRUCT> *pListRecords, const QSet<RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct);

protected:
    virtual void _processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // SPECABSTRACT_H
