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
#include "specabstract.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"
#include "modules/nfd_dex.h"
#include "modules/nfd_pe.h"
#include "modules/nfd_text.h"
#include "modules/nfd_dex.h"

#include "signatures.cpp"  // Do not include in CMAKE files!

SpecAbstract::SpecAbstract(QObject *pParent) : XScanEngine(pParent)
{
}

// JARINFO delegated to NFD_JAR::getInfo

SpecAbstract::BINARYINFO_STRUCT SpecAbstract::getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions,
                                                            qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    BINARYINFO_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);
    binary.setFileType(fileType);

    if (binary.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&binary, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        // Scan Header
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getBinaryRecords(),
                                  NFD_Binary::getBinaryRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getArchiveRecords(),
                                  NFD_Binary::getArchiveRecordsSize(), result.basic_info.id.fileType, XBinary::FT_ARCHIVE, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_OVERLAY) {
            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getPEOverlayRecords(),
                                      NFD_Binary::getPEOverlayRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY,
                                      pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_DEBUGDATA) {
            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getDebugdataRecords(),
                                      NFD_Binary::getDebugdataRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info),
                                      DETECTTYPE_DEBUGDATA, pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            //            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _PE_resource_records,
            //            sizeof(_PE_resource_records),
            //                          result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

            // TODO a function

            if (result.basic_info.mapHeaderDetects.count() == 0) {
                _SCANS_STRUCT ss = {};
                ss.fileType = result.basic_info.id.fileType;
                ss.type = RECORD_TYPE_FORMAT;

                quint32 nId = pOptions->varInfo.toUInt();

                if (nId == XPE_DEF::S_RT_DIALOG) {
                    ss.name = RECORD_NAME_RESOURCE_DIALOG;
                } else if (nId == XPE_DEF::S_RT_STRING) {
                    ss.name = RECORD_NAME_RESOURCE_STRINGTABLE;
                } else if (nId == XPE_DEF::S_RT_VERSION) {
                    ss.name = RECORD_NAME_RESOURCE_VERSIONINFO;
                } else if (nId == XPE_DEF::S_RT_ICON) {
                    ss.name = RECORD_NAME_RESOURCE_ICON;
                } else if (nId == XPE_DEF::S_RT_CURSOR) {
                    ss.name = RECORD_NAME_RESOURCE_CURSOR;
                } else if (nId == XPE_DEF::S_RT_MENU) {
                    ss.name = RECORD_NAME_RESOURCE_MENU;
                }

                if (ss.name != RECORD_NAME_UNKNOWN) {
                    result.basic_info.mapHeaderDetects.insert(ss.name, ss);
                }
            }
        }

        // TODO header data!
        result.bIsPlainText = binary.isPlainTextType();
        result.bIsUTF8 = binary.isUTF8TextType();
        result.unicodeType = binary.getUnicodeType();

        // TODO Try QTextStream functions! Check
        if (result.unicodeType != XBinary::UNICODE_TYPE_NONE) {
            result.sHeaderText = binary.read_unicodeString(2, qMin(result.basic_info.id.nSize, (qint64)0x1000), (result.unicodeType == XBinary::UNICODE_TYPE_BE));
            result.basic_info.id.fileType = XBinary::FT_UNICODE;
        } else if (result.bIsUTF8) {
            result.sHeaderText = binary.read_utf8String(3, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_UTF8;
        } else if (result.bIsPlainText) {
            result.sHeaderText = binary.read_ansiString(0, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_PLAINTEXT;
        }

        NFD_Binary::Binary_handle_Texts(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Formats(pDevice, pOptions, &result);
        Binary_handle_Databases(pDevice, pOptions, &result);
        Binary_handle_Images(pDevice, pOptions, &result);
        Binary_handle_Archives(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Certificates(pDevice, pOptions, &result);
        Binary_handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_InstallerData(pDevice, pOptions, &result);
        Binary_handle_SFXData(pDevice, pOptions, &result);
        Binary_handle_ProtectorData(pDevice, pOptions, &result);
        Binary_handle_LibraryData(pDevice, pOptions, &result);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            Binary_handle_Resources(pDevice, pOptions, &result);
        }

        Binary_handle_FixDetects(pDevice, pOptions, &result);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::ZIPINFO_STRUCT SpecAbstract::getZIPInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    ZIPINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&xzip, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.listArchiveRecords = xzip.getRecords(20000, pPdStruct);

        if (pOptions->fileType == XBinary::FT_UNKNOWN) {
            QSet<XBinary::FT> stFT = XFormats::getFileTypesZIP(pDevice, &(result.listArchiveRecords), pPdStruct);

            result.bIsJAR = stFT.contains(XBinary::FT_JAR);
            result.bIsAPKS = stFT.contains(XBinary::FT_APKS);
            result.bIsIPA = stFT.contains(XBinary::FT_IPA);
        } else if (pOptions->fileType == XBinary::FT_JAR) {
            result.bIsJAR = true;
        } else if (pOptions->fileType == XBinary::FT_IPA) {
            result.bIsIPA = true;
        } else if (pOptions->fileType == XBinary::FT_APKS) {
            result.bIsAPKS = true;
        }

        result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
                           XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);

        if (result.bIsIPA) {
            result.basic_info.id.fileType = XBinary::FT_IPA;
        } else if (result.bIsJAR) {
            result.basic_info.id.fileType = XBinary::FT_JAR;
        } else if (result.bIsAPKS) {
            result.basic_info.id.fileType = XBinary::FT_APKS;
        }

        Zip_handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);
        Zip_handle_Microsoftoffice(pDevice, pOptions, &result, pPdStruct);
        Zip_handle_OpenOffice(pDevice, pOptions, &result, pPdStruct);

        if (result.bIsJAR) {
            Zip_handle_JAR(pDevice, pOptions, &result, pPdStruct);
        }

        if (result.bIsIPA) {
            Zip_handle_IPA(pDevice, pOptions, &result, pPdStruct);
        }

        Zip_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}










void SpecAbstract::Binary_handle_Archives(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                          XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // 7-Zip
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        //        // TODO more options
        //        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        //        if(ss.type==RECORD_TYPE_ARCHIVE)
        //        {
        //            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
        //            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        XSevenZip xsevenzip(pDevice);

        if (xsevenzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

            ss.sVersion = xsevenzip.getVersion();
#ifdef QT_DEBUG
            qint32 nNumberOfRecords = xsevenzip.getNumberOfRecords(pPdStruct);
            Q_UNUSED(nNumberOfRecords)
#endif
            //            ss.sInfo=QString("%1 records").arg(xsevenzip.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // ZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZIP)) && (pBinaryInfo->basic_info.id.nSize >= 64))  // TODO min size
    {
        XZip xzip(pDevice);

        if (xzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZIP);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, "Encrypted");
            }

            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // GZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GZIP)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO type gzip
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // xar
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XAR)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XAR);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LZFSE
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZFSE)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZFSE);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // CAB
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CAB)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XCab xcab(pDevice);

        if (xcab.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

            ss.sVersion = xcab.getVersion();
            ss.sInfo = QString("%1 records").arg(xcab.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // MAch-O FAT
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MACHOFAT)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XMACHOFat xmachofat(pDevice);

        if (xmachofat.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MACHOFAT);

            ss.sVersion = xmachofat.getVersion();
            ss.sInfo = QString("%1 records").arg(xmachofat.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // RAR
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RAR)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        XRar xrar(pDevice);

        if (xrar.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RAR);

            ss.sVersion = xrar.getVersion();
            ss.sInfo = QString("%1 records").arg(xrar.getNumberOfRecords(pPdStruct));
            // TODO options

            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // zlib
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZLIB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // XZ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XZ)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XZ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // ARJ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARJ)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARJ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LHA
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHA)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHA);

        bool bDetected = false;

        switch (binary.read_uint8(0x5)) {
            case 0x30: bDetected = 1; break;
            case 0x31: bDetected = 1; break;
            case 0x32: bDetected = 1; break;
            case 0x33: bDetected = 1; break;
            case 0x34: bDetected = 1; break;
            case 0x35: bDetected = 1; break;
            case 0x36: bDetected = 1; break;
            case 0x64: bDetected = 1; break;
            case 0x73: bDetected = 1; break;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // BZIP2
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BZIP2)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BZIP2);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // TAR
    else if ((pBinaryInfo->basic_info.id.nSize >= 500) && (binary.getSignature(0x100, 6) == "007573746172"))  // "00'ustar'"
    {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_TAR, "", "", 0);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Certificates(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Windows Authenticode Portable Executable Signature Format
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINAUTH)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        quint32 nLength = XBinary::hexToUint32(pBinaryInfo->basic_info.sHeaderSignature.mid(0, 8));

        if (nLength >= pBinaryInfo->basic_info.id.nSize) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINAUTH);
            pBinaryInfo->basic_info.mapResultCertificates.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MINGW)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MinGW debug data
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MINGW);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDBFILELINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PDB File Link
        // TODO more infos
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDBFILELINK);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BORLANDDEBUGINFO)) && (pBinaryInfo->basic_info.id.nSize >= 16)) {
        quint16 nSignature = binary.read_uint16(0);

        if (nSignature == 0x52FB) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_BORLANDDEBUGINFO, "", "", 0);

            quint8 nMajor = binary.read_uint8(3);
            quint8 nMinor = binary.read_uint8(2);
            quint16 nNumberOfSymbols = binary.read_uint16(0xE);
            double dVersion = nMajor + (double)nMinor / 100.0;

            ss.type = RECORD_TYPE_DEBUGDATA;
            ss.name = RECORD_NAME_BORLANDDEBUGINFO;
            ss.sVersion = QString::number(dVersion, 'f', 2);
            ss.sInfo = "TDS";

            if (nNumberOfSymbols) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));
            }

            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        } else {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BORLANDDEBUGINFO);
            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    if (binary.getSize() > 16) {
        // unsigned_16     signature;      /* == 0x8386                    */
        // unsigned_8      exe_major_ver;  /* == 2 or 3                    */
        // unsigned_8      exe_minor_ver;  /* == 0                         */
        // unsigned_8      obj_major_ver;  /* == 1                         */
        // unsigned_8      obj_minor_ver;  /* == 1                         */
        // unsigned_16     lang_size;
        // unsigned_16     segment_size;
        // unsigned_32     debug_size;
        // TODO more
        if (binary.read_uint16(binary.getSize() - 14) == 0x8386) {
            qint64 nHeaderOffset = binary.getSize() - 14;
            quint8 exe_major_ver = binary.read_uint16(nHeaderOffset + 2);
            quint8 exe_minor_ver = binary.read_uint16(nHeaderOffset + 3);
            // quint8 obj_major_ver = binary.read_uint16(nHeaderOffset + 4);
            // quint8 obj_minor_ver = binary.read_uint16(nHeaderOffset + 5);
            // quint16 nLangSize = binary.read_uint16(nHeaderOffset + 6);
            // quint16 nSegmentSize = binary.read_uint16(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 10);

            qint64 nDebugOffset = binary.getSize() - nDebugSize;

            if (nDebugOffset >= 0) {
                // TODO Language
                // https://github.com/open-watcom/open-watcom-v2/blob/e7d0bef544987dd0429f547a2119e0c9d9472770/bld/exedump/c/wdwarf.c#L132
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_WATCOMDEBUGINFO, "", "", 0);
                ss.sVersion = QString("%1.%2").arg(QString::number(exe_major_ver), QString::number(exe_minor_ver));
                ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint16(binary.getSize() - 8) == 0x424E) {
            QString sSignature = binary.read_ansiString(binary.getSize() - 8, 4);

            if ((sSignature == "NB05") || (sSignature == "NB07") || (sSignature == "NB08") || (sSignature == "NB09") || (sSignature == "NB10") ||
                (sSignature == "NB11")) {
                qint64 nHeaderOffset = binary.getSize() - 8;
                quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 4);

                qint64 nDebugOffset = binary.getSize() - nDebugSize;

                if (nDebugOffset >= 0) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_CODEVIEWDEBUGINFO, "", "", 0);
                    ss.sVersion = "4.0";
                    ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                    pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
                }
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint32(binary.getSize() - 16) == 0x534954) {
            // typedef struct {
            //     unsigned_32 signature;
            //     unsigned_32 vendor;
            //     unsigned_32 type;
            //     unsigned_32 size;
            // } TISTrailer;

            qint64 nHeaderOffset = binary.getSize() - 16;

            quint32 nVendor = binary.read_uint32(nHeaderOffset + 4);
            quint32 nType = binary.read_uint32(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 12);

            if ((nVendor == 0) && (nType == 0)) {
                qint64 nDebugOffset = nHeaderOffset - nDebugSize;

                if (nDebugOffset >= 0) {
                    VI_STRUCT viStruct = NFD_Binary::get_DWRAF_vi(pDevice, pOptions, nDebugOffset, binary.getSize() - nDebugOffset, pPdStruct);

                    if (viStruct.bIsValid) {
                        _SCANS_STRUCT ssDebugInfo = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                        ssDebugInfo.sVersion = viStruct.sVersion;
                        ssDebugInfo.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));
                        ssDebugInfo.sInfo = XBinary::appendComma(ssDebugInfo.sInfo, "Watcom");

                        pBinaryInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ssDebugInfo));
                    }
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if (pBinaryInfo->basic_info.id.nSize == 0) {
        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_EMPTYFILE, "", "", 0);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TODO move to own type
        // PDF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDF);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5 * 2, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compound
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPOUND);

        quint16 nSub1 = binary.read_uint16(0x200);
        quint16 nSub2 = binary.read_uint16(0x1000);

        // TODO More
        if ((nSub1 == 0) && (nSub2 == 0xFFFD)) {
            ss.type = RECORD_TYPE_INSTALLER;  // TODO mapResultInstallers
            ss.name = RECORD_NAME_MICROSOFTINSTALLER;
            ss.sVersion = "";
            ss.sInfo = "";
        } else if (nSub1 == 0xA5EC) {
            ss.type = RECORD_TYPE_FORMAT;
            ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.sVersion = "97-2003";
            ss.sInfo = "";
        }

        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compiled HTML Help
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AUTOIT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AutoIt Compiled Script
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AUTOIT);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // RTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RTF);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LUACOMPILED)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Lua
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LUACOMPILED);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JAVACOMPILEDCLASS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // java
        quint16 nMinor = binary.read_uint16(4, true);
        quint16 nMajor = binary.read_uint16(6, true);

        if (nMajor) {
            QString sVersion = XJavaClass::_getJDKVersion(nMajor, nMinor);

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JAVACOMPILEDCLASS);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_COFF)) && (pBinaryInfo->basic_info.id.nSize >= 76)) {
        // COFF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_COFF);

        bool bDetected = false;

        qint64 nOffset = binary.read_uint32(72, true) + 58;

        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEX)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // dex
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEX);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(8, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SWF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // SWF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SWF);
        ss.sVersion = QString("%1").arg(binary.read_uint8(3));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTWINHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft WinHelp
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTWINHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP3)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP3
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP3);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP4)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP4
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP4);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSMEDIA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Windows Media
        // TODO WMV/WMA
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSMEDIA);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FLASHVIDEO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Flash Video
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FLASHVIDEO);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WAV)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // VAW
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WAV);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AU
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AU);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEB)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DEB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEB);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVI)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVI);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WEBP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WEBP);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TTF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDARSC)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDARSC);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDXML)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDXML);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AR)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AR
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AR);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if (pBinaryInfo->basic_info.id.nSize >= 0x8010) {
        if (binary.compareSignature("01'CD001'01", 0x8000)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_ISO9660, "", "", 0);
            // TODO Version
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Databases(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // PDB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDB);
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKERDATABASE)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // Microsoft Linker Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTLINKERDATABASE);
        //        ss.sVersion=QString("%1.%2").arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(32*2,4))).arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(34*2,4)));
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTACCESS)) && (pBinaryInfo->basic_info.id.nSize >= 128)) {
        // Microsoft Access Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTACCESS);

        quint32 nVersion = binary.read_int32(0x14);

        switch (nVersion) {
            case 0x0000: ss.sVersion = "JET3"; break;  // TODO
            case 0x0001: ss.sVersion = "JET4"; break;  // TODO
            case 0x0002: ss.sVersion = "2007"; break;
            case 0x0103: ss.sVersion = "2010"; break;
        }

        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Images(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JPEG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // JPEG
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JPEG);
        quint32 nMajor = pBinaryInfo->basic_info.sHeaderSignature.mid(11 * 2, 2).toUInt(nullptr, 16);
        quint32 nMinor = pBinaryInfo->basic_info.sHeaderSignature.mid(12 * 2, 2).toUInt(nullptr, 16);
        ss.sVersion = QString("%1.%2").arg(nMajor).arg(nMinor, 2, 10, QChar('0'));
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GIF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // GIF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GIF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TIFF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TIFF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TIFF);
        // More information
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSICON)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Icon
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSICON);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSCURSOR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Cursor
        // TODO more information
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSCURSOR);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSBITMAP)) && (pBinaryInfo->basic_info.id.nSize >= 40)) {
        // Windows Bitmap
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        quint32 _nSize = qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(2 * 2, 8).toUInt(nullptr, 16));
        if (pBinaryInfo->basic_info.id.nSize >= _nSize) {
            QString sVersion;

            switch (qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(14 * 2, 8).toUInt(nullptr, 16))) {
                case 40: sVersion = "3"; break;
                case 108: sVersion = "4"; break;
                case 124: sVersion = "5"; break;
            }

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSBITMAP);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PNG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PNG
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PNG);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(16, true)).arg(binary.read_uint32(20, true));

        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DJVU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DJVU
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DJVU);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_InstallerData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Inno Setup
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INNOSETUP);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLANYWHERE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLANYWHERE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GHOSTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GHOSTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSIS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSIS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SIXXPACK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SIXXPACK);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_THINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_THINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SMARTINSTALLMAKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SMARTINSTALLMAKER);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(46, 14));
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TARMAINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TARMAINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CLICKTEAM)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CLICKTEAM);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ADVANCEDINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ADVANCEDINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_OPERA)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_OPERA);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GPINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GPINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVASTANTIVIRUS)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVASTANTIVIRUS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLSHIELD)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLSHIELD);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SETUPFACTORY)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SETUPFACTORY);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTUALINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTUALINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALL4J)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALL4J);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VMWARE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_VMWARE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOSINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_SFXData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINRAR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINRAR);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SQUEEZSFX)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SQUEEZSFX);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        if (ss.type == RECORD_TYPE_SFXDATA) {
            pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_ProtectorData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FISHNET)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Inno Setup
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FISHNET);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XENOCODE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Xenocode
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XENOCODE);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MOLEBOXULTRA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MOLEBOXULTRA);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_1337EXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_1337EXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTIVEMARK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTIVEMARK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOXCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOXCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASTFILECRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FASTFILECRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZELDACRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZELDACRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WLCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WLCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DOTNETSHRINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DOTNETSHRINK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPOONSTUDIO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPOONSTUDIO);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SECUROM)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SECUROM);
        ss.sVersion = binary.read_ansiString(8);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SERGREENAPPACKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SERGREENAPPACKER);
        // TODO Version
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_LibraryData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SHELL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        QString sString = binary.read_ansiString(0);

        if (sString.contains("python")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);
            pBinaryInfo->basic_info.mapResultLibraryData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Resources(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_VERSIONINFO)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_VERSIONINFO);
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BITMAPINFOHEADER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BITMAPINFOHEADER);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(4)).arg(binary.read_uint32(8));
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_STRINGTABLE)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_STRINGTABLE);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_DIALOG)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_DIALOG);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_ICON)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_ICON);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_CURSOR)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_CURSOR);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_MENU)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_MENU);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Zip_handle_Microsoftoffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("docProps/app.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                QString sData = xzip.decompress(&record, pPdStruct).data();
                QString sApplication = XBinary::regExp("<Application>(.*?)</Application>", sData, 1);

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_MICROSOFTOFFICE, "", "", 0);

                if (sApplication == "Microsoft Office Word") {
                    ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
                } else if (sApplication == "Microsoft Excel") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                } else if (sApplication == "Microsoft Visio") {
                    ss.name = RECORD_NAME_MICROSOFTVISIO;
                } else if (sApplication == "SheetJS") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                    ss.sInfo = "SheetJS";
                }

                ss.sVersion = XBinary::regExp("<AppVersion>(.*?)</AppVersion>", sData, 1);
                pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_OpenOffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("meta.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                QString sData = xzip.decompress(&record, pPdStruct).data();

                // TODO
                if (sData.contains(":opendocument:")) {
                    pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_OPENDOCUMENT, "", "", 0);

                    pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::Zip_handle_Metainfos(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BASIC_INFO *pBasicInfo, QList<XArchive::RECORD> *pListArchiveRecords,
                                        XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pListArchiveRecords, pPdStruct)) {
        QString sDataManifest = xjar.decompress(pListArchiveRecords, "META-INF/MANIFEST.MF", pPdStruct).data();

        if (sDataManifest != "") {
            QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sAntVersion = XBinary::regExp("Ant-Version: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltJdk = XBinary::regExp("Build-Jdk: (.*?)\n", sDataManifest, 1).remove("\r");

            if (sCreatedBy.contains("Android Gradle")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDGRADLE, "", "", 0);
                ss.sVersion = XBinary::regExp("Android Gradle (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("MOTODEV Studio for Android") || sCreatedBy.contains("MOTODEV Studio for ANDROID")) {
                // TODO Check "MOTODEV Studio for ANDROID" version
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_MOTODEVSTUDIOFORANDROID, "", "", 0);
                ss.sVersion = XBinary::regExp("MOTODEV Studio for Android v(.*?).release", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("Android Maven") || sCreatedBy.contains("Apache Maven Bundle Plugin")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDMAVENPLUGIN, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Radialix")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_RADIALIX, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Radialix", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("AntiLVL")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_ANTILVL, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkEditor")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_APKEDITOR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("d2j-apk-sign")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_D2JAPKSIGN, "", "", 0);
                ss.sVersion = XBinary::regExp("d2j-apk-sign (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("singlejar")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_SINGLEJAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("PseudoApkSigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_PSEUDOAPKSIGNER, "", "", 0);
                ss.sVersion = XBinary::regExp("PseudoApkSigner (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkSigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNER, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("www.HiAPK.com")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_HIAPKCOM, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("com.haibison.apksigner") || sCreatedBy.contains("com.haibison.apksigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APK_SIGNER, "", "", 0);

                if (sBuiltBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sBuiltBy, 1);
                } else if (sCreatedBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sCreatedBy, 1);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("BundleTool") || sCreatedBy.contains("BundleTool")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_BUNDLETOOL, "", "", 0);

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(COMEX SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_COMEXSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (COMEX SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(NetEase ApkSigner)"))  // TODO Check " " !!!
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_NETEASEAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (NetEase ApkSigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signatory)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNATORY, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signatory)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signupdate)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNUPDATE, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signupdate)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(KT Android SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (KT Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(abc SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (abc SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(dotools sign apk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_DOTOOLSSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (dotools sign apk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android apksigner)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android apksigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(ApkModifier SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKMODIFIERSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (ApkModifier SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Baidu Signature platform)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_BAIDUSIGNATUREPLATFORM, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Baidu Signature platform)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("tiny-sign")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_TINYSIGN, "", "", 0);
                ss.sVersion = sCreatedBy.section("tiny-sign-", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("DexGuard, version")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);
                ss.sVersion = XBinary::regExp("DexGuard, version (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkProtector")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_APKPROTECTOR, "", "", 0);

                if (sCreatedBy.section(" ", 0, 0) == "ApkProtector") {
                    ss.sVersion = sCreatedBy.section(" ", 1, 1).remove(")").remove("(");
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Sun Microsystems Inc.)") || sCreatedBy.contains("(BEA Systems, Inc.)") || sCreatedBy.contains("(The FreeBSD Foundation)") ||
                       sCreatedBy.contains("(d2j-null)") || sCreatedBy.contains("(d2j-2.1-SNAPSHOT)") || sCreatedBy.contains("(Oracle Corporation)") ||
                       sCreatedBy.contains("(Apple Inc.)") || sCreatedBy.contains("(Google Inc.)") || sCreatedBy.contains("(Jeroen Frijters)") ||
                       sCreatedBy.contains("(IBM Corporation)") || sCreatedBy.contains("(JetBrains s.r.o)") || sCreatedBy.contains("(Alibaba)") ||
                       sCreatedBy.contains("(AdoptOpenJdk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);

                if (sCreatedBy.contains("(Apple Inc.)")) {
                    ss.name = RECORD_NAME_APPLEJDK;
                } else if (sCreatedBy.contains("(IBM Corporation)")) {
                    ss.name = RECORD_NAME_IBMJDK;
                } else if (sCreatedBy.contains("(AdoptOpenJdk)")) {
                    ss.name = RECORD_NAME_OPENJDK;
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy == "1.6.0_21") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(JetBrains s.r.o)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JETBRAINS, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-null)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-2.1-SNAPSHOT)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "2.1", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Jeroen Frijters)")) {
                // Check OpenJDK
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_IKVMDOTNET, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(BEA Systems, Inc.)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_BEAWEBLOGIC, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("dx ")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_COMPILER, RECORD_NAME_DX, "", "", 0);
                ss.sVersion = sCreatedBy.section("dx ", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sAntVersion.contains("Apache Ant")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_APACHEANT, "", "", 0);
                ss.sVersion = XBinary::regExp("Apache Ant (.*?)$", sAntVersion, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltBy.contains("Generated-by-ADT")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ECLIPSE, "", "ADT", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltJdk != "") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sBuiltJdk;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sProtectedBy.contains("DexProtector")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXPROTECTOR, "", "", 0);

                if (sProtectedBy.section(" ", 0, 0) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 1, 1).remove(")").remove("(");
                } else if (sProtectedBy.section(" ", 1, 1) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 0, 0);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (XBinary::regExp("^\\d+(\\.\\d+)*$", sCreatedBy, 0) != "")  // 0.0.0
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(d8)") || sCreatedBy.contains("(dx)"))  // Dexguard
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            // TODO heur if String contains add to heur
        }
    }
}

void SpecAbstract::Zip_handle_JAR(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xjar.getFileFormatInfo(pPdStruct));

        pZipInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ssOperationSystem));

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APPLEJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APPLEJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IBMJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IBMJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_OPENJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_OPENJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JETBRAINS)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JETBRAINS);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IKVMDOTNET)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IKVMDOTNET);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BEAWEBLOGIC)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BEAWEBLOGIC);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APACHEANT)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APACHEANT);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SINGLEJAR)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SINGLEJAR);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(&(pApkInfo->listArchiveRecords), pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xapk.getFileFormatInfo(pPdStruct));

        pApkInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssOperationSystem));

        // 0x7109871a APK_SIGNATURE_SCHEME_V2_BLOCK_ID
        // TODO Check 0x7109871f
        // https://github.com/18598925736/ApkChannelPackageJavaCore/blob/9342d57a1fc5f9271d569612df6028758f6ee42d/src/channel/data/Constants.java#L38
        // 0xf05368c0 APK_SIGNATURE_SCHEME_V3_BLOCK_ID
        // 0x42726577 padding
        // 0x504b4453 DEPENDENCY_INFO_BLOCK_ID;
        // https://github.com/jomof/CppBuildCacheWorkInProgress/blob/148b94d712d14b6f2a13ab37a526c7795e2215b3/agp-7.1.0-alpha01/tools/base/signflinger/src/com/android/signflinger/SignedApk.java#L56
        // 0x71777777 Walle
        // https://github.com/Meituan-Dianping/walle/blob/f78edcf1117a0aa858a3d04bb24d86bf9ad51bb2/payload_reader/src/main/java/com/meituan/android/walle/ApkUtil.java#L40
        // 0x6dff800d SOURCE_STAMP_BLOCK_ID
        // 0x2146444e Google Play

        QList<XAPK::APK_SIG_BLOCK_RECORD> listApkSignaturesBlockRecords = xapk.getAPKSignaturesBlockRecordsList();

        _SCANS_STRUCT ssSignTool = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNATURESCHEME, "", "", 0);

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x7109871a)) {
            ssSignTool.sVersion = "v2";
        } else if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0xf05368c0)) {
            ssSignTool.sVersion = "v3";
        }

        // TODO V4

        if (ssSignTool.sVersion != "") {
            pApkInfo->basic_info.mapResultSigntools.insert(ssSignTool.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssSignTool));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x71777777)) {
            _SCANS_STRUCT ssWalle = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_WALLE, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssWalle.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssWalle));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x2146444e)) {
            _SCANS_STRUCT ssGooglePlay = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_GOOGLEPLAY, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssGooglePlay.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssGooglePlay));
        }

        if (pApkInfo->bIsKotlin) {
            _SCANS_STRUCT ssKotlin = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_KOTLIN, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssKotlin.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssKotlin));
        } else {
            _SCANS_STRUCT ssJava = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_JAVA, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssJava.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssJava));
        }

        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_UNKNOWN, "", "", 0);

            qint32 nNumberOfRecords = listApkSignaturesBlockRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listApkSignaturesBlockRecords.at(i).nID > 0xFFFF) {
                    if ((listApkSignaturesBlockRecords.at(i).nID != 0x7109871a) && (listApkSignaturesBlockRecords.at(i).nID != 0xf05368c0) &&
                        (listApkSignaturesBlockRecords.at(i).nID != 0x42726577)) {
                        ss.name = (RECORD_NAME)((int)RECORD_NAME_UNKNOWN0 + i);
                        ss.sVersion = XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nID);
                        // ss.sInfo=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nDataSize);
                        pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
                    }
                }
            }
        }

        QByteArray baAndroidManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "AndroidManifest.xml", pPdStruct);

        if (baAndroidManifest.size() > 0) {
            QString sAndroidManifest = XAndroidBinary::getDecoded(&baAndroidManifest, pPdStruct);

            QString sCompileSdkVersion = XBinary::regExp("android:compileSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sCompileSdkVersionCodename = XBinary::regExp("android:compileSdkVersionCodename=\"(.*?)\"", sAndroidManifest, 1);
            QString sTargetSdkVersion = XBinary::regExp("android:targetSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sMinSdkVersion = XBinary::regExp("android:minSdkVersion=\"(.*?)\"", sAndroidManifest, 1);

            // Check
            if (!XBinary::checkStringNumber(sCompileSdkVersion, 1, 40)) sCompileSdkVersion = "";
            if (!XBinary::checkStringNumber(sTargetSdkVersion, 1, 40)) sTargetSdkVersion = "";
            if (!XBinary::checkStringNumber(sMinSdkVersion, 1, 40)) sMinSdkVersion = "";

            if (!XBinary::checkStringNumber(sCompileSdkVersionCodename.section(".", 0, 0), 1, 15)) sCompileSdkVersionCodename = "";

            if ((sCompileSdkVersion != "") || (sCompileSdkVersionCodename != "") || (sTargetSdkVersion != "") || (sMinSdkVersion != "")) {
                _SCANS_STRUCT ssAndroidSDK = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);

                QString _sVersion;
                QString _sAndroidVersion;

                _sVersion = sCompileSdkVersion;
                _sAndroidVersion = sCompileSdkVersionCodename;

                if (_sVersion == "") _sVersion = sMinSdkVersion;
                if (_sVersion == "") _sVersion = sTargetSdkVersion;

                if (_sVersion != "") {
                    ssAndroidSDK.sVersion = QString("API %1").arg(_sVersion);

                    pApkInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssAndroidSDK));
                }
            }

            QString sJetpack = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/androidx.core_core.version").data();
            if (sJetpack != "") {
                QString sJetpackVersion = XBinary::regExp("(.*?)\n", sJetpack, 1).remove("\r");

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LIBRARY, RECORD_NAME_ANDROIDJETPACK, "", "", 0);
                ss.sVersion = sJetpackVersion;
                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDGRADLE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDGRADLE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDMAVENPLUGIN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDMAVENPLUGIN);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_RADIALIX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_RADIALIX);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_MOTODEVSTUDIOFORANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANTILVL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANTILVL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKEDITOR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKEDITOR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BUNDLETOOL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BUNDLETOOL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEX2JAR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEX2JAR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_D2JAPKSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_D2JAPKSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_PSEUDOAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_PSEUDOAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APK_SIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APK_SIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_NETEASEAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_NETEASEAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DOTOOLSSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DOTOOLSSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNATORY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNATORY);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNUPDATE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNUPDATE);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKMODIFIERSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKMODIFIERSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BAIDUSIGNATUREPLATFORM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_TINYSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_TINYSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_COMEXSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_COMEXSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ECLIPSE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ECLIPSE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_HIAPKCOM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_HIAPKCOM);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DX);
                pApkInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECSHELL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECSHELL);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_JIAGU)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_JIAGU);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IJIAMI)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IJIAMI);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTPROTECTION);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU) ||
                pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTLEGU);
                } else if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MOBILETENCENTPROTECT);
                }

                qint32 nNumberOfRecords = pApkInfo->listArchiveRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/arm64-v8a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/arm64-v8a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi-v7a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi-v7a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/x86/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/x86/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    }
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppGuard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Kiro
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_KIRO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_KIRO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DxShield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DXSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DXSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // qdbh
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QDBH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QDBH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Bangcle Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BANGCLEPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BANGCLEPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Qihoo 360 Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QIHOO360PROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QIHOO360PROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Alibaba Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_ALIBABAPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_ALIBABAPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Baidu Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BAIDUPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BAIDUPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // NQ Shield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NQSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NQSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Nagapt Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NAGAPTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NAGAPTPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SecNeo
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECNEO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECNEO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // LIAPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_LIAPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_LIAPP);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // yidun
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_YIDUN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_YIDUN);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // PangXie
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PANGXIE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PANGXIE);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Hdus-Wjus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_HDUS_WJUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_HDUS_WJUS);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Medusah
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MEDUSAH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MEDUSAH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppSolid
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPSOLID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPSOLID);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Proguard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PROGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PROGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // VDog
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_VDOG)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_VDOG);

                QString sVersion = xapk.decompress(&(pApkInfo->listArchiveRecords), "assets/version").data();

                if (sVersion != "") {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion = sVersion.section("VDOG-", 1, 1).section("_", 0, 0);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // APKProtect
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECT)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECT);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ollvm-tll
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_OLLVMTLL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_OLLVMTLL);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DexGuard
            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD) ||
                pApkInfo->dexInfoClasses.basic_info.mapResultProtectors.contains(RECORD_NAME_DEXGUARD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXGUARD).sVersion;
                } else if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_GENERIC)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_GENERIC).sVersion;
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DEXPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DEXPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SandHook
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SANDHOOK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SANDHOOK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unicom SDK
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNICOMSDK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNICOMSDK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unity
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNITY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNITY);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // IL2CPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IL2CPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IL2CPP);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Basic4Android
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BASIC4ANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BASIC4ANDROID);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ApkToolPlus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKTOOLPLUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKTOOLPLUS);

                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // QML
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QML)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QML);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_IPA(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->bIsIPA) {
            _SCANS_STRUCT ssFormat = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_IPA, "", "", 0);

            ssFormat.sVersion = xzip.getVersion();
            ssFormat.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.listDetects.append(NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ssFormat));
        }
    }
}

void SpecAbstract::Zip_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->basic_info.id.fileType == XBinary::FT_ZIP) {
            pZipInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, "Encrypted");
            }

            // TODO files
            pZipInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        } else if (pZipInfo->basic_info.id.fileType == XBinary::FT_APKS) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle_FixDetects(QIODevice *pDevice, SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(pPdStruct)) {
        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            if (pApkInfo->basic_info.mapMetainfosDetects.count() == 0) {
                QString sDataManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/MANIFEST.MF").data();

                QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");

                if (sProtectedBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                    recordSS.sVersion = "Protected: " + sProtectedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sCreatedBy != "") && (sCreatedBy != "1.0 (Android)")) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion = "Created: " + sCreatedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if (sBuiltBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion = "Built: " + sBuiltBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sProtectedBy != "") && (sCreatedBy != "") && (sBuiltBy != "")) {
                    if (sDataManifest.contains("-By")) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_PROTECTOR;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                        recordSS.sVersion = "CHECK";

                        pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                    }
                }
            }
        }
    }
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::APKINFO_STRUCT *pApkInfo,
                                                        XBinary::PDSTRUCT *pPdStruct, const QString &sFileName)
{
    Q_UNUSED(pOptions)

    DEXINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        QByteArray baRecordData = xzip.decompress(&(pApkInfo->listArchiveRecords), sFileName, pPdStruct);

        QBuffer buffer(&baRecordData);

        if (buffer.open(QIODevice::ReadOnly)) {
            result = NFD_DEX::getInfo(&buffer, pApkInfo->basic_info.id, pOptions, 0, pPdStruct);

            buffer.close();
        }
    }

    return result;
}

void SpecAbstract::Binary_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    if (pBinaryInfo->basic_info.mapResultFormats.contains(RECORD_NAME_PDF)) {
        pBinaryInfo->basic_info.mapResultTexts.clear();

        pBinaryInfo->basic_info.mapResultFormats[RECORD_NAME_PDF].id.fileType = XBinary::FT_BINARY;
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_BINARY;
    }
}

// LX Microsoft-specific handling moved to NFD_LX::getInfo


// void SpecAbstract::fixDetects(SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//     if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
//     {
//         pPEInfo->basic_info.mapHeaderDetects.remove(RECORD_NAME_MICROSOFTLINKER);
//     }

//    if(pPEInfo->_mapImportDetects.contains(RECORD_NAME_C)&&pPEInfo->_mapImportDetects.contains(RECORD_NAME_VISUALCPP))
//    {
//        pPEInfo->_mapImportDetects.remove(RECORD_NAME_VISUALCPP);
//    }

//    if(pPEInfo->basic_info.mapSpecialDetects.contains(RECORD_NAME_ENIGMA))
//    {
//        pPEInfo->basic_info.mapEntryPointDetects.remove(RECORD_NAME_BORLANDCPP);
//    }
//}

QList<XScanEngine::SCANSTRUCT> SpecAbstract::convert(QList<SCAN_STRUCT> *pListScanStructs)
{
    QList<XScanEngine::SCANSTRUCT> listResult;

    qint32 nNumberOfRecords = pListScanStructs->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::SCANSTRUCT record = {};

        record.bIsHeuristic = pListScanStructs->at(i).bIsHeuristic;
        record.bIsUnknown = pListScanStructs->at(i).bIsUnknown;
        record.id = pListScanStructs->at(i).id;
        record.parentId = pListScanStructs->at(i).parentId;
        record.nType = pListScanStructs->at(i).type;
        record.nName = pListScanStructs->at(i).name;
        record.sType = recordTypeIdToString(pListScanStructs->at(i).type);
        record.sName = recordNameIdToString(pListScanStructs->at(i).name);
        record.sVersion = pListScanStructs->at(i).sVersion;
        record.sInfo = pListScanStructs->at(i).sInfo;

        record.globalColorRecord = typeToGlobalColorRecord(record.sType);
        record.nPrio = typeToPrio(record.sType);
        record.bIsProtection = isProtection(record.sType);
        record.sType = translateType(record.sType);

        listResult.append(record);
    }

    // XFormats::sortRecords(&listResult); // TODO Check

    return listResult;
}

QList<XScanEngine::DEBUG_RECORD> SpecAbstract::convertHeur(QList<DETECT_RECORD> *pListDetectRecords)
{
    QList<XScanEngine::DEBUG_RECORD> listResult;

    qint32 nNumberOfRecords = pListDetectRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::DEBUG_RECORD record = {};

        record.sType = XScanEngine::heurTypeIdToString(pListDetectRecords->at(i).detectType);
        record.sName = QString("%1(%2)[%3]")
                           .arg(SpecAbstract::recordNameIdToString(pListDetectRecords->at(i).name), pListDetectRecords->at(i).sVersion, pListDetectRecords->at(i).sInfo);
        record.sValue = pListDetectRecords->at(i).sValue;

        listResult.append(record);
    }

    return listResult;
}

// MSDOS_compareRichRecord moved to NFD_MSDOS

void SpecAbstract::filterResult(QList<SpecAbstract::SCAN_STRUCT> *pListRecords, const QSet<SpecAbstract::RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct)
{
    QList<SpecAbstract::SCAN_STRUCT> listRecords;
    qint32 nNumberOfRecords = pListRecords->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        if (stRecordTypes.contains((RECORD_TYPE)pListRecords->at(i).type)) {
            listRecords.append(pListRecords->at(i));
        }
    }

    *pListRecords = listRecords;
}

void SpecAbstract::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                  XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO basic_info = {};

    if ((fileType == XBinary::FT_PE32) || (fileType == XBinary::FT_PE64)) {
        NFD_PE::PEINFO_STRUCT pe_info = NFD_PE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pe_info.basic_info;
    } else if ((fileType == XBinary::FT_ELF32) || (fileType == XBinary::FT_ELF64)) {
        SpecAbstract::ELFINFO_STRUCT elf_info = NFD_ELF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = elf_info.basic_info;
    } else if ((fileType == XBinary::FT_MACHO32) || (fileType == XBinary::FT_MACHO64)) {
        SpecAbstract::MACHOINFO_STRUCT mach_info = NFD_MACH::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = mach_info.basic_info;
    } else if (fileType == XBinary::FT_LE) {
        SpecAbstract::LEINFO_STRUCT le_info = NFD_LE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = le_info.basic_info;
    } else if (fileType == XBinary::FT_LX) {
        SpecAbstract::LXINFO_STRUCT lx_info = NFD_LX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = lx_info.basic_info;
    } else if (fileType == XBinary::FT_NE) {
        SpecAbstract::NEINFO_STRUCT ne_info = NFD_NE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = ne_info.basic_info;
    } else if (fileType == XBinary::FT_MSDOS) {
        SpecAbstract::MSDOSINFO_STRUCT msdos_info = NFD_MSDOS::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = msdos_info.basic_info;
    } else if (fileType == XBinary::FT_JAR) {
        SpecAbstract::JARINFO_STRUCT jar_info = NFD_JAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jar_info.basic_info;
    } else if (fileType == XBinary::FT_APK) {
        SpecAbstract::APKINFO_STRUCT apk_info = NFD_APK::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = apk_info.basic_info;
    } else if ((fileType == XBinary::FT_ZIP) || (fileType == XBinary::FT_IPA)) {
        // mb TODO split detects
        SpecAbstract::ZIPINFO_STRUCT zip_info = SpecAbstract::getZIPInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = zip_info.basic_info;
    } else if (fileType == XBinary::FT_RAR) {
        SpecAbstract::RARINFO_STRUCT rar_info = NFD_RAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = rar_info.basic_info;
    } else if (fileType == XBinary::FT_JAVACLASS) {
        SpecAbstract::JAVACLASSINFO_STRUCT javaclass_info = NFD_JavaClass::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = javaclass_info.basic_info;
    } else if (fileType == XBinary::FT_DEX) {
        SpecAbstract::DEXINFO_STRUCT dex_info = NFD_DEX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = dex_info.basic_info;
    } else if (fileType == XBinary::FT_AMIGAHUNK) {
        SpecAbstract::AMIGAHUNKINFO_STRUCT amigaHunk_info = NFD_Amiga::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = amigaHunk_info.basic_info;
    } else if (fileType == XBinary::FT_PDF) {
        SpecAbstract::PDFINFO_STRUCT pdf_info = NFD_PDF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pdf_info.basic_info;
    } else if (fileType == XBinary::FT_JPEG) {
        SpecAbstract::JPEGINFO_STRUCT jpeg_info = NFD_JPEG::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jpeg_info.basic_info;
    } else if (fileType == XBinary::FT_CFBF) {
        SpecAbstract::CFBFINFO_STRUCT cfbf_info = NFD_CFBF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = cfbf_info.basic_info;
    } else if (fileType == XBinary::FT_COM) {
        SpecAbstract::COMINFO_STRUCT com_info = NFD_COM::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = com_info.basic_info;
    } else {
        SpecAbstract::BINARYINFO_STRUCT binary_info = SpecAbstract::getBinaryInfo(pDevice, fileType, parentId, pScanOptions, 0, pPdStruct);
        basic_info = binary_info.basic_info;
    }

    if (bAddUnknown) {
        if (!basic_info.listDetects.count()) {
            _SCANS_STRUCT ssUnknown = {};

            ssUnknown.type = SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name = SpecAbstract::RECORD_NAME_UNKNOWN;
            ssUnknown.bIsUnknown = true;

            basic_info.listDetects.append(NFD_Binary::scansToScan(&basic_info, &ssUnknown));
        }
    }

    QList<XScanEngine::SCANSTRUCT> listScanStructs = convert(&(basic_info.listDetects));

    if (pScanOptions->bIsSort) {
        sortRecords(&listScanStructs);
    }

    pScanResult->listRecords.append(listScanStructs);
    pScanResult->listDebugRecords.append(convertHeur(&(basic_info.listHeurs)));

    if (pScanID) {
        *pScanID = basic_info.id;
    }
}
