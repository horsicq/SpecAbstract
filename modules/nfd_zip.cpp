/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
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
#include "nfd_zip.h"

NFD_ZIP::NFD_ZIP(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : ZIP_Script(pZip, filePart, pOptions, pPdStruct)
{
}

NFD_ZIP::ZIPINFO_STRUCT NFD_ZIP::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
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

        NFD_ZIP::handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);
        NFD_ZIP::handle_Microsoftoffice(pDevice, pOptions, &result, pPdStruct);
        NFD_ZIP::handle_OpenOffice(pDevice, pOptions, &result, pPdStruct);

        if (result.bIsJAR) {
            NFD_ZIP::handle_JAR(pDevice, pOptions, &result, pPdStruct);
        }

        if (result.bIsIPA) {
            NFD_ZIP::handle_IPA(pDevice, pOptions, &result, pPdStruct);
        }

        NFD_ZIP::handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

void NFD_ZIP::handle_Microsoftoffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
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

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MICROSOFTOFFICE, "", "", 0);

                if (sApplication == "Microsoft Office Word") {
                    ss.name = XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD;
                } else if (sApplication == "Microsoft Excel") {
                    ss.name = XScanEngine::RECORD_NAME_MICROSOFTEXCEL;
                } else if (sApplication == "Microsoft Visio") {
                    ss.name = XScanEngine::RECORD_NAME_MICROSOFTVISIO;
                } else if (sApplication == "SheetJS") {
                    ss.name = XScanEngine::RECORD_NAME_MICROSOFTEXCEL;
                    ss.sInfo = "SheetJS";
                }

                ss.sVersion = XBinary::regExp("<AppVersion>(.*?)</AppVersion>", sData, 1);
                pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
            }
        }
    }
}

void NFD_ZIP::handle_OpenOffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
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

                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_OPENDOCUMENT, "", "", 0);

                    pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
                }
            }
        }
    }
}

void NFD_ZIP::handle_Metainfos(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BASIC_INFO *pBasicInfo, QList<XArchive::RECORD> *pListArchiveRecords,
                                   XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pListArchiveRecords, pPdStruct)) {
        QString sDataManifest = xjar.decompress(pListArchiveRecords, "META-INF/MANIFEST.MF", pPdStruct).data();

        if (sDataManifest != "") {
            // ... existing code for manifest processing ...
        }
    }
}

void NFD_ZIP::handle_JAR(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pPdStruct)) {
        // ... existing JAR handling code ...
    }
}

void NFD_ZIP::handle_IPA(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->bIsIPA) {
            // ... existing IPA handling code ...
        }
    }
}

void NFD_ZIP::handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        // ... existing fix detects code ...
    }
}
