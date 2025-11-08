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
#include "nfd_rar.h"

NFD_RAR::NFD_RAR(XRar *pRar, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : RAR_Script(pRar, filePart, pOptions, pPdStruct)
{
}

void NFD_RAR::handle_formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, RARINFO_STRUCT *pRARInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XRar xrar(pDevice);

    if (xrar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        if (XBinary::getDeviceFileSuffix(pDevice).toLower() == "cbr") {
            NFD_Binary::SCANS_STRUCT recordSS =
                NFD_Binary::getScansStruct(0, XBinary::FT_RAR, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_COMICBOOKARCHIVE, "", "", 0);
            pRARInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pRARInfo->basic_info), &recordSS));
        }
    }
}

NFD_RAR::RARINFO_STRUCT NFD_RAR::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    RARINFO_STRUCT result = {};

    XRar rar(pDevice);

    if (rar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&rar, parentId, pOptions, nOffset, pPdStruct);

        // Populate
        result.listArchiveRecords = rar.getRecords(20000, pPdStruct);

        NFD_Binary::SCANS_STRUCT ssFormat = NFD_Binary::getFormatScansStruct(rar.getFileFormatInfo(pPdStruct));
        result.basic_info.mapResultFormats.insert(ssFormat.name, NFD_Binary::scansToScan(&(result.basic_info), &ssFormat));

        handle_formats(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
