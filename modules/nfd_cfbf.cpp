/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
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
#include "nfd_cfbf.h"

NFD_CFBF::NFD_CFBF(XCFBF *pCFBF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : CFBF_Script(pCFBF, filePart, pOptions, pPdStruct)
{
}

NFD_CFBF::CFBFINFO_STRUCT NFD_CFBF::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                            XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    CFBFINFO_STRUCT result = {};

    XCFBF cfbf(pDevice);

    if (cfbf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Initialize BASIC_INFO
        result.basic_info = NFD_Binary::_initBasicInfo(&cfbf, parentId, pOptions, nOffset, pPdStruct);

        // Generic format record
        NFD_Binary::SCANS_STRUCT ssFormat = NFD_Binary::getFormatScansStruct(cfbf.getFileFormatInfo(pPdStruct));

        // CFBF sub-detection (MSI, Word 97-2003) replicating legacy logic
        // Read a couple of offsets used historically for differentiation
        const quint16 sub1 = cfbf.read_uint16(0x200);
        const quint16 sub2 = cfbf.read_uint16(0x1000);

        if ((sub1 == 0) && (sub2 == 0xFFFD)) {
            ssFormat.type = XScanEngine::RECORD_TYPE_INSTALLER;
            ssFormat.name = XScanEngine::RECORD_NAME_MICROSOFTINSTALLER;
            ssFormat.sVersion = "";
            ssFormat.sInfo = "";
        } else if (sub1 == 0xA5EC) {
            ssFormat.type = XScanEngine::RECORD_TYPE_FORMAT;
            ssFormat.name = XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD;
            ssFormat.sVersion = "97-2003";
            ssFormat.sInfo = "";
        }

        result.basic_info.mapResultFormats.insert(ssFormat.name, NFD_Binary::scansToScan(&(result.basic_info), &ssFormat));

        // Finalize
        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
