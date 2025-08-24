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
#include "nfd_binary.h"
#include "xscanengine.h"

NFD_Binary::NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pBinary, filePart, pOptions, pPdStruct)
{

}

QString NFD_Binary::_SCANS_STRUCT_toString(const SCANS_STRUCT *pScanStruct, bool bShowType)
{
    QString sResult;

    if (pScanStruct->bIsHeuristic) {
        sResult += "(Heur)";
    }

    if (bShowType) {
        sResult += QString("%1: ").arg(XScanEngine::translateType(XScanEngine::recordTypeIdToString(pScanStruct->type)));
    }

    sResult += QString("%1").arg(XScanEngine::recordNameIdToString(pScanStruct->name));

    if (pScanStruct->sVersion != "") {
        sResult += QString("(%1)").arg(pScanStruct->sVersion);
    }

    if (pScanStruct->sInfo != "") {
        sResult += QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

NFD_Binary::SCAN_STRUCT NFD_Binary::scansToScan(NFD_Binary::BASIC_INFO *pBasicInfo, NFD_Binary::SCANS_STRUCT *pScansStruct)
{
    SCAN_STRUCT result = {};

    result.id = pBasicInfo->id;
    result.parentId = pBasicInfo->parentId;
    result.bIsHeuristic = pScansStruct->bIsHeuristic;
    result.bIsUnknown = pScansStruct->bIsUnknown;
    result.type = pScansStruct->type;
    result.name = pScansStruct->name;
    result.sVersion = pScansStruct->sVersion;
    result.sInfo = pScansStruct->sInfo;

    return result;
}

NFD_Binary::SCANS_STRUCT NFD_Binary::detectOperationSystem(const XBinary::FILEFORMATINFO &ffi)
{
    SCANS_STRUCT result = {};

    // Type: OS vs VM
    result.type = ffi.bIsVM ? XScanEngine::RECORD_TYPE_VIRTUALMACHINE : XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;

    // File type context
    result.fileType = ffi.fileType;

    // Map known OS names (extendable)
    if (ffi.osName == XBinary::OSNAME_AMIGA) {
        result.name = XScanEngine::RECORD_NAME_AMIGA;
    } else if (ffi.osName == XBinary::OSNAME_AROS) {
        result.name = XScanEngine::RECORD_NAME_AROS;
    } else {
        result.name = XScanEngine::RECORD_NAME_UNKNOWN;
        result.bIsUnknown = true;
    }

    // Version and info
    result.sVersion = ffi.sOsVersion;
    result.sInfo = QString("%1, %2, %3").arg(ffi.sArch, XBinary::modeIdToString(ffi.mode), ffi.sType);
    if (ffi.endian == XBinary::ENDIAN_BIG) {
        result.sInfo.append(QString(", %1").arg(XBinary::endianToString(XBinary::ENDIAN_BIG)));
    }

    // Flags
    result.bIsHeuristic = false;

    return result;
}
