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
#include "nfd_com.h"
#include "nfd_binary.h"
#include "xcom.h"
#include "xscanengine.h"

NFD_COM::NFD_COM(XCOM *pCOM, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : COM_Script(pCOM, filePart, pOptions, pPdStruct)
{
}

// No local helper; use NFD_Binary::addHeaderDetectToResults

// COM signature arrays moved from SpecAbstract/signatures.cpp
static NFD_Binary::SIGNATURE_RECORD g_COM_records[] = {
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.00, 1.03", "exe2com"},
     "B8....BA....8CDB03D83B1E....73..83EB..FA8ED3BC....FB83EB..8EC353B9....33FF57BE....FCF3A5CB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.00c", ""},
     "BA....A1....2D....8CCB81C3....3BC377..05....3BC377..B4..BA....CD21CD20"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.12, 1.20", ""},
     "B8....BA....3BC473..8BC42D....25....8BF8B9....BE....FCF3A58BD8B1..D3EB8CD903D95333DB53CB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.15", ""},
     "B8....BA....3BC473..8BC42D....9025....8BF8B9....90BE....FCF3A58BD8B1..D3EB8CD903D95333DB53CB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.50", ""},
     "50B8....BA....3BC473..8BC42D....25....8BF8B9....BE....FCF3A58BD8B1..D3EB8CD903D95333DB53CB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_PKLITE, "1.1x", ""},
     "BA....B8....05....3B06....73..2D....FA8ED0FB2D....8EC050B9....33FF57BE....FCF3A5CB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HACKSTOP, "1.13cs", ""}, "FABD....FFE5"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HACKSTOP, "1.14s", ""}, "FABB....FFE3"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HACKSTOP, "1.17cr", ""}, "FABE....FFE6"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_UPX, "0.30-0.40", ""}, "B9....BE....BF....BD....FDF3A4FCF7E19387F783C6..57E9"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_UPX, "0.50", ""}, "B9....BE....BF....FDF3A4FCF7E19387F783EE..19ED57"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_UPX, "0.81-1.20", ""}, "81FC....77..CD20B9....BE....BF....BB....FDF3A4FC87F783EE"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_CRYPTDISMEMBER, "1.7", ""},
     "0E179C58F6C4..74..EB..90B4..BE....BF....B9....68....68....68....57F3A4C3"},
};

static NFD_Binary::SIGNATURE_RECORD g_COM_Exp_records[] = {
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SPIRIT, "1.X", ""}, "E9$$$$B430CD21F6D12EA6E8....B462CD21E8....3636FB969034..C3"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SPIRIT, "1.5", ""}, "E9$$$$AEE8$$$$E4210C..FBE62190B8....FB5026509087C1"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SPIRIT, "1.5", ""},
     "E9$$$$369F9F1C..E9$$$$E8$$$$E421F80C..E6218D06....FC505089C1FB"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SPIRIT, "1.5", ""},
     "E9$$$$F8D72606B435CD2107E8$$$$1C..1C..33D226F6DA12DDFCF905....F8F5F6EA"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_ICE, "1.0", ""}, "EB$$BE....8BFE8B0E....8B16....B8....50FCAD33C2AB8BD0E2"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_DIET, "1.00", ""}, "BF....3BFC72$$FDBE....B9....F3A5FC8BF7BF....ADAD8BE8B2..E9"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_DIET, "1.00, 1.00d", ""},
     "BF....3BFC72$$BE....B9....FDF3A5FC8BF7BF....ADAD8BE8B2..E9"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_DIET, "1.02b, 1.10a", ""},
     "......BF....B9....3BFC72$$FDF3A5FC8BF7BF....ADAD8BE8B2..E9"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_DIET, "1.20", ""},
     "......BF....B9....3BFC72$$31DBEB$$FDF3A5FC8BF7BF....ADAD8BE8B2..E9"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_DIET, "1.44-1.45", ""}, "F99CEB$$55061E575652515350E8$$$$59B1..D3E98CC803C18ED88EC0"},
    {{0, XBinary::FT_COM, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_CRYPTCOM, "2.0", ""},
     "E9$$$$BE....56B9....C704....C644....8134....4646E2..31F631C9C3"},
};

NFD_Binary::SIGNATURE_RECORD *NFD_COM::getHeaderRecords()
{
    return g_COM_records;
}
qint32 NFD_COM::getHeaderRecordsSize()
{
    return sizeof(g_COM_records);
}
NFD_Binary::SIGNATURE_RECORD *NFD_COM::getHeaderExpRecords()
{
    return g_COM_Exp_records;
}
qint32 NFD_COM::getHeaderExpRecordsSize()
{
    return sizeof(g_COM_Exp_records);
}

NFD_COM::COMINFO_STRUCT NFD_COM::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    COMINFO_STRUCT result = {};

    XCOM com(pDevice, pOptions->bIsImage);

    if (com.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Initialize basic info via shared utility
        result.basic_info = NFD_Binary::_initBasicInfo(&com, parentId, pOptions, nOffset, pPdStruct);

        // Overlay info (COM may have an overlay when packaged inside MSDOS)
        result.nOverlayOffset = com.getOverlayOffset(pPdStruct);
        result.nOverlaySize = com.getOverlaySize(pPdStruct);
        if (result.nOverlaySize) {
            result.sOverlaySignature = com.getSignature(result.nOverlayOffset, 150);
        }

        // Entry point signature (offset 0 for plain COM; retain API parity)
        result.nEntryPointOffset = com.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = com.getSignature(result.nEntryPointOffset, 150);

        // Header signature scans (moved from SpecAbstract)
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, g_COM_records, sizeof(g_COM_records),
                                  result.basic_info.id.fileType, XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        NFD_Binary::signatureExpScan(&com, &(result.basic_info.memoryMap), &result.basic_info.mapHeaderDetects, 0, g_COM_Exp_records, sizeof(g_COM_Exp_records),
                                     result.basic_info.id.fileType, XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        // Additional handlers formerly in SpecAbstract
        if (pOptions->bIsVerbose) {
            NFD_COM::handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        }

        NFD_COM::handle_Protection(pDevice, pOptions, &result, pPdStruct);

        if (result.basic_info.mapResultProtectors.size() || result.basic_info.mapResultPackers.size()) {
            NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(com.getFileFormatInfo(pPdStruct));
            result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));
        }

        // Finalize core info
        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

void NFD_COM::handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XCOM xcom(pDevice, pOptions->bIsImage);

    if (xcom.isValid(pPdStruct)) {
        NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xcom.getFileFormatInfo(pPdStruct));
        pCOMInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pCOMInfo->basic_info), &ssOperationSystem));
    }
}

void NFD_COM::handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    using RECORD_NAME = XScanEngine::RECORD_NAME;

    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_PKLITE, false);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_UPX, false);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_HACKSTOP, true);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_CRYPTDISMEMBER, true);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_SPIRIT, true);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_ICE, false);
    NFD_Binary::addHeaderDetectToResults(&pCOMInfo->basic_info, RECORD_NAME::RECORD_NAME_DIET, false);
}
