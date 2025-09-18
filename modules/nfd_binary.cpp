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
#include "xbinary.h"
#include "xpe.h"
#include "xarchive.h"
#include "nfd_text.h"

NFD_Binary::NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pBinary, filePart, pOptions, pPdStruct)
{
}

QString NFD_Binary::SCANS_STRUCT_toString(const SCANS_STRUCT *pScanStruct, bool bShowType)
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

// Scanning helpers: implementations centralized in NFD_Binary
void NFD_Binary::memoryScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                            qint64 nSize, SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                            DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    if (!nSize) return;

    XBinary binary(pDevice, pOptions->bIsImage);

    qint32 nSignaturesCount = nRecordsSize / (qint32)sizeof(SIGNATURE_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                qint64 _nOffset = binary.find_signature(&(pBasicInfo->memoryMap), nOffset, nSize, (char *)pRecords[i].pszSignature, nullptr, pPdStruct);

                if (_nOffset != -1) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = _nOffset;

                        pMapRecords->insert(record.name, record);
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};
                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = _nOffset;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void NFD_Binary::signatureScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, const QString &sSignature, SIGNATURE_RECORD *pRecords, qint32 nRecordsSize,
                               XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (qint32)sizeof(SIGNATURE_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                if (XBinary::compareSignatureStrings(sSignature, pRecords[i].pszSignature)) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = 0;
                        pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                        qDebug("SIGNATURE SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};
                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = pRecords[i].pszSignature;
                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void NFD_Binary::PE_resourcesScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, PE_RESOURCES_RECORD *pRecords,
                                  qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                  XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (qint32)sizeof(PE_RESOURCES_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                bool bSuccess = false;
                QString sValue;

                if (pRecords[i].bIsString1) {
                    if (pRecords[i].bIsString2) {
                        bSuccess = XPE::isResourcePresent(pRecords[i].pszName1, pRecords[i].pszName2, pListResources);
                        sValue = QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].pszName2);
                    } else {
                        bSuccess = XPE::isResourcePresent(pRecords[i].pszName1, pRecords[i].nID2, pListResources);
                        sValue = QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].nID2);
                    }
                } else {
                    if (pRecords[i].bIsString2) {
                        bSuccess = XPE::isResourcePresent(pRecords[i].nID1, pRecords[i].pszName2, pListResources);
                        sValue = QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].pszName2);
                    } else {
                        bSuccess = XPE::isResourcePresent(pRecords[i].nID1, pRecords[i].nID2, pListResources);
                        sValue = QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].nID2);
                    }
                }

                if (bSuccess) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = 0;
                        pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                        qDebug("RESOURCES SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};
                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = sValue;
                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void NFD_Binary::stringScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, STRING_RECORD *pRecords, qint32 nRecordsSize,
                            XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    qint32 nNumberOfStrings = pListStrings->count();
    qint32 nNumberOfSignatures = nRecordsSize / (qint32)sizeof(STRING_RECORD);

    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfStrings);
        for (qint32 i = 0; (i < nNumberOfStrings) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nCRC = XBinary::getStringCustomCRC32(pListStrings->at(i));
            listStringCRC.append(nCRC);
            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }
    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfSignatures);
        for (qint32 i = 0; (i < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nCRC = XBinary::getStringCustomCRC32(pRecords[i].pszString);
            listSignatureCRC.append(nCRC);
            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfStrings);
        for (qint32 i = 0; (i < nNumberOfStrings) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            for (qint32 j = 0; j < nNumberOfSignatures; j++) {
                if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                    if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                        quint32 nCRC1 = listStringCRC[i];
                        quint32 nCRC2 = listSignatureCRC[j];
                        if (nCRC1 == nCRC2) {
                            if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                                SCANS_STRUCT record = {};
                                record.nVariant = pRecords[j].basicInfo.nVariant;
                                record.fileType = pRecords[j].basicInfo.fileType;
                                record.type = pRecords[j].basicInfo.type;
                                record.name = pRecords[j].basicInfo.name;
                                record.sVersion = pRecords[j].basicInfo.pszVersion;
                                record.sInfo = pRecords[j].basicInfo.pszInfo;
                                record.nOffset = 0;
                                pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                                qDebug("STRING SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                            }
                            if (pBasicInfo->scanOptions.bShowInternalDetects) {
                                DETECT_RECORD heurRecord = {};
                                heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                                heurRecord.fileType = pRecords[j].basicInfo.fileType;
                                heurRecord.type = pRecords[j].basicInfo.type;
                                heurRecord.name = pRecords[j].basicInfo.name;
                                heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                                heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                                heurRecord.nOffset = 0;
                                heurRecord.filepart = pBasicInfo->id.filePart;
                                heurRecord.detectType = detectType;
                                heurRecord.sValue = pRecords[j].pszString;
                                pBasicInfo->listHeurs.append(heurRecord);
                            }
                        }
                    }
                }
            }
            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }
}

void NFD_Binary::constScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, CONST_RECORD *pRecords, qint32 nRecordsSize,
                           XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(CONST_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects) || (pRecords[i].nConst1 == 0xFFFFFFFF)) {
                bool bSuccess = false;
                bSuccess =
                    ((pRecords[i].nConst1 == nCost1) || (pRecords[i].nConst1 == 0xFFFFFFFF)) && ((pRecords[i].nConst2 == nCost2) || (pRecords[i].nConst2 == 0xFFFFFFFF));
                if (bSuccess) {
                    if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pRecords[i].nConst1 == 0xFFFFFFFF)) {
                        SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = 0;
                        pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                        qDebug("CONST SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};
                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nConst1)).arg(XBinary::valueToHex(pRecords[i].nConst2));
                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void NFD_Binary::archiveScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords,
                             qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                             XBinary::PDSTRUCT *pPdStruct)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    qint32 nNumberOfArchives = pListArchiveRecords->count();
    qint32 nNumberOfSignatures = nRecordsSize / (qint32)sizeof(STRING_RECORD);

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        quint32 nCRC = XBinary::getStringCustomCRC32(pListArchiveRecords->at(i).spInfo.sRecordName);
        listStringCRC.append(nCRC);
    }

    for (qint32 i = 0; (i < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        quint32 nCRC = XBinary::getStringCustomCRC32(pRecords[i].pszString);
        listSignatureCRC.append(nCRC);
    }

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        for (qint32 j = 0; (j < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); j++) {
            if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                    quint32 nCRC1 = listStringCRC[i];
                    quint32 nCRC2 = listSignatureCRC[j];
                    if (nCRC1 == nCRC2) {
                        if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                            SCANS_STRUCT record = {};
                            record.nVariant = pRecords[j].basicInfo.nVariant;
                            record.fileType = pRecords[j].basicInfo.fileType;
                            record.type = pRecords[j].basicInfo.type;
                            record.name = pRecords[j].basicInfo.name;
                            record.sVersion = pRecords[j].basicInfo.pszVersion;
                            record.sInfo = pRecords[j].basicInfo.pszInfo;
                            record.nOffset = 0;
                            pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }
                        if (pBasicInfo->scanOptions.bShowInternalDetects) {
                            DETECT_RECORD heurRecord = {};
                            heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType = pRecords[j].basicInfo.fileType;
                            heurRecord.type = pRecords[j].basicInfo.type;
                            heurRecord.name = pRecords[j].basicInfo.name;
                            heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset = 0;
                            heurRecord.filepart = pBasicInfo->id.filePart;
                            heurRecord.detectType = detectType;
                            heurRecord.sValue = pRecords[j].pszString;
                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void NFD_Binary::archiveExpScan(QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, STRING_RECORD *pRecords,
                                qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nNumberOfArchives = pListArchiveRecords->count();
    qint32 nNumberOfSignatures = nRecordsSize / (qint32)sizeof(STRING_RECORD);

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        for (qint32 j = 0; (j < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); j++) {
            if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                    if (XBinary::isRegExpPresent(pRecords[j].pszString, pListArchiveRecords->at(i).spInfo.sRecordName)) {
                        if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                            SCANS_STRUCT record = {};
                            record.nVariant = pRecords[j].basicInfo.nVariant;
                            record.fileType = pRecords[j].basicInfo.fileType;
                            record.type = pRecords[j].basicInfo.type;
                            record.name = pRecords[j].basicInfo.name;
                            record.sVersion = pRecords[j].basicInfo.pszVersion;
                            record.sInfo = pRecords[j].basicInfo.pszInfo;
                            record.nOffset = 0;
                            pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }
                        if (pBasicInfo->scanOptions.bShowInternalDetects) {
                            DETECT_RECORD heurRecord = {};
                            heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType = pRecords[j].basicInfo.fileType;
                            heurRecord.type = pRecords[j].basicInfo.type;
                            heurRecord.name = pRecords[j].basicInfo.name;
                            heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset = 0;
                            heurRecord.filepart = pBasicInfo->id.filePart;
                            heurRecord.detectType = detectType;
                            heurRecord.sValue = pRecords[j].pszString;
                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void NFD_Binary::signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<XScanEngine::RECORD_NAME, SCANS_STRUCT> *pMapRecords, qint64 nOffset,
                                  SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                                  DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(SIGNATURE_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                if (pXBinary->compareSignature(pMemoryMap, pRecords[i].pszSignature, nOffset)) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = 0;
                        pMapRecords->insert(record.name, record);
#ifdef QT_DEBUG
                        qDebug("SIGNATURE EXP SCAN: %s", SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }
                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};
                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = pRecords[i].pszSignature;
                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

NFD_Binary::SCANS_STRUCT NFD_Binary::getScansStruct(quint32 nVariant, XBinary::FT fileType, XScanEngine::RECORD_TYPE type, XScanEngine::RECORD_NAME name, const QString &sVersion, const QString &sInfo, qint64 nOffset)
{
    // TODO bIsHeuristic;
    SCANS_STRUCT result = {};

    result.nVariant = nVariant;
    result.fileType = fileType;
    result.type = type;
    result.name = name;
    result.sVersion = sVersion;
    result.sInfo = sInfo;
    result.nOffset = nOffset;

    return result;
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

NFD_Binary::SCANS_STRUCT NFD_Binary::detectOperationSystem(XBinary *pBinary, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pBinary) {
        SCANS_STRUCT unknown = {};
        unknown.type = XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;
        unknown.name = XScanEngine::RECORD_NAME_UNKNOWN;
        unknown.bIsUnknown = true;
        return unknown;
    }

    XBinary::FILEFORMATINFO ffi = pBinary->getFileFormatInfo(pPdStruct);

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

// Moved helpers from SpecAbstract into NFD_Binary (static)
NFD_Binary::BASIC_INFO NFD_Binary::_initBasicInfo(XBinary *pBinary, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                  XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    NFD_Binary::BASIC_INFO result = {};

    result.parentId = parentId;
    result.memoryMap = pBinary->getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    result.sHeaderSignature = pBinary->getSignature(0, 150);
    result.id.nSize = pBinary->getSize();

    result.id.fileType = result.memoryMap.fileType;
    result.id.filePart = XBinary::FILEPART_HEADER;
    result.id.sUuid = XBinary::generateUUID();
    result.scanOptions = *pOptions;
    result.id.sArch = result.memoryMap.sArch;
    result.id.mode = result.memoryMap.mode;
    result.id.endian = result.memoryMap.endian;
    result.id.sType = result.memoryMap.sType;
    result.id.nOffset = nOffset;

    return result;
}

void NFD_Binary::_handleResult(NFD_Binary::BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct)
{
    // Aggregate languages from multiple maps
    getLanguage(&(pBasic_info->mapResultLinkers), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultCompilers), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultLibraries), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultTools), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultPackers), &(pBasic_info->mapResultLanguages), pPdStruct);

    fixLanguage(&(pBasic_info->mapResultLanguages));

    pBasic_info->listDetects.append(pBasic_info->mapResultOperationSystems.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultFormats.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDosExtenders.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLinkers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultCompilers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLanguages.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLibraries.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultTools.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultPackers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSFX.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultProtectors.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultAPKProtectors.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDongleProtection.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSigntools.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultInstallers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultJoiners.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultPETools.values());

    pBasic_info->listDetects.append(pBasic_info->mapResultTexts.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultArchives.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultCertificates.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDebugData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultInstallerData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSFXData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultProtectorData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLibraryData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultResources.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDatabases.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultImages.values());
}

void NFD_Binary::getLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages,
                             XBinary::PDSTRUCT *pPdStruct)
{
    QMapIterator<XScanEngine::RECORD_NAME, SCAN_STRUCT> i(*pMapDetects);
    while (i.hasNext() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        i.next();

        SCAN_STRUCT ssDetect = i.value();
        SCANS_STRUCT ssLanguage = {};
        ssLanguage.type = XScanEngine::RECORD_TYPE_LANGUAGE;
        ssLanguage.name = XScanEngine::RECORD_NAME_UNKNOWN;

        switch (ssDetect.name) {
            case XScanEngine::RECORD_NAME_C:
            case XScanEngine::RECORD_NAME_ARMC:
            case XScanEngine::RECORD_NAME_LCCLNK:
            case XScanEngine::RECORD_NAME_LCCWIN:
            case XScanEngine::RECORD_NAME_MICROSOFTC:
            case XScanEngine::RECORD_NAME_THUMBC:
            case XScanEngine::RECORD_NAME_TINYC:
            case XScanEngine::RECORD_NAME_TURBOC:
            case XScanEngine::RECORD_NAME_WATCOMC: ssLanguage.name = XScanEngine::RECORD_NAME_C; break;
            case XScanEngine::RECORD_NAME_CCPP:
            case XScanEngine::RECORD_NAME_ARMCCPP:
            case XScanEngine::RECORD_NAME_ARMNEONCCPP:
            case XScanEngine::RECORD_NAME_ARMTHUMBCCPP:
            case XScanEngine::RECORD_NAME_BORLANDCCPP:
            case XScanEngine::RECORD_NAME_MINGW:
            case XScanEngine::RECORD_NAME_MSYS:
            case XScanEngine::RECORD_NAME_MSYS2:
            case XScanEngine::RECORD_NAME_VISUALCCPP:
            case XScanEngine::RECORD_NAME_OPENWATCOMCCPP:
            case XScanEngine::RECORD_NAME_WATCOMCCPP: ssLanguage.name = XScanEngine::RECORD_NAME_CCPP; break;
            case XScanEngine::RECORD_NAME_CLANG:
            case XScanEngine::RECORD_NAME_GCC:
            case XScanEngine::RECORD_NAME_ALIPAYCLANG:
            case XScanEngine::RECORD_NAME_ANDROIDCLANG:
            case XScanEngine::RECORD_NAME_APPORTABLECLANG:
            case XScanEngine::RECORD_NAME_PLEXCLANG:
            case XScanEngine::RECORD_NAME_UBUNTUCLANG:
            case XScanEngine::RECORD_NAME_DEBIANCLANG:
                if (ssDetect.sInfo.contains("Objective-C")) {
                    ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTIVEC;
                } else {
                    ssLanguage.name = XScanEngine::RECORD_NAME_CCPP;
                }
                break;
            case XScanEngine::RECORD_NAME_CPP:
            case XScanEngine::RECORD_NAME_BORLANDCPP:
            case XScanEngine::RECORD_NAME_BORLANDCPPBUILDER:
            case XScanEngine::RECORD_NAME_CODEGEARCPP:
            case XScanEngine::RECORD_NAME_CODEGEARCPPBUILDER:
            case XScanEngine::RECORD_NAME_EMBARCADEROCPP:
            case XScanEngine::RECORD_NAME_EMBARCADEROCPPBUILDER:
            case XScanEngine::RECORD_NAME_MICROSOFTCPP:
            case XScanEngine::RECORD_NAME_TURBOCPP: ssLanguage.name = XScanEngine::RECORD_NAME_CPP; break;
            case XScanEngine::RECORD_NAME_ASSEMBLER:
            case XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER:
            case XScanEngine::RECORD_NAME_GNUASSEMBLER: ssLanguage.name = XScanEngine::RECORD_NAME_ASSEMBLER; break;
            case XScanEngine::RECORD_NAME_FASM:
            case XScanEngine::RECORD_NAME_GOASM:
            case XScanEngine::RECORD_NAME_MASM:
            case XScanEngine::RECORD_NAME_MASM32:
            case XScanEngine::RECORD_NAME_NASM: ssLanguage.name = XScanEngine::RECORD_NAME_X86ASSEMBLER; break;
            case XScanEngine::RECORD_NAME_AUTOIT: ssLanguage.name = XScanEngine::RECORD_NAME_AUTOIT; break;
            case XScanEngine::RECORD_NAME_OBJECTPASCAL:
            case XScanEngine::RECORD_NAME_LAZARUS:
            case XScanEngine::RECORD_NAME_FPC:
            case XScanEngine::RECORD_NAME_VIRTUALPASCAL:
            case XScanEngine::RECORD_NAME_IBMPCPASCAL: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTPASCAL; break;
            case XScanEngine::RECORD_NAME_BORLANDDELPHI:
            case XScanEngine::RECORD_NAME_BORLANDDELPHIDOTNET:
            case XScanEngine::RECORD_NAME_BORLANDOBJECTPASCALDELPHI:
            case XScanEngine::RECORD_NAME_CODEGEARDELPHI:
            case XScanEngine::RECORD_NAME_CODEGEAROBJECTPASCALDELPHI:
            case XScanEngine::RECORD_NAME_EMBARCADERODELPHI:
            case XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET:
            case XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTPASCALDELPHI; break;
            case XScanEngine::RECORD_NAME_D:
            case XScanEngine::RECORD_NAME_DMD:
            case XScanEngine::RECORD_NAME_DMD32:
            case XScanEngine::RECORD_NAME_LDC: ssLanguage.name = XScanEngine::RECORD_NAME_D; break;
            case XScanEngine::RECORD_NAME_CSHARP:
            case XScanEngine::RECORD_NAME_DOTNET: ssLanguage.name = XScanEngine::RECORD_NAME_CSHARP; break;
            case XScanEngine::RECORD_NAME_GO: ssLanguage.name = XScanEngine::RECORD_NAME_GO; break;
            case XScanEngine::RECORD_NAME_JAVA:
            case XScanEngine::RECORD_NAME_JVM:
            case XScanEngine::RECORD_NAME_JDK:
            case XScanEngine::RECORD_NAME_OPENJDK:
            case XScanEngine::RECORD_NAME_IBMJDK:
            case XScanEngine::RECORD_NAME_APPLEJDK: ssLanguage.name = XScanEngine::RECORD_NAME_JAVA; break;
            case XScanEngine::RECORD_NAME_JSCRIPT: ssLanguage.name = XScanEngine::RECORD_NAME_ECMASCRIPT; break;
            case XScanEngine::RECORD_NAME_KOTLIN: ssLanguage.name = XScanEngine::RECORD_NAME_KOTLIN; break;
            case XScanEngine::RECORD_NAME_FORTRAN:
            case XScanEngine::RECORD_NAME_LAYHEYFORTRAN90: ssLanguage.name = XScanEngine::RECORD_NAME_FORTRAN; break;
            case XScanEngine::RECORD_NAME_NIM: ssLanguage.name = XScanEngine::RECORD_NAME_NIM; break;
            case XScanEngine::RECORD_NAME_OBJECTIVEC: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTIVEC; break;
            case XScanEngine::RECORD_NAME_BASIC:
            case XScanEngine::RECORD_NAME_BASIC4ANDROID:
            case XScanEngine::RECORD_NAME_POWERBASIC:
            case XScanEngine::RECORD_NAME_PUREBASIC:
            case XScanEngine::RECORD_NAME_TURBOBASIC:
            case XScanEngine::RECORD_NAME_VBNET:
            case XScanEngine::RECORD_NAME_VISUALBASIC: ssLanguage.name = XScanEngine::RECORD_NAME_BASIC; break;
            case XScanEngine::RECORD_NAME_RUST: ssLanguage.name = XScanEngine::RECORD_NAME_RUST; break;
            case XScanEngine::RECORD_NAME_RUBY: ssLanguage.name = XScanEngine::RECORD_NAME_RUBY; break;
            case XScanEngine::RECORD_NAME_PYTHON:
            case XScanEngine::RECORD_NAME_PYINSTALLER: ssLanguage.name = XScanEngine::RECORD_NAME_PYTHON; break;
            case XScanEngine::RECORD_NAME_SWIFT: ssLanguage.name = XScanEngine::RECORD_NAME_SWIFT; break;
            case XScanEngine::RECORD_NAME_PERL: ssLanguage.name = XScanEngine::RECORD_NAME_PERL; break;
            case XScanEngine::RECORD_NAME_ZIG: ssLanguage.name = XScanEngine::RECORD_NAME_ZIG; break;
            case XScanEngine::RECORD_NAME_QML: ssLanguage.name = XScanEngine::RECORD_NAME_QML; break;
            default: ssLanguage.name = XScanEngine::RECORD_NAME_UNKNOWN;
        }

        if (ssLanguage.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            SCAN_STRUCT ss = ssDetect;
            ss.type = ssLanguage.type;
            ss.name = ssLanguage.name;
            ss.sInfo = "";
            ss.sVersion = "";
            pMapLanguages->insert(ss.name, ss);
        }
    }
}

void NFD_Binary::addHeaderDetectToResults(NFD_Binary::BASIC_INFO *pBasicInfo, XScanEngine::RECORD_NAME rn, bool toProtector)
{
    if (!pBasicInfo) return;

    if (pBasicInfo->mapHeaderDetects.contains(rn)) {
        pBasicInfo->id.fileType = XBinary::FT_COM;  // context: caller sets FT as needed; COM callers rely on COM type
        NFD_Binary::SCANS_STRUCT ss = pBasicInfo->mapHeaderDetects.value(rn);
        if (toProtector) {
            pBasicInfo->mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(pBasicInfo, &ss));
        } else {
            pBasicInfo->mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(pBasicInfo, &ss));
        }
    }
}

void NFD_Binary::fixLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages)
{
    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_C) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CPP)) {
        SCAN_STRUCT ss = pMapLanguages->value(XScanEngine::RECORD_NAME_C);
        ss.name = XScanEngine::RECORD_NAME_CCPP;
        pMapLanguages->insert(ss.name, ss);
    }

    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_C) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CCPP)) {
        pMapLanguages->remove(XScanEngine::RECORD_NAME_C);
    }

    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_CPP) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CCPP)) {
        pMapLanguages->remove(XScanEngine::RECORD_NAME_CPP);
    }
}

NFD_Binary::SCANS_STRUCT NFD_Binary::getFormatScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    SCANS_STRUCT result = {};
    result.type = XScanEngine::RECORD_TYPE_FORMAT;
    if (fileFormatInfo.fileType == XBinary::FT_PDF) result.name = XScanEngine::RECORD_NAME_PDF;
    else if (fileFormatInfo.fileType == XBinary::FT_JPEG) result.name = XScanEngine::RECORD_NAME_JPEG;
    else if (fileFormatInfo.fileType == XBinary::FT_CFBF) result.name = XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND;
    else result.name = XScanEngine::RECORD_NAME_UNKNOWN;
    result.sVersion = fileFormatInfo.sVersion;
    result.sInfo = XBinary::getFileFormatInfoString(&fileFormatInfo);
    return result;
}

NFD_Binary::SCANS_STRUCT NFD_Binary::getOperationSystemScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    SCANS_STRUCT result = {};
    result.type = fileFormatInfo.bIsVM ? XScanEngine::RECORD_TYPE_VIRTUALMACHINE : XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;
    if (fileFormatInfo.osName == XBinary::OSNAME_MSDOS) result.name = XScanEngine::RECORD_NAME_MSDOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_POSIX) result.name = XScanEngine::RECORD_NAME_POSIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UNIX) result.name = XScanEngine::RECORD_NAME_UNIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_LINUX) result.name = XScanEngine::RECORD_NAME_LINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWS) result.name = XScanEngine::RECORD_NAME_WINDOWS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWSCE) result.name = XScanEngine::RECORD_NAME_WINDOWSCE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_XBOX) result.name = XScanEngine::RECORD_NAME_XBOX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS2) result.name = XScanEngine::RECORD_NAME_OS2;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS) result.name = XScanEngine::RECORD_NAME_MAC_OS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS_X) result.name = XScanEngine::RECORD_NAME_MAC_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS_X) result.name = XScanEngine::RECORD_NAME_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACOS) result.name = XScanEngine::RECORD_NAME_MACOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPHONEOS) result.name = XScanEngine::RECORD_NAME_IPHONEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPADOS) result.name = XScanEngine::RECORD_NAME_IPADOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IOS) result.name = XScanEngine::RECORD_NAME_IOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WATCHOS) result.name = XScanEngine::RECORD_NAME_WATCHOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TVOS) result.name = XScanEngine::RECORD_NAME_TVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BRIDGEOS) result.name = XScanEngine::RECORD_NAME_BRIDGEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ANDROID) result.name = XScanEngine::RECORD_NAME_ANDROID;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FREEBSD) result.name = XScanEngine::RECORD_NAME_FREEBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENBSD) result.name = XScanEngine::RECORD_NAME_OPENBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NETBSD) result.name = XScanEngine::RECORD_NAME_NETBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HPUX) result.name = XScanEngine::RECORD_NAME_HPUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SOLARIS) result.name = XScanEngine::RECORD_NAME_SOLARIS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AIX) result.name = XScanEngine::RECORD_NAME_AIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IRIX) result.name = XScanEngine::RECORD_NAME_IRIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TRU64) result.name = XScanEngine::RECORD_NAME_TRU64;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MODESTO) result.name = XScanEngine::RECORD_NAME_MODESTO;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVMS) result.name = XScanEngine::RECORD_NAME_OPENVMS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FENIXOS) result.name = XScanEngine::RECORD_NAME_FENIXOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BORLANDOSSERVICES) result.name = XScanEngine::RECORD_NAME_BORLANDOSSERVICES;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NSK) result.name = XScanEngine::RECORD_NAME_NSK;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AROS) result.name = XScanEngine::RECORD_NAME_AROS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UBUNTULINUX) result.name = XScanEngine::RECORD_NAME_UBUNTULINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_DEBIANLINUX) result.name = XScanEngine::RECORD_NAME_DEBIANLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_STARTOSLINUX) result.name = XScanEngine::RECORD_NAME_STARTOSLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_GENTOOLINUX) result.name = XScanEngine::RECORD_NAME_GENTOOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ALPINELINUX) result.name = XScanEngine::RECORD_NAME_ALPINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDRIVERLINUX) result.name = XScanEngine::RECORD_NAME_WINDRIVERLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUSELINUX) result.name = XScanEngine::RECORD_NAME_SUSELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MANDRAKELINUX) result.name = XScanEngine::RECORD_NAME_MANDRAKELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ASPLINUX) result.name = XScanEngine::RECORD_NAME_ASPLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_REDHATLINUX) result.name = XScanEngine::RECORD_NAME_REDHATLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HANCOMLINUX) result.name = XScanEngine::RECORD_NAME_HANCOMLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TURBOLINUX) result.name = XScanEngine::RECORD_NAME_TURBOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_VINELINUX) result.name = XScanEngine::RECORD_NAME_VINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUNOS) result.name = XScanEngine::RECORD_NAME_SUNOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVOS) result.name = XScanEngine::RECORD_NAME_OPENVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MCLINUX) result.name = XScanEngine::RECORD_NAME_MCLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_QNX) result.name = XScanEngine::RECORD_NAME_QNX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SYLLABLE) result.name = XScanEngine::RECORD_NAME_SYLLABLE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MINIX) result.name = XScanEngine::RECORD_NAME_MINIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_JVM) result.name = XScanEngine::RECORD_NAME_JVM;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AMIGA) result.name = XScanEngine::RECORD_NAME_AMIGA;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACCATALYST) result.name = XScanEngine::RECORD_NAME_MACCATALYST;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACDRIVERKIT) result.name = XScanEngine::RECORD_NAME_MACDRIVERKIT;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACFIRMWARE) result.name = XScanEngine::RECORD_NAME_MACFIRMWARE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SEPOS) result.name = XScanEngine::RECORD_NAME_SEPOS;
    else result.name = XScanEngine::RECORD_NAME_UNKNOWN;
    result.sVersion = fileFormatInfo.sOsVersion;
    result.sInfo = QString("%1, %2, %3").arg(fileFormatInfo.sArch, XBinary::modeIdToString(fileFormatInfo.mode), fileFormatInfo.sType);
    if (fileFormatInfo.endian == XBinary::ENDIAN_BIG) {
        result.sInfo.append(QString(", %1").arg(XBinary::endianToString(XBinary::ENDIAN_BIG)));
    }
    return result;
}

// Options conversion implementation (static)
Binary_Script::OPTIONS NFD_Binary::toOptions(const XScanEngine::SCAN_OPTIONS *pScanOptions)
{
    Binary_Script::OPTIONS opts = {};
    opts.bIsDeepScan = pScanOptions->bIsDeepScan;
    opts.bIsHeuristicScan = pScanOptions->bIsHeuristicScan;
    opts.bIsAggressiveScan = pScanOptions->bIsAggressiveScan;
    opts.bIsVerbose = pScanOptions->bIsVerbose;
    // Profiling is a runtime tracing option; default to false here
    opts.bIsProfiling = false;
    return opts;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType,
                                             XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nStringOffset1 = binary.find_ansiString(nOffset, nSize, "$Id: UPX", pPdStruct);
    qint64 nStringOffset2 = binary.find_ansiString(nOffset, nSize, "UPX!", pPdStruct);

    if (nStringOffset1 != -1) {
        result.bIsValid = true;

        result.sVersion = binary.read_ansiString(nStringOffset1 + 9, 10);
        result.sVersion = result.sVersion.section(" ", 0, 0);

        if (!XBinary::checkVersionString(result.sVersion)) {
            result.sVersion = "";
        }

        // NRV
        qint64 nNRVStringOffset1 = binary.find_array(nOffset, nSize, "\x24\x49\x64\x3a\x20\x4e\x52\x56\x20", 9, pPdStruct);

        if (nNRVStringOffset1 != -1) {
            QString sNRVVersion = binary.read_ansiString(nNRVStringOffset1 + 9, 10);
            sNRVVersion = sNRVVersion.section(" ", 0, 0);

            if (XBinary::checkVersionString(sNRVVersion)) {
                result.sInfo = QString("NRV %1").arg(sNRVVersion);
            }
        }
    }

    if (nStringOffset2 != -1) {
        VI_STRUCT viUPX = _get_UPX_vi(pDevice, pOptions, nStringOffset2, 0x24, fileType);

        if (viUPX.bIsValid) {
            result.sInfo = XBinary::appendComma(result.sInfo, viUPX.sInfo);

            if (result.sVersion == "") {
                result.sVersion = viUPX.sVersion;
            }
        }

        result.bIsValid = true;  // TODO Check

        if (result.sVersion == "") {
            result.sVersion = binary.read_ansiString(nStringOffset2 - 5, 4);
        }
    }

    if (!XBinary::checkVersionString(result.sVersion)) {
        result.sVersion = "";
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.isOffsetAndSizeValid(nOffset, nSize)) {
        if (nSize >= 22) {
            result.bIsValid = true;

            quint8 nVersion = binary.read_uint8(nOffset + 4);
            quint8 nFormat = binary.read_uint8(nOffset + 5);
            quint8 nMethod = binary.read_uint8(nOffset + 6);
            quint8 nLevel = binary.read_uint8(nOffset + 7);

            quint32 nULen = 0;
            quint32 nCLen = 0;
            quint32 nUAdler = 0;
            quint32 nCAdler = 0;
            quint32 nFileSize = 0;
            quint8 nFilter = 0;
            quint8 nFilterCTO = 0;
            quint8 nMRU = 0;
            quint8 nHeaderChecksum = 0;

            if (nFormat < 128) {
                if ((nFormat == 1) || (nFormat == 2))  // UPX_F_DOS_COM, UPX_F_DOS_SYS
                {
                    if (nSize >= 22) {
                        nULen = binary.read_uint16(nOffset + 16);
                        nCLen = binary.read_uint16(nOffset + 18);
                        nFilter = binary.read_uint8(nOffset + 20);
                        nHeaderChecksum = binary.read_uint8(nOffset + 21);
                    } else {
                        result.bIsValid = false;
                    }
                } else if (nFormat == 3)  // UPX_F_DOS_EXE
                {
                    if (nSize >= 27) {
                        nULen = binary.read_uint24(nOffset + 16);
                        nCLen = binary.read_uint24(nOffset + 19);
                        nFileSize = binary.read_uint24(nOffset + 22);
                        nFilter = binary.read_uint8(nOffset + 25);
                        nHeaderChecksum = binary.read_uint8(nOffset + 26);
                    } else {
                        result.bIsValid = false;
                    }
                } else {
                    if (nSize >= 32) {
                        nULen = binary.read_uint32(nOffset + 16);
                        nCLen = binary.read_uint32(nOffset + 20);
                        nFileSize = binary.read_uint32(nOffset + 24);
                        nFilter = binary.read_uint8(nOffset + 28);
                        nFilterCTO = binary.read_uint8(nOffset + 29);
                        nMRU = binary.read_uint8(nOffset + 30);
                        nHeaderChecksum = binary.read_uint8(nOffset + 31);
                    } else {
                        result.bIsValid = false;
                    }
                }

                if (result.bIsValid) {
                    nUAdler = binary.read_uint32(nOffset + 8);
                    nCAdler = binary.read_uint32(nOffset + 12);
                }
            } else {
                if (nSize >= 32) {
                    nULen = binary.read_uint32(nOffset + 8, true);
                    nCLen = binary.read_uint32(nOffset + 12, true);
                    nUAdler = binary.read_uint32(nOffset + 16, true);
                    nCAdler = binary.read_uint32(nOffset + 20, true);
                    nFileSize = binary.read_uint32(nOffset + 24, true);
                    nFilter = binary.read_uint8(nOffset + 28);
                    nFilterCTO = binary.read_uint8(nOffset + 29);
                    nMRU = binary.read_uint8(nOffset + 30);
                    nHeaderChecksum = binary.read_uint8(nOffset + 31);
                } else {
                    result.bIsValid = false;
                }
            }

            Q_UNUSED(nUAdler)
            Q_UNUSED(nCAdler)
            Q_UNUSED(nFileSize)
            Q_UNUSED(nFilter)
            Q_UNUSED(nFilterCTO)
            Q_UNUSED(nMRU)
            Q_UNUSED(nHeaderChecksum)

            if (result.bIsValid) {
                // Check Executable formats
                if (nFormat == 0) result.bIsValid = false;
                if ((nFormat > 42) && (nFormat < 129)) result.bIsValid = false;
                if (nFormat > 142) result.bIsValid = false;
                if (nFormat == 7) result.bIsValid = false;    // UPX_F_DOS_EXEH        OBSOLETE
                if (nFormat == 6) result.bIsValid = false;    // UPX_F_VXD_LE NOT      IMPLEMENTED
                if (nFormat == 11) result.bIsValid = false;   // UPX_F_WIN16_NE NOT    IMPLEMENTED
                if (nFormat == 13) result.bIsValid = false;   // UPX_F_LINUX_SEP_i386  NOT IMPLEMENTED
                if (nFormat == 17) result.bIsValid = false;   // UPX_F_ELKS_8086 NOT   IMPLEMENTED
                if (nFormat == 130) result.bIsValid = false;  // UPX_F_SOLARIS_SPARC   NOT IMPLEMENTED

                if (fileType == XBinary::FT_COM) {
                    if ((nFormat != 1) &&  // UPX_F_DOS_COM
                        (nFormat != 2))    // UPX_F_DOS_SYS
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_MSDOS) {
                    if ((nFormat != 3))  // UPX_F_DOS_EXE
                    {
                        result.bIsValid = false;
                    }
                } else if ((fileType == XBinary::FT_LE) || (fileType == XBinary::FT_LX)) {
                    if ((nFormat != 5))  // UPX_F_WATCOM_LE
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_PE) {
                    if ((nFormat != 9) &&   // UPX_F_WIN32_PE
                        (nFormat != 21) &&  // UPX_F_WINCE_ARM_PE
                        (nFormat != 36))    // UPX_F_WIN64_PEP
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_MACHO) {
                    if ((nFormat != 29) &&   // UPX_F_MACH_i386
                        (nFormat != 32) &&   // UPX_F_MACH_ARMEL
                        (nFormat != 33) &&   // UPX_F_DYLIB_i386
                        (nFormat != 34) &&   // UPX_F_MACH_AMD64
                        (nFormat != 35) &&   // UPX_F_DYLIB_AMD64
                        (nFormat != 37) &&   // UPX_F_MACH_ARM64EL
                        (nFormat != 38) &&   // UPX_F_MACH_PPC64LE
                        (nFormat != 41) &&   // UPX_F_DYLIB_PPC64LE
                        (nFormat != 131) &&  // UPX_F_MACH_PPC32
                        (nFormat != 134) &&  // UPX_F_MACH_FAT
                        (nFormat != 138) &&  // UPX_F_DYLIB_PPC32
                        (nFormat != 139) &&  // UPX_F_MACH_PPC64
                        (nFormat != 142))    // UPX_F_DYLIB_PPC64
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_ELF) {
                    if ((nFormat != 10) &&   // UPX_F_LINUX_i386
                        (nFormat != 12) &&   // UPX_F_LINUX_ELF_i386
                        (nFormat != 14) &&   // UPX_F_LINUX_SH_i386
                        (nFormat != 15) &&   // UPX_F_VMLINUZ_i386
                        (nFormat != 16) &&   // UPX_F_BVMLINUZ_i386
                        (nFormat != 19) &&   // UPX_F_VMLINUX_i386
                        (nFormat != 20) &&   // UPX_F_LINUX_ELFI_i386
                        (nFormat != 22) &&   // UPX_F_LINUX_ELF64_AMD
                        (nFormat != 23) &&   // UPX_F_LINUX_ELF32_ARMEL
                        (nFormat != 24) &&   // UPX_F_BSD_i386
                        (nFormat != 25) &&   // UPX_F_BSD_ELF_i386
                        (nFormat != 26) &&   // UPX_F_BSD_SH_i386
                        (nFormat != 27) &&   // UPX_F_VMLINUX_AMD64
                        (nFormat != 28) &&   // UPX_F_VMLINUX_ARMEL
                        (nFormat != 30) &&   // UPX_F_LINUX_ELF32_MIPSEL
                        (nFormat != 31) &&   // UPX_F_VMLINUZ_ARMEL
                        (nFormat != 39) &&   // UPX_F_LINUX_ELFPPC64LE
                        (nFormat != 40) &&   // UPX_F_VMLINUX_PPC64LE
                        (nFormat != 42) &&   // UPX_F_LINUX_ELF64_ARM
                        (nFormat != 132) &&  // UPX_F_LINUX_ELFPPC32
                        (nFormat != 133) &&  // UPX_F_LINUX_ELF32_ARMEB
                        (nFormat != 135) &&  // UPX_F_VMLINUX_ARMEB
                        (nFormat != 136) &&  // UPX_F_VMLINUX_PPC32
                        (nFormat != 137) &&  // UPX_F_LINUX_ELF32_MIPSEB
                        (nFormat != 140) &&  // UPX_F_LINUX_ELFPPC64
                        (nFormat != 141))    // UPX_F_VMLINUX_PPC64
                    {
                        result.bIsValid = false;
                    }
                }

                // Check Version
                if (nVersion > 14) {
                    result.bIsValid = false;
                }

                // Check Methods
                if ((nMethod < 2) || (nMethod > 15)) {
                    result.bIsValid = false;
                }

                // Check Level
                if (nLevel > 10) {
                    result.bIsValid = false;
                }

                // Check size
                if (nCLen > nULen) {
                    result.bIsValid = false;
                }
            }

            if (result.bIsValid) {
                switch (nMethod)  // From https://github.com/upx/upx/blob/master/src/conf.h
                {
                    case 2: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2B_LE32"); break;
                    case 3: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2B_8"); break;
                    case 4: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2B_LE16"); break;
                    case 5: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2D_LE32"); break;
                    case 6: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2D_8"); break;
                    case 7: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2D_LE16"); break;
                    case 8: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2E_LE32"); break;
                    case 9: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2E_8"); break;
                    case 10: result.sInfo = XBinary::appendComma(result.sInfo, "NRV2E_LE16"); break;
                    case 14: result.sInfo = XBinary::appendComma(result.sInfo, "LZMA"); break;
                    case 15: result.sInfo = XBinary::appendComma(result.sInfo, "zlib"); break;
                }

                if (result.sInfo != "") {
                    if (nLevel == 8) {
                        result.sInfo = XBinary::appendComma(result.sInfo, "best");
                    } else {
                        result.sInfo = XBinary::appendComma(result.sInfo, "brute");
                    }
                }

                result.vValue = binary.read_uint32(nOffset);

                if (result.vValue.toUInt() != 0x21585055)  // UPX!
                {
                    result.sInfo = XBinary::appendComma(result.sInfo, QString("Modified(%1)").arg(XBinary::valueToHex((quint32)result.vValue.toUInt())));
                }
            }
        }
    }

    return result;
}

// ---- VI helpers moved from SpecAbstract ----
NFD_Binary::VI_STRUCT NFD_Binary::get_Enigma_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_array(nOffset, nSize, "\x00\x00\x00\x45\x4e\x49\x47\x4d\x41", 9, pPdStruct);  // \x00\x00\x00ENIGMA

        if (_nOffset != -1) {
            quint8 nMajor = binary.read_uint8(_nOffset + 9);
            quint8 nMinor = binary.read_uint8(_nOffset + 10);
            quint16 nYear = binary.read_uint16(_nOffset + 11);
            quint16 nMonth = binary.read_uint16(_nOffset + 13);
            quint16 nDay = binary.read_uint16(_nOffset + 15);
            quint16 nHour = binary.read_uint16(_nOffset + 17);
            quint16 nMin = binary.read_uint16(_nOffset + 19);
            quint16 nSec = binary.read_uint16(_nOffset + 21);

            result.sVersion = QString("%1.%2 build %3.%4.%5 %6:%7:%8")
                                  .arg(nMajor)
                                  .arg(nMinor, 2, 10, QChar('0'))
                                  .arg(nYear, 4, 10, QChar('0'))
                                  .arg(nMonth, 2, 10, QChar('0'))
                                  .arg(nDay, 2, 10, QChar('0'))
                                  .arg(nHour, 2, 10, QChar('0'))
                                  .arg(nMin, 2, 10, QChar('0'))
                                  .arg(nSec, 2, 10, QChar('0'));

            result.bIsValid = true;
        }
    }

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, " *** Enigma protector v", pPdStruct);

        if (_nOffset != -1) {
            result.sVersion = binary.read_ansiString(_nOffset + 23).section(" ", 0, 0);
            result.bIsValid = true;
        }
    }

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "The Enigma Protector version", pPdStruct);

        if (_nOffset != -1) {
            result.sVersion = binary.read_ansiString(_nOffset + 23).section(" ", 0, 0);
            result.bIsValid = true;
        }
    }

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "Enigma Protector", pPdStruct);

        if (_nOffset != -1) {
            result.sVersion = "5.XX";  // TODO version
            result.bIsValid = true;
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_DeepSea_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "DeepSeaObfuscator", pPdStruct);

    if (_nOffset != -1) {
        result.bIsValid = true;  // TODO Check
        result.sVersion = "4.X";

        QString sFullString = binary.read_ansiString(_nOffset + 18);

        if (sFullString.contains("Evaluation")) {
            result.sInfo = "Evaluation";
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_SmartAssembly_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                       XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "Powered by SmartAssembly ", pPdStruct);

    if (_nOffset != -1) {
        result.bIsValid = true;
        result.sVersion = binary.read_ansiString(_nOffset + 25);
        // TODO more checks!
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_R8_marker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java
    // X~~D8{"compilation-mode":"release","has-checksums":false,"min-api":14,"version":"2.0.88"}
    // h~~D8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":28,"version":"8.6.17"}
    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "\"compilation-mode\":\"", pPdStruct);

    if (_nOffset > 20)  // TODO rewrite
    {
        _nOffset = binary.find_ansiString(_nOffset - 21, 20, "~~", pPdStruct);

        if (_nOffset != -1) {
            result.bIsValid = true;
            QString sString = binary.read_ansiString(_nOffset);

            result.sVersion = XBinary::regExp("\"version\":\"(.*?)\"", sString, 1);

            if (sString.contains("~~D8") || sString.contains("~~R8")) {
                result.sInfo = XBinary::regExp("\"compilation-mode\":\"(.*?)\"", sString, 1);
            } else {
                result.sInfo = "CHECK D8: " + sString;
            }
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_Go_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = nOffset;
    qint64 _nSize = nSize;

    QString sVersion;

    qint64 nMaxVersion = 0;

    while ((_nSize > 0) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _nOffset = binary.find_ansiString(_nOffset, _nSize, "go1.", pPdStruct);

        if (_nOffset == -1) {
            break;
        }

        QString _sVersion = XBinary::getVersionString(binary.read_ansiString(_nOffset + 2, 10));

        qint64 nVersionValue = XBinary::getVersionIntValue(_sVersion);

        if (nVersionValue > nMaxVersion) {
            nMaxVersion = nVersionValue;
            sVersion = _sVersion;
        }

        _nOffset++;
        _nSize = nSize - (_nOffset - nOffset) - 1;
    }

    if (sVersion != "") {
        result.bIsValid = true;
        result.sVersion = sVersion;
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_Rust_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO version
    qint64 nOffset_Version = -1;

    if (nOffset_Version == -1) {
        // TODO false positives in die.exe
        nOffset_Version = binary.find_ansiString(nOffset, nSize, "Local\\RustBacktraceMutex", pPdStruct);

        if (nOffset_Version != -1) {
            result.bIsValid = true;
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_ObfuscatorLLVM_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                        XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nOffset_Version = -1;  // TODO get max version

    if (nOffset_Version == -1) {
        nOffset_Version = binary.find_ansiString(nOffset, nSize, "Obfuscator-", pPdStruct);  // 3.4 - 6.0.0

        if (nOffset_Version != -1) {
            QString sVersionString = binary.read_ansiString(nOffset_Version);

            result = _get_ObfuscatorLLVM_string(sVersionString);
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ObfuscatorLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Obfuscator-clang version") ||     // 3.4
        sString.contains("Obfuscator- clang version") ||    // 3.51
        sString.contains("Obfuscator-LLVM clang version"))  // 3.6.1 - 6.0.0
    {
        result.bIsValid = true;

        result.sVersion = sString.section("version ", 1, 1).section("(", 0, 0).section(" ", 0, 0);
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_AndroidClang_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "Android clang", pPdStruct);

    if (nOffset_Version != -1) {
        QString sVersionString = binary.read_ansiString(nOffset_Version);

        result = _get_AndroidClang_string(sVersionString);
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AndroidClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Android clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    } else if (sString.contains("Android (") && sString.contains(" clang version ")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" clang version ", 1, 1).section(" ", 0, 0);
    }

    return result;
}

// ---- Additional VI helpers moved from SpecAbstract ----
NFD_Binary::VI_STRUCT NFD_Binary::get_GCC_vi1(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "GCC:", pPdStruct);

    if (nOffset_Version != -1) {
        QString sVersionString = binary.read_ansiString(nOffset_Version);

        // Inline parse copied from SpecAbstract::_get_GCC_string to avoid back dependency
        if (sVersionString.contains("GCC:")) {
            result.bIsValid = true;

            if (sVersionString.contains("MinGW")) {
                result.sInfo = "MinGW";
            } else if (sVersionString.contains("MSYS2")) {
                result.sInfo = "MSYS2";
            } else if (sVersionString.contains("Cygwin")) {
                result.sInfo = "Cygwin";
            }

            if ((sVersionString.contains("(experimental)")) || (sVersionString.contains("(prerelease)"))) {
                result.sVersion = sVersionString.section(" ", -3, -1);
            } else if (sVersionString.contains("(GNU) c ")) {
                result.sVersion = sVersionString.section("(GNU) c ", 1, -1);
            } else if (sVersionString.contains("GNU")) {
                result.sVersion = sVersionString.section(" ", 2, -1);
            } else if (sVersionString.contains("Rev1, Built by MSYS2 project")) {
                result.sVersion = sVersionString.section(" ", -2, -1);
            } else if (sVersionString.contains("(Ubuntu ")) {
                result.sVersion = sVersionString.section(") ", 1, 1).section(" ", 0, 0);
            } else if (sVersionString.contains("StartOS)")) {
                result.sVersion = sVersionString.section(")", 1, 1).section(" ", 0, 0);
            } else if (sVersionString.contains("GCC: (c) ")) {
                result.sVersion = sVersionString.section("GCC: (c) ", 1, 1);
            } else {
                result.sVersion = sVersionString.section(" ", -1, -1);
            }
        }
    }

    return result;
}

// String-only parsers moved from SpecAbstract
NFD_Binary::VI_STRUCT NFD_Binary::_get_GCC_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("GCC:")) {
        result.bIsValid = true;

        if (sString.contains("MinGW")) {
            result.sInfo = "MinGW";
        } else if (sString.contains("MSYS2")) {
            result.sInfo = "MSYS2";
        } else if (sString.contains("Cygwin")) {
            result.sInfo = "Cygwin";
        }

        if ((sString.contains("(experimental)")) || (sString.contains("(prerelease)"))) {
            result.sVersion = sString.section(" ", -3, -1);  // TODO Check
        } else if (sString.contains("(GNU) c ")) {
            result.sVersion = sString.section("(GNU) c ", 1, -1);
        } else if (sString.contains("GNU")) {
            result.sVersion = sString.section(" ", 2, -1);
        } else if (sString.contains("Rev1, Built by MSYS2 project")) {
            result.sVersion = sString.section(" ", -2, -1);
        } else if (sString.contains("(Ubuntu ")) {
            result.sVersion = sString.section(") ", 1, 1).section(" ", 0, 0);
        } else if (sString.contains("StartOS)")) {
            result.sVersion = sString.section(")", 1, 1).section(" ", 0, 0);
        } else if (sString.contains("GCC: (c) ")) {
            result.sVersion = sString.section("GCC: (c) ", 1, 1);
        } else {
            result.sVersion = sString.section(" ", -1, -1);
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AlipayClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Alipay clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AlpineClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Alpine clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AlibabaClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Alibaba clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_PlexClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Plex clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_UbuntuClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Ubuntu clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_DebianClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Debian clang")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AlipayObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Alipay")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
        if (sString.contains("Trial")) result.sInfo = "Trial";
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_wangzehuaLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("wangzehua  clang version")) {
        result.bIsValid = true;
        result.sVersion = sString.section("wangzehua  clang version", 1, 1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ByteGuard_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ByteGuard")) {
        result.bIsValid = true;
        result.sVersion = sString.section("ByteGuard ", 1, 1).section("-", 0, 0).section(")", 0, 0);
    } else if (sString.contains("Byteguard")) {
        result.bIsValid = true;
        result.sVersion = sString.section("Byteguard ", 1, 1).section("-", 0, 0).section(")", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_TencentObfuscation_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Tencent-Obfuscation Compiler")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AppImage_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("AppImage by Simon Peter, http://appimage.org/")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_HikariObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("HikariObfuscator") || sString.contains("_Hikari") || sString.contains("Hikari.git")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SnapProtect_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("snap.protect version ")) {
        result.sVersion = sString.section("snap.protect version ", 1, 1).section(" ", 0, 0);
        result.bIsValid = true;
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ByteDanceSecCompiler_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ByteDance-SecCompiler")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_DingbaozengNativeObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("dingbaozeng/native_obfuscator.git")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SafeengineLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Safengine clang version")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_NagainLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Nagain-LLVM clang version")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_iJiami_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ijiami LLVM Compiler- clang version")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 5, 5);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_AppleLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Apple LLVM version")) {
        result.bIsValid = true;
        result.sVersion = sString.section("Apple LLVM version ", 1, 1).section(" ", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ApportableClang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Apportable clang version")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 3, 3);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMAssembler_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM Assembler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMLinker_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM Linker,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1).section("]", 0, 0) + "]";
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMC_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM C Compiler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM C/C++ Compiler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMNEONCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM NEON C/C++ Compiler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMThumbCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM/Thumb C/C++ Compiler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ARMThumbMacroAssembler_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ARM/Thumb Macro Assembler")) {
        result.bIsValid = true;
        if (sString.contains("vsn ")) {
            result.sVersion = sString.section("vsn ", 1, -1);
        } else {
            result.sVersion = sString.section(", ", 1, -1);
        }
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_ThumbC_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("Thumb C Compiler,")) {
        result.bIsValid = true;
        result.sVersion = sString.section(", ", 1, -1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_clang_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^clang version", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 2, 2);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_DynASM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("DynASM")) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 1, 1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_Delphi_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^Embarcadero Delphi for", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("version ", 1, 1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_LLD_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^Linker: LLD", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("Linker: LLD ", 1, 1).section("(", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_mold_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^mold ", sString)) {
        result.bIsValid = true;  // TODO version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_OracleSolarisLinkEditors_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^ld: Software Generation Utilities - Solaris Link Editors:", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("Solaris Link Editors: ", 1, 1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SunWorkShop_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("Sun WorkShop", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("Sun WorkShop ", 1, 1).section(" ", 0, 1).section("\r", 0, 0).section("\n", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SunWorkShopCompilers_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("WorkShop Compilers", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("WorkShop Compilers ", 1, 1).section("\r", 0, 0).section("\n", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SnapdragonLLVMARM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^Snapdragon LLVM ARM Compiler", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section(" ", 4, 4);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_NASM_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^The Netwide Assembler", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("The Netwide Assembler ", 1, 1);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_TencentLegu_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^legu", sString)) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_OllvmTll_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (sString.contains("ollvm-tll.git")) {
        result.bIsValid = true;  // TODO Version
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_DelphiVersionFromCompiler(const QString &sString)
{
    VI_STRUCT result = {};
    QString _sString = sString.section(" ", 0, 0);
    if (_sString != "") {
        result.bIsValid = true;
        result.sVersion = "12.x Athens++";
        if (_sString == "28.0") {
            result.sVersion = "XE7";
        } else if (_sString == "29.0") {
            result.sVersion = "XE8";
        } else if (_sString == "30.0") {
            result.sVersion = "10 Seattle";
        } else if (_sString == "31.0") {
            result.sVersion = "10.1 Berlin";
        } else if (_sString == "32.0") {
            result.sVersion = "10.2 Tokyo";
        } else if (_sString == "33.0") {
            result.sVersion = "10.3 Rio";
        } else if (_sString == "34.0") {
            result.sVersion = "10.4 Sydney";
        } else if (_sString == "35.0") {
            result.sVersion = "11.0 Alexandria";
        } else if (_sString == "36.0") {
            result.sVersion = "12.0 Athens";
        }
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_SourceryCodeBench_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("Sourcery CodeBench Lite ", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("Sourcery CodeBench Lite ", 1, 1).section(")", 0, 0);
        result.sInfo = "lite";
    } else if (XBinary::isRegExpPresent("Sourcery CodeBench ", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("Sourcery CodeBench ", 1, 1).section(")", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::_get_Rust_string(const QString &sString)
{
    VI_STRUCT result = {};
    if (XBinary::isRegExpPresent("^rustc ", sString)) {
        result.bIsValid = true;
        result.sVersion = sString.section("rustc version ", 1, 1).section(" ", 0, 0);
    }
    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_GCC_vi2(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "gcc-", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        QString sVersionString = binary.read_ansiString(nOffset_Version);
        result.sVersion = sVersionString.section("-", 1, 1).section("/", 0, 0);
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_Nim_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO false positives in die.exe
    if ((binary.find_ansiString(nOffset, nSize, "io.nim", pPdStruct) != -1) || (binary.find_ansiString(nOffset, nSize, "fatal.nim", pPdStruct) != -1)) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_Zig_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((binary.find_unicodeString(nOffset, nSize, "ZIG_DEBUG_COLOR", false, pPdStruct) != -1) ||
        (binary.find_ansiString(nOffset, nSize, "ZIG_DEBUG_COLOR", pPdStruct) != -1)) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

// ---- VI helpers newly centralized from SpecAbstract ----
NFD_Binary::VI_STRUCT NFD_Binary::get_Watcom_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.find_ansiString(nOffset, nSize, "Open Watcom", pPdStruct) != -1) {
        result.bIsValid = true;
        result.vValue = XScanEngine::RECORD_NAME_OPENWATCOMCCPP;

        qint64 nVersionOffset = binary.find_ansiString(nOffset, nSize, " 2002-", pPdStruct);

        if (nVersionOffset != -1) {
            result.sVersion = binary.read_ansiString(nVersionOffset + 6, 4);
        } else {
            result.sVersion = "2002";
        }
    } else if (binary.find_ansiString(nOffset, nSize, "WATCOM", pPdStruct) != -1) {
        result.bIsValid = true;
        result.vValue = XScanEngine::RECORD_NAME_WATCOMCCPP;

        qint64 nVersionOffset = binary.find_ansiString(nOffset, nSize, ". 1988-", pPdStruct);

        if (nVersionOffset != -1) {
            result.sVersion = binary.read_ansiString(nVersionOffset + 7, 4);
        } else {
            result.sVersion = "1988";
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_PyInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "PyInstaller: FormatMessageW failed.", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_DWRAF_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (nSize > 8) {
        qint16 nVersion = binary.read_int16(nOffset + 4);

        if ((nVersion >= 0) && (nVersion <= 7)) {
            result.sVersion = QString::number(nVersion) + ".0";
            result.bIsValid = true;
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_WindowsInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                          XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nStringOffset = binary.find_ansiString(nOffset, nSize, "Windows Installer", pPdStruct);

    if (nStringOffset != -1) {
        result.bIsValid = true;

        QString _sString = binary.read_ansiString(nStringOffset);

        if (_sString.contains("xml", Qt::CaseInsensitive)) {
            result.sInfo = "XML";
        }

        QString sVersion = XBinary::regExp("\\((.*?)\\)", _sString, 1);

        if (sVersion != "") {
            result.sVersion = sVersion;
        }
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_gold_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "gold ", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        QString sVersionString = binary.read_ansiString(nOffset_Version, nSize - (nOffset_Version - nOffset));
        result.sVersion = sVersionString.section(" ", 1, 1);
    }

    return result;
}

NFD_Binary::VI_STRUCT NFD_Binary::get_TurboLinker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.read_uint8(0x1E) == 0xFB) {
        result.bIsValid = true;

        result.sVersion = QString::number((double)binary.read_uint8(0x1F) / 16, 'f', 1);
    }

    return result;
}

// TODO separate
NFD_Binary::SIGNATURE_RECORD g_binary_records[] = {
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_CERTIFICATE, XScanEngine::RECORD_NAME_WINAUTH, "2.0", "PKCS #7"}, "........00020200"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DATABASE, XScanEngine::RECORD_NAME_MICROSOFTACCESS, "", ""}, "00010000'Standard Jet DB'00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DATABASE, XScanEngine::RECORD_NAME_MICROSOFTACCESS, "2010", ""}, "00010000'Standard ACE DB'00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DATABASE, XScanEngine::RECORD_NAME_MICROSOFTLINKERDATABASE, "", ""}, "'Microsoft Linker Database\n\n'071A"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DATABASE, XScanEngine::RECORD_NAME_PDB, "2.00", ""}, "'Microsoft C/C++ program database 2.00\r\n'1A'JG'0000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DATABASE, XScanEngine::RECORD_NAME_PDB, "7.00", ""}, "'Microsoft C/C++ MSF 7.00\r\n'1A'DS'000000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_AUTOIT, "2.XX-3.XX", "Compiled script"}, "A3484BBE986C4AA9"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_AR, "", ""}, "'!<arch>'0A"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_COFF, "", ""}, "'!<arch>'0A2F"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_DEX, "", ""}, "'dex\n'......00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_JAVACOMPILEDCLASS, "", ""}, "CAFEBABE"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_LUACOMPILED, "", ""}, "1B'Lua'..000104040408"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP, "", ""}, "'ITSF'03000000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND, "", "MSO 97-2003 or MSI"}, "D0CF11E0A1B11AE1"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MICROSOFTWINHELP, "", ""}, "3f5f0300"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MP3, "", ""}, "'ID3'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MP4, "", ""}, "000000..'ftyp'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_PDF, "", ""}, "'%PDF'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_RTF, "", ""}, "'{'5C'rtf'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_SWF, "", "LZMA"}, "'ZWS'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_SWF, "", "Uncompressed"}, "'FWS'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_SWF, "", "zlib"}, "'CWS'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WAV, "", ""}, "................'WAVEfmt'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_DJVU, "", ""}, "'AT&T'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_JPEG, "", ""}, "FFD8FFE0....'JFIF'00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_JPEG, "", "EXIF"}, "FFD8FFE1....'Exif'00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TIFF, "", "BE"}, "'MM'002A"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TIFF, "", "LE"}, "'II'2A00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_GIF, "", ""}, "'GIF8'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_PNG, "", ""}, "89'PNG\r\n'1A0A........'IHDR'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WINDOWSBITMAP, "", ""}, "'BM'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WINDOWSICON, "", ""}, "00000100"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WINDOWSCURSOR, "", ""}, "00000200"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_AU, "", ""}, "'.snd'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_DEB, "", ""}, "'!<arch>'0a'debian-binary'"},  // TODO Check
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_AVI, "", ""}, "'RIFF'........'AVI '"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WEBP, "", ""}, "'RIFF'........'WEBPVP8'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'OS/2'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'BASE'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'cmap'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'DSIG'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'EBDT'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'Feat'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'FFTM'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'GPOS'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'GSUB'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TTF, "", ""}, "........................................................'LTSH'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ANDROIDXML, "", ""}, "03000800"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ANDROIDARSC, "", ""}, "02000C00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_WINDOWSMEDIA, "", ""}, "3026B2758E66CF11A6D900AA0062CE6C"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_FLASHVIDEO, "", ""}, "'FLV'01"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_SHELL, "", ""}, "'#!'"},  // "'#!c:\python\python.exe'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_BORLANDDEBUGINFO, "", "TDS"}, "FB52"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_BORLANDDEBUGINFO, "", "Delphi TDS"}, "'FB09'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_BORLANDDEBUGINFO, "", "C++ TDS"}, "'FB0A'"}};

static NFD_Binary::SIGNATURE_RECORD g_debugdata_records[] = {
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_PDBFILELINK, "7.0", ""}, "'RSDS'"},
};

static NFD_Binary::SIGNATURE_RECORD g_archive_records[] = {
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_7Z, "", ""}, "'7z'BCAF271C"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ARJ, "", ""}, "60EA"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_BZIP2, "", ""}, "'BZh'"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_CAB, "", ""}, "'MSCF'00000000"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_GZIP, "", ""}, "1F8B08"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_LHA, "", ""}, "....'-lh'..2D"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_LHA, "", ""}, "....'-lz'..2D"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_LZFSE, "", ""}, "'bvxn'"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_RAR, "1.4", ""}, "'RE~^'"},
    {{1, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_RAR, "4.X", ""}, "'Rar!'1A0700"},
    {{1, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_RAR, "5.X", ""}, "'Rar!'1A070100"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_XAR, "", ""}, "'xar!'001C00010000"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZLIB, "", "level 1(no/low)"}, "7801"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZLIB, "", "level 2-5"}, "785E"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZLIB, "", "level 6(default)"}, "789C"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZLIB, "", "level 7-9(best)"}, "78DA"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_XZ, "", ""}, "FD'7zXZ'00"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MACHOFAT, "", ""}, "CAFEBABE"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_MACHOFAT, "", ""}, "BEBAFECA"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZIP, "", ""}, "'PK'0304"},
    {{0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ZIP, "", "Empty"}, "'PK'0506"},
};

static NFD_Binary::SIGNATURE_RECORD g_PE_overlay_records[] = {
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_ACTUALINSTALLER, "", ""}, "....................'MSCF'00"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_AVASTANTIVIRUS, "", ""}, "'ASWsetupFPkgFil3'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_CLICKTEAM, "", ""}, "'wwgT)'"},
    {{1, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_CLICKTEAM, "", ""}, "..120100....0000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_GHOSTINSTALLER, "1.0", "Xored MSCF, mask: 8D"}, "C0DECECB8D8D8D8D"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_GPINSTALL, "", ""}, "........'SPIS'1a'LH5'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INNOSETUP, "", ""}, "'Inno Setup Setup Data'"},  // TODO Check version
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INNOSETUP, "", "Install"}, "'idska32'1A"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INNOSETUP, "", "Install"}, "'zlb'1A"},                  // TODO none
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INNOSETUP, "", "Uninstall"}, "'Inno Setup Messages'"},  // TODO check
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INSTALL4J, "", ""}, "D513E4E801000000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INSTALLANYWHERE, "", ""}, "5B3E"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", ""}, "'ISSetupStream'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", "PackageForTheWeb"}, "....0000dcedbd"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_NSIS, "", ""}, "EFBEADDE'Null'..'oftInst'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_NSIS, "", ""}, "..000000EFBEADDE'NullsoftInst'"},
    {{1, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_NSIS, "", ""}, "EFBEADDE'nsisinstall'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_OPERA, "", ""}, "'OPR7z'BCAF271C"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_QTINSTALLER, "", ""}, "'qres'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_SETUPFACTORY, "4.X-7.X", ""}, "E0E1E2E3E4E5E6"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_SETUPFACTORY, "8.X-9.X", ""}, "E0E0E1E1E2E2E3E3E4E4E5E5E6E6E7E7"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_SMARTINSTALLMAKER, "", ""}, "'Smart Install Maker v'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_TARMAINSTALLER, "", "zlib"}, "'tiz1'........78DA'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_VMWARE, "", ""}, "'RWMV'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_1337EXECRYPTER, "1", ""}, "60'*[S-P-L-I-T]*'60"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_1337EXECRYPTER, "2", ""}, "'~SPLIT~'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_ACTIVEMARK, "", ""}, "00'TMSAMVOH"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_AGAINNATIVITYCRYPTER, "", ""}, "'<%*#%>'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_ARCRYPT, "", ""}, "'@@##@@'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_FASTFILECRYPT, "", ""}, "'(==#==)'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_FISHNET, "1.X", ""}, "0800'FISH_NET'0100"},
    {{1, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_FISHNET, "1.X", ""}, "000800'FISH_NET'0100"},
    {{2, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_FISHNET, "1.X", ""}, "00000800'FISH_NET'0100"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME, "", ""}, "'F3B14NVA'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_MOLEBOXULTRA, "", ""}, "'XOJUMANJ'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_NOXCRYPT, "", ""}, "'|||'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_WLCRYPT, "", ""}, "'[Crypted Key]'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_WOUTHRSEXECRYPTER, "", ""}, "'<%>'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_XENOCODE, "", ""},
     "'xvm'0001"},  // Check Turbo https://en.wikipedia.org/wiki/Turbo_(software)
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_SPOONSTUDIO, "", ""}, "'xvm'0003"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_ZELDACRYPT, "", ""}, "2F232F2B5C235C"},  // '/#/+\#\'
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_SFXDATA, XScanEngine::RECORD_NAME_7Z, "", ""}, "';!@Install@!UTF-8!'"},
    {{1, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_SFXDATA, XScanEngine::RECORD_NAME_7Z, "", ""}, "EFBBBF';!@Install@!UTF-8!'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_SFXDATA, XScanEngine::RECORD_NAME_SQUEEZSFX, "", ""}, "'SQ5SFX'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_SFXDATA, XScanEngine::RECORD_NAME_WINRAR, "", ""}, "'***messages***'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_ADVANCEDINSTALLER, "", ""}, "2F30EE1F5E4EE51E"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_MINGW, "", ""}, "'.file'000000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_PDBFILELINK, "2.0", ""}, "'NB10'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_PDBFILELINK, "7.0", ""}, "'RSDS'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_DOTNETSHRINK, "2.01", ""}, "5D00000002"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_SIXXPACK, "", ""}, "5D0000800000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_THINSTALL, "", ""}, "09050000"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_INSTALLERDATA, XScanEngine::RECORD_NAME_NOSINSTALLER, "", ""}, "'NOS_PO'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_SECUROM, "", ""}, "'AddD'03"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_SERGREENAPPACKER, "", ""}, "'<SerGreen>'"},
    {{0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_PROTECTORDATA, XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, "", ""}, "'7stgc_hdr'00"},
};

// Accessors for centralized signature arrays
NFD_Binary::SIGNATURE_RECORD *NFD_Binary::getBinaryRecords()
{
    return g_binary_records;
}

qint32 NFD_Binary::getBinaryRecordsSize()
{
    return sizeof(g_binary_records);
}

NFD_Binary::SIGNATURE_RECORD *NFD_Binary::getDebugdataRecords()
{
    return g_debugdata_records;
}

qint32 NFD_Binary::getDebugdataRecordsSize()
{
    return sizeof(g_debugdata_records);
}

NFD_Binary::SIGNATURE_RECORD *NFD_Binary::getArchiveRecords()
{
    return g_archive_records;
}

qint32 NFD_Binary::getArchiveRecordsSize()
{
    return sizeof(g_archive_records);
}

NFD_Binary::SIGNATURE_RECORD *NFD_Binary::getPEOverlayRecords()
{
    return g_PE_overlay_records;
}

qint32 NFD_Binary::getPEOverlayRecordsSize()
{
    return sizeof(g_PE_overlay_records);
}

// Check if any protection-related detections are present (moved from SpecAbstract)
bool NFD_Binary::isProtectionPresent(BASIC_INFO *pBasicInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    return (pBasicInfo->mapResultPackers.count() || pBasicInfo->mapResultProtectors.count() || pBasicInfo->mapResultSFX.count() ||
            pBasicInfo->mapResultInstallers.count() || pBasicInfo->mapResultNETObfuscators.count() ||
            pBasicInfo->mapResultDongleProtection.count());
}

void NFD_Binary::handle_Texts(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo,
                                     XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->bIsPlainText) || (pBinaryInfo->unicodeType != XBinary::UNICODE_TYPE_NONE) || (pBinaryInfo->bIsUTF8)) {
        qint32 nSignaturesCount = NFD_TEXT::getTextExpRecordsSize() / sizeof(NFD_Binary::STRING_RECORD);

        for (qint32 i = 0; (i < nSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++)  // TODO move to an own function !!!
        {
            if (XBinary::isRegExpPresent(NFD_TEXT::getTextExpRecords()[i].pszString, pBinaryInfo->sHeaderText)) {
                SCANS_STRUCT record = {};
                record.nVariant = NFD_TEXT::getTextExpRecords()[i].basicInfo.nVariant;
                record.fileType = NFD_TEXT::getTextExpRecords()[i].basicInfo.fileType;
                record.type = NFD_TEXT::getTextExpRecords()[i].basicInfo.type;
                record.name = NFD_TEXT::getTextExpRecords()[i].basicInfo.name;
                record.sVersion = NFD_TEXT::getTextExpRecords()[i].basicInfo.pszVersion;
                record.sInfo = NFD_TEXT::getTextExpRecords()[i].basicInfo.pszInfo;
                record.nOffset = 0;

                pBinaryInfo->basic_info.mapTextHeaderDetects.insert(record.name, record);
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_CCPP)) {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(XScanEngine::RECORD_NAME_CCPP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_PYTHON)) {
            if ((pBinaryInfo->sHeaderText.contains("class")) && (pBinaryInfo->sHeaderText.contains("self"))) {
                SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(XScanEngine::RECORD_NAME_PYTHON);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_HTML)) {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(XScanEngine::RECORD_NAME_HTML);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_XML)) {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(XScanEngine::RECORD_NAME_XML);
            ss.sVersion = XBinary::regExp("version=['\"](.*?)['\"]", pBinaryInfo->sHeaderText, 1);

            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_PHP)) {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(XScanEngine::RECORD_NAME_PHP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        //        if(pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PERL))
        //        {
        //            SCANS_STRUCT ss=pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PERL);
        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(XScanEngine::RECORD_NAME_SHELL)) {
            QString sInterpreter;

            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/local\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);  // #!/usr/local/bin/ruby
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/env (\\w+)", pBinaryInfo->sHeaderText, 1);      // #!/usr/bin/env perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);          // #!/usr/bin/perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);                // #!/bin/sh
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!(\\w+)", pBinaryInfo->sHeaderText, 1);                         // #!perl

            if (sInterpreter == "perl") {
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_PERL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "sh") {
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_SHELL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "ruby") {
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_RUBY, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "python") {
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_PYTHON, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else {
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_SHELL, sInterpreter, "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        //        if(pBinaryInfo->basic_info.mapResultTexts.count()==0)
        //        {
        //            SCANS_STRUCT ss=NFD_Binary::getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_FORMAT,RECORD_NAME_PLAIN,"","",0);

        //            if(pBinaryInfo->unicodeType!=XBinary::UNICODE_TYPE_NONE)
        //            {
        //                ss.name=RECORD_NAME_UNICODE;

        //                if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_BE)
        //                {
        //                    ss.sVersion="Big Endian";
        //                }
        //                else if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_LE)
        //                {
        //                    ss.sVersion="Little Endian";
        //                }
        //            }
        //            else if(pBinaryInfo->bIsUTF8)
        //            {
        //                ss.name=XScanEngine::RECORD_NAME_UTF8;
        //            }
        //            else if(pBinaryInfo->bIsPlainText)
        //            {
        //                ss.name=XScanEngine::RECORD_NAME_PLAIN;
        //            }

        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }
    }
}

void NFD_Binary::handle_Archives(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo,
                                        XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // 7-Zip
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        //        // TODO more options
        //        SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        //        if(ss.type==RECORD_TYPE_ARCHIVE)
        //        {
        //            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
        //            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        XSevenZip xsevenzip(pDevice);

        if (xsevenzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_7Z);

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
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ZIP)) && (pBinaryInfo->basic_info.id.nSize >= 64))  // TODO min size
    {
        XZip xzip(pDevice);

        if (xzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ZIP);

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
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_GZIP)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_GZIP);

        // TODO options
        // TODO type gzip
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // xar
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_XAR)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_XAR);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LZFSE
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_LZFSE)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_LZFSE);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // CAB
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_CAB)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XCab xcab(pDevice);

        if (xcab.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_CAB);

            ss.sVersion = xcab.getVersion();
            ss.sInfo = QString("%1 records").arg(xcab.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // MAch-O FAT
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MACHOFAT)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XMACHOFat xmachofat(pDevice);

        if (xmachofat.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MACHOFAT);

            ss.sVersion = xmachofat.getVersion();
            ss.sInfo = QString("%1 records").arg(xmachofat.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // RAR
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RAR)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        XRar xrar(pDevice);

        if (xrar.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RAR);

            ss.sVersion = xrar.getVersion();
            ss.sInfo = QString("%1 records").arg(xrar.getNumberOfRecords(pPdStruct));
            // TODO options

            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // zlib
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ZLIB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // XZ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_XZ)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_XZ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // ARJ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ARJ)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ARJ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LHA
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_LHA)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_LHA);

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
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_BZIP2)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_BZIP2);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // TAR
    else if ((pBinaryInfo->basic_info.id.nSize >= 500) && (binary.getSignature(0x100, 6) == "007573746172"))  // "00'ustar'"
    {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

        SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_TAR, "", "", 0);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void NFD_Binary::handle_Certificates(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Windows Authenticode Portable Executable Signature Format
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINAUTH)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        quint32 nLength = XBinary::hexToUint32(pBinaryInfo->basic_info.sHeaderSignature.mid(0, 8));

        if (nLength >= pBinaryInfo->basic_info.id.nSize) {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINAUTH);
            pBinaryInfo->basic_info.mapResultCertificates.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void NFD_Binary::handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MINGW)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MinGW debug data
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MINGW);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_PDBFILELINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PDB File Link
        // TODO more infos
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_PDBFILELINK);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_BORLANDDEBUGINFO)) && (pBinaryInfo->basic_info.id.nSize >= 16)) {
        quint16 nSignature = binary.read_uint16(0);

        if (nSignature == 0x52FB) {
            SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_BORLANDDEBUGINFO, "", "", 0);

            quint8 nMajor = binary.read_uint8(3);
            quint8 nMinor = binary.read_uint8(2);
            quint16 nNumberOfSymbols = binary.read_uint16(0xE);
            double dVersion = nMajor + (double)nMinor / 100.0;

            ss.type = XScanEngine::RECORD_TYPE_DEBUGDATA;
            ss.name = XScanEngine::RECORD_NAME_BORLANDDEBUGINFO;
            ss.sVersion = QString::number(dVersion, 'f', 2);
            ss.sInfo = "TDS";

            if (nNumberOfSymbols) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));
            }

            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        } else {
            SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_BORLANDDEBUGINFO);
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
                SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_WATCOMDEBUGINFO, "", "", 0);
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
                    SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_CODEVIEWDEBUGINFO, "", "", 0);
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
                        SCANS_STRUCT ssDebugInfo = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
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

void NFD_Binary::handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if (pBinaryInfo->basic_info.id.nSize == 0) {
        SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_EMPTYFILE, "", "", 0);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_PDF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TODO move to own type
        // PDF
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_PDF);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5 * 2, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compound
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND);

        quint16 nSub1 = binary.read_uint16(0x200);
        quint16 nSub2 = binary.read_uint16(0x1000);

        // TODO More
        if ((nSub1 == 0) && (nSub2 == 0xFFFD)) {
            ss.type = XScanEngine::RECORD_TYPE_INSTALLER;  // TODO mapResultInstallers
            ss.name = XScanEngine::RECORD_NAME_MICROSOFTINSTALLER;
            ss.sVersion = "";
            ss.sInfo = "";
        } else if (nSub1 == 0xA5EC) {
            ss.type = XScanEngine::RECORD_TYPE_FORMAT;
            ss.name = XScanEngine::RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.sVersion = "97-2003";
            ss.sInfo = "";
        }

        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compiled HTML Help
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AUTOIT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AutoIt Compiled Script
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AUTOIT);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // RTF
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RTF);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_LUACOMPILED)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Lua
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_LUACOMPILED);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_JAVACOMPILEDCLASS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // java
        quint16 nMinor = binary.read_uint16(4, true);
        quint16 nMajor = binary.read_uint16(6, true);

        if (nMajor) {
            QString sVersion = XJavaClass::_getJDKVersion(nMajor, nMinor);

            if (sVersion != "") {
                SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_JAVACOMPILEDCLASS);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_COFF)) && (pBinaryInfo->basic_info.id.nSize >= 76)) {
        // COFF
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_COFF);

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
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_DEX)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // dex
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_DEX);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(8, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SWF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // SWF
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SWF);
        ss.sVersion = QString("%1").arg(binary.read_uint8(3));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTWINHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft WinHelp
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MICROSOFTWINHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MP3)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP3
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MP3);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MP4)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP4
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MP4);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINDOWSMEDIA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Windows Media
        // TODO WMV/WMA
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINDOWSMEDIA);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_FLASHVIDEO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Flash Video
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_FLASHVIDEO);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WAV)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // VAW
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WAV);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AU
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AU);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_DEB)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DEB
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_DEB);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AVI)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AVI);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WEBP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WEBP);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_TTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TTF
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_TTF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ANDROIDARSC)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ANDROIDARSC);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ANDROIDXML)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ANDROIDXML);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AR)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AR
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AR);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if (pBinaryInfo->basic_info.id.nSize >= 0x8010) {
        if (binary.compareSignature("01'CD001'01", 0x8000)) {
            SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::RECORD_NAME_ISO9660, "", "", 0);
            // TODO Version
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void NFD_Binary::handle_Databases(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_PDB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // PDB
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_PDB);
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTLINKERDATABASE)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // Microsoft Linker Database
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MICROSOFTLINKERDATABASE);
        //        ss.sVersion=QString("%1.%2").arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(32*2,4))).arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(34*2,4)));
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTACCESS)) && (pBinaryInfo->basic_info.id.nSize >= 128)) {
        // Microsoft Access Database
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MICROSOFTACCESS);

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

void NFD_Binary::handle_Images(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_JPEG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // JPEG
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_JPEG);
        quint32 nMajor = pBinaryInfo->basic_info.sHeaderSignature.mid(11 * 2, 2).toUInt(nullptr, 16);
        quint32 nMinor = pBinaryInfo->basic_info.sHeaderSignature.mid(12 * 2, 2).toUInt(nullptr, 16);
        ss.sVersion = QString("%1.%2").arg(nMajor).arg(nMinor, 2, 10, QChar('0'));
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_GIF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // GIF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_GIF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_TIFF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TIFF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_TIFF);
        // More information
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINDOWSICON)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Icon
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINDOWSICON);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINDOWSCURSOR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Cursor
        // TODO more information
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINDOWSCURSOR);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINDOWSBITMAP)) && (pBinaryInfo->basic_info.id.nSize >= 40)) {
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
                SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINDOWSBITMAP);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_PNG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PNG
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_PNG);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(16, true)).arg(binary.read_uint32(20, true));

        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_DJVU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DJVU
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_DJVU);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void NFD_Binary::handle_InstallerData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Inno Setup
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_INNOSETUP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_INNOSETUP);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_INSTALLANYWHERE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_INSTALLANYWHERE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_GHOSTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_GHOSTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_NSIS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_NSIS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SIXXPACK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SIXXPACK);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_THINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_THINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SMARTINSTALLMAKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SMARTINSTALLMAKER);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(46, 14));
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_TARMAINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_TARMAINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_CLICKTEAM)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_CLICKTEAM);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_QTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_QTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ADVANCEDINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ADVANCEDINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_OPERA)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_OPERA);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_GPINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_GPINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AVASTANTIVIRUS)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AVASTANTIVIRUS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_INSTALLSHIELD)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_INSTALLSHIELD);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SETUPFACTORY)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SETUPFACTORY);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ACTUALINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ACTUALINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_INSTALL4J)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_INSTALL4J);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_VMWARE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_VMWARE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_NOSINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_NOSINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void NFD_Binary::handle_ProtectorData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_FISHNET)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Inno Setup
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_FISHNET);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_XENOCODE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Xenocode
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_XENOCODE);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_MOLEBOXULTRA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_MOLEBOXULTRA);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_1337EXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_1337EXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ACTIVEMARK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ACTIVEMARK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_AGAINNATIVITYCRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_AGAINNATIVITYCRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ARCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ARCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_NOXCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_NOXCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_FASTFILECRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_FASTFILECRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_ZELDACRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_ZELDACRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WOUTHRSEXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WOUTHRSEXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WLCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WLCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_DOTNETSHRINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_DOTNETSHRINK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SPOONSTUDIO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SPOONSTUDIO);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SECUROM)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SECUROM);
        ss.sVersion = binary.read_ansiString(8);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SERGREENAPPACKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SERGREENAPPACKER);
        // TODO Version
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void NFD_Binary::handle_LibraryData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SHELL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        QString sString = binary.read_ansiString(0);

        if (sString.contains("python")) {
            SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_PYTHON, "", "", 0);
            pBinaryInfo->basic_info.mapResultLibraryData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void NFD_Binary::handle_Resources(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_VERSIONINFO)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_VERSIONINFO);
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_BITMAPINFOHEADER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_BITMAPINFOHEADER);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(4)).arg(binary.read_uint32(8));
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_STRINGTABLE)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_STRINGTABLE);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_DIALOG)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_DIALOG);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_ICON)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_ICON);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_CURSOR)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_CURSOR);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_RESOURCE_MENU)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_RESOURCE_MENU);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void NFD_Binary::handle_SFXData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_WINRAR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_WINRAR);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_SQUEEZSFX)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_SQUEEZSFX);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(XScanEngine::RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(XScanEngine::RECORD_NAME_7Z);

        if (ss.type == XScanEngine::RECORD_TYPE_SFXDATA) {
            pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void NFD_Binary::handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    if (pBinaryInfo->basic_info.mapResultFormats.contains(XScanEngine::RECORD_NAME_PDF)) {
        pBinaryInfo->basic_info.mapResultTexts.clear();

        pBinaryInfo->basic_info.mapResultFormats[XScanEngine::RECORD_NAME_PDF].id.fileType = XBinary::FT_BINARY;
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_BINARY;
    }
}

NFD_Binary::BINARYINFO_STRUCT NFD_Binary::getInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions,
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
                SCANS_STRUCT ss = {};
                ss.fileType = result.basic_info.id.fileType;
                ss.type = XScanEngine::RECORD_TYPE_FORMAT;

                quint32 nId = pOptions->varInfo.toUInt();

                if (nId == XPE_DEF::S_RT_DIALOG) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_DIALOG;
                } else if (nId == XPE_DEF::S_RT_STRING) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_STRINGTABLE;
                } else if (nId == XPE_DEF::S_RT_VERSION) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_VERSIONINFO;
                } else if (nId == XPE_DEF::S_RT_ICON) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_ICON;
                } else if (nId == XPE_DEF::S_RT_CURSOR) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_CURSOR;
                } else if (nId == XPE_DEF::S_RT_MENU) {
                    ss.name = XScanEngine::RECORD_NAME_RESOURCE_MENU;
                }

                if (ss.name != XScanEngine::RECORD_NAME_UNKNOWN) {
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

        NFD_Binary::handle_Texts(pDevice, pOptions, &result, pPdStruct);
        NFD_Binary::handle_Formats(pDevice, pOptions, &result);
        NFD_Binary::handle_Databases(pDevice, pOptions, &result);
        NFD_Binary::handle_Images(pDevice, pOptions, &result);
        NFD_Binary::handle_Archives(pDevice, pOptions, &result, pPdStruct);
        NFD_Binary::handle_Certificates(pDevice, pOptions, &result);
        NFD_Binary::handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        NFD_Binary::handle_InstallerData(pDevice, pOptions, &result);
        NFD_Binary::handle_SFXData(pDevice, pOptions, &result);
        NFD_Binary::handle_ProtectorData(pDevice, pOptions, &result);
        NFD_Binary::handle_LibraryData(pDevice, pOptions, &result);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            NFD_Binary::handle_Resources(pDevice, pOptions, &result);
        }

        NFD_Binary::handle_FixDetects(pDevice, pOptions, &result);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

QList<XScanEngine::SCANSTRUCT> NFD_Binary::convert(QList<SCAN_STRUCT> *pListScanStructs)
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
        record.sType = XScanEngine::recordTypeIdToString(pListScanStructs->at(i).type);
        record.sName = XScanEngine::recordNameIdToString(pListScanStructs->at(i).name);
        record.sVersion = pListScanStructs->at(i).sVersion;
        record.sInfo = pListScanStructs->at(i).sInfo;

        record.globalColorRecord = XScanEngine::typeToGlobalColorRecord(record.sType);
        record.nPrio = XScanEngine::typeToPrio(record.sType);
        record.bIsProtection = XScanEngine::isProtection(record.sType);
        record.sType = XScanEngine::translateType(record.sType);

        listResult.append(record);
    }

    // XFormats::sortRecords(&listResult); // TODO Check

    return listResult;
}

QList<XScanEngine::DEBUG_RECORD> NFD_Binary::convertHeur(QList<DETECT_RECORD> *pListDetectRecords)
{
    QList<XScanEngine::DEBUG_RECORD> listResult;

    qint32 nNumberOfRecords = pListDetectRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::DEBUG_RECORD record = {};

        record.sType = XScanEngine::heurTypeIdToString(pListDetectRecords->at(i).detectType);
        record.sName = QString("%1(%2)[%3]")
                           .arg(XScanEngine::recordNameIdToString(pListDetectRecords->at(i).name), pListDetectRecords->at(i).sVersion, pListDetectRecords->at(i).sInfo);
        record.sValue = pListDetectRecords->at(i).sValue;

        listResult.append(record);
    }

    return listResult;
}
