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
#include "staticscan.h"

StaticScan::StaticScan(QObject *pParent) : QObject(pParent)
{
    m_pOptions = nullptr;
    m_pScanResult = nullptr;
    m_scanType = SCAN_TYPE_UNKNOWN;
    m_pDevice = nullptr;
    m_pData = nullptr;
    m_pPdStruct = nullptr;
}

void StaticScan::setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_sFileName = sFileName;
    m_pOptions = pOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_FILE;
}

void StaticScan::setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_pDevice = pDevice;
    m_pOptions = pOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_DEVICE;
}

void StaticScan::setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct)
{
    m_pData = pData;
    m_nDataSize = nDataSize;
    m_pOptions = pOptions;
    m_pScanResult = pScanResult;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_MEMORY;
}

void StaticScan::setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    m_sDirectoryName = sDirectoryName;
    m_pOptions = pOptions;
    m_pPdStruct = pPdStruct;

    m_scanType = SCAN_TYPE_DIRECTORY;
}

void StaticScan::process()
{
    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    XBinary::PDSTRUCT *pPdStruct = m_pPdStruct;

    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }

    QElapsedTimer scanTimer;
    scanTimer.start();

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, 0);

    if (m_scanType == SCAN_TYPE_FILE) {
        if ((m_pScanResult) && (m_sFileName != "")) {
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("File scan"));

            emit scanFileStarted(m_sFileName);

            *m_pScanResult = scanFile(m_sFileName, pPdStruct);

            emit scanResult(*m_pScanResult);
        }
    } else if (m_scanType == SCAN_TYPE_DEVICE) {
        if (m_pDevice) {
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Device scan"));

            *m_pScanResult = scanDevice(m_pDevice, pPdStruct);

            emit scanResult(*m_pScanResult);
        }
    } else if (m_scanType == SCAN_TYPE_MEMORY) {
        XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Memory scan"));

        *m_pScanResult = scanMemory(m_pData, m_nDataSize, pPdStruct);

        emit scanResult(*m_pScanResult);
    } else if (m_scanType == SCAN_TYPE_DIRECTORY) {
        if (m_sDirectoryName != "") {
            XBinary::setPdStructStatus(pPdStruct, _nFreeIndex, tr("Directory scan"));
            QList<QString> listFileNames;

            XBinary::findFiles(m_sDirectoryName, &listFileNames, m_pOptions->bSubdirectories, 0, pPdStruct);

            qint32 _nFreeIndexFiles = XBinary::getFreeIndex(pPdStruct);

            qint32 nTotal = listFileNames.count();

            XBinary::setPdStructInit(pPdStruct, _nFreeIndexFiles, nTotal);

            for (qint32 i = 0; (i < nTotal) && (!(pPdStruct->bIsStop)); i++) {
                QString sFileName = listFileNames.at(i);

                XBinary::setPdStructCurrent(pPdStruct, _nFreeIndexFiles, i);
                XBinary::setPdStructStatus(pPdStruct, _nFreeIndexFiles, sFileName);

                emit scanFileStarted(sFileName);

                XScanEngine::SCAN_RESULT _scanResult = scanFile(sFileName, pPdStruct);

                emit scanResult(_scanResult);
            }

            XBinary::setPdStructFinished(pPdStruct, _nFreeIndexFiles);
        }
    }

    XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);

    emit completed(scanTimer.elapsed());
}

XScanEngine::SCAN_RESULT StaticScan::processDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};
    StaticScan scan;
    scan.setData(pDevice, pOptions, &result, pPdStruct);
    scan.process();

    return result;
}

XScanEngine::SCAN_RESULT StaticScan::processFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};
    StaticScan scan;
    scan.setData(sFileName, pOptions, &result, pPdStruct);
    scan.process();

    return result;
}

XScanEngine::SCAN_RESULT StaticScan::processMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};
    StaticScan scan;
    scan.setData(pData, nDataSize, pOptions, &result, pPdStruct);
    scan.process();

    return result;
}

XScanEngine::SCAN_RESULT StaticScan::processSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (XBinary::isOffsetAndSizeValid(pDevice, nOffset, nSize)) {
        SubDevice sd(pDevice, nOffset, nSize);

        if (sd.open(QIODevice::ReadOnly)) {
            StaticScan scan;
            scan.setData(&sd, pOptions, &result, pPdStruct);
            scan.process();

            sd.close();
        }
    }

    return result;
}

QString StaticScan::getEngineVersion()
{
    return SSE_VERSION;
}

// StaticScan::STATS StaticScan::getCurrentStats()
//{
//     if(g_pElapsedTimer)
//     {
//         if(g_pElapsedTimer->isValid())
//         {
//             g_currentStats.nElapsed=g_pElapsedTimer->elapsed();
//         }
//         else
//         {
//             g_currentStats.nElapsed=0;
//         }
//     }

//    if(g_pOptions)
//    {
//        g_currentStats.sStatus2=g_pOptions->sStatus;
//    }

//    return g_currentStats;
//}

void StaticScan::_process(QIODevice *pDevice, XScanEngine::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, XScanEngine::SCANID parentId,
                          XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
{
    XBinary::PDSTRUCT pdStructEmpty = XBinary::createPdStruct();

    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }

    *pScanResult = SpecAbstract::scanSubdevice(pDevice, nOffset, nSize, parentId, pOptions, true, pPdStruct);
}

XScanEngine::SCAN_RESULT StaticScan::scanFile(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    if (sFileName != "") {
        QFile file;
        file.setFileName(sFileName);

        if (file.open(QIODevice::ReadOnly)) {
            result = scanDevice(&file, pPdStruct);
            file.close();
        }
    }

    return result;
}

XScanEngine::SCAN_RESULT StaticScan::scanDevice(QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    XScanEngine::SCANID parentId = {};
    parentId.fileType = XBinary::FT_UNKNOWN;

    if (m_pOptions->initFilePart == XBinary::FILEPART_UNKNOWN) {
        parentId.filePart = XBinary::FILEPART_HEADER;
    } else {
        parentId.filePart = m_pOptions->initFilePart;
    }

    _process(pDevice, &result, 0, pDevice->size(), parentId, m_pOptions, pPdStruct);

    return result;
}

XScanEngine::SCAN_RESULT StaticScan::scanMemory(char *pData, qint32 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    XScanEngine::SCAN_RESULT result = {};

    QBuffer buffer;

    buffer.setData(pData, nSize);

    if (buffer.open(QIODevice::ReadOnly)) {
        result = scanDevice(&buffer, pPdStruct);

        buffer.close();
    }

    return result;
}
