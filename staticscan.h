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
#ifndef STATICSCAN_H
#define STATICSCAN_H

#include <QElapsedTimer>
#include <QTimer>

#include "specabstract.h"

#define SSE_VERSION __DATE__

class StaticScan : public QObject {
    Q_OBJECT

public:
    explicit StaticScan(QObject *pParent = nullptr);

    void setData(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XScanEngine::SCAN_RESULT *pScanResult, XBinary::PDSTRUCT *pPdStruct);
    void setData(const QString &sDirectoryName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    static XScanEngine::SCAN_RESULT processDevice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    static XScanEngine::SCAN_RESULT processFile(const QString &sFileName, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    static XScanEngine::SCAN_RESULT processMemory(char *pData, qint32 nDataSize, XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    static XScanEngine::SCAN_RESULT processSubdevice(QIODevice *pDevice, qint64 nOffset, qint64 nSize, XScanEngine::SCAN_OPTIONS *pOptions,
                                                     XBinary::PDSTRUCT *pPdStruct = nullptr);

    static QString getEngineVersion();

private:
    enum SCAN_TYPE {
        SCAN_TYPE_UNKNOWN = 0,
        SCAN_TYPE_DEVICE,
        SCAN_TYPE_DIRECTORY,
        SCAN_TYPE_FILE,
        SCAN_TYPE_MEMORY
    };

    void _process(QIODevice *pDevice, XScanEngine::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, XScanEngine::SCANID parentId,
                  XScanEngine::SCAN_OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanFile(const QString &sFileName, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanDevice(QIODevice *pDevice, XBinary::PDSTRUCT *pPdStruct = nullptr);
    XScanEngine::SCAN_RESULT scanMemory(char *pData, qint32 nSize, XBinary::PDSTRUCT *pPdStruct = nullptr);

signals:
    // TODO error and info signals !!!
    void scanFileStarted(const QString &sFileName);
    void completed(qint64 nElapsedTime);
    void scanResult(const XScanEngine::SCAN_RESULT &scanResult);

public slots:
    void process();

private:
    QString g_sFileName;
    QString g_sDirectoryName;
    QIODevice *g_pDevice;
    char *g_pData;
    qint32 g_nDataSize;
    XScanEngine::SCAN_OPTIONS *g_pOptions;
    XScanEngine::SCAN_RESULT *g_pScanResult;
    SCAN_TYPE g_scanType;
    XBinary::PDSTRUCT *g_pPdStruct;
};

#endif  // STATICSCAN_H
