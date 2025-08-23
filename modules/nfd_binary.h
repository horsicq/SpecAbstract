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
#ifndef NFD_BINARY_H
#define NFD_BINARY_H

#include "binary_script.h"
#include "xscanengine.h"
#include <QtCore/QString>
#include <QtCore/QVariant>

// Common detection type used across NFD and SpecAbstract
// Kept as unscoped enum so legacy DETECTTYPE_* constants remain available
enum DETECTTYPE {
    DETECTTYPE_UNKNOWN = 0,
    DETECTTYPE_ARCHIVE,
    DETECTTYPE_CODESECTION,
    DETECTTYPE_DEXSTRING,
    DETECTTYPE_DEXTYPE,
    DETECTTYPE_ENTRYPOINT,
    DETECTTYPE_ENTRYPOINTSECTION,
    DETECTTYPE_HEADER,
    DETECTTYPE_IMPORTHASH,
    DETECTTYPE_NETANSISTRING,
    DETECTTYPE_NETUNICODESTRING,
    DETECTTYPE_OVERLAY,
    DETECTTYPE_DEBUGDATA,
    DETECTTYPE_RESOURCES,
    DETECTTYPE_RICH,
    DETECTTYPE_SECTIONNAME
};

class NFD_Binary : public Binary_Script
{
    Q_OBJECT

public:
    // Common detection/scan types used across NFD and SpecAbstract
    struct SCAN_STRUCT {
        bool bIsHeuristic;
        bool bIsUnknown;
        XScanEngine::SCANID id;
        XScanEngine::SCANID parentId;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    struct DETECT_RECORD {
        qint64 nOffset;  // memory scan
        XBinary::FILEPART filepart;
        DETECTTYPE detectType;
        QString sValue;  // mb TODO variant
        quint32 nVariant;
        XBinary::FT fileType;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    // Unified scan record structure moved from SpecAbstract
    struct SCANS_STRUCT {
        qint64 nOffset;
        quint32 nVariant;
        XBinary::FT fileType;
        XScanEngine::RECORD_TYPE type;
        XScanEngine::RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        bool bIsHeuristic;
        bool bIsUnknown;
        QVariant varExtra;
    };

    explicit NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, Binary_Script::OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

signals:
};

#endif // NFD_BINARY_H
