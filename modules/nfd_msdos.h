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
#ifndef NFD_MSDOS_H
#define NFD_MSDOS_H

#include "msdos_script.h"
#include "nfd_binary.h"
#include "xscanengine.h"

class NFD_MSDOS : public MSDOS_Script {
    Q_OBJECT

public:
    explicit NFD_MSDOS(XMSDOS *pMSDOS, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct MSDOSINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
    };

    // Move of SpecAbstract::MSDOS_richScan
    static void MSDOS_richScan(QMap<XScanEngine::RECORD_NAME, NFD_Binary::SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, quint32 nCount,
                               NFD_Binary::MSRICH_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, NFD_Binary::BASIC_INFO *pBasicInfo,
                               DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct);

    static QList<NFD_Binary::SCANS_STRUCT> MSDOS_richScan(quint16 nID, quint32 nBuild, quint32 nCount, NFD_Binary::MSRICH_RECORD *pRecords, qint32 nRecordsSize,
                                                          XBinary::FT fileType1, XBinary::FT fileType2, NFD_Binary::BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                                          XBinary::PDSTRUCT *pPdStruct);

    // Accessors for MSDOS linker header signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getHeaderLinkerRecords();
    static qint32 getHeaderLinkerRecordsSize();

    // Accessors for generic MSDOS header signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getHeaderRecords();
    static qint32 getHeaderRecordsSize();

    // Accessors for Microsoft Rich signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::MSRICH_RECORD *getRichRecords();
    static qint32 getRichRecordsSize();

    // Accessors for MSDOS entrypoint signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getEntryPointRecords();
    static qint32 getEntryPointRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getEntryPointExpRecords();
    static qint32 getEntryPointExpRecordsSize();

    // Handlers migrated from SpecAbstract
    static void handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_DosExtenders(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct);

    // Core info extractor migrated from SpecAbstract::getMSDOSInfo
    static MSDOSINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    static QString getMsRichString(quint16 nId, quint16 nBuild, quint32 nCount, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_MSDOS_H
