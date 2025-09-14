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
#ifndef NFD_DEX_H
#define NFD_DEX_H

#include "dex_script.h"
#include "nfd_binary.h"

class NFD_DEX : public DEX_Script {
    Q_OBJECT

public:
    explicit NFD_DEX(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct DEXINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        XDEX_DEF::HEADER header;
        QList<XDEX_DEF::MAP_ITEM> mapItems;
        QList<QString> listStrings;
        QList<QString> listTypeItemStrings;
        QList<XDEX_DEF::FIELD_ITEM_ID> listFieldIDs;
        QList<XDEX_DEF::METHOD_ITEM_ID> listMethodIDs;
        bool bIsStringPoolSorted;
        bool bIsOverlayPresent;
    };

    // Accessors for DEX string/type signature records (moved from SpecAbstract/signatures.cpp)
    static NFD_Binary::STRING_RECORD *getStringRecords();
    static qint32 getStringRecordsSize();
    static NFD_Binary::STRING_RECORD *getTypeRecords();
    static qint32 getTypeRecordsSize();

    // Main DEX analysis function
    static DEXINFO_STRUCT getDEXInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    // Handlers migrated from SpecAbstract
    static void handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Dexguard(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Protection(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_DEX_H
