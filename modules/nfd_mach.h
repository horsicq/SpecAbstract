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
#ifndef NFD_MACH_H
#define NFD_MACH_H

#include "mach_script.h"
#include "nfd_binary.h"
#include "xmach.h"

class NFD_MACH : public MACH_Script {
    Q_OBJECT

public:
    explicit NFD_MACH(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct MACHOINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;
        QList<XMACH::COMMAND_RECORD> listCommandRecords;
        QList<XMACH::LIBRARY_RECORD> listLibraryRecords;
        QList<XMACH::SEGMENT_RECORD> listSegmentRecords;
        QList<XMACH::SECTION_RECORD> listSectionRecords;
    };

    // Handlers migrated from SpecAbstract
    static void handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);
    static void handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_MACH_H
