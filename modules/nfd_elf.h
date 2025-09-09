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
#ifndef NFD_ELF_H
#define NFD_ELF_H

#include "elf_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_ELF : public ELF_Script {
    Q_OBJECT

public:
    explicit NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct ELFINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;

        QList<XELF::TAG_STRUCT> listTags;
        QList<QString> listLibraries;
        QList<QString> listComments;
        QList<XELF_DEF::Elf_Shdr> listSectionHeaders;
        QList<XELF_DEF::Elf_Phdr> listProgramHeaders;
        QList<XELF::SECTION_RECORD> listSectionRecords;
        QList<XELF::NOTE> listNotes;

        qint32 nSymTabSection;
        qint64 nSymTabOffset;
        qint32 nDebugSection;
        qint64 nDWARFDebugOffset;
        qint64 nDWARFDebugSize;

        qint32 nCommentSection;
        qint32 nStringTableSection;
        QByteArray baStringTable;
        QString sRunPath;

        XBinary::OFFSETSIZE osCommentSection;
    };

    static ELFINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    // SIGNATURE_RECORD based tables (migrated from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getEntrypointRecords();
    static qint32 getEntrypointRecordsSize();
};

#endif  // NFD_ELF_H
