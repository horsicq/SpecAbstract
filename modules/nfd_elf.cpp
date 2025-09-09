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
#include "nfd_elf.h"

NFD_ELF::NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : ELF_Script(pELF, filePart, pOptions, pPdStruct)
{
}

// ELF entrypoint signature table (migrated from SpecAbstract/signatures.cpp)
static NFD_Binary::SIGNATURE_RECORD g_ELF_entrypoint_records[] = {
    {{0, XBinary::FT_ELF32, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BURNEYE, "1.00", ""}, "FF35........9C608B0D........E9"},
};

NFD_Binary::SIGNATURE_RECORD *NFD_ELF::getEntrypointRecords()
{
    return g_ELF_entrypoint_records;
}

qint32 NFD_ELF::getEntrypointRecordsSize()
{
    return sizeof(g_ELF_entrypoint_records);
}

NFD_ELF::ELFINFO_STRUCT NFD_ELF::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    ELFINFO_STRUCT result = {};

    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Basic info
        result.basic_info = NFD_Binary::_initBasicInfo(&elf, parentId, pOptions, nOffset, pPdStruct);

        result.bIs64 = elf.is64();
        result.bIsBigEndian = elf.isBigEndian();
        result.sEntryPointSignature = elf.getSignature(elf.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        result.nStringTableSection = elf.getSectionStringTable(result.bIs64);
        result.baStringTable = elf.getSection(result.nStringTableSection);

        result.listTags = elf.getTagStructs();
        result.listLibraries = elf.getLibraries(&(result.basic_info.memoryMap), &result.listTags);

        result.listSectionHeaders = elf.getElf_ShdrList(100);
        result.listProgramHeaders = elf.getElf_PhdrList(100);
        result.listSectionRecords = XELF::getSectionRecords(&result.listSectionHeaders, pOptions->bIsImage, &result.baStringTable);
        result.listNotes = elf.getNotes(&result.listProgramHeaders);
        if (result.listNotes.count() == 0) {
            result.listNotes = elf.getNotes(&result.listSectionHeaders);
        }

        result.sRunPath = elf.getRunPath(&(result.basic_info.memoryMap), &result.listTags).sString;

        result.nSymTabSection = elf.getSectionIndexByName(".symtab", &result.listSectionRecords);
        if (result.nSymTabSection != -1) {
            result.nSymTabOffset = result.listSectionRecords.at(result.nSymTabSection).nOffset;
        }

        result.nDebugSection = elf.getSectionIndexByName(".debug_info", &result.listSectionRecords);
        if (result.nDebugSection != -1) {
            result.nDWARFDebugOffset = result.listSectionRecords.at(result.nDebugSection).nOffset;
            result.nDWARFDebugSize = result.listSectionRecords.at(result.nDebugSection).nSize;
        }

        result.nCommentSection = XELF::getSectionNumber(".comment", &result.listSectionRecords);
        if (result.nCommentSection != -1) {
            result.osCommentSection.nOffset = result.listSectionRecords.at(result.nCommentSection).nOffset;
            result.osCommentSection.nSize = result.listSectionRecords.at(result.nCommentSection).nSize;
            result.listComments = elf.getStringsFromSection(result.nCommentSection).values();
        }

        // Format/OS contribution to maps via common helpers can be added by callers as needed.
        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
