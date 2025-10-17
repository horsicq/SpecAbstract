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
#include "specabstract.h"
#include "modules/nfd_binary.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"
#include "modules/nfd_dex.h"
#include "modules/nfd_pe.h"
#include "modules/nfd_text.h"
#include "modules/nfd_dex.h"

#include "signatures.cpp"  // Do not include in CMAKE files!

SpecAbstract::SpecAbstract(QObject *pParent) : XScanEngine(pParent)
{
}

void SpecAbstract::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                  XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO basic_info = {};

    if ((fileType == XBinary::FT_PE32) || (fileType == XBinary::FT_PE64)) {
        NFD_PE::PEINFO_STRUCT pe_info = NFD_PE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pe_info.basic_info;
    } else if ((fileType == XBinary::FT_ELF32) || (fileType == XBinary::FT_ELF64)) {
        NFD_ELF::ELFINFO_STRUCT elf_info = NFD_ELF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = elf_info.basic_info;
    } else if ((fileType == XBinary::FT_MACHO32) || (fileType == XBinary::FT_MACHO64)) {
        NFD_MACH::MACHOINFO_STRUCT mach_info = NFD_MACH::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = mach_info.basic_info;
    } else if (fileType == XBinary::FT_LE) {
        NFD_LE::LEINFO_STRUCT le_info = NFD_LE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = le_info.basic_info;
    } else if (fileType == XBinary::FT_LX) {
        NFD_LX::LXINFO_STRUCT lx_info = NFD_LX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = lx_info.basic_info;
    } else if (fileType == XBinary::FT_NE) {
        NFD_NE::NEINFO_STRUCT ne_info = NFD_NE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = ne_info.basic_info;
    } else if (fileType == XBinary::FT_MSDOS) {
        NFD_MSDOS::MSDOSINFO_STRUCT msdos_info = NFD_MSDOS::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = msdos_info.basic_info;
    } else if (fileType == XBinary::FT_JAR) {
        NFD_JAR::JARINFO_STRUCT jar_info = NFD_JAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jar_info.basic_info;
    } else if (fileType == XBinary::FT_APK) {
        NFD_APK::APKINFO_STRUCT apk_info = NFD_APK::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = apk_info.basic_info;
    } else if ((fileType == XBinary::FT_ZIP) || (fileType == XBinary::FT_IPA)) {
        // mb TODO split detects
        NFD_ZIP::ZIPINFO_STRUCT zip_info = NFD_ZIP::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = zip_info.basic_info;
    } else if (fileType == XBinary::FT_RAR) {
        NFD_RAR::RARINFO_STRUCT rar_info = NFD_RAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = rar_info.basic_info;
    } else if (fileType == XBinary::FT_JAVACLASS) {
        NFD_JavaClass::JAVACLASSINFO_STRUCT javaclass_info = NFD_JavaClass::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = javaclass_info.basic_info;
    } else if (fileType == XBinary::FT_DEX) {
        NFD_DEX::DEXINFO_STRUCT dex_info = NFD_DEX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = dex_info.basic_info;
    } else if (fileType == XBinary::FT_AMIGAHUNK) {
        NFD_Amiga::AMIGAHUNKINFO_STRUCT amigaHunk_info = NFD_Amiga::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = amigaHunk_info.basic_info;
    } else if (fileType == XBinary::FT_PDF) {
        NFD_PDF::PDFINFO_STRUCT pdf_info = NFD_PDF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pdf_info.basic_info;
    } else if (fileType == XBinary::FT_JPEG) {
        NFD_JPEG::JPEGINFO_STRUCT jpeg_info = NFD_JPEG::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jpeg_info.basic_info;
    } else if (fileType == XBinary::FT_CFBF) {
        NFD_CFBF::CFBFINFO_STRUCT cfbf_info = NFD_CFBF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = cfbf_info.basic_info;
    } else if (fileType == XBinary::FT_COM) {
        NFD_COM::COMINFO_STRUCT com_info = NFD_COM::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = com_info.basic_info;
    } else {
        NFD_Binary::BINARYINFO_STRUCT binary_info = NFD_Binary::getInfo(pDevice, fileType, parentId, pScanOptions, 0, pPdStruct);
        basic_info = binary_info.basic_info;
    }

    if (bAddUnknown) {
        if (!basic_info.listDetects.count()) {
            _SCANS_STRUCT ssUnknown = {};

            ssUnknown.type = SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name = SpecAbstract::RECORD_NAME_UNKNOWN;
            ssUnknown.bIsUnknown = true;

            basic_info.listDetects.append(NFD_Binary::scansToScan(&basic_info, &ssUnknown));
        }
    }

    QList<XScanEngine::SCANSTRUCT> listScanStructs = NFD_Binary::convert(&(basic_info.listDetects));

    if (pScanOptions->bIsSort) {
        sortRecords(&listScanStructs);
    }

    pScanResult->listRecords.append(listScanStructs);
    pScanResult->listDebugRecords.append(NFD_Binary::convertHeur(&(basic_info.listHeurs)));

    if (pScanID) {
        *pScanID = basic_info.id;
    }
}
