/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
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
#include "nfd_ne.h"

NFD_NE::NFD_NE(XNE *pNE, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct) : NE_Script(pNE, filePart, scanOptions, pPdStruct)
{
}

// NE entry-point signatures. The NE entry point lands in the language runtime's startup code,
// which is characteristic of the toolchain even though the rest of the image is user code.
static NFD_Binary::SIGNATURE_RECORD g_NE_entrypoint_records[] = {
    // Borland C++ for Windows - three distinct RTL startups
    {{0, XBinary::FT_NE, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_BORLANDCPP, "1994", "type 2"},
     "893E..0056571E510656E3"},
    {{0, XBinary::FT_NE, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_BORLANDCPP, "1994", "type 1"},
     "53510633C0509AFFFF0000"},
    {{0, XBinary::FT_NE, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_BORLANDCPP, "1993", "type 1"},
     "53510633C050E8....580759"},
    // Borland Pascal for Windows 7.x
    {{0, XBinary::FT_NE, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_TURBOPASCAL, "7.X", "Windows"},
     "9AFFFF00009AFFFF00009AFF"},
    // PKZIP self-extractor (NE build)
    {{0, XBinary::FT_NE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_PKSFX, "", ""},
     "FCA3....891E....49890E"},
};

NFD_Binary::SIGNATURE_RECORD *NFD_NE::getEntryPointRecords()
{
    return g_NE_entrypoint_records;
}

qint32 NFD_NE::getEntryPointRecordsSize()
{
    return sizeof(g_NE_entrypoint_records);
}

NFD_NE::NEINFO_STRUCT NFD_NE::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    NEINFO_STRUCT result = {};

    XNE ne(pDevice, pOptions->bIsImage);

    if (ne.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&ne, parentId, pOptions, nOffset, pPdStruct);

        result.nEntryPointOffset = ne.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = ne.getSignature(result.nEntryPointOffset, 150);

        result.nOverlayOffset = ne.getOverlayOffset(&(result.basic_info.memoryMap), pPdStruct);
        result.nOverlaySize = ne.getOverlaySize(&(result.basic_info.memoryMap), pPdStruct);
        if (result.nOverlaySize) {
            result.sOverlaySignature = ne.getSignature(result.nOverlayOffset, 150);
        }

        // MSDOS header linker signatures (moved from SpecAbstract)
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_MSDOS::getHeaderLinkerRecords(),
                                  NFD_MSDOS::getHeaderLinkerRecordsSize(), result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);

        // NE entry-point signatures (compiler/SFX runtime startups)
        NFD_Binary::signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, g_NE_entrypoint_records, sizeof(g_NE_entrypoint_records),
                                  result.basic_info.id.fileType, XBinary::FT_NE, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);

        if (result.basic_info.mapEntryPointDetects.contains(XScanEngine::RECORD_NAME_BORLANDCPP)) {
            NFD_Binary::SCANS_STRUCT ss = result.basic_info.mapEntryPointDetects.value(XScanEngine::RECORD_NAME_BORLANDCPP);
            result.basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
        }

        if (result.basic_info.mapEntryPointDetects.contains(XScanEngine::RECORD_NAME_TURBOPASCAL)) {
            NFD_Binary::SCANS_STRUCT ss = result.basic_info.mapEntryPointDetects.value(XScanEngine::RECORD_NAME_TURBOPASCAL);
            result.basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
        }

        if (result.basic_info.mapEntryPointDetects.contains(XScanEngine::RECORD_NAME_PKSFX)) {
            NFD_Binary::SCANS_STRUCT ss = result.basic_info.mapEntryPointDetects.value(XScanEngine::RECORD_NAME_PKSFX);
            result.basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
        }

        // Deep-scan string tells. NE images are ordinary user applications, so only the runtime
        // banner and the installer's own text are reliable.
        if (result.basic_info.scanOptions.bIsDeepScan) {
            qint64 _nOffset = 0;
            qint64 _nSize = result.basic_info.id.nSize;

            if (result.nOverlayOffset != -1) {
                _nSize = result.nOverlayOffset;
            }

            if (!result.basic_info.mapResultCompilers.contains(XScanEngine::RECORD_NAME_BORLANDCPP)) {
                if (ne.find_ansiString(_nOffset, _nSize, "Borland C++ - Copyright 1995 Borland Intl.", pPdStruct) != -1) {
                    NFD_Binary::SCANS_STRUCT ss = {};
                    ss.nVariant = 0;
                    ss.fileType = XBinary::FT_NE;
                    ss.type = XScanEngine::RECORD_TYPE_COMPILER;
                    ss.name = XScanEngine::RECORD_NAME_BORLANDCPP;
                    ss.sVersion = "1995";
                    result.basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
                }
            }

            // Setup-Specialist by Thilo-Alexander Ginkel. Only the branded builds carry this;
            // the later stubs embed no vendor text at all.
            if (ne.find_ansiString(_nOffset, _nSize, "Ginkel", pPdStruct) != -1) {
                NFD_Binary::SCANS_STRUCT ss = {};
                ss.nVariant = 0;
                ss.fileType = XBinary::FT_NE;
                ss.type = XScanEngine::RECORD_TYPE_INSTALLER;
                ss.name = XScanEngine::RECORD_NAME_SETUPSPECIALIST;
                result.basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
            }
        }

        // Operation System
        {
            NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(ne.getFileFormatInfo(pPdStruct));
            result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));
        }

        // Borland Turbo Linker (version from VI if available)
        {
            NFD_Binary::VI_STRUCT vi = NFD_Binary::get_TurboLinker_vi(pDevice, pOptions);
            if (vi.bIsValid) {
                NFD_Binary::SCANS_STRUCT ssLinker = {};
                ssLinker.nVariant = 0;
                ssLinker.fileType = XBinary::FT_MSDOS;  // parity with previous implementation for NE block
                ssLinker.type = XScanEngine::RECORD_TYPE_LINKER;
                ssLinker.name = XScanEngine::RECORD_NAME_TURBOLINKER;
                ssLinker.sVersion = vi.sVersion;
                ssLinker.sInfo = vi.sInfo;
                result.basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(result.basic_info), &ssLinker));
            }
        }

        // Watcom C/C++ toolchain (compiler + linker)
        {
            NFD_Binary::VI_STRUCT vi = NFD_Binary::get_Watcom_vi(pDevice, pOptions, result.nEntryPointOffset, 0x100, pPdStruct);
            if (vi.bIsValid) {
                // Compiler
                NFD_Binary::SCANS_STRUCT ssCompiler = {};
                ssCompiler.nVariant = 0;
                ssCompiler.fileType = XBinary::FT_MSDOS;
                ssCompiler.type = XScanEngine::RECORD_TYPE_COMPILER;
                ssCompiler.name = static_cast<XScanEngine::RECORD_NAME>(vi.vValue.toUInt());
                ssCompiler.sVersion = vi.sVersion;
                ssCompiler.sInfo = vi.sInfo;
                result.basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(result.basic_info), &ssCompiler));

                // Linker
                NFD_Binary::SCANS_STRUCT ssLinker = {};
                ssLinker.nVariant = 0;
                ssLinker.fileType = XBinary::FT_MSDOS;
                ssLinker.type = XScanEngine::RECORD_TYPE_LINKER;
                ssLinker.name = XScanEngine::RECORD_NAME_WATCOMLINKER;
                result.basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(result.basic_info), &ssLinker));
            }
        }

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
