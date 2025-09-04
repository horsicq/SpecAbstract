#include "nfd_le.h"

NFD_LE::NFD_LE(XLE *pLE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : LE_Script(pLE, filePart, pOptions, pPdStruct)
{
}

NFD_LE::LEINFO_STRUCT NFD_LE::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    LEINFO_STRUCT result = {};

    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&le, parentId, pOptions, nOffset, pPdStruct);

        result.nEntryPointOffset = le.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = le.getSignature(result.nEntryPointOffset, 150);
        result.listRichSignatures = le.getRichSignatureRecords();

        result.nOverlayOffset = le.getOverlayOffset(&(result.basic_info.memoryMap), pPdStruct);
        result.nOverlaySize = le.getOverlaySize(&(result.basic_info.memoryMap), pPdStruct);
        if (result.nOverlaySize) {
            result.sOverlaySignature = le.getSignature(result.nOverlayOffset, 150);
        }

        // MSDOS header linker signatures (moved from SpecAbstract)
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_MSDOS::getHeaderLinkerRecords(),
                                  NFD_MSDOS::getHeaderLinkerRecordsSize(), result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);

        // Operation System
        {
            NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(le.getFileFormatInfo(pPdStruct));
            result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));
        }

        // Borland Turbo Linker (version from VI if available)
        {
            NFD_Binary::VI_STRUCT vi = NFD_Binary::get_TurboLinker_vi(pDevice, pOptions);
            if (vi.bIsValid) {
                NFD_Binary::SCANS_STRUCT ssLinker = {};
                ssLinker.nVariant = 0;
                ssLinker.fileType = XBinary::FT_LX;  // keep parity with previous implementation
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
                ssCompiler.fileType = XBinary::FT_LX;  // keep parity with previous implementation
                ssCompiler.type = XScanEngine::RECORD_TYPE_COMPILER;
                ssCompiler.name = static_cast<XScanEngine::RECORD_NAME>(vi.vValue.toUInt());
                ssCompiler.sVersion = vi.sVersion;
                ssCompiler.sInfo = vi.sInfo;
                result.basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(result.basic_info), &ssCompiler));

                // Linker
                NFD_Binary::SCANS_STRUCT ssLinker = {};
                ssLinker.nVariant = 0;
                ssLinker.fileType = XBinary::FT_LX;  // keep parity with previous implementation
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
