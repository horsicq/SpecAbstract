#include "nfd_amiga.h"

NFD_Amiga::NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Amiga_Script(pAmiga, filePart, pOptions, pPdStruct) {}

NFD_Binary::SCANS_STRUCT NFD_Amiga::detectOperationSystem(XBinary::PDSTRUCT *pPdStruct)
{
    XAmigaHunk *pAmiga = getAmiga();
    if (!pAmiga) {
        NFD_Binary::SCANS_STRUCT unknown = {};
        unknown.type = XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;
        unknown.name = XScanEngine::RECORD_NAME_UNKNOWN;
        unknown.bIsUnknown = true;
        return unknown;
    }

    XBinary::FILEFORMATINFO ffi = pAmiga->getFileFormatInfo(pPdStruct);
    return NFD_Binary::detectOperationSystem(ffi);
}

NFD_Amiga::AMIGAHUNKINFO_STRUCT NFD_Amiga::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    AMIGAHUNKINFO_STRUCT result = {};

    XAmigaHunk amigaHunk(pDevice);

    if (amigaHunk.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Initialize BASIC_INFO
        NFD_Binary::BASIC_INFO bi = {};
        bi.parentId = parentId;
        bi.memoryMap = amigaHunk.getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
        bi.sHeaderSignature = amigaHunk.getSignature(0, 150);
        bi.id.nSize = amigaHunk.getSize();
        bi.id.fileType = bi.memoryMap.fileType;
        bi.id.filePart = XBinary::FILEPART_HEADER;
        bi.id.sUuid = XBinary::generateUUID();
        bi.scanOptions = *pOptions;
        bi.id.sArch = bi.memoryMap.sArch;
        bi.id.mode = bi.memoryMap.mode;
        bi.id.endian = bi.memoryMap.endian;
        bi.id.sType = bi.memoryMap.sType;
        bi.id.nOffset = nOffset;

        result.basic_info = bi;

        // Delegate OS detection to NFD
        Binary_Script::OPTIONS opts = {};
        opts.bIsDeepScan = pOptions->bIsDeepScan;
        opts.bIsHeuristicScan = pOptions->bIsHeuristicScan;
        opts.bIsAggressiveScan = pOptions->bIsAggressiveScan;
        opts.bIsVerbose = pOptions->bIsVerbose;
        opts.bIsProfiling = false;

        NFD_Amiga nfd(&amigaHunk, result.basic_info.id.filePart, &opts, pPdStruct);
        NFD_Binary::SCANS_STRUCT ssOperationSystem = nfd.detectOperationSystem(pPdStruct);
        // Convert and store via shared utility
        result.basic_info.mapResultOperationSystems.insert(
            ssOperationSystem.name,
            NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem)
        );
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
