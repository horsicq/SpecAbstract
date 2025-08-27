#include "nfd_amiga.h"

NFD_Amiga::NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Amiga_Script(pAmiga, filePart, pOptions, pPdStruct)
{
}

NFD_Amiga::AMIGAHUNKINFO_STRUCT NFD_Amiga::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                   XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    AMIGAHUNKINFO_STRUCT result = {};

    XAmigaHunk amigaHunk(pDevice);

    if (amigaHunk.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Initialize BASIC_INFO via shared utility
        result.basic_info = NFD_Binary::_initBasicInfo(&amigaHunk, parentId, pOptions, nOffset, pPdStruct);

        // Delegate OS detection to NFD
        Binary_Script::OPTIONS opts = NFD_Binary::toOptions(pOptions);

        NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::detectOperationSystem(&amigaHunk, pPdStruct);
        // Convert and store via shared utility
        result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));

        // Aggregate and finalize result lists
        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
