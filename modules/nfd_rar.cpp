#include "nfd_rar.h"

NFD_RAR::NFD_RAR(XRar *pRar, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : RAR_Script(pRar, filePart, pOptions, pPdStruct)
{
}

NFD_RAR::RARINFO_STRUCT NFD_RAR::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    RARINFO_STRUCT result = {};

    XRar rar(pDevice);

    if (rar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&rar, parentId, pOptions, nOffset, pPdStruct);

        // Populate
        result.listArchiveRecords = rar.getRecords(20000, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
