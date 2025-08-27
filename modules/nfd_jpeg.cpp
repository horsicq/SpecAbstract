#include "nfd_jpeg.h"

NFD_JPEG::NFD_JPEG(XJpeg *pJpeg, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : Jpeg_Script(pJpeg, filePart, pOptions, pPdStruct)
{
}

NFD_JPEG::JPEGINFO_STRUCT NFD_JPEG::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                            XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    JPEGINFO_STRUCT result = {};

    XJpeg jpeg(pDevice);

    if (jpeg.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Initialize BASIC_INFO via shared utility
        result.basic_info = NFD_Binary::_initBasicInfo(&jpeg, parentId, pOptions, nOffset, pPdStruct);

        // Formats: reuse generic format detection mapping
        NFD_Binary::SCANS_STRUCT ssFormat = NFD_Binary::getFormatScansStruct(jpeg.getFileFormatInfo(pPdStruct));
        result.basic_info.mapResultFormats.insert(ssFormat.name, NFD_Binary::scansToScan(&(result.basic_info), &ssFormat));

        // Aggregate and finalize result lists
        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
