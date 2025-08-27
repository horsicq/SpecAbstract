#include "nfd_pdf.h"

NFD_PDF::NFD_PDF(XPDF *pPDF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : PDF_Script(pPDF, filePart, pOptions, pPdStruct)
{
}

NFD_PDF::PDFINFO_STRUCT NFD_PDF::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    PDFINFO_STRUCT result = {};

    XPDF pdf(pDevice);

    if (pdf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Basic info via shared utility
        result.basic_info = NFD_Binary::_initBasicInfo(&pdf, parentId, pOptions, nOffset, pPdStruct);

        // Collect objects
        result.listObjects = pdf.getParts(20, pPdStruct);

        // Format mapping
        NFD_Binary::SCANS_STRUCT ssFormat = NFD_Binary::getFormatScansStruct(pdf.getFileFormatInfo(pPdStruct));
        result.basic_info.mapResultFormats.insert(ssFormat.name, NFD_Binary::scansToScan(&(result.basic_info), &ssFormat));

        // Tags: Producer
        QList<XBinary::XVARIANT> listProd = pdf.getValuesByKey(&(result.listObjects), QString("/Producer"));
        qint32 nProdCount = listProd.count();
        for (qint32 i = 0; (i < nProdCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            if (listProd.at(i).varType == XBinary::VT_STRING) {
                NFD_Binary::SCANS_STRUCT ssTool = {};
                ssTool.type = XScanEngine::RECORD_TYPE_TOOL;
                ssTool.name = (XScanEngine::RECORD_NAME)((qint32)XScanEngine::RECORD_NAME_UNKNOWN0 + i);
                ssTool.sVersion = listProd.at(i).var.toString();
                ssTool.sInfo = "";
                result.basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(result.basic_info), &ssTool));
            }
        }

        // Tags: Creator
        QList<XBinary::XVARIANT> listCreator = pdf.getValuesByKey(&(result.listObjects), QString("/Creator"));
        qint32 nCreatorCount = listCreator.count();
        for (qint32 i = 0; (i < nCreatorCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            if (listCreator.at(i).varType == XBinary::VT_STRING) {
                NFD_Binary::SCANS_STRUCT ssTool = {};
                ssTool.type = XScanEngine::RECORD_TYPE_TOOL;
                ssTool.name = (XScanEngine::RECORD_NAME)((qint32)XScanEngine::RECORD_NAME_UNKNOWN0 + i);
                ssTool.sVersion = listCreator.at(i).var.toString();
                ssTool.sInfo = "";
                result.basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(result.basic_info), &ssTool));
            }
        }

        // Hook: Tags/Producer/etc. could be added here if desired in the future.

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}
