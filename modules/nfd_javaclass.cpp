#include "nfd_javaclass.h"

NFD_JavaClass::NFD_JavaClass(XJavaClass *pJavaClass, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : JavaClass_Script(pJavaClass, filePart, pOptions, pPdStruct)
{
}

NFD_JavaClass::JAVACLASSINFO_STRUCT NFD_JavaClass::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions,
                                                           qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    JAVACLASSINFO_STRUCT result = {};

    XJavaClass javaClass(pDevice);

    if (javaClass.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&javaClass, parentId, pOptions, nOffset, pPdStruct);

        // TODO: Add JavaClass-specific analysis here using scripts when needed

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
