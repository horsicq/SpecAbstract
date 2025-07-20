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

#include "signatures.cpp"  // Do not include in CMAKE files!

SpecAbstract::SpecAbstract(QObject *pParent) : XScanEngine(pParent)
{
}

QString SpecAbstract::append(const QString &sResult, const QString &sString)
{
    return XBinary::appendText(sResult, sString, ", ");
}

QString SpecAbstract::heurTypeIdToString(qint32 nId)
{
    QString sResult = tr("Unknown");

    switch (nId) {
        case DETECTTYPE_UNKNOWN: sResult = tr("Unknown"); break;
        case DETECTTYPE_HEADER: sResult = tr("Header"); break;
        case DETECTTYPE_OVERLAY: sResult = tr("Overlay"); break;
        case DETECTTYPE_DEBUGDATA: sResult = tr("Debug data"); break;
        case DETECTTYPE_ENTRYPOINT: sResult = tr("Entry point"); break;
        case DETECTTYPE_SECTIONNAME: sResult = tr("Section name"); break;
        case DETECTTYPE_IMPORTHASH: sResult = tr("Import hash"); break;
        case DETECTTYPE_CODESECTION: sResult = tr("Code section"); break;
        case DETECTTYPE_ENTRYPOINTSECTION: sResult = tr("Entry point section"); break;
        case DETECTTYPE_NETANSISTRING: sResult = QString(".NET ANSI %1").arg(tr("String")); break;
        case DETECTTYPE_NETUNICODESTRING: sResult = QString(".NET Unicode %1").arg(tr("String")); break;
        case DETECTTYPE_RICH: sResult = QString("Rich"); break;
        case DETECTTYPE_ARCHIVE: sResult = tr("Archive"); break;
        case DETECTTYPE_RESOURCES: sResult = tr("Resources"); break;
        case DETECTTYPE_DEXSTRING: sResult = QString("DEX %1").arg(tr("String")); break;
        case DETECTTYPE_DEXTYPE: sResult = QString("DEX %1").arg(tr("Type")); break;
    }

    return sResult;
}

QString SpecAbstract::_SCANS_STRUCT_toString(const _SCANS_STRUCT *pScanStruct, bool bShowType)
{
    QString sResult;

    if (pScanStruct->bIsHeuristic) {
        sResult += "(Heur)";
    }

    if (bShowType) {
        sResult += QString("%1: ").arg(translateType(SpecAbstract::recordTypeIdToString(pScanStruct->type)));
    }

    sResult += QString("%1").arg(SpecAbstract::recordNameIdToString(pScanStruct->name));

    if (pScanStruct->sVersion != "") {
        sResult += QString("(%1)").arg(pScanStruct->sVersion);
    }

    if (pScanStruct->sInfo != "") {
        sResult += QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

SpecAbstract::JAVACLASSINFO_STRUCT SpecAbstract::getJavaClassInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                                  XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    JAVACLASSINFO_STRUCT result = {};

    XJavaClass javaClass(pDevice);

    if (javaClass.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&javaClass, parentId, pOptions, nOffset, pPdStruct);

        // TODO

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::RARINFO_STRUCT SpecAbstract::getRARInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    RARINFO_STRUCT result = {};

    XRar rar(pDevice);

    if (rar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&rar, parentId, pOptions, nOffset, pPdStruct);

        // TODO

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::BASIC_INFO SpecAbstract::_initBasicInfo(XBinary *pBinary, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO result = {};

    result.parentId = parentId;
    result.memoryMap = pBinary->getMemoryMap(XBinary::MAPMODE_UNKNOWN, pPdStruct);
    result.sHeaderSignature = pBinary->getSignature(0, 150);
    result.id.nSize = pBinary->getSize();

    result.id.fileType = result.memoryMap.fileType;
    result.id.filePart = XBinary::FILEPART_HEADER;
    result.id.sUuid = XBinary::generateUUID();
    result.scanOptions = *pOptions;
    result.id.sArch = result.memoryMap.sArch;
    result.id.mode = result.memoryMap.mode;
    result.id.endian = result.memoryMap.endian;
    result.id.sType = result.memoryMap.sType;
    result.id.nOffset = nOffset;

    return result;
}

SpecAbstract::JARINFO_STRUCT SpecAbstract::getJARInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    JARINFO_STRUCT result = {};

    XJAR jar(pDevice);

    if (jar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&jar, parentId, pOptions, nOffset, pPdStruct);

        // TODO

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::JPEGINFO_STRUCT SpecAbstract::getJpegInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    JPEGINFO_STRUCT result = {};

    XJpeg jpeg(pDevice);

    if (jpeg.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&jpeg, parentId, pOptions, nOffset, pPdStruct);

        Jpeg_handle_Formats(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::PDFINFO_STRUCT SpecAbstract::getPDFInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    PDFINFO_STRUCT result = {};

    XPDF pdf(pDevice);

    if (pdf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&pdf, parentId, pOptions, nOffset, pPdStruct);

        result.listObjects = pdf.getParts(20, pPdStruct);

        PDF_handle_Formats(pDevice, pOptions, &result, pPdStruct);
        PDF_handle_Tags(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Enigma_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_array(nOffset, nSize, "\x00\x00\x00\x45\x4e\x49\x47\x4d\x41", 9, pPdStruct);  // \x00\x00\x00ENIGMA

        if (_nOffset != -1) {
            quint8 nMajor = binary.read_uint8(_nOffset + 9);
            quint8 nMinor = binary.read_uint8(_nOffset + 10);
            quint16 nYear = binary.read_uint16(_nOffset + 11);
            quint16 nMonth = binary.read_uint16(_nOffset + 13);
            quint16 nDay = binary.read_uint16(_nOffset + 15);
            quint16 nHour = binary.read_uint16(_nOffset + 17);
            quint16 nMin = binary.read_uint16(_nOffset + 19);
            quint16 nSec = binary.read_uint16(_nOffset + 21);

            result.sVersion = QString("%1.%2 build %3.%4.%5 %6:%7:%8")
                                  .arg(nMajor)
                                  .arg(nMinor, 2, 10, QChar('0'))
                                  .arg(nYear, 4, 10, QChar('0'))
                                  .arg(nMonth, 2, 10, QChar('0'))
                                  .arg(nDay, 2, 10, QChar('0'))
                                  .arg(nHour, 2, 10, QChar('0'))
                                  .arg(nMin, 2, 10, QChar('0'))
                                  .arg(nSec, 2, 10, QChar('0'));

            result.bIsValid = true;
        }
    }

    // 0 variant
    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, " *** Enigma protector v", pPdStruct);

        if (_nOffset != -1) {
            result.sVersion = binary.read_ansiString(_nOffset + 23).section(" ", 0, 0);
            result.bIsValid = true;
        }
    }

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "The Enigma Protector version", pPdStruct);

        if (_nOffset != -1) {
            result.sVersion = binary.read_ansiString(_nOffset + 23).section(" ", 0, 0);
            result.bIsValid = true;
        }
    }

    if (!result.bIsValid) {
        qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "Enigma Protector", pPdStruct);

        if (_nOffset != -1) {
            // TODO version
            result.sVersion = "5.XX";
            result.bIsValid = true;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_DeepSea_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "DeepSeaObfuscator", pPdStruct);

    if (_nOffset != -1) {
        // TODO Check
        result.bIsValid = true;
        result.sVersion = "4.X";

        QString sFullString = binary.read_ansiString(_nOffset + 18);

        if (sFullString.contains("Evaluation")) {
            result.sInfo = "Evaluation";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_SmartAssembly_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                           XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "Powered by SmartAssembly ", pPdStruct);

    if (_nOffset != -1) {
        result.bIsValid = true;
        result.sVersion = binary.read_ansiString(_nOffset + 25);
        // TODO more checks!
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_R8_marker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                       XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java
    // X~~D8{"compilation-mode":"release","has-checksums":false,"min-api":14,"version":"2.0.88"}
    // h~~D8{"backend":"dex","compilation-mode":"release","has-checksums":false,"min-api":28,"version":"8.6.17"}
    qint64 _nOffset = binary.find_ansiString(nOffset, nSize, "\"compilation-mode\":\"", pPdStruct);

    if (_nOffset > 20)  // TODO rewrite
    {
        _nOffset = binary.find_ansiString(_nOffset - 21, 20, "~~", pPdStruct);

        if (_nOffset != -1) {
            result.bIsValid = true;
            QString sString = binary.read_ansiString(_nOffset);

            result.sVersion = XBinary::regExp("\"version\":\"(.*?)\"", sString, 1);

            if (sString.contains("~~D8") || sString.contains("~~R8")) {
                result.sInfo = XBinary::regExp("\"compilation-mode\":\"(.*?)\"", sString, 1);
            } else {
                result.sInfo = "CHECK D8: " + sString;
            }
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Go_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 _nOffset = nOffset;
    qint64 _nSize = nSize;

    QString sVersion;

    qint64 nMaxVersion = 0;

    while ((_nSize > 0) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _nOffset = binary.find_ansiString(_nOffset, _nSize, "go1.", pPdStruct);

        if (_nOffset == -1) {
            break;
        }

        QString _sVersion = XBinary::getVersionString(binary.read_ansiString(_nOffset + 2, 10));

        qint64 nVersionValue = XBinary::getVersionIntValue(_sVersion);

        if (nVersionValue > nMaxVersion) {
            nMaxVersion = nVersionValue;

            sVersion = _sVersion;
        }

        _nOffset++;

        _nSize = nSize - (_nOffset - nOffset) - 1;
    }

    if (sVersion != "") {
        result.bIsValid = true;
        result.sVersion = sVersion;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Rust_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO version
    qint64 nOffset_Version = -1;

    if (nOffset_Version == -1) {
        // TODO false positives in die.exe
        nOffset_Version = binary.find_ansiString(nOffset, nSize, "Local\\RustBacktraceMutex", pPdStruct);

        if (nOffset_Version != -1) {
            result.bIsValid = true;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_ObfuscatorLLVM_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                            XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = -1;

    if (nOffset_Version == -1) {
        nOffset_Version = binary.find_ansiString(nOffset, nSize, "Obfuscator-", pPdStruct);  // 3.4 - 6.0.0

        if (nOffset_Version != -1) {
            QString sVersionString = binary.read_ansiString(nOffset_Version);

            result = _get_ObfuscatorLLVM_string(sVersionString);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ObfuscatorLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Obfuscator-clang version") ||     // 3.4
        sString.contains("Obfuscator- clang version") ||    // 3.51
        sString.contains("Obfuscator-LLVM clang version"))  // 3.6.1 - 6.0.0
    {
        result.bIsValid = true;

        result.sVersion = sString.section("version ", 1, 1).section("(", 0, 0).section(" ", 0, 0);
        //        result.sVersion=sString.section("version ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_AndroidClang_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                          XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "Android clang", pPdStruct);

    if (nOffset_Version != -1) {
        QString sVersionString = binary.read_ansiString(nOffset_Version);

        result = _get_AndroidClang_string(sVersionString);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AndroidClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Android clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    } else if (sString.contains("Android (") && sString.contains(" clang version ")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" clang version ", 1, 1).section(" ", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AlipayClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Alipay clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AlpineClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Alpine clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AlibabaClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Alibaba clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_PlexClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Plex clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_UbuntuClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Ubuntu clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DebianClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Debian clang")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AlipayObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Alipay")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);

        if (sString.contains("Trial")) {
            result.sInfo = "Trial";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_wangzehuaLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("wangzehua  clang version")) {
        result.bIsValid = true;

        result.sVersion = sString.section("wangzehua  clang version", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ByteGuard_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ByteGuard")) {
        result.bIsValid = true;

        result.sVersion = sString.section("ByteGuard ", 1, 1).section("-", 0, 0).section(")", 0, 0);
    } else if (sString.contains("Byteguard")) {
        result.bIsValid = true;

        result.sVersion = sString.section("Byteguard ", 1, 1).section("-", 0, 0).section(")", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_TencentObfuscation_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Tencent-Obfuscation Compiler")) {
        // TODO Version
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AppImage_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("AppImage by Simon Peter, http://appimage.org/")) {
        // TODO Version
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_HikariObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("HikariObfuscator") || sString.contains("_Hikari") || sString.contains("Hikari.git")) {
        // TODO Version
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SnapProtect_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("snap.protect version ")) {
        result.sVersion = sString.section("snap.protect version ", 1, 1).section(" ", 0, 0);
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ByteDanceSecCompiler_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ByteDance-SecCompiler")) {
        // TODO Version
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DingbaozengNativeObfuscator_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("dingbaozeng/native_obfuscator.git")) {
        // TODO Version
        result.bIsValid = true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SafeengineLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Safengine clang version")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_NagainLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};
    // http://www.nagain.com/
    if (sString.contains("Nagain-LLVM clang version")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_iJiami_string(const QString &sString)
{
    VI_STRUCT result = {};
    // https://www.ijiami.cn/
    if (sString.contains("ijiami LLVM Compiler- clang version")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 5, 5);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AppleLLVM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Apple LLVM version")) {
        result.bIsValid = true;

        result.sVersion = sString.section("Apple LLVM version ", 1, 1).section(" ", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ApportableClang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Apportable clang version")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 3, 3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMAssembler_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM Assembler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMLinker_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM Linker,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1).section("]", 0, 0) + "]";
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMC_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM C Compiler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM C/C++ Compiler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMNEONCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM NEON C/C++ Compiler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMThumbCCPP_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM/Thumb C/C++ Compiler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMThumbMacroAssembler_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ARM/Thumb Macro Assembler")) {
        result.bIsValid = true;

        if (sString.contains("vsn ")) {
            result.sVersion = sString.section("vsn ", 1, -1);
        } else {
            result.sVersion = sString.section(", ", 1, -1);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ThumbC_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("Thumb C Compiler,")) {
        result.bIsValid = true;

        result.sVersion = sString.section(", ", 1, -1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_clang_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^clang version", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 2, 2);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DynASM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("DynASM")) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_Delphi_string(const QString &sString)
{
    VI_STRUCT result = {};

    // Embarcadero Delphi for Android compiler version
    if (XBinary::isRegExpPresent("^Embarcadero Delphi for", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("version ", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_LLD_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^Linker: LLD", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("Linker: LLD ", 1, 1).section("(", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_mold_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^mold ", sString)) {
        // TODO version
        result.bIsValid = true;

        //        result.sVersion=sString.section("mold ",1,1).section("(",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_OracleSolarisLinkEditors_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^ld: Software Generation Utilities - Solaris Link Editors:", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("Solaris Link Editors: ", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SunWorkShop_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("Sun WorkShop", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("Sun WorkShop ", 1, 1).section(" ", 0, 1).section("\r", 0, 0).section("\n", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SunWorkShopCompilers_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("WorkShop Compilers", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("WorkShop Compilers ", 1, 1).section("\r", 0, 0).section("\n", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SnapdragonLLVMARM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^Snapdragon LLVM ARM Compiler", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section(" ", 4, 4);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_NASM_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^The Netwide Assembler", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("The Netwide Assembler ", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_TencentLegu_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^legu", sString)) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_OllvmTll_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("ollvm-tll.git")) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DelphiVersionFromCompiler(const QString &sString)
{
    VI_STRUCT result = {};

    QString _sString = sString.section(" ", 0, 0);

    if (_sString != "") {
        result.bIsValid = true;

        result.sVersion = "12.x Athens++";

        if (_sString == "28.0") {
            result.sVersion = "XE7";
        } else if (_sString == "29.0") {
            result.sVersion = "XE8";
        } else if (_sString == "30.0") {
            result.sVersion = "10 Seattle";
        } else if (_sString == "31.0") {
            result.sVersion = "10.1 Berlin";
        } else if (_sString == "32.0") {
            result.sVersion = "10.2 Tokyo";
        } else if (_sString == "33.0") {
            result.sVersion = "10.3 Rio";
        } else if (_sString == "34.0") {
            result.sVersion = "10.4 Sydney";
        } else if (_sString == "35.0") {
            result.sVersion = "11.0 Alexandria";
        } else if (_sString == "36.0") {
            result.sVersion = "12.0 Athens";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SourceryCodeBench_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("Sourcery CodeBench Lite ", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("Sourcery CodeBench Lite ", 1, 1).section(")", 0, 0);
        result.sInfo = "lite";
    } else if (XBinary::isRegExpPresent("Sourcery CodeBench ", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("Sourcery CodeBench ", 1, 1).section(")", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_Rust_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (XBinary::isRegExpPresent("^rustc ", sString)) {
        result.bIsValid = true;

        result.sVersion = sString.section("rustc version ", 1, 1).section(" ", 0, 0);
    }

    return result;
}

void SpecAbstract::_handleResult(BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct)
{
    getLanguage(&(pBasic_info->mapResultLinkers), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultCompilers), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultLibraries), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultTools), &(pBasic_info->mapResultLanguages), pPdStruct);
    getLanguage(&(pBasic_info->mapResultPackers), &(pBasic_info->mapResultLanguages), pPdStruct);

    fixLanguage(&(pBasic_info->mapResultLanguages));

    pBasic_info->listDetects.append(pBasic_info->mapResultOperationSystems.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultFormats.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDosExtenders.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLinkers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultCompilers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLanguages.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLibraries.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultTools.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultPackers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSFX.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultProtectors.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultAPKProtectors.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDongleProtection.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSigntools.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultInstallers.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultJoiners.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultPETools.values());

    pBasic_info->listDetects.append(pBasic_info->mapResultTexts.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultArchives.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultCertificates.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDebugData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultInstallerData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultSFXData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultProtectorData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultLibraryData.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultResources.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultDatabases.values());
    pBasic_info->listDetects.append(pBasic_info->mapResultImages.values());
}

SpecAbstract::BINARYINFO_STRUCT SpecAbstract::getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions,
                                                            qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    BINARYINFO_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);
    binary.setFileType(fileType);

    if (binary.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&binary, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        // Scan Header
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _binary_records, sizeof(_binary_records), result.basic_info.id.fileType,
                      XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _archive_records, sizeof(_archive_records), result.basic_info.id.fileType,
                      XBinary::FT_ARCHIVE, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _COM_records, sizeof(_COM_records), result.basic_info.id.fileType,
                      XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureExpScan(&binary, &(result.basic_info.memoryMap), &result.basic_info.mapHeaderDetects, 0, _COM_Exp_records, sizeof(_COM_Exp_records),
                         result.basic_info.id.fileType, XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_OVERLAY) {
            signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _PE_overlay_records, sizeof(_PE_overlay_records),
                          result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_DEBUGDATA) {
            signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _debugdata_records, sizeof(_debugdata_records),
                          result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_DEBUGDATA, pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            //            signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _PE_resource_records, sizeof(_PE_resource_records),
            //                          result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

            // TODO a function

            if (result.basic_info.mapHeaderDetects.count() == 0) {
                _SCANS_STRUCT ss = {};
                ss.fileType = result.basic_info.id.fileType;
                ss.type = RECORD_TYPE_FORMAT;

                quint32 nId = pOptions->varInfo.toUInt();

                if (nId == XPE_DEF::S_RT_DIALOG) {
                    ss.name = RECORD_NAME_RESOURCE_DIALOG;
                } else if (nId == XPE_DEF::S_RT_STRING) {
                    ss.name = RECORD_NAME_RESOURCE_STRINGTABLE;
                } else if (nId == XPE_DEF::S_RT_VERSION) {
                    ss.name = RECORD_NAME_RESOURCE_VERSIONINFO;
                } else if (nId == XPE_DEF::S_RT_ICON) {
                    ss.name = RECORD_NAME_RESOURCE_ICON;
                } else if (nId == XPE_DEF::S_RT_CURSOR) {
                    ss.name = RECORD_NAME_RESOURCE_CURSOR;
                } else if (nId == XPE_DEF::S_RT_MENU) {
                    ss.name = RECORD_NAME_RESOURCE_MENU;
                }

                if (ss.name != RECORD_NAME_UNKNOWN) {
                    result.basic_info.mapHeaderDetects.insert(ss.name, ss);
                }
            }
        }

        // TODO header data!
        result.bIsPlainText = binary.isPlainTextType();
        result.bIsUTF8 = binary.isUTF8TextType();
        result.unicodeType = binary.getUnicodeType();

        // TODO Try QTextStream functions! Check
        if (result.unicodeType != XBinary::UNICODE_TYPE_NONE) {
            result.sHeaderText = binary.read_unicodeString(2, qMin(result.basic_info.id.nSize, (qint64)0x1000), (result.unicodeType == XBinary::UNICODE_TYPE_BE));
            result.basic_info.id.fileType = XBinary::FT_UNICODE;
        } else if (result.bIsUTF8) {
            result.sHeaderText = binary.read_utf8String(3, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_UTF8;
        } else if (result.bIsPlainText) {
            result.sHeaderText = binary.read_ansiString(0, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_PLAINTEXT;
        }

        Binary_handle_Texts(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Formats(pDevice, pOptions, &result);
        Binary_handle_Databases(pDevice, pOptions, &result);
        Binary_handle_Images(pDevice, pOptions, &result);
        Binary_handle_Archives(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Certificates(pDevice, pOptions, &result);
        Binary_handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_InstallerData(pDevice, pOptions, &result);
        Binary_handle_SFXData(pDevice, pOptions, &result);
        Binary_handle_ProtectorData(pDevice, pOptions, &result);
        Binary_handle_LibraryData(pDevice, pOptions, &result);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            Binary_handle_Resources(pDevice, pOptions, &result);
        }

        Binary_handle_FixDetects(pDevice, pOptions, &result);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::COMINFO_STRUCT SpecAbstract::getCOMInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    COMINFO_STRUCT result = {};

    XCOM com(pDevice, pOptions->bIsImage);

    if (com.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&com, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        // Scan Header
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _COM_records, sizeof(_COM_records), result.basic_info.id.fileType,
                      XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureExpScan(&com, &(result.basic_info.memoryMap), &result.basic_info.mapHeaderDetects, 0, _COM_Exp_records, sizeof(_COM_Exp_records),
                         result.basic_info.id.fileType, XBinary::FT_COM, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        if (pOptions->bIsVerbose) {
            COM_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        }

        COM_handle_Protection(pDevice, pOptions, &result, pPdStruct);

        if (result.basic_info.mapResultProtectors.size() || result.basic_info.mapResultPackers.size()) {
            //            _SCANS_STRUCT ssOperationSystem=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_OPERATIONSYSTEM,RECORD_NAME_MSDOS,"","",0);

            //            result.mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pCOMInfo->basic_info),&ssOperationSystem));

            _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(com.getFileFormatInfo(pPdStruct));

            result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(result.basic_info), &ssOperationSystem));
        }

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::MSDOSINFO_STRUCT SpecAbstract::getMSDOSInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                          XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    MSDOSINFO_STRUCT result = {};

    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&msdos, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.nOverlayOffset = msdos.getOverlayOffset(&(result.basic_info.memoryMap), pPdStruct);
        result.nOverlaySize = msdos.getOverlaySize(&(result.basic_info.memoryMap), pPdStruct);

        if (result.nOverlaySize) {
            result.sOverlaySignature = msdos.getSignature(result.nOverlayOffset, 150);
        }

        result.nEntryPointOffset = msdos.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = msdos.getSignature(msdos.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_linker_header_records, sizeof(_MSDOS_linker_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_header_records, sizeof(_MSDOS_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, _MSDOS_entrypoint_records, sizeof(_MSDOS_entrypoint_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);

        signatureExpScan(&msdos, &(result.basic_info.memoryMap), &result.basic_info.mapEntryPointDetects, result.nEntryPointOffset, _MSDOS_entrypointExp_records,
                         sizeof(_MSDOS_entrypointExp_records), result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);

        MSDOS_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        MSDOS_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        MSDOS_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        MSDOS_handle_Protection(pDevice, pOptions, &result, pPdStruct);
        MSDOS_handle_SFX(pDevice, pOptions, &result, pPdStruct);
        MSDOS_handle_DosExtenders(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::ELFINFO_STRUCT SpecAbstract::getELFInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    ELFINFO_STRUCT result = {};

    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&elf, parentId, pOptions, nOffset, pPdStruct);

        result.bIs64 = elf.is64();
        result.bIsBigEndian = elf.isBigEndian();

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

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

        signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, _ELF_entrypoint_records, sizeof(_ELF_entrypoint_records),
                      result.basic_info.id.fileType, XBinary::FT_ELF, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);

        ELF_handle_CommentSection(pDevice, pOptions, &result, pPdStruct);

        ELF_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        ELF_handle_GCC(pDevice, pOptions, &result, pPdStruct);
        ELF_handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        ELF_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        ELF_handle_Protection(pDevice, pOptions, &result, pPdStruct);

        ELF_handle_UnknownProtection(pDevice, pOptions, &result, pPdStruct);

        ELF_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::MACHOINFO_STRUCT SpecAbstract::getMACHOInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                          XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    MACHOINFO_STRUCT result = {};

    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&mach, parentId, pOptions, nOffset, pPdStruct);

        result.bIs64 = mach.is64();
        result.bIsBigEndian = mach.isBigEndian();

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.sEntryPointSignature = mach.getSignature(mach.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        result.listCommandRecords = mach.getCommandRecords();

        result.listLibraryRecords = mach.getLibraryRecords(&result.listCommandRecords, XMACH_DEF::S_LC_LOAD_DYLIB);
        result.listSegmentRecords = mach.getSegmentRecords(&result.listCommandRecords);
        result.listSectionRecords = mach.getSectionRecords(&result.listCommandRecords);

        // TODO Segments
        // TODO Sections

        MACHO_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        MACHO_handle_Protection(pDevice, pOptions, &result, pPdStruct);

        MACHO_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::LEINFO_STRUCT SpecAbstract::getLEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    LEINFO_STRUCT result = {};

    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&le, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.nEntryPointOffset = le.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = le.getSignature(le.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        result.listRichSignatures = le.getRichSignatureRecords();

        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_linker_header_records, sizeof(_MSDOS_linker_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        LE_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        LE_handle_Microsoft(pDevice, pOptions, &result, pPdStruct);
        LE_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        LE_handle_Tools(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::LXINFO_STRUCT SpecAbstract::getLXInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    LXINFO_STRUCT result = {};

    XLE lx(pDevice, pOptions->bIsImage);

    if (lx.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&lx, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.nEntryPointOffset = lx.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = lx.getSignature(lx.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        result.listRichSignatures = lx.getRichSignatureRecords();

        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_linker_header_records, sizeof(_MSDOS_linker_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        LX_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        LX_handle_Microsoft(pDevice, pOptions, &result, pPdStruct);
        LX_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        LX_handle_Tools(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::NEINFO_STRUCT SpecAbstract::getNEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    NEINFO_STRUCT result = {};

    XNE ne(pDevice, pOptions->bIsImage);

    if (ne.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&ne, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.nEntryPointOffset = ne.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = ne.getSignature(ne.getEntryPointOffset(&(result.basic_info.memoryMap)), 150);

        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_linker_header_records, sizeof(_MSDOS_linker_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

        NE_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        NE_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        NE_handle_Tools(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::PEINFO_STRUCT SpecAbstract::getPEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    PEINFO_STRUCT result = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&pe, parentId, pOptions, nOffset, pPdStruct);

        result.bIs64 = pe.is64();

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.nEntryPointOffset = pe.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = pe.getSignature(result.nEntryPointOffset, 150);

        result.dosHeader = pe.getDosHeaderEx();
        result.fileHeader = pe.getFileHeader();
        result.nOverlayOffset = pe.getOverlayOffset(pPdStruct);
        result.nOverlaySize = pe.getOverlaySize(pPdStruct);

        if (result.nOverlaySize) {
            result.sOverlaySignature = pe.getSignature(result.nOverlayOffset, 150);
        }

        if (result.bIs64) {
            result.optional_header.optionalHeader64 = pe.getOptionalHeader64();
        } else {
            result.optional_header.optionalHeader32 = pe.getOptionalHeader32();
        }

        result.listSectionHeaders = pe.getSectionHeaders(pPdStruct);
        result.listSectionRecords = pe.getSectionRecords(&result.listSectionHeaders, pPdStruct);
        result.listSectionNames = XPE::getSectionNames(&(result.listSectionRecords), pPdStruct);

        result.listImports = pe.getImports(&(result.basic_info.memoryMap));
        result.listImportRecords = pe.getImportRecords(&(result.basic_info.memoryMap));
        //        for(qint32 i=0;i<result.listImports.count();i++)
        //        {
        //            qDebug(result.listImports.at(i).sName.toLatin1().data());
        //            for(qint32 j=0;j<result.listImports.at(i).listPositions.count();j++)
        //            {
        //                qDebug("%d %s",j,result.listImports.at(i).listPositions.at(j).sFunction.toLatin1().data());
        //            }
        //        }
        result.nImportHash64 = pe.getImportHash64(&(result.listImportRecords), pPdStruct);
        result.nImportHash32 = pe.getImportHash32(&(result.listImportRecords), pPdStruct);
        result.listImportPositionHashes = pe.getImportPositionHashes(&(result.listImports));

#ifdef QT_DEBUG
        QString sDebugString = QString::number(result.nImportHash64, 16) + " " + QString::number(result.nImportHash32, 16);
        qDebug("Import hash: %s", sDebugString.toLatin1().data());

        QList<XPE::IMPORT_RECORD> listImports = pe.getImportRecords(&(result.basic_info.memoryMap));

        qint32 _nNumberOfImports = listImports.count();

        for (qint32 i = 0; (i < _nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            QString sRecord = listImports.at(i).sLibrary + " " + listImports.at(i).sFunction;

            qDebug("%s", sRecord.toLatin1().data());
        }

        qDebug("=====================================================================");

        QList<quint32> listImportPositionHashesOld = pe.getImportPositionHashes(&(result.listImports), true);

        QList<XPE::IMPORT_HEADER> listImportHeaders = pe.getImports(&(result.basic_info.memoryMap));

        for (qint32 i = 0; (i < listImportHeaders.count()) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            qDebug("Import hash: %x", result.listImportPositionHashes.at(i));
            qDebug("Import hash(OLD): %x", listImportPositionHashesOld.at(i));
            for (qint32 j = 0; (j < listImportHeaders.at(i).listPositions.count()) && (XBinary::isPdStructNotCanceled(pPdStruct)); j++) {
                qDebug("%s %s", listImportHeaders.at(i).sName.toLatin1().data(), listImportHeaders.at(i).listPositions.at(j).sFunction.toLatin1().data());
            }
        }
#endif
        result.exportHeader = pe.getExport(&(result.basic_info.memoryMap), false, pPdStruct);
        result.listExportFunctionNames = pe.getExportFunctionsList(&(result.exportHeader), pPdStruct);
        result.listResources = pe.getResources(&(result.basic_info.memoryMap), 10000, pPdStruct);
        result.listRichSignatures = pe.getRichSignatureRecords(pPdStruct);
        result.cliInfo = pe.getCliInfo(true, &(result.basic_info.memoryMap), pPdStruct);
        result.listAnsiStrings = pe.getAnsiStrings(&(result.cliInfo), pPdStruct);
        result.listUnicodeStrings = pe.getUnicodeStrings(&(result.cliInfo), pPdStruct);
        result.sResourceManifest = pe.getResourceManifest(&result.listResources);
        result.resVersion = pe.getResourcesVersion(&result.listResources, pPdStruct);

        result.nEntryPointAddress =
            result.bIs64 ? result.optional_header.optionalHeader64.AddressOfEntryPoint : result.optional_header.optionalHeader32.AddressOfEntryPoint;
        result.nImageBaseAddress = result.bIs64 ? result.optional_header.optionalHeader64.ImageBase : result.optional_header.optionalHeader32.ImageBase;
        result.nMinorLinkerVersion =
            result.bIs64 ? result.optional_header.optionalHeader64.MinorLinkerVersion : result.optional_header.optionalHeader32.MinorLinkerVersion;
        result.nMajorLinkerVersion =
            result.bIs64 ? result.optional_header.optionalHeader64.MajorLinkerVersion : result.optional_header.optionalHeader32.MajorLinkerVersion;
        result.nMinorImageVersion = result.bIs64 ? result.optional_header.optionalHeader64.MinorImageVersion : result.optional_header.optionalHeader32.MinorImageVersion;
        result.nMajorImageVersion = result.bIs64 ? result.optional_header.optionalHeader64.MajorImageVersion : result.optional_header.optionalHeader32.MajorImageVersion;

        result.nEntryPointSection = pe.getEntryPointSection(&(result.basic_info.memoryMap));
        result.nResourcesSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE);
        result.nImportSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);
        result.nCodeSection = pe.getNormalCodeSection(&(result.basic_info.memoryMap));
        result.nDataSection = pe.getNormalDataSection(&(result.basic_info.memoryMap));
        result.nConstDataSection = pe.getConstDataSection(&(result.basic_info.memoryMap));
        result.nRelocsSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC);
        result.nTLSSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS);
        result.nIATSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT);

        result.bIsNetPresent = ((result.cliInfo.bValid) || (pe.isNETPresent() && (result.basic_info.scanOptions.bIsDeepScan)));
        result.bIsTLSPresent = (result.nTLSSection != -1);

        if (result.nEntryPointSection != -1) {
            result.sEntryPointSectionName = result.listSectionRecords.at(result.nEntryPointSection).sName;
        }

        //        result.mmCodeSectionSignatures=memoryScan(pDevice,nFirstSectionOffset,qMin((qint64)0x10000,nFirstSectionSize),_memory_records,sizeof(_memory_records),_filetype,SpecAbstract::XBinary::FT_PE);
        //        if(result.nCodeSection!=-1)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.listSections.at(result.nCodeSection).PointerToRawData,result.listSections.at(result.nCodeSection).SizeOfRawData,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        result.osHeader.nOffset = 0;
        result.osHeader.nSize = qMin(result.basic_info.id.nSize, (qint64)2048);

        if (result.nCodeSection != -1) {
            result.osCodeSection.nOffset = result.listSectionRecords.at(result.nCodeSection).nOffset;
            result.osCodeSection.nSize = result.listSectionRecords.at(result.nCodeSection).nSize;  // TODO limit?
        }

        if (result.nDataSection != -1) {
            result.osDataSection.nOffset = result.listSectionRecords.at(result.nDataSection).nOffset;
            result.osDataSection.nSize = result.listSectionRecords.at(result.nDataSection).nSize;
        }

        if (result.nConstDataSection != -1) {
            result.osConstDataSection.nOffset = result.listSectionRecords.at(result.nConstDataSection).nOffset;
            result.osConstDataSection.nSize = result.listSectionRecords.at(result.nConstDataSection).nSize;
        }

        if (result.nEntryPointSection != -1) {
            result.osEntryPointSection.nOffset = result.listSectionRecords.at(result.nEntryPointSection).nOffset;
            result.osEntryPointSection.nSize = result.listSectionRecords.at(result.nEntryPointSection).nSize;
        }

        if (result.nImportSection != -1) {
            result.osImportSection.nOffset = result.listSectionRecords.at(result.nImportSection).nOffset;
            result.osImportSection.nSize = result.listSectionRecords.at(result.nImportSection).nSize;
        }

        if (result.nResourcesSection != -1) {
            result.osResourcesSection.nOffset = result.listSectionRecords.at(result.nResourcesSection).nOffset;
            result.osResourcesSection.nSize = result.listSectionRecords.at(result.nResourcesSection).nSize;
        }

        //        if(result.nCodeSectionSize)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.nCodeSectionOffset,result.nCodeSectionSize,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        if(result.nDataSectionSize)
        //        {
        //            memoryScan(&result.mapDataSectionScanDetects,pDevice,result.nDataSectionOffset,result.nDataSectionSize,_datasectionscan_records,sizeof(_datasectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        // TODO Check if resources exists

        //        memoryScan(&result.mapHeaderScanDetects,pDevice,0,qMin(result.basic_info.nSize,(qint64)1024),_headerscan_records,sizeof(_headerscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);

        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _MSDOS_linker_header_records, sizeof(_MSDOS_linker_header_records),
                      result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _PE_header_records, sizeof(_PE_header_records),
                      result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, _PE_entrypoint_records, sizeof(_PE_entrypoint_records),
                      result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
        signatureExpScan(&pe, &(result.basic_info.memoryMap), &result.basic_info.mapEntryPointDetects, result.nEntryPointOffset, _PE_entrypointExp_records,
                         sizeof(_PE_entrypointExp_records), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
        signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, _binary_records, sizeof(_binary_records), result.basic_info.id.fileType,
                      XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);
        signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, _archive_records, sizeof(_archive_records), result.basic_info.id.fileType,
                      XBinary::FT_ARCHIVE, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);
        signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, _PE_overlay_records, sizeof(_PE_overlay_records), result.basic_info.id.fileType,
                      XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);

        stringScan(&result.basic_info.mapSectionNamesDetects, &result.listSectionNames, _PE_sectionNames_records, sizeof(_PE_sectionNames_records),
                   result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_SECTIONNAME, pPdStruct);

        // Import
        constScan(&(result.basic_info.mapImportDetects), result.nImportHash64, result.nImportHash32, _PE_importhash_records, sizeof(_PE_importhash_records),
                  result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH, pPdStruct);

        constScan(&(result.basic_info.mapImportDetects), result.nImportHash64, result.nImportHash32, _PE_importhash_records_armadillo,
                  sizeof(_PE_importhash_records_armadillo), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH, pPdStruct);

        // Export
        qint32 nNumberOfImports = result.listImportPositionHashes.count();

        for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            constScan(&(result.basic_info.mapImportDetects), i, result.listImportPositionHashes.at(i), _PE_importpositionhash_records,
                      sizeof(_PE_importpositionhash_records), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH, pPdStruct);
        }

        // TODO Resources scan
        PE_resourcesScan(&(result.basic_info.mapResourcesDetects), &(result.listResources), _PE_resources_records, sizeof(_PE_resources_records),
                         result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_RESOURCES, pPdStruct);

        PE_x86Emul(pDevice, pOptions, &result, pPdStruct);

        // Rich
        //        qint32 nNumberOfRichSignatures=result.listRichSignatures.count();

        //        for(qint32 i=0;i<nNumberOfRichSignatures;i++)
        //        {
        //            PE_richScan(&(result.mapRichDetects),result.listRichSignatures.at(i).nId,result.listRichSignatures.at(i).nVersion,_PE_rich_records,sizeof(_PE_rich_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        for(qint32 i=0;i<result.listImports.count();i++)
        //        {
        //            signatureScan(&result._mapImportDetects,QBinary::stringToHex(result.listImports.at(i).sName.toUpper()),_import_records,sizeof(_import_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        for(qint32 i=0;i<result.export_header.listPositions.count();i++)
        //        {
        //            signatureScan(&result.mapExportDetects,QBinary::stringToHex(result.export_header.listPositions.at(i).sFunctionName),_export_records,sizeof(_export_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        resourcesScan(&result.mapResourcesDetects,&result.listResources,_resources_records,sizeof(_resources_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);

        if (result.bIsNetPresent) {
            stringScan(&result.basic_info.mapDotAnsiStringsDetects, &result.listAnsiStrings, _PE_dot_ansistrings_records, sizeof(_PE_dot_ansistrings_records),
                       result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_NETANSISTRING, pPdStruct);
            stringScan(&result.basic_info.mapDotUnicodeStringsDetects, &result.listUnicodeStrings, _PE_dot_unicodestrings_records, sizeof(_PE_dot_unicodestrings_records),
                       result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_NETUNICODESTRING, pPdStruct);

            //            for(qint32 i=0;i<result.cliInfo.listUnicodeStrings.count();i++)
            //            {
            //                signatureScan(&result.mapDotUnicodestringsDetects,QBinary::stringToHex(result.cliInfo.listUnicodeStrings.at(i)),_dot_unicodestrings_records,sizeof(_dot_unicodestrings_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
            //            }

            if (result.basic_info.scanOptions.bIsDeepScan) {
                if (pe.checkOffsetSize(result.osCodeSection)) {
                    qint64 nSectionOffset = result.osCodeSection.nOffset;
                    qint64 nSectionSize = result.osCodeSection.nSize;

                    memoryScan(&result.basic_info.mapCodeSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize, _PE_dot_codesection_records,
                               sizeof(_PE_dot_codesection_records), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_CODESECTION,
                               pPdStruct);
                }
            }
        }

        if (result.basic_info.scanOptions.bIsDeepScan) {
            if (pe.checkOffsetSize(result.osCodeSection)) {
                qint64 nSectionOffset = result.osCodeSection.nOffset;
                qint64 nSectionSize = result.osCodeSection.nSize;

                memoryScan(&result.basic_info.mapCodeSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize, _PE_codesection_records,
                           sizeof(_PE_codesection_records), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_CODESECTION, pPdStruct);
            }

            if (pe.checkOffsetSize(result.osEntryPointSection)) {
                qint64 nSectionOffset = result.osEntryPointSection.nOffset;
                qint64 nSectionSize = result.osEntryPointSection.nSize;

                memoryScan(&result.basic_info.mapEntryPointSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize, _PE_entrypointsection_records,
                           sizeof(_PE_entrypointsection_records), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_ENTRYPOINTSECTION,
                           pPdStruct);
            }
        }

        PE_handle_import(pDevice, pOptions, &result, pPdStruct);

        PE_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Protection(pDevice, pOptions, &result, pPdStruct);
        PE_handle_SafeengineShielden(pDevice, pOptions, &result, pPdStruct);
        PE_handle_VProtect(pDevice, pOptions, &result, pPdStruct);
        PE_handle_TTProtect(pDevice, pOptions, &result, pPdStruct);  // TODO remove
        PE_handle_VMProtect(pDevice, pOptions, &result, pPdStruct);
        PE_handle_tElock(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Armadillo(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Obsidium(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Themida(pDevice, pOptions, &result, pPdStruct);
        PE_handle_StarForce(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Petite(pDevice, pOptions, &result, pPdStruct);
        PE_handle_NETProtection(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PolyMorph(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Microsoft(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Watcom(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        PE_handle_wxWidgets(pDevice, pOptions, &result, pPdStruct);
        PE_handle_GCC(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Signtools(pDevice, pOptions, &result, pPdStruct);
        PE_handle_SFX(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Installers(pDevice, pOptions, &result, pPdStruct);
        PE_handle_DongleProtection(pDevice, pOptions, &result, pPdStruct);
        //        PE_handle_AnslymPacker(pDevice,pOptions,&result);
        PE_handle_NeoLite(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PrivateEXEProtector(pDevice, pOptions, &result, pPdStruct);

        PE_handle_VisualBasicCryptors(pDevice, pOptions, &result, pPdStruct);
        PE_handle_DelphiCryptors(pDevice, pOptions, &result, pPdStruct);

        PE_handle_Joiners(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PETools(pDevice, pOptions, &result, pPdStruct);

        PE_handle_DebugData(pDevice, pOptions, &result, pPdStruct);

        if (pOptions->bIsHeuristicScan) {
            PE_handle_UnknownProtection(pDevice, pOptions, &result, pPdStruct);
        }

        PE_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::getDEXInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    DEXINFO_STRUCT result = {};

    XDEX dex(pDevice);

    if (dex.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&dex, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.header = dex.getHeader();
        result.mapItems = dex.getMapItems(pPdStruct);

#ifdef QT_DEBUG
        qDebug("%lli msec", timer.elapsed());
#endif

        result.bIsStringPoolSorted = dex.isStringPoolSorted(&(result.mapItems), pPdStruct);
        result.bIsOverlayPresent = dex.isOverlayPresent(&(result.basic_info.memoryMap), pPdStruct);

#ifdef QT_DEBUG
        qDebug("%lli msec", timer.elapsed());
#endif

        result.listStrings = dex.getStrings(&(result.mapItems), pPdStruct);
        result.listTypeItemStrings = dex.getTypeItemStrings(&(result.mapItems), &result.listStrings, pPdStruct);

#ifdef QT_DEBUG
        qDebug("%lli msec", timer.elapsed());
#endif

        stringScan(&result.basic_info.mapStringDetects, &result.listStrings, _DEX_string_records, sizeof(_DEX_string_records), result.basic_info.id.fileType,
                   XBinary::FT_DEX, &(result.basic_info), DETECTTYPE_DEXSTRING, pPdStruct);
        stringScan(&result.basic_info.mapTypeDetects, &result.listTypeItemStrings, _DEX_type_records, sizeof(_DEX_type_records), result.basic_info.id.fileType,
                   XBinary::FT_DEX, &(result.basic_info), DETECTTYPE_DEXTYPE, pPdStruct);

        if (pOptions->bIsDeepScan) {
            //            QList<XDEX_DEF::STRING_ITEM_ID> getList_STRING_ITEM_ID(&mapItems);
            //            QList<XDEX_DEF::TYPE_ITEM_ID> getList_TYPE_ITEM_ID(&mapItems);
            //            QList<XDEX_DEF::PROTO_ITEM_ID> getList_PROTO_ITEM_ID(&mapItems);
            result.listFieldIDs = dex.getList_FIELD_ITEM_ID(&(result.mapItems), pPdStruct);
            result.listMethodIDs = dex.getList_METHOD_ITEM_ID(&(result.mapItems), pPdStruct);
            //            QList<XDEX_DEF::CLASS_ITEM_DEF> getList_CLASS_ITEM_DEF(&mapItems);

#ifdef QT_DEBUG
//            {
//                QList<XDEX_DEF::CLASS_ITEM_DEF> listClasses=dex.getList_CLASS_ITEM_DEF(&mapItems);

//                qint32 nNumberOfItems=listClasses.count();

//                for(qint32 i=0;i<nNumberOfItems;i++)
//                {

//                    QString sString=QString("%1|%2|%3") .arg(XBinary::getStringByIndex(&result.listTypeItemStrings,listClasses.at(i).class_idx))
//                                                        .arg(XBinary::getStringByIndex(&result.listTypeItemStrings,listClasses.at(i).superclass_idx))
//                                                        .arg(XBinary::getStringByIndex(&result.listStrings,listClasses.at(i).source_file_idx));

//                    qDebug(sString.toLatin1().data());
//                }
//            }
//            {
//                QList<XDEX_DEF::METHOD_ITEM_ID> listMethods=dex.getList_METHOD_ITEM_ID(&mapItems);

//                qint32 nNumberOfItems=listMethods.count();

//                for(qint32 i=0;i<nNumberOfItems;i++)
//                {

//                    QString sString=QString("%1|%2") .arg(XBinary::getStringByIndex(&result.listTypeItemStrings,listMethods.at(i).class_idx))
//                                                        .arg(XBinary::getStringByIndex(&result.listStrings,listMethods.at(i).name_idx));

//                    qDebug(sString.toLatin1().data());
//                }
//            }
#endif
        }

        // TODO Check Strings

        DEX_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        DEX_handle_Protection(pDevice, &result, pPdStruct);
        DEX_handle_Dexguard(pDevice, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::ZIPINFO_STRUCT SpecAbstract::getZIPInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    ZIPINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&xzip, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.listArchiveRecords = xzip.getRecords(20000, pPdStruct);

        if (pOptions->fileType == XBinary::FT_UNKNOWN) {
            QSet<XBinary::FT> stFT = XFormats::getFileTypesZIP(pDevice, &(result.listArchiveRecords), pPdStruct);

            result.bIsJAR = stFT.contains(XBinary::FT_JAR);
            result.bIsAPKS = stFT.contains(XBinary::FT_APKS);
            result.bIsIPA = stFT.contains(XBinary::FT_IPA);
        } else if (pOptions->fileType == XBinary::FT_JAR) {
            result.bIsJAR = true;
        } else if (pOptions->fileType == XBinary::FT_IPA) {
            result.bIsIPA = true;
        } else if (pOptions->fileType == XBinary::FT_APKS) {
            result.bIsAPKS = true;
        }

        result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
                           XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);

        if (result.bIsIPA) {
            result.basic_info.id.fileType = XBinary::FT_IPA;
        } else if (result.bIsJAR) {
            result.basic_info.id.fileType = XBinary::FT_JAR;
        } else if (result.bIsAPKS) {
            result.basic_info.id.fileType = XBinary::FT_APKS;
        }

        Zip_handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);
        Zip_handle_Microsoftoffice(pDevice, pOptions, &result, pPdStruct);
        Zip_handle_OpenOffice(pDevice, pOptions, &result, pPdStruct);

        if (result.bIsJAR) {
            Zip_handle_JAR(pDevice, pOptions, &result, pPdStruct);
        }

        if (result.bIsIPA) {
            Zip_handle_IPA(pDevice, pOptions, &result, pPdStruct);
        }

        Zip_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::APKINFO_STRUCT SpecAbstract::getAPKInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    APKINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&xzip, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.listArchiveRecords = xzip.getRecords(20000, pPdStruct);

        result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
                           XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);

        archiveScan(&(result.basic_info.mapArchiveDetects), &(result.listArchiveRecords), _APK_file_records, sizeof(_APK_file_records), result.basic_info.id.fileType,
                    XBinary::FT_APK, &(result.basic_info), DETECTTYPE_ARCHIVE, pPdStruct);
        archiveExpScan(&(result.basic_info.mapArchiveDetects), &(result.listArchiveRecords), _APK_fileExp_records, sizeof(_APK_fileExp_records),
                       result.basic_info.id.fileType, XBinary::FT_APK, &(result.basic_info), DETECTTYPE_ARCHIVE, pPdStruct);

        if (XArchive::isArchiveRecordPresent("classes.dex", &(result.listArchiveRecords), pPdStruct)) {
            result.dexInfoClasses = APK_scan_DEX(pDevice, pOptions, &result, pPdStruct, "classes.dex");
        }

        Zip_handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);

        APK_handle(pDevice, pOptions, &result, pPdStruct);
        APK_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::AMIGAHUNKINFO_STRUCT SpecAbstract::getAmigaHunkInfo(QIODevice *pDevice, SCANID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                                  XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    AMIGAHUNKINFO_STRUCT result = {};

    XPDF amigaHunk(pDevice);

    if (amigaHunk.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = _initBasicInfo(&amigaHunk, parentId, pOptions, nOffset, pPdStruct);

        AmigaHunk_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);

        _handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::getScansStruct(quint32 nVariant, XBinary::FT fileType, SpecAbstract::RECORD_TYPE type, SpecAbstract::RECORD_NAME name,
                                                         const QString &sVersion, const QString &sInfo, qint64 nOffset)
{
    // TODO bIsHeuristic;
    _SCANS_STRUCT result = {};

    result.nVariant = nVariant;
    result.fileType = fileType;
    result.type = type;
    result.name = name;
    result.sVersion = sVersion;
    result.sInfo = sInfo;
    result.nOffset = nOffset;

    return result;
}

void SpecAbstract::PE_handle_import(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)
    // Import Check

    // #ifdef QT_DEBUG
    //     for(qint32 j=0;j<pPEInfo->listImports.count();j++)
    //     {
    //         for(qint32 i=0;i<pPEInfo->listImports.at(j).listPositions.count();i++)
    //         {
    //             qDebug("(pPEInfo->listImports.at(%d).listPositions.at(%d).sName==\"%s\")&&",j,i,pPEInfo->listImports.at(j).listPositions.at(i).sName.toLatin1().data());
    //         }
    //     }
    // #endif

    QSet<QString> stDetects;

    if (pPEInfo->listImports.count() >= 1) {
        if (pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 2) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "LoadLibraryA")) {
                    stDetects.insert("kernel32_zprotect");
                }
            } else if (pPEInfo->listImports.at(0).listPositions.count() == 13) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(0).listPositions.at(3).sName == "VirtualFree") &&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName == "ExitProcess") && (pPEInfo->listImports.at(0).listPositions.at(5).sName == "CreateFileA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName == "CloseHandle") && (pPEInfo->listImports.at(0).listPositions.at(7).sName == "WriteFile") &&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName == "GetSystemDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName == "GetFileTime") && (pPEInfo->listImports.at(0).listPositions.at(10).sName == "SetFileTime") &&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName == "GetWindowsDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(12).sName == "lstrcatA")) {
                    if (pPEInfo->listImports.count() == 1) {
                        stDetects.insert("kernel32_alloy0");
                    }
                }
            } else if (pPEInfo->listImports.at(0).listPositions.count() == 15) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(0).listPositions.at(3).sName == "VirtualFree") &&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName == "ExitProcess") && (pPEInfo->listImports.at(0).listPositions.at(5).sName == "CreateFileA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName == "CloseHandle") && (pPEInfo->listImports.at(0).listPositions.at(7).sName == "WriteFile") &&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName == "GetSystemDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName == "GetFileTime") && (pPEInfo->listImports.at(0).listPositions.at(10).sName == "SetFileTime") &&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName == "GetWindowsDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(12).sName == "lstrcatA") && (pPEInfo->listImports.at(0).listPositions.at(13).sName == "FreeLibrary") &&
                    (pPEInfo->listImports.at(0).listPositions.at(14).sName == "GetTempPathA")) {
                    if (pPEInfo->listImports.count() == 1) {
                        stDetects.insert("kernel32_alloy2");
                    }
                }
            }
        } else if (pPEInfo->listImports.at(0).sName.toUpper() == "USER32.DLL") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "MessageBoxA")) {
                    if (pPEInfo->listImports.count() == 2) {
                        stDetects.insert("user32_pespina");
                    }

                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("user32_pespin");
                    }
                }
            }
        } else if (pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).nOrdinal == 1)) {
                    if (pPEInfo->listImports.count() == 1) {
                        stDetects.insert("kernel32_yzpack_b");
                    }
                }
            }
        }
    }

    if (pPEInfo->listImports.count() >= 2) {
        if (pPEInfo->listImports.at(1).sName.toUpper() == "COMCTL32.DLL") {
            if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(1).listPositions.at(0).sName == "InitCommonControls")) {
                    if (pPEInfo->listImports.count() == 2) {
                        stDetects.insert("comctl32_pespina");
                    }

                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("comctl32_pespin");
                    }
                }
            }
        }
    }

    if (pPEInfo->listImports.count() >= 3) {
        if (pPEInfo->listImports.at(2).sName.toUpper() == "KERNEL32.DLL") {
            if (pPEInfo->listImports.at(2).listPositions.count() == 2) {
                if ((pPEInfo->listImports.at(2).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName == "GetProcAddress")) {
                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("kernel32_pespinx");
                    }
                }
            } else if (pPEInfo->listImports.at(2).listPositions.count() == 4) {
                if ((pPEInfo->listImports.at(2).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(2).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(2).listPositions.at(3).sName == "VirtualFree")) {
                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("kernel32_pespin");
                    }
                }
            }
        }
    }

#ifdef QT_DEBUG
    qDebug() << stDetects;
#endif

    // TODO 32/64
    if (stDetects.contains("kernel32_zprotect")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_ZPROTECT, getScansStruct(0, XBinary::FT_PE32, RECORD_TYPE_PROTECTOR, RECORD_NAME_ZPROTECT, "", "", 0));
    }

    if (stDetects.contains("user32_pespina") && stDetects.contains("comctl32_pespina")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_PESPIN, getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PESPIN, "1.0-1.2", "", 0));
    }

    if (stDetects.contains("user32_pespin") && stDetects.contains("comctl32_pespin") && stDetects.contains("kernel32_pespin")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_PESPIN, getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PESPIN, "", "", 0));
    }

    if (stDetects.contains("user32_pespin") && stDetects.contains("comctl32_pespin") && stDetects.contains("kernel32_pespinx")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_PESPIN, getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PESPIN, "1.3X", "", 0));
    }

    if (stDetects.contains("kernel32_alloy0")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_ALLOY, getScansStruct(0, XBinary::FT_PE32, RECORD_TYPE_PROTECTOR, RECORD_NAME_ALLOY, "4.X", "", 0));
    }

    if (stDetects.contains("kernel32_alloy2")) {
        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_ALLOY, getScansStruct(2, XBinary::FT_PE32, RECORD_TYPE_PROTECTOR, RECORD_NAME_ALLOY, "4.X", "", 0));
    }

    //    if(stDetects.contains("kernel32_pecompact2"))
    //    {
    //        pPEInfo->basic_info.mapImportDetects.insert(RECORD_NAME_PECOMPACT,getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_PECOMPACT,"2.X","",0));
    //    }

    // TODO
    // Import
}

void SpecAbstract::PE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(pe.getFileFormatInfo(pPdStruct));

        pPEInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pPEInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::PE_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // MPRESS
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MPRESS)) {
            _SCANS_STRUCT recordMPRESS = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MPRESS);

            qint64 nOffsetMPRESS = pe.find_ansiString(0x1f0, 16, "v", pPdStruct);

            if (nOffsetMPRESS != -1) {
                // TODO Check!
                recordMPRESS.sVersion = pe.read_ansiString(nOffsetMPRESS + 1, 0x1ff - nOffsetMPRESS);
            }

            pPEInfo->basic_info.mapResultPackers.insert(recordMPRESS.name, scansToScan(&(pPEInfo->basic_info), &recordMPRESS));
        }

        if (XPE::isImportLibraryPresent("KeRnEl32.dLl", &(pPEInfo->listImports))) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_HYPERTECHCRACKPROOF, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Spoon Studio
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Spoon Studio 2011")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_SPOONSTUDIO2011, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ", ".");
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Spoon Studio")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_SPOONSTUDIO, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ", ".");
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2009")) {
            // Xenocode Virtual Application Studio 2009
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010 ISV Edition")) {
            // Xenocode Virtual Application Studio 2010 (ISV Edition)
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2012 ISV Edition")) {
            // Xenocode Virtual Application Studio 2012 (ISV Edition)
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2013 ISV Edition")) {
            // Xenocode Virtual Application Studio 2013 (ISV Edition)
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Turbo Studio")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_TURBOSTUDIO, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SPOONSTUDIO)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_SPOONSTUDIO, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_XENOCODE)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODE, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("SerGreen")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PACKER, RECORD_NAME_SERGREENAPPACKER, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // MoleBox Ultra
        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_MOLEBOXULTRA)) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_MOLEBOXULTRA)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_MOLEBOXULTRA);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // NativeCryptor by DosX
        if (pPEInfo->listSectionNames.count() >= 3) {
            if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_NATIVECRYPTORBYDOSX)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_NATIVECRYPTORBYDOSX, "", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ACTIVEMARK)) {
            _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_ACTIVEMARK);
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ACTIVEMARK, ssOverlay.sVersion, ssOverlay.sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SECUROM)) {
            // TODO Version
            _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_SECUROM);
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_SECUROM, ssOverlay.sVersion, ssOverlay.sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_ENIGMAVIRTUALBOX)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_ENIGMAVIRTUALBOX);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ZLIB)) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = get_PyInstaller_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PACKER, RECORD_NAME_PYINSTALLER, "", "", 0);

                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (!pPEInfo->cliInfo.bValid) {
            // TODO MPRESS import

            // UPX
            // TODO 32-64
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UPX)) {
                VI_STRUCT viUPX = get_UPX_vi(pDevice, pOptions, pPEInfo->osHeader.nOffset, pPEInfo->osHeader.nSize, XBinary::FT_PE, pPdStruct);

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_UPX)) {
                    if ((viUPX.bIsValid)) {
                        _SCANS_STRUCT recordUPX = {};

                        recordUPX.type = RECORD_TYPE_PACKER;
                        recordUPX.name = RECORD_NAME_UPX;
                        recordUPX.sVersion = viUPX.sVersion;
                        recordUPX.sInfo = viUPX.sInfo;

                        pPEInfo->basic_info.mapResultPackers.insert(recordUPX.name, scansToScan(&(pPEInfo->basic_info), &recordUPX));
                    } else {
                        _SCANS_STRUCT recordUPX = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_UPX);

                        recordUPX.sInfo = append(recordUPX.sInfo, "Modified");

                        pPEInfo->basic_info.mapResultPackers.insert(recordUPX.name, scansToScan(&(pPEInfo->basic_info), &recordUPX));
                    }
                }
            }

            // EXPRESSOR
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXPRESSOR) || (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXPRESSOR_KERNEL32) &&
                                                                                         pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXPRESSOR_USER32))) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXPRESSOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXPRESSOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // ASProtect
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ASPROTECT)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ASPROTECT)) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ASPROTECT);

                    pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }

            // PE-Quake
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEQUAKE)) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEQUAKE);

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }

            // MORPHNAH
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_MORPHNAH)) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_MORPHNAH);

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }

            // PECompact
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PECOMPACT)) {
                _SCANS_STRUCT recordPC = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PECOMPACT);

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PECOMPACT)) {
                    if (recordPC.nVariant == 1) {
                        recordPC.sVersion = "1.10b4-1.10b5";
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(recordPC.name, scansToScan(&(pPEInfo->basic_info), &recordPC));
                } else {
                    VI_STRUCT viPECompact = PE_get_PECompact_vi(pDevice, pOptions, pPEInfo);

                    if (viPECompact.bIsValid) {
                        recordPC.sVersion = viPECompact.sVersion;
                        recordPC.sInfo = viPECompact.sInfo;

                        pPEInfo->basic_info.mapResultPackers.insert(recordPC.name, scansToScan(&(pPEInfo->basic_info), &recordPC));
                    }
                }
            }

            // NSPack
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NSPACK)) {
                if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSPACK)) {
                    _SCANS_STRUCT recordNSPack = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSPACK);
                    pPEInfo->basic_info.mapResultPackers.insert(recordNSPack.name, scansToScan(&(pPEInfo->basic_info), &recordNSPack));
                } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_NSPACK)) {
                    _SCANS_STRUCT recordNSPack = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_NSPACK);
                    pPEInfo->basic_info.mapResultPackers.insert(recordNSPack.name, scansToScan(&(pPEInfo->basic_info), &recordNSPack));
                }
            }

            // ENIGMA
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ENIGMA)) {
                if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 nSectionOffset = pPEInfo->osImportSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osImportSection.nSize;

                    bool bDetect = false;

                    _SCANS_STRUCT recordEnigma = {};

                    recordEnigma.type = SpecAbstract::RECORD_TYPE_PROTECTOR;
                    recordEnigma.name = SpecAbstract::RECORD_NAME_ENIGMA;

                    if (!bDetect) {
                        VI_STRUCT viEngima = get_Enigma_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                        if (viEngima.bIsValid) {
                            recordEnigma.sVersion = viEngima.sVersion;
                            bDetect = true;
                        }
                    }

                    if (!bDetect) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ENIGMA)) {
                            recordEnigma.sVersion = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ENIGMA).sVersion;
                            bDetect = true;
                        }
                    }

                    if (bDetect) {
                        pPEInfo->basic_info.mapResultProtectors.insert(recordEnigma.name, scansToScan(&(pPEInfo->basic_info), &recordEnigma));
                    }
                }
            }

            // Alienyze
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_ALIENYZE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_ALIENYZE);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // PESpin
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PESPIN)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PESPIN);

                // Get version
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PESPIN)) {
                    quint8 nByte = pPEInfo->sEntryPointSignature.mid(54, 2).toUInt(nullptr, 16);

                    switch (nByte) {
                        case 0x5C: ss.sVersion = "0.1"; break;
                        case 0xB7: ss.sVersion = "0.3"; break;
                        case 0x73: ss.sVersion = "0.4"; break;
                        case 0x83: ss.sVersion = "0.7"; break;
                        case 0xC8: ss.sVersion = "1.0"; break;
                        case 0x7D: ss.sVersion = "1.1"; break;
                        case 0x71: ss.sVersion = "1.3beta"; break;
                        case 0xAC: ss.sVersion = "1.3"; break;
                        case 0x88: ss.sVersion = "1.3x"; break;
                        case 0x17: ss.sVersion = "1.32"; break;
                        case 0x77: ss.sVersion = "1.33"; break;
                    }
                }

                pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // nPack
            // TODO Timestamp 'nPck'
            // TODO Check 64
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NPACK)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_NPACK)) {
                    _SCANS_STRUCT recordNPACK = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_NPACK);

                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "nPack v", pPdStruct);

                        if (nOffset_Version != -1) {
                            recordNPACK.sVersion = pe.read_ansiString(nOffset_Version + 7).section(":", 0, 0);
                        } else {
                            recordNPACK.sVersion = "1.1.200.2006";
                        }
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(recordNPACK.name, scansToScan(&(pPEInfo->basic_info), &recordNPACK));
                }
            }

            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ELECKEY)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ELECKEY);

                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_ELECKEY)) {
                    ss.sInfo = append(ss.sInfo, "Section");
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ELECKEY)) {
                    ss.sInfo = append(ss.sInfo, "Import");
                }

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Oreans CodeVirtualizer
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_OREANSCODEVIRTUALIZER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_OREANSCODEVIRTUALIZER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->nOverlaySize) {
                qint64 nSize = pPEInfo->nOverlaySize;

                if (!pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                    nSize = qMin(pPEInfo->nOverlaySize, (qint64)0x100);
                }

                if (pe.find_signature(pPEInfo->nOverlaySize, nSize, "'asmg-protected'00", nullptr, pPdStruct) != -1) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ASMGUARD, "2.XX", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_ASMGUARD)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ASMGUARD, "2.XX", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (!pPEInfo->bIs64) {
                // MaskPE
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_MASKPE)) {
                    if (pPEInfo->basic_info.mapEntryPointSectionDetects.contains(RECORD_NAME_MASKPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointSectionDetects.value(RECORD_NAME_MASKPE);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PE-Armor
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PEARMOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEARMOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEARMOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DalCrypt
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_DALKRYPT))  // TODO more checks!
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_DALKRYPT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // N-Code
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_NCODE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_NCODE);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // LameCrypt
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LAMECRYPT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LAMECRYPT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // SC Obfuscator
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SCOBFUSCATOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SCOBFUSCATOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PCShrink
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PCSHRINK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PCSHRINK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PCSHRINK);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DragonArmor
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DRAGONARMOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_DRAGONARMOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_DRAGONARMOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // NoodleCrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NOODLECRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_NOODLECRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_NOODLECRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PEnguinCrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PENGUINCRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PENGUINCRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PENGUINCRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXECrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXECRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXECRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXECRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXE Password Protector
                // TODO Manifest name: Microsoft.Windows.ExeProtector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXEPASSWORDPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXEPASSWORDPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXEPASSWORDPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXESTEALTH)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXESTEALTH)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXESTEALTH);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PE Diminisher
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEDIMINISHER)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEDIMINISHER);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // G!X Protector
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_GIXPROTECTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_GIXPROTECTOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PC Guard
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PCGUARD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PCGUARD)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PCGUARD);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Soft Defender
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SOFTDEFENDER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SOFTDEFENDER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SOFTDEFENDER);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PECRYPT32
                // TODO Check!!!
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PECRYPT32)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PECRYPT32)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PECRYPT32);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXECryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXECRYPTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXECRYPTOR);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // YZPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_YZPACK)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_YZPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_YZPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // BCPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR))  // TODO !!!
                    {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // CRYPToCRACks PE Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTOCRACKPEPROTECTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTOCRACKPEPROTECTOR);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRYPTOCRACKPEPROTECTOR)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRYPTOCRACKPEPROTECTOR);
                    }

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ZProtect
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ZPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSTUBLINKER)) {
                        if (pPEInfo->listSectionRecords.count() >= 2) {
                            if (pe.compareSignature(&(pPEInfo->basic_info.memoryMap), "'kernel32.dll'00000000'VirtualAlloc'00000000",
                                                    pPEInfo->listSectionRecords.at(1).nOffset)) {
                                _SCANS_STRUCT recordZProtect = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ZPROTECT, "1.3-1.4.4", "", 0);
                                pPEInfo->basic_info.mapResultProtectors.insert(recordZProtect.name, scansToScan(&(pPEInfo->basic_info), &recordZProtect));
                            }
                        }
                    }
                } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ZPROTECT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ZPROTECT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_ZPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSTUBLINKER)) {
                        if (pPEInfo->listSectionRecords.count() >= 2) {
                            if ((pPEInfo->listSectionHeaders.at(0).PointerToRawData == 0) && (pPEInfo->listSectionHeaders.at(0).SizeOfRawData == 0) &&
                                (pPEInfo->listSectionHeaders.at(0).Characteristics == 0xe00000a0)) {
                                bool bDetect1 = (pPEInfo->nEntryPointSection == 1);
                                bool bDetect2 = (pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, pPEInfo->listSectionRecords.at(2).nOffset,
                                                                    pPEInfo->listSectionRecords.at(2).nSize, pPdStruct) > 7.6);

                                if (bDetect1 || bDetect2) {
                                    _SCANS_STRUCT recordZProtect = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ZPROTECT, "1.XX", "", 0);
                                    pPEInfo->basic_info.mapResultProtectors.insert(recordZProtect.name, scansToScan(&(pPEInfo->basic_info), &recordZProtect));
                                }
                            }
                        }
                    }
                }

                // ExeFog
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXEFOG)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_EXEFOG);

                    if ((pPEInfo->fileHeader.TimeDateStamp == 0) && (pPEInfo->optional_header.optionalHeader32.MajorLinkerVersion == 0) &&
                        (pPEInfo->optional_header.optionalHeader32.MinorLinkerVersion == 0) && (pPEInfo->optional_header.optionalHeader32.BaseOfData == 0x1000)) {
                        if (pPEInfo->listSectionHeaders.count()) {
                            if (pPEInfo->listSectionHeaders.at(0).Characteristics == 0xe0000020) {
                                pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // AHPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AHPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AHPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AHPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // 12311134
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_12311134))  // TODO Check!
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_12311134);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AZProtect
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AZPROTECT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AZPROTECT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AverCryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AVERCRYPTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_AVERCRYPTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AVERCRYPTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // WinKript
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_WINKRIPT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_WINKRIPT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AffilliateEXE
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AFFILLIATEEXE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AFFILLIATEEXE);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // Advanced UPX Scrammbler
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UPX)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ADVANCEDUPXSCRAMMBLER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ADVANCEDUPXSCRAMMBLER);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // BeRoEXEPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BEROEXEPACKER)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BEROEXEPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_BEROEXEPACKER);

                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BEROEXEPACKER)) {
                            ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BEROEXEPACKER);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC)) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BEROEXEPACKER)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BEROEXEPACKER);
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // Winupack
                if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINUPACK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINUPACK);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_WINUPACK)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_WINUPACK);
                    }

                    //                    recordWinupack.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(((pPEInfo->nMinorLinkerVersion)/16)*10+(pPEInfo->nMinorLinkerVersion)%16);

                    qint32 nBuildNumber = 0;

                    if ((ss.nVariant == 1) || (ss.nVariant == 2)) {
                        nBuildNumber = pPEInfo->nMinorLinkerVersion;
                    } else if ((ss.nVariant == 3) || (ss.nVariant == 4)) {
                        nBuildNumber = pPEInfo->nMinorImageVersion;
                    }
#ifdef QT_DEBUG
                    qDebug("nBuildNumber: %x", nBuildNumber);
#endif
                    switch (nBuildNumber) {
                        case 0x21: ss.sVersion = "0.21"; break;
                        case 0x22: ss.sVersion = "0.22"; break;
                        case 0x23: ss.sVersion = "0.23"; break;
                        case 0x24: ss.sVersion = "0.24"; break;
                        case 0x25: ss.sVersion = "0.25"; break;
                        case 0x26: ss.sVersion = "0.26"; break;
                        case 0x27: ss.sVersion = "0.27"; break;
                        case 0x28: ss.sVersion = "0.28"; break;
                        case 0x29: ss.sVersion = "0.29"; break;
                        case 0x30: ss.sVersion = "0.30"; break;
                        case 0x31: ss.sVersion = "0.31"; break;
                        case 0x32: ss.sVersion = "0.32"; break;
                        case 0x33: ss.sVersion = "0.33"; break;
                        case 0x34: ss.sVersion = "0.34"; break;
                        case 0x35: ss.sVersion = "0.35"; break;
                        case 0x36: ss.sVersion = "0.36 beta"; break;
                        case 0x37: ss.sVersion = "0.37 beta"; break;
                        case 0x38: ss.sVersion = "0.38 beta"; break;
                        case 0x39: ss.sVersion = "0.39 final"; break;
                        case 0x3A: ss.sVersion = "0.399"; break;
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ANDpakk2
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ANDPAKK2) || pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDPAKK2)) {
                    // TODO compare entryPoint and import sections TODO Check
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ANDPAKK2)) {
                        _SCANS_STRUCT recordANFpakk2 = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ANDPAKK2);
                        pPEInfo->basic_info.mapResultPackers.insert(recordANFpakk2.name, scansToScan(&(pPEInfo->basic_info), &recordANFpakk2));
                    }
                }

                // KByS
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KBYS)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_KBYS)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_KBYS);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crunch
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRUNCH)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRUNCH)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRUNCH);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // ASDPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ASDPACK)) {
                    bool bDetected = false;
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ASDPACK);

                    if (pPEInfo->listSectionRecords.count() == 2) {
                        if (pPEInfo->bIsTLSPresent) {
                            bDetected = true;  // 1.00
                        }
                    }

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ASDPACK)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ASDPACK);
                        bDetected = true;
                    }

                    if (bDetected) {
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // VPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_VPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_VPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_VPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // RLP
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RLP)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RLP)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RLP);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crinkler
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRINKLER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRINKLER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRINKLER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EZIP TODO CHECK
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EZIP)) {
                    if (pPEInfo->nOverlaySize) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EZIP);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // KKrunchy
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KKRUNCHY)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_KKRUNCHY) || pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC)) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_KKRUNCHY)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_KKRUNCHY);

                            if (!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_KKRUNCHY)) {
                                ss.sInfo = "Patched";
                            }

                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // QuickPack NT
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_QUICKPACKNT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QUICKPACKNT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QUICKPACKNT);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // MKFPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MKFPACK)) {
                    qint64 mLfanew = pPEInfo->dosHeader.e_lfanew - 5;

                    if (mLfanew > 0) {
                        QString sSignature = pe.read_ansiString(mLfanew, 5);

                        if (sSignature == "llydd") {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MKFPACK);
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // 32lite
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_32LITE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_32LITE)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_32LITE);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EProt
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_EPROT)) {
                    if (pPEInfo->nEntryPointSection > 0) {
                        if (pPEInfo->sEntryPointSectionName == "!eprot") {
                            quint32 nValue = pe.read_uint32(pPEInfo->osEntryPointSection.nOffset + pPEInfo->osEntryPointSection.nSize - 4);

                            if (nValue == 0x78787878) {
                                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_EPROT);
                                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // RLPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RLPACK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_RLPACK);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RLPACK)) {
                        ss.sInfo = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RLPACK).sInfo;
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_FAKESIGNATURE)) {
                        if (pPEInfo->listSectionHeaders.count() >= 2) {
                            if (pPEInfo->listSectionHeaders.at(0).SizeOfRawData <= 0x200) {
                                ss.sInfo = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_FAKESIGNATURE).sInfo;
                                pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // Packman
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PACKMAN)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PACKMAN)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PACKMAN);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Fish PE Packer
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FISHPEPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_FISHPEPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_FISHPEPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Inquartos Obfuscator
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR) &&
                        pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_INQUARTOSOBFUSCATOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Hide & Protect
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HIDEANDPROTECT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_HIDEANDPROTECT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_HIDEANDPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // mPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_MPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_MPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EncryptPE
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ENCRYPTPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ENCRYPTPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ENCRYPTPE);

                        qint64 _nOffset = pPEInfo->osHeader.nOffset;
                        qint64 _nSize = pPEInfo->osHeader.nSize;

                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "EncryptPE V", pPdStruct);

                        if (nOffset_Version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_Version + 11).section(",", 0, 0);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Yoda's Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_YODASPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_YODASPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_YODASPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Xtreme-Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_XTREMEPROTECTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_XTREMEPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_XTREMEPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // ACProtect 1.X-2.X
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ACPROTECT)) {
                    if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 nSectionOffset = pPEInfo->osImportSection.nOffset;
                        qint64 nSectionSize = pPEInfo->osImportSection.nSize;

                        qint64 nOffset1 = pe.find_array(nSectionOffset, nSectionSize, "MineImport_Endss", 16, pPdStruct);

                        if (nOffset1 != -1) {
                            _SCANS_STRUCT recordACProtect = {};
                            recordACProtect.type = RECORD_TYPE_PROTECTOR;
                            recordACProtect.name = RECORD_NAME_ACPROTECT;

                            recordACProtect.sVersion = "1.XX-2.XX";

                            //                            qint64 nOffset2=pe.find_array(nSectionOffset,nSectionSize,"Randimize",9);

                            //                            if(nOffset2!=-1)
                            //                            {
                            //                                recordACProtect.sVersion="1.X";
                            //                            }

                            pPEInfo->basic_info.mapResultProtectors.insert(recordACProtect.name, scansToScan(&(pPEInfo->basic_info), &recordACProtect));
                        }
                    }
                }

                // ACProtect
                // 2.0.X
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ACPROTECT))  // TODO CHECK
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ACPROTECT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // FSG
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FSG)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FSG)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FSG);

                        if (ss.nVariant == 0) {
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        } else if (ss.nVariant == 1) {
                            if (pe.read_ansiString(0x154) == "KERNEL32.dll") {
                                ss.sVersion = "1.33";
                            } else {
                                ss.sVersion = "2.00";
                            }

                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // MEW
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MEW10)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_MEW10)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_MEW10);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MEW11SE)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MEW11SE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MEW11SE);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Alex Protector
                // 2.0.X
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ALEXPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ALEXPROTECTOR)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ALEXPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PEBundle
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PEBUNDLE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEBUNDLE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEBUNDLE);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PE-SHiELD
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PESHIELD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PESHIELD)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PESHIELD);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PUNiSHER
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PUNISHER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PUNISHER)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PUNISHER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Shrinker
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SHRINKER)) {
                    if (pe.isImportFunctionPresentI("KERNEL32.DLL", "8", &(pPEInfo->listImports))) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SHRINKER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Secure Shade
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SECURESHADE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SECURESHADE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SECURESHADE);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PolyCrypt PE
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_POLYCRYPTPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_POLYCRYPTPE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_POLYCRYPTPE);

                        if (pPEInfo->nImportSection == pPEInfo->nEntryPointSection) {
                            if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                                qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                                qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                                qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "PolyCrypt PE (c) 2004-2005, JLabSoftware.", pPdStruct);

                                if (nOffset_Version == -1) {
                                    recordSS.sInfo = "Modified";
                                }
                            }
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HMIMYSPROTECTOR)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_HMIMYSPROTECTOR)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HMIMYSPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PEPACKSPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PEPACKSPROTECT)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_PEPACKSPROTECT)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HMIMYSPACKER)) {
                    if (XPE::isSectionNamePresent(".hmimys", &(pPEInfo->listSectionRecords)))  // TODO Check, pdStruct
                    {
                        _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PACKER, RECORD_NAME_HMIMYSPACKER, "", "", 0);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ORIEN)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ORIEN)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ORIEN);

                        QString sVersion = pPEInfo->sEntryPointSignature.mid(16, 2);

                        if (sVersion == "CE") {
                            recordSS.sVersion = "2.11";
                        } else if (sVersion == "CD") {
                            recordSS.sVersion = "2.12";
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Alloy 4.X
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ALLOY)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ALLOY)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ALLOY);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PeX
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PEX)) {
                    // TODO compare entryPoint and import sections
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEX)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEX);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PEVProt
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_REVPROT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_REVPROT)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_REVPROT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Software Compress
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SOFTWARECOMPRESS)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SOFTWARECOMPRESS)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SOFTWARECOMPRESS);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // SDProtector Pro
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SDPROTECTORPRO)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SDPROTECTORPRO)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SDPROTECTORPRO);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Simple Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SIMPLEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SIMPLEPACK)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SIMPLEPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // NakedPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NAKEDPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_NAKEDPACKER) &&
                        (!pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_NAKEDPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // KaOs PE-DLL eXecutable Undetecter
                // the same as NakedPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER) &&
                        pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // ASPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ASPACK)) {
                    // TODO compare entryPoint and import sections
                    QString _sSignature = pPEInfo->sEntryPointSignature;
                    qint64 _nOffset = 0;
                    //                    QString _sVersion;

                    // TODO a function
                    // TODO emul !!!
                    while (XBinary::isPdStructNotCanceled(pPdStruct)) {
                        bool bContinue = false;

                        if (XBinary::compareSignatureStrings(_sSignature, "90")) {
                            bContinue = true;
                            _nOffset++;
                            _sSignature.remove(0, 2);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "7500")) {
                            bContinue = true;
                            _nOffset += 2;
                            _sSignature.remove(0, 4);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "7501")) {
                            bContinue = true;
                            _nOffset += 3;
                            _sSignature.remove(0, 6);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "E9")) {
                            bContinue = true;
                            _nOffset++;
                            _sSignature.remove(0, 2);
                            qint32 nAddress = XBinary::hexToInt32(_sSignature);
                            _nOffset += 4;
                            // TODO image
                            qint64 nSignatureOffset = pe.addressToOffset(pPEInfo->nImageBaseAddress + pPEInfo->nEntryPointAddress + _nOffset + nAddress);

                            if (nSignatureOffset != -1) {
                                _sSignature = pe.getSignature(nSignatureOffset, 150);
                            } else {
                                break;
                            }
                        }

                        if (_nOffset) {
                            signatureScan(&(pPEInfo->basic_info.mapEntryPointDetects), _sSignature, _PE_entrypoint_records, sizeof(_PE_entrypoint_records),
                                          pPEInfo->basic_info.id.fileType, XBinary::FT_PE, &(pPEInfo->basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
                            signatureExpScan(&pe, &(pPEInfo->basic_info.memoryMap), &(pPEInfo->basic_info.mapEntryPointDetects), pPEInfo->nEntryPointOffset + _nOffset,
                                             _PE_entrypointExp_records, sizeof(_PE_entrypointExp_records), pPEInfo->basic_info.id.fileType, XBinary::FT_PE,
                                             &(pPEInfo->basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
                        }

                        if (_nOffset > 20) {
                            break;
                        }

                        if (!bContinue) {
                            break;
                        }

                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ASPACK)) {
                            break;
                        }
                    }

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ASPACK)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ASPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // No Import
                // WWPACK32
                // TODO false
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_WWPACK32)) {
                    _SCANS_STRUCT ss = {};

                    ss.type = RECORD_TYPE_PACKER;
                    ss.name = RECORD_NAME_WWPACK32;
                    ss.sVersion = XBinary::hexToString(pPEInfo->sEntryPointSignature.mid(102, 8));
                    // recordAndpakk.sInfo;

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // EXE Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EPEXEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EPEXEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_EPEXEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_EPROT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_EPROT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // RCryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RCRYPTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RCRYPTOR);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PE-PACK
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PEPACK);

                        if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            qint64 _nOffset = pPEInfo->osImportSection.nOffset;
                            qint64 _nSize = pPEInfo->osImportSection.nSize;

                            qint64 nOffset_PEPACK = pe.find_ansiString(_nOffset, _nSize, "PE-PACK v", pPdStruct);

                            if (nOffset_PEPACK != -1) {
                                ss.sVersion = pe.read_ansiString(nOffset_PEPACK + 9, 50);
                                ss.sVersion = ss.sVersion.section(" ", 0, 0);
                            }
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PKLITE32
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PKLITE32)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PKLITE32);

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // MoleBox
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_MOLEBOX)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_MOLEBOX);

                    QString sComment = XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion));

                    if (sComment.contains("MoleBox ")) {
                        ss.sVersion = sComment.section("MoleBox ", 1, -1);
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // XComp
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_XCOMP)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_XCOMP)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_XCOMP);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // XPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_XPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_XPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_XPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Krypton
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KRYPTON)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_KRYPTON)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_KRYPTON);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // SVK Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SVKPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SVKPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SVKPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // TPP Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TPPPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_TPPPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_TPPPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // VCasm-Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_VCASMPROTECTOR)) {
                    _SCANS_STRUCT ss = {};
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_VCASMPROTECTOR)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_VCASMPROTECTOR);
                    }

                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_VCASMPROTECTOR);

                        qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "vcasm_protect_", pPdStruct);

                        QString sVersionString;

                        if (nOffset_Version != -1) {
                            sVersionString = pe.read_ansiString(nOffset_Version).section("_", 2, -1);
                        }

                        if (sVersionString == "2004_11_30") {
                            ss.sVersion = "1.0";
                        }
                        if (sVersionString == "2005_3_18") {
                            ss.sVersion = "1.1-1.2";
                        }
                    }

                    if (ss.name != RECORD_NAME_UNKNOWN) {
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // JDPack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_JDPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_JDPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_JDPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Yoda's crypter
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_YODASCRYPTER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_YODASCRYPTER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_YODASCRYPTER);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // QrYPt0r
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_QRYPT0R)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_QRYPT0R)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_QRYPT0R);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DBPE
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DBPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_DBPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_DBPE);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // FISH PE Shield
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FISHPESHIELD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_FISHPESHIELD)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_FISHPESHIELD);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // bambam
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BAMBAM)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BAMBAM)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BAMBAM);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DotFix NeceProtect
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DOTFIXNICEPROTECT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_DOTFIXNICEPROTECT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_DOTFIXNICEPROTECT);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // The Best Cryptor [by FsK]
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_THEBESTCRYPTORBYFSK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_THEBESTCRYPTORBYFSK);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // DYAMAR
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DYAMAR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_DYAMAR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DYAMAR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // CExe
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CEXE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CEXE);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // K!Cryptor
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KCRYPTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_KCRYPTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_KCRYPTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crypter
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRYPTER)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRYPTER);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // Thinstall
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_THINSTALL))  // TODO Imports EP
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_THINSTALL);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (XPE::getResourcesVersionValue("ThinAppVersion", &(pPEInfo->resVersion)) != "") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THINSTALL, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ThinAppVersion", &(pPEInfo->resVersion)).trimmed();

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (XPE::getResourcesVersionValue("ThinstallVersion", &(pPEInfo->resVersion)) != "") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THINSTALL, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ThinstallVersion", &(pPEInfo->resVersion)).trimmed();

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ABC Cryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ABCCRYPTOR)) {
                    _SCANS_STRUCT recordEP = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ABCCRYPTOR);

                    if ((pPEInfo->nEntryPointAddress - pPEInfo->listSectionHeaders.at(pPEInfo->nEntryPointSection).VirtualAddress) == 1) {
                        pPEInfo->basic_info.mapResultPackers.insert(recordEP.name, scansToScan(&(pPEInfo->basic_info), &recordEP));
                    }
                }

                // exe 32 pack
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXE32PACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXE32PACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXE32PACK);

                        qint64 _nOffset = pPEInfo->osHeader.nOffset;
                        qint64 _nSize = qMin(pPEInfo->basic_info.id.nSize, (qint64)0x2000);

                        qint64 nOffset_version = pe.find_ansiString(_nOffset, _nSize, "Packed by exe32pack", pPdStruct);

                        if (nOffset_version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_version + 20, 50);
                            ss.sVersion = ss.sVersion.section(" ", 0, 0);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // SC PACK
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SCPACK)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_SCPACK)) {
                        if (pPEInfo->listSectionRecords.count() >= 3) {
                            if (pPEInfo->nEntryPointSection == 1) {
                                if (pPEInfo->listSectionHeaders.at(1).VirtualAddress == pPEInfo->nEntryPointAddress) {
                                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SCPACK);

                                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                                }
                            }
                        }
                    }
                }

                // dePack
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_DEPACK)) {
                    if (pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$60")) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_DEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            } else {
                // Only 64
                // lARP64
                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LARP64)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_LARP64)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LARP64);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_VMProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    qint32 nNumberOfSections = pPEInfo->listSectionRecords.count();

    bool bDetected = false;

    QString sVMPSectionName;

    for (qint32 i = nNumberOfSections - 1; (i >= 0) && (XBinary::isPdStructNotCanceled(pPdStruct)); i--) {
        if (i == pPEInfo->nRelocsSection) {
            continue;
        }
        if (i == pPEInfo->nResourcesSection) {
            continue;
        }

        if (pPEInfo->listSectionRecords.at(i).sName != "") {
            sVMPSectionName = pPEInfo->listSectionRecords.at(i).sName;

            if ((i > 0) && (sVMPSectionName == ".vmp0")) {
                bDetected = true;

                break;
            } else if ((i > 1) && (sVMPSectionName.at(sVMPSectionName.size() - 1) == QChar('1'))) {
                QString sCollision = XBinary::getStringCollision(&(pPEInfo->listSectionNames), "0", "1");

                if (XPE::isSectionNamePresent(sCollision + "0", &(pPEInfo->listSectionRecords))) {
                    bDetected = true;

                    break;
                }
            } else if ((i > 2) && (sVMPSectionName.at(sVMPSectionName.size() - 1) == QChar('2'))) {
                QString sCollision = XBinary::getStringCollision(&(pPEInfo->listSectionNames), "1", "2");

                if (XPE::isSectionNamePresent(sCollision + "1", &(pPEInfo->listSectionRecords)) &&
                    XPE::isSectionNamePresent(sCollision + "0", &(pPEInfo->listSectionRecords))) {
                    bDetected = true;

                    break;
                }
            } else if ((i > 3) && (sVMPSectionName.at(sVMPSectionName.size() - 1) == QChar('3'))) {
                QString sCollision = XBinary::getStringCollision(&(pPEInfo->listSectionNames), "2", "3");

                if (XPE::isSectionNamePresent(sCollision + "2", &(pPEInfo->listSectionRecords)) &&
                    XPE::isSectionNamePresent(sCollision + "1", &(pPEInfo->listSectionRecords)) &&
                    XPE::isSectionNamePresent(sCollision + "0", &(pPEInfo->listSectionRecords))) {
                    bDetected = true;

                    break;
                }
            }
        }

        break;
    }

    if (!bDetected) {
        if (pOptions->bIsHeuristicScan) {
            if (pPEInfo->nEntryPointSection >= 4) {
                if ((pPEInfo->nImportSection == pPEInfo->nEntryPointSection) && (pPEInfo->nEntryPointSection - 1 == pPEInfo->nIATSection)) {
                    if ((pPEInfo->listSectionHeaders.at(pPEInfo->nEntryPointSection - 1).Characteristics == 0xc0000040) &&
                        (pPEInfo->listSectionHeaders.at(pPEInfo->nEntryPointSection - 2).Characteristics == 0x60000020)) {
                        bDetected = true;
                    }
                }
            }
        }
    }

    if (bDetected) {
        _SCANS_STRUCT ssVMProtect = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_VMPROTECT, "", "", 0);

        if (pPEInfo->bIs64) {
            ssVMProtect.sVersion = "2.XX-3.XX";
        }

        if (sVMPSectionName != "") {
            if (sVMPSectionName.at(sVMPSectionName.size() - 1) == QChar('0')) {
                ssVMProtect.sInfo = "Min protection";
            }
        }

        // TODO more checks
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_VMPROTECT)) {
            _SCANS_STRUCT ssVersion = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_VMPROTECT);

            ssVMProtect.sVersion = ssVersion.sVersion;
            ssVMProtect.sInfo = ssVersion.sInfo;
        }

        pPEInfo->basic_info.mapResultProtectors.insert(ssVMProtect.name, scansToScan(&(pPEInfo->basic_info), &ssVMProtect));
    }

    //    return;
    //    // TODO Check
    //    XPE pe(pDevice,pOptions->bIsImage);

    //    if(pe.isValid(pPdStruct))
    //    {
    //        if(!pPEInfo->cliInfo.bValid)
    //        {
    //            bool bSuccess=false;

    //            // Import
    //            if(!bSuccess)
    //            {
    //                bSuccess=pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_VMPROTECT);
    //            }

    //            if(!bSuccess)
    //            {
    //                bSuccess=pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_VMPROTECT);
    //            }

    //            if(!bSuccess)
    //            {
    //                if(pPEInfo->nEntryPointSection>=3)
    //                {
    //                    bSuccess=true;

    //                    qint32 nNumberOfSections=pPEInfo->listSectionHeaders.count();

    //                    for(qint32 i=0;i<nNumberOfSections;i++)
    //                    {
    //                        if( (i==pPEInfo->nEntryPointSection)||
    //                            (i==pPEInfo->nResourcesSection)||
    //                            (i==pPEInfo->nTLSSection)||
    //                            (i==pPEInfo->nRelocsSection)||
    //                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name)==".INIT")||
    //                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name)==".tls")||
    //                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name).contains("0"))
    //                          )
    //                        {
    //                            continue;
    //                        }

    //                        if(pPEInfo->listSectionHeaders.at(i).SizeOfRawData)
    //                        {
    //                            bSuccess=false;
    //                            break;
    //                        }
    //                    }
    //                }
    //            }

    //            if(bSuccess)
    //            {
    //                if( pe.compareEntryPoint("68........E8")||
    //                    pe.compareEntryPoint("68........E9")||
    //                    pe.compareEntryPoint("9C60")||
    //                    pe.compareEntryPoint("EB$$E9$$$$$$$$68........E8")||
    //                    pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_VMPROTECT))
    //                {
    //                    // TODO more checks
    //                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VMPROTECT,"","",0);
    //                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
    //                }
    //            }
    //        }
    //    }
}

void SpecAbstract::PE_handle_VProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->nEntryPointSection > 0) {
                if (pPEInfo->sEntryPointSectionName == "VProtect")  // TODO !!!
                {
                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 nSectionOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 nSectionSize = pPEInfo->osEntryPointSection.nSize;

                        qint64 nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "VProtect", pPdStruct);

                        if (nOffset_Version != -1) {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_VIRTUALIZEPROTECT, "", "", 0);

                            nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "VProtect Ultimate v", pPdStruct);

                            if (nOffset_Version != -1) {
                                ss.sVersion = pe.read_ansiString(nOffset_Version).section(" v", 1, 1);
                            }

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_TTProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImportPositionHashes.count() >= 1) {
                if (pPEInfo->listImportPositionHashes.at(0) == 0xf3f52749)  // TODO !!!
                {
                    if (pPEInfo->nEntryPointSection > 0) {
                        if (pPEInfo->sEntryPointSectionName == ".TTP")  // TODO !!!
                        {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_TTPROTECT, "", "", 0);

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_SafeengineShielden(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SAFEENGINESHIELDEN)) {
                if (pPEInfo->nEntryPointSection > 0) {
                    if (pPEInfo->sEntryPointSectionName == ".sedata")  // TODO !!!
                    {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_SAFEENGINESHIELDEN, "2.XX", "", 0);

                        qint64 nSectionOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                        qint64 nSectionSize = pPEInfo->listSectionRecords.at(1).nSize;

                        qint64 nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "Safengine Shielden v", pPdStruct);

                        if (nOffset_Version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_Version).section(" v", 1, 1);
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_tElock(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImports.count() == 2) {
                bool bKernel32 = false;
                bool bUser32 = false;

                // TODO
                if (pPEInfo->listImports.at(0).sName == "kernel32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if (pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "GetModuleHandleA") {
                            bKernel32 = true;
                        }
                    }
                }
                if (pPEInfo->listImports.at(1).sName == "user32.dll") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "MessageBoxA")) {
                            bUser32 = true;
                        }
                    }
                }

                if (bKernel32 && bUser32) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_TELOCK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_TELOCK);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Armadillo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bHeaderDetect = false;
            bool bImportDetect = false;

            if ((pPEInfo->nMajorLinkerVersion == 0x53) && (pPEInfo->nMinorLinkerVersion == 0x52)) {
                bHeaderDetect = true;
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            if (nNumberOfImports >= 3) {
                bImportDetect = ((pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") && (pPEInfo->listImports.at(1).sName.toUpper() == "USER32.DLL") &&
                                 (pPEInfo->listImports.at(2).sName.toUpper() == "GDI32.DLL")) ||
                                ((pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") && (pPEInfo->listImports.at(1).sName.toUpper() == "GDI32.DLL") &&
                                 (pPEInfo->listImports.at(2).sName.toUpper() == "USER32.DLL"));
            }

            if (bImportDetect || bHeaderDetect) {
                bool bDetect = false;

                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ARMADILLO, "", "", 0);

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ARMADILLO)) {
                    ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ARMADILLO);

                    bDetect = true;
                }

                if (bHeaderDetect) {
                    bDetect = true;
                }

                if (bDetect) {
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Obsidium(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // TODO x64
        // KERNEL32.DLL
        // USER32.DLL
        // ADVAPI32.DLL
        // SHEL32.DLL
        if (!pPEInfo->cliInfo.bValid) {
            qint32 nNumberOfImports = pPEInfo->listImports.count();

            if ((nNumberOfImports == 2) || (nNumberOfImports == 3)) {
                bool bKernel32 = false;
                bool bUser32 = false;
                //                bool bAdvapi32=false;

                if (pPEInfo->listImports.at(0).sName == "KERNEL32.DLL") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "ExitProcess")) {
                            bKernel32 = true;
                        }
                    }
                }

                if (pPEInfo->listImports.at(1).sName == "USER32.DLL") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "MessageBoxA")) {
                            bUser32 = true;
                        }
                    }
                }

                if (nNumberOfImports == 3) {
                    if (pPEInfo->listImports.at(2).sName == "ADVAPI32.DLL") {
                        if (pPEInfo->listImports.at(2).listPositions.count() == 1) {
                            if ((pPEInfo->listImports.at(2).listPositions.at(0).sFunction == "RegOpenKeyExA")) {
                                //                                bAdvapi32=true;
                            }
                        }
                    }
                }

                if (bKernel32 && bUser32) {
                    if (pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$50EB$$E8") ||
                        pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$E8........EB$$EB")) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_OBSIDIUM, "", "", 0);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Themida(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImports.count() == 1) {
                if (pPEInfo->listImports.at(0).sName == "kernel32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_THEMIDAWINLICENSE)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_THEMIDAWINLICENSE);

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            } else if (pPEInfo->listImports.count() == 2) {
                bool bKernel32 = false;
                bool bComctl32 = false;

                // TODO
                if (pPEInfo->listImports.at(0).sName == "KERNEL32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 2) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "CreateFileA") ||
                            (pPEInfo->listImports.at(0).listPositions.at(1).sFunction == "lstrcpy")) {
                            bKernel32 = true;
                        }
                    }
                } else if (pPEInfo->listImports.at(0).sName == "kernel32.dll")  // TODO Check
                {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "lstrcpy")) {
                            bKernel32 = true;
                        }
                    }
                }

                if ((pPEInfo->listImports.at(1).sName == "COMCTL32.dll") || (pPEInfo->listImports.at(1).sName == "comctl32.dll")) {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "InitCommonControls")) {
                            bComctl32 = true;
                        }
                    }
                }

                if (bKernel32 && bComctl32) {
                    // TODO Version
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THEMIDAWINLICENSE, "1.XX-2.XX", "", 0);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_THEMIDAWINLICENSE)) {
                // New version
                qint32 nNumbersOfImport = pPEInfo->listImports.count();

                bool bSuccess = true;

                for (qint32 i = 0; (i < nNumbersOfImport) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pPEInfo->listImports.at(i).listPositions.count() != 1) {
                        bSuccess = false;
                        break;
                    }
                }

                if (bSuccess) {
                    if (pPEInfo->listSectionNames.count() > 1) {
                        if (pPEInfo->listSectionNames.at(0) == "        ") {
                            bSuccess = false;

                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THEMIDAWINLICENSE, "3.XX", "", 0);

                            if (XPE::isSectionNamePresent(".themida", &(pPEInfo->listSectionRecords))) {
                                ss.sInfo = "Themida";
                                bSuccess = true;
                            } else if (XPE::isSectionNamePresent(".winlice", &(pPEInfo->listSectionRecords))) {
                                ss.sInfo = "Winlicense";
                                bSuccess = true;
                            }

                            if (bSuccess) {
                                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_StarForce(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        bool bSF3 = XPE::isSectionNamePresent(".sforce3", &(pPEInfo->listSectionRecords));  // TODO
        bool bSF4 = XPE::isSectionNamePresent(".ps4", &(pPEInfo->listSectionRecords));      // TODO

        if (bSF3 || bSF4) {
            QString sVersion;
            QString sInfo;

            if (bSF3) {
                sVersion = "3.X";
            }

            if (bSF4) {
                sVersion = "4.X-5.X";
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (pPEInfo->listImports.at(i).listPositions.count() == 1) {
                    if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "") || (pPEInfo->listImports.at(i).listPositions.at(0).sName == "1")) {
                        sInfo = pPEInfo->listImports.at(i).sName;
                    }
                }
            }

            _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_STARFORCE, sVersion, sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
        }
    }
}

void SpecAbstract::PE_handle_Petite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (!pPEInfo->bIs64) {
                bool bKernel32 = false;
                bool bUser32 = false;
                QString sVersion;

                // TODO !!!
                // TODO Petite 2.4 Check header

                qint32 nNumberOfImports = pPEInfo->listImports.count();

                for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pPEInfo->listImports.at(i).sName.toUpper() == "USER32.DLL") {
                        if (pPEInfo->listImports.at(i).listPositions.count() == 2) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "MessageBoxA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "wsprintfA")) {
                                bUser32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 1) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "MessageBoxA")) {
                                bUser32 = true;
                            }
                        }
                    } else if (pPEInfo->listImports.at(i).sName.toUpper() == "KERNEL32.DLL") {
                        if (pPEInfo->listImports.at(i).listPositions.count() == 7) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetModuleHandleA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "VirtualAlloc") &&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName == "VirtualFree") &&
                                (pPEInfo->listImports.at(i).listPositions.at(6).sName == "LoadLibraryA")) {
                                sVersion = "2.4";
                                bKernel32 = true;
                            } else if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(1).sName == "LoadLibraryA") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(5).sName == "GlobalFree") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(6).sName == "GetModuleHandleA")) {
                                sVersion = "2.3";
                                bKernel32 = true;
                            }
                        }

                        if (pPEInfo->listImports.at(i).listPositions.count() == 6) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetModuleHandleA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc") &&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName == "GlobalFree")) {
                                sVersion = "2.3";  // DLL only?? // TODO Check
                                bKernel32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 5) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "LoadLibraryA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc")) {
                                sVersion = "2.2";
                                bKernel32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 4) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "LoadLibraryA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "GlobalAlloc")) {
                                sVersion = "1.4";
                                bKernel32 = true;
                            }
                        }
                    }
                }

                // TODO Import hash
                if (bUser32 && bKernel32) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PETITE)) {
                        _SCANS_STRUCT recordPETITE = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        recordPETITE.sVersion = sVersion;
                        pPEInfo->basic_info.mapResultPackers.insert(recordPETITE.name, scansToScan(&(pPEInfo->basic_info), &recordPETITE));
                    }
                } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_PETITE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PETITE)) {
                        _SCANS_STRUCT recordPETITE = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        pPEInfo->basic_info.mapResultPackers.insert(recordPETITE.name, scansToScan(&(pPEInfo->basic_info), &recordPETITE));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_NETProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pPEInfo->bIsNetPresent) {
            // .NET
            // Enigma
            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan))  // TODO
            {
                qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                VI_STRUCT viEnigma = get_Enigma_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                if (viEnigma.bIsValid) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ENIGMA, viEnigma.sVersion, ".NET", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // .Net reactor
            if (pPEInfo->listSectionRecords.count() >= 2) {
                if (pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                    qint64 _nOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize = pPEInfo->listSectionRecords.at(1).nSize;

                    qint64 nOffset_NetReactor = pe.find_signature(&(pPEInfo->basic_info.memoryMap), _nOffset, _nSize,
                                                                  "5266686E204D182276B5331112330C6D0A204D18229EA129611C76B505190158", nullptr, pPdStruct);

                    if (nOffset_NetReactor != -1) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_DOTNETREACTOR, "4.8-4.9", "", 0);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // TODO
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_YANO)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_YANO);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_AGILENET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_AGILENET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SKATER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SKATER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_BABELNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_BABELNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_GOLIATHNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_GOLIATHNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SPICESNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SPICESNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_OBFUSCATORNET2009)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_OBFUSCATORNET2009);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            {
                bool bDetect = false;
                _SCANS_STRUCT ss = {};

                if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA)) {
                    ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect = true;
                } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DEEPSEA)) {
                    ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect = true;
                }

                if (bDetect) {
                    qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi = get_DeepSea_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                    if (vi.bIsValid) {
                        ss.sVersion = vi.sVersion;
                        ss.sInfo = vi.sInfo;
                    }

                    pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // cliSecure
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CLISECURE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CLISECURE);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else {
                if (pPEInfo->listSectionHeaders.count() >= 2) {
                    qint64 _nOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize = pPEInfo->listSectionRecords.at(1).nSize;
                    qint32 _nCharacteristics = pPEInfo->listSectionRecords.at(1).nCharacteristics;

                    if (_nCharacteristics & (XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE)) {
                        qint64 nOffset_CliSecure = pe.find_unicodeString(_nOffset, _nSize, "CliSecure", false, pPdStruct);

                        if (nOffset_CliSecure != -1) {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_CLISECURE, "4.X", "", 0);
                            pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }

            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_FISHNET)) || (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_FISHNET))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_FISHNET, "1.X", "", 0);  // TODO
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));                   // TODO obfuscator?
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_NSPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_NSPACK);
                pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DNGUARD)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DNGUARD);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // .NETZ
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETZ)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETZ)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_MAXTOCODE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_MAXTOCODE);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_PHOENIXPROTECTOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            {
                bool bDetect = false;
                _SCANS_STRUCT ss = {};

                if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SMARTASSEMBLY)) {
                    ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect = true;
                } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SMARTASSEMBLY)) {
                    ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect = true;
                }

                if (bDetect) {
                    qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi = get_SmartAssembly_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                    if (vi.bIsValid) {
                        ss.sVersion = vi.sVersion;
                        ss.sInfo = vi.sInfo;
                    }

                    pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CONFUSER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CONFUSER);

                if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize = pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_detect = pe.find_ansiString(_nOffset, _nSize, "Confuser v", pPdStruct);

                    if (nOffset_detect != -1) {
                        ss.sVersion = pe.read_ansiString(nOffset_detect + 10);
                    }

                    if (nOffset_detect == -1) {
                        qint64 nOffset_ConfuserEx = pe.find_ansiString(_nOffset, _nSize, "ConfuserEx v", pPdStruct);

                        if (nOffset_ConfuserEx != -1) {
                            ss.name = RECORD_NAME_CONFUSEREX;
                            ss.sVersion = pe.read_ansiString(nOffset_ConfuserEx + 12);
                        }
                    }
                }

                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Xenocode Postbuild
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_XENOCODEPOSTBUILD)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_XENOCODEPOSTBUILD);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // CodeVeil
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CODEVEIL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapDotUnicodeStringsDetects.contains(RECORD_NAME_CODEVEIL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotUnicodeStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // CodeWall
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_CODEWALL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_CODEWALL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Crypto Obfuscator for .NET
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_CRYPTOOBFUSCATORFORNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_CRYPTOOBFUSCATORFORNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Eazfuscator
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_EAZFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_EAZFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Obfuscar
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_OBFUSCAR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_OBFUSCAR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // .NET Spider
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETSPIDER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSPIDER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Phoenix Protector
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_PHOENIXPROTECTOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Sixxpack
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SIXXPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SIXXPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // ReNET-Pack
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_RENETPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_RENETPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // .netshrink
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSHRINK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETSHRINK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Xenocode Virtual Application Studio 2009
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Postbuild 2009 for .NET")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Xenocode Postbuild 2010 for .NET
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Postbuild 2010 for .NET")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_DOTNETREACTOR)) {
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DOTNETREACTOR) &&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "__", &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DOTNETREACTOR);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
        if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_CODEVEIL)) {
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CODEVEIL)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CODEVEIL)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CODEVEIL);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    _SCANS_STRUCT ssLinker = {};
    _SCANS_STRUCT ssCompilerCPP = {};
    _SCANS_STRUCT ssCompilerMASM = {};
    _SCANS_STRUCT ssCompilerVB = {};
    _SCANS_STRUCT ssCompilerDot = {};
    _SCANS_STRUCT ssTool = {};
    _SCANS_STRUCT ssMFC = {};
    _SCANS_STRUCT ssNET = {};

    QMap<QString, QString> mapVersions;

    mapVersions.insert("1", "8");
    mapVersions.insert("2", "9");
    mapVersions.insert("4", "10");
    mapVersions.insert("5", "11");
    mapVersions.insert("6", "12");
    mapVersions.insert("7", "13");
    mapVersions.insert("8", "14");
    mapVersions.insert("9", "15");
    mapVersions.insert("10", "16");
    mapVersions.insert("11", "17");
    mapVersions.insert("12", "18");
    mapVersions.insert("14", "19");

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Linker
        if ((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)) && (!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
            ssLinker.type = RECORD_TYPE_LINKER;
            ssLinker.name = RECORD_NAME_MICROSOFTLINKER;
            //        } else if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
            //            bool bMicrosoftLinker = false;

            //            if ((pPEInfo->nMajorLinkerVersion == 8) && (pPEInfo->nMinorImageVersion == 0))  // 8.0
            //            {
            //                bMicrosoftLinker = true;
            //            }

            //            if (bMicrosoftLinker) {
            //                ssLinker.type = RECORD_TYPE_LINKER;
            //                ssLinker.name = RECORD_NAME_MICROSOFTLINKER;
            //            }
        } else if ((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) && (pPEInfo->cliInfo.bValid)) {
            ssLinker.type = RECORD_TYPE_LINKER;
            ssLinker.name = RECORD_NAME_MICROSOFTLINKER;

            ssCompilerDot.type = RECORD_TYPE_COMPILER;
            ssCompilerDot.name = RECORD_NAME_VISUALCSHARP;
        }

        // MFC
        // Static
        if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            qint64 _nOffset = pPEInfo->osDataSection.nOffset;
            qint64 _nSize = pPEInfo->osDataSection.nSize;

            qint64 nOffset_MFC = pe.find_ansiString(_nOffset, _nSize, "CMFCComObject", pPdStruct);

            if (nOffset_MFC != -1) {
                ssMFC.type = RECORD_TYPE_LIBRARY;
                ssMFC.name = RECORD_NAME_MFC;
                ssMFC.sInfo = "Static";
            }
        }

        qint32 nNumberOfImports = pPEInfo->listImports.count();

        for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            // https://en.wikipedia.org/wiki/Microsoft_Foundation_Class_Library
            // TODO eMbedded Visual C++ 4.0 		mfcce400.dll 	MFC 6.0
            if (XBinary::isRegExpPresent("^MFC", pPEInfo->listImports.at(i).sName.toUpper())) {
                //                    QRegularExpression rxVersion("(\\d+)");
                //                    QRegularExpressionMatch matchVersion=rxVersion.match(pPEInfo->listImports.at(i).sName.toUpper());
                //
                //                    if(matchVersion.hasMatch())
                //                    {
                //                        double dVersion=matchVersion.captured(0).toDouble()/10;
                //
                //                        if(dVersion)
                //                        {
                //                            recordMFC.type=RECORD_TYPE_LIBRARY;
                //                            recordMFC.name=RECORD_NAME_MFC;
                //                            recordMFC.sVersion=QString::number(dVersion,'f',2);
                //
                //                            if(pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL"))
                //                            {
                //                                recordMFC.sInfo="Unicode";
                //                            }
                //                        }
                //                    }

                QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                if (sVersion != "") {
                    double dVersion = sVersion.toDouble() / 10;

                    if (dVersion) {
                        ssMFC.type = RECORD_TYPE_LIBRARY;
                        ssMFC.name = RECORD_NAME_MFC;
                        ssMFC.sVersion = QString::number(dVersion, 'f', 2);

                        if (pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL")) {
                            ssMFC.sInfo = "Unicode";
                        }
                    }
                }

                break;
            }
        }

        // Rich
        // https://github.com/dishather/richprint/blob/master/comp_id.txt
        qint32 nRichSignaturesCount = pPEInfo->listRichSignatures.count();

        QList<_SCANS_STRUCT> listRichDescriptions;

        for (qint32 i = 0; (i < nRichSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            listRichDescriptions.append(MSDOS_richScan(pPEInfo->listRichSignatures.at(i).nId, pPEInfo->listRichSignatures.at(i).nVersion,
                                                       pPEInfo->listRichSignatures.at(i).nCount, _MS_rich_records, sizeof(_MS_rich_records),
                                                       pPEInfo->basic_info.id.fileType, XBinary::FT_MSDOS, &(pPEInfo->basic_info), DETECTTYPE_RICH, pPdStruct));
        }

        _fixRichSignatures(&listRichDescriptions, pPEInfo->nMajorLinkerVersion, pPEInfo->nMinorLinkerVersion, pPdStruct);

        qint32 nRichDescriptionsCount = listRichDescriptions.count();

        _SCANS_STRUCT _ssLinker = {};
        _SCANS_STRUCT _ssCompilerCPP = {};
        _SCANS_STRUCT _ssCompilerMASM = {};
        _SCANS_STRUCT _ssCompilerVB = {};

        for (qint32 i = nRichDescriptionsCount - 1; (i >= 0) && (XBinary::isPdStructNotCanceled(pPdStruct)); i--) {
            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_LINKER) {
                if (listRichDescriptions.at(i).sVersion > _ssLinker.sVersion) {
                    _ssLinker.name = listRichDescriptions.at(i).name;
                    _ssLinker.sVersion = listRichDescriptions.at(i).sVersion;
                    _ssLinker.sInfo = listRichDescriptions.at(i).sInfo;
                    _ssLinker.type = listRichDescriptions.at(i).type;
                }
            } else if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_COMPILER) {
                if (listRichDescriptions.at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) {
                    if (listRichDescriptions.at(i).sInfo != "Basic") {
                        if (listRichDescriptions.at(i).sVersion > _ssCompilerCPP.sVersion) {
                            _ssCompilerCPP.name = RECORD_NAME_VISUALCCPP;
                            _ssCompilerCPP.sVersion = listRichDescriptions.at(i).sVersion;
                            _ssCompilerCPP.sInfo = listRichDescriptions.at(i).sInfo;
                            _ssCompilerCPP.type = listRichDescriptions.at(i).type;
                        }
                    } else {
                        if (listRichDescriptions.at(i).sVersion > _ssCompilerVB.sVersion) {
                            _ssCompilerVB.type = RECORD_TYPE_COMPILER;
                            _ssCompilerVB.name = RECORD_NAME_VISUALBASIC;
                            _ssCompilerVB.sVersion = listRichDescriptions.at(i).sVersion;

                            QString _sVersion = _ssCompilerVB.sVersion.section(".", 0, 0);
                            QString _sVersionCompiler = mapVersions.key(_sVersion, "");

                            if (_sVersionCompiler != "") {
                                _ssCompilerVB.sVersion = _sVersionCompiler + "." + _ssCompilerVB.sVersion.section(".", 1, 2);
                            }

                            _ssCompilerVB.sInfo = "Native";
                        }
                    }
                } else if (listRichDescriptions.at(i).name == RECORD_NAME_MASM) {
                    if (listRichDescriptions.at(i).sVersion > _ssCompilerMASM.sVersion) {
                        _ssCompilerMASM.name = listRichDescriptions.at(i).name;
                        _ssCompilerMASM.sVersion = listRichDescriptions.at(i).sVersion;
                        _ssCompilerMASM.sInfo = listRichDescriptions.at(i).sInfo;
                        _ssCompilerMASM.type = listRichDescriptions.at(i).type;
                    }
                } else {
                    if (listRichDescriptions.at(i).sVersion > _ssCompilerCPP.sVersion) {
                        _ssCompilerCPP.name = listRichDescriptions.at(i).name;
                        _ssCompilerCPP.sVersion = listRichDescriptions.at(i).sVersion;
                        _ssCompilerCPP.sInfo = listRichDescriptions.at(i).sInfo;
                        _ssCompilerCPP.type = listRichDescriptions.at(i).type;
                    }
                }
            }

            //            if (listRichDescriptions.at(i).name == SpecAbstract::RECORD_NAME_IMPORT) {
            //                break;
            //            }
        }

        if (_ssLinker.name != RECORD_NAME_UNKNOWN) {
            ssLinker.name = _ssLinker.name;
            ssLinker.sVersion = _ssLinker.sVersion;
            ssLinker.sInfo = _ssLinker.sInfo;
            ssLinker.type = _ssLinker.type;
        }

        if (_ssCompilerVB.name != RECORD_NAME_UNKNOWN) {
            ssCompilerVB.name = _ssCompilerVB.name;
            ssCompilerVB.sVersion = _ssCompilerVB.sVersion;
            ssCompilerVB.sInfo = _ssCompilerVB.sInfo;
            ssCompilerVB.type = _ssCompilerVB.type;
        } else if (_ssCompilerCPP.name != RECORD_NAME_UNKNOWN) {
            ssCompilerCPP.name = _ssCompilerCPP.name;
            ssCompilerCPP.sVersion = _ssCompilerCPP.sVersion;
            ssCompilerCPP.sInfo = _ssCompilerCPP.sInfo;
            ssCompilerCPP.type = _ssCompilerCPP.type;
        } else if (_ssCompilerMASM.name != RECORD_NAME_UNKNOWN) {
            ssCompilerMASM.name = _ssCompilerMASM.name;
            ssCompilerMASM.sVersion = _ssCompilerMASM.sVersion;
            ssCompilerMASM.sInfo = _ssCompilerMASM.sInfo;
            ssCompilerMASM.type = _ssCompilerMASM.type;
        }

        // TODO Check MASM for .NET

        if (!pPEInfo->cliInfo.bValid) {
            // VB
            bool bVBnew = false;

            _SCANS_STRUCT _recordCompiler = {};

            if (XPE::isImportLibraryPresentI("VB40032.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "4.0";
            } else if (XPE::isImportLibraryPresentI("MSVBVM50.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "5.0";
                bVBnew = true;
            }

            if (XPE::isImportLibraryPresentI("MSVBVM60.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "6.0";
                bVBnew = true;
            }

            if (bVBnew) {
                if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize = pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_Options = pe.find_uint32(_nOffset, _nSize, 0x21354256, false, pPdStruct);

                    if (nOffset_Options == -1) {
                        nOffset_Options = pe.find_uint32(_nOffset, _nSize, 0x21364256, false, pPdStruct);
                    }

                    if (nOffset_Options != -1) {
                        quint32 nOffsetOptions2 = pe.read_uint32(_nOffset + 0x30);

                        quint32 nOffsetOptions3 = pe.addressToOffset(pe.getBaseAddress() + nOffsetOptions2);
                        quint32 nValue = pe.read_uint32(nOffsetOptions3 + 0x20);
                        _recordCompiler.sInfo = nValue ? "P-Code" : "Native";
                    }
                }
            }

            if (ssCompilerCPP.name != RECORD_NAME_VISUALBASIC) {
                if (_recordCompiler.name == RECORD_NAME_VISUALBASIC) {
                    ssCompilerVB = _recordCompiler;
                }
            }
        } else {
            ssNET.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            ssNET.name = SpecAbstract::RECORD_NAME_DOTNET;
            ssNET.sVersion = pPEInfo->cliInfo.metaData.header.sVersion;

            if (pPEInfo->cliInfo.bHidden) {
                ssNET.sInfo = "Hidden";
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_VBNET)) {
                ssCompilerVB.type = RECORD_TYPE_COMPILER;
                ssCompilerVB.name = RECORD_NAME_VBNET;
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_JSCRIPT)) {
                ssCompilerVB.type = RECORD_TYPE_COMPILER;
                ssCompilerVB.name = RECORD_NAME_JSCRIPT;
            }
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssCompilerCPP.type == RECORD_TYPE_UNKNOWN)) {
            ssCompilerCPP.type = SpecAbstract::RECORD_TYPE_COMPILER;
            ssCompilerCPP.name = SpecAbstract::RECORD_NAME_VISUALCCPP;

            QString _sVersion = mapVersions.value(ssMFC.sVersion.section(".", 0, 0)) + "." + ssMFC.sVersion.section(".", 1, 1);

            if (_sVersion != "") {
                ssCompilerCPP.sVersion = _sVersion;
            }
        }

        if (ssCompilerCPP.name != RECORD_NAME_VISUALCCPP) {
            // TODO Check mb MS Linker only

            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_VISUALCCPP)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_VISUALCCPP);

                ssCompilerCPP.type = ss.type;
                ssCompilerCPP.name = ss.name;
                ssCompilerCPP.sVersion = ss.sVersion;
            }
        }

        // TODO if Export ^? RECORD_NAME_VISUALCCPP/C++

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssMFC.sVersion == "")) {
            if ((ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) && (ssLinker.sVersion != "")) {
                ssMFC.sVersion = ssLinker.sVersion.section(".", 0, 1);
            }
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssLinker.name != RECORD_NAME_MICROSOFTLINKER)) {
            ssLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name = SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if ((ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) && (ssLinker.name != RECORD_NAME_MICROSOFTLINKER)) {
            ssLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name = SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if ((ssLinker.name == RECORD_NAME_MICROSOFTLINKER) && (ssLinker.sVersion == "")) {
            ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssLinker.sVersion == "") && (pPEInfo->nMinorLinkerVersion != 10)) {
            ssLinker.sVersion = ssMFC.sVersion;
            //            recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
        }

        if (ssLinker.name == RECORD_NAME_MICROSOFTLINKER) {
            if (ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) {
                if (ssCompilerCPP.sVersion == "") {
                    QString sLinkerVersion = ssLinker.sVersion;
                    QString sLinkerMajorVersion = sLinkerVersion.section(".", 0, 1);

                    QString _sVersion = mapVersions.value(sLinkerMajorVersion);

                    if (_sVersion != "") {
                        ssCompilerCPP.sVersion = _sVersion;
                    }
                }
            }
        }

        if (ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) {
            QString sCompilerVersion = ssCompilerCPP.sVersion;
            QString sCompilerBuildVersion = sCompilerVersion.section(".", 2, 2);

            bool bNewMSVC = false;
            if (sCompilerVersion.toInt() == 19) {
                bNewMSVC = true;
            }

            ssTool.type = SpecAbstract::RECORD_TYPE_TOOL;
            ssTool.name = SpecAbstract::RECORD_NAME_MICROSOFTVISUALSTUDIO;

            // https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warnings-by-compiler-version?view=vs-2019
            // https://github.com/dishather/richprint/blob/master/comp_id.txt

            if (!bNewMSVC) {
                if (sCompilerVersion == "12.00.8168") ssTool.sVersion = "6.0";
                else if (sCompilerVersion == "12.00.8804") ssTool.sVersion = "6.0 SP5-SP6";
                else if (sCompilerVersion == "12.00.8447") ssTool.sVersion = "6.0 SP5";
                else if (sCompilerVersion == "13.00.9176") ssTool.sVersion = "Windows XP SP1 DDK";
                else if (sCompilerVersion == "13.00.9466") ssTool.sVersion = "2002(.NET) 7.0.9466";
                else if (sCompilerVersion == "13.10.3052") ssTool.sVersion = "2003";
                else if (sCompilerVersion == "13.10.3077") ssTool.sVersion = "2003(.NET) 7.0.1.3088";
                else if (sCompilerVersion == "13.10.4035") ssTool.sVersion = "Windows Server 2003 SP1 DDK";
                else if (sCompilerVersion == "13.10.6030") ssTool.sVersion = "2003(.NET) SP1 (kb918007)";
                else if (sCompilerVersion == "14.00.40310") ssTool.sVersion = "Windows Server 2003 SP1 DDK (for AMD64)";
                else if (sCompilerVersion == "14.00.40607") ssTool.sVersion = "2005 Beta 1 [8.0]";
                else if (sCompilerVersion == "14.00.50215") ssTool.sVersion = "2005 Beta 2 [8.0]";
                else if (sCompilerVersion == "14.00.50320") ssTool.sVersion = "2005 [8.0]";
                else if (sCompilerVersion == "14.00.50727") ssTool.sVersion = "2005 SP1";
                else if (sCompilerVersion == "15.00.20706") ssTool.sVersion = "2008 Beta 2 [9.0]";
                else if (sCompilerVersion == "15.00.21022") ssTool.sVersion = "2008 (9.0.21022.8 RTM)";
                else if (sCompilerVersion == "15.00.30411") ssTool.sVersion = "2008 with Feature Pack";
                else if (sCompilerVersion == "15.00.30729") ssTool.sVersion = "2008 SP1 (9.0.30729.1 SP)";
                else if (sCompilerVersion == "16.00.20506") ssTool.sVersion = "2010 Beta 1";
                else if (sCompilerVersion == "16.00.21003") ssTool.sVersion = "2010 Beta 2";
                else if (sCompilerVersion == "16.00.30319") ssTool.sVersion = "2010 (10.0.30319.1 RTMRel)";
                else if (sCompilerVersion == "16.00.40219") ssTool.sVersion = "2010 SP1 kb 983509 (10.0.40219.1 SP1Rel)";
                else if (sCompilerVersion == "17.00.50727") ssTool.sVersion = "2012 Premium (11.0.50727.1 RTMREL)";
                else if (sCompilerVersion == "17.00.51025") ssTool.sVersion = "2012 November CTP [11.0]";
                else if (sCompilerVersion == "17.00.51106") ssTool.sVersion = "2012 Update 1 (17.00.51106.1 Update 1)";
                else if (sCompilerVersion == "17.00.60315") ssTool.sVersion = "2012 Update 2 (17.00.60315.1 Update 2)";
                else if (sCompilerVersion == "17.00.60610") ssTool.sVersion = "2012 Update 3 (17.00.60610.1 Update 3)";
                else if (sCompilerVersion == "17.00.61030") ssTool.sVersion = "2012 Premium Update 4 (11.0.61030.00 Update 4)";
                else if (sCompilerVersion == "18.00.20617") ssTool.sVersion = "2013 Preview [12.0]";
                else if (sCompilerVersion == "18.00.20827") ssTool.sVersion = "2013 RC [12.0]";
                else if (sCompilerVersion == "18.00.21005") ssTool.sVersion = "2013 RTM";
                else if (sCompilerVersion == "18.00.21114") ssTool.sVersion = "2013 Nobemver CTP [12.0";
                else if (sCompilerVersion == "18.00.30324") ssTool.sVersion = "2013 Update2 RC [12.0]";
                else if (sCompilerVersion == "18.00.30501") ssTool.sVersion = "2013 12.0.30501.00 Update 2";
                else if (sCompilerVersion == "18.00.30723") ssTool.sVersion = "2013 12.0.30723.00 Update 3";
                else if (sCompilerVersion == "18.00.31101") ssTool.sVersion = "2013 12.0.31101.00 Update 4";
                else if (sCompilerVersion == "18.00.40629") ssTool.sVersion = "2013 12.0.40629.00 Update 5";
            } else {
                if (sCompilerBuildVersion == "22215") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23007") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23013") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23026") ssTool.sVersion = "Community 2015 [14.0]";
                else if (sCompilerBuildVersion == "23506") ssTool.sVersion = "Community 2015 14.0.24728.2 (UPD 1)";
                else if (sCompilerBuildVersion == "23918") ssTool.sVersion = "Community 2015 UPD2 (14.0.25123.0)";
                else if (sCompilerBuildVersion == "24103") ssTool.sVersion = "2015 SP1";  // ???
                else if (sCompilerBuildVersion == "24118") ssTool.sVersion = "2015 SP1";  // ???
                else if (sCompilerBuildVersion == "24123") ssTool.sVersion = "Community 2015 UPD3";
                else if (sCompilerBuildVersion == "24210") ssTool.sVersion = "2015 Update 3 [14.0]";
                else if (sCompilerBuildVersion == "24212") ssTool.sVersion = "2015 Update 3";
                else if (sCompilerBuildVersion == "24213") ssTool.sVersion = "Community 2015 UPD3.1";
                else if (sCompilerBuildVersion == "24215") ssTool.sVersion = "2015 Update 3.1";
                else if (sCompilerBuildVersion == "24218") ssTool.sVersion = "2015 Update 3.1";
                else if (sCompilerBuildVersion == "24723") ssTool.sVersion = "2015";                    // Update 4? 2017?
                else if (sCompilerBuildVersion == "25017") ssTool.sVersion = "2017 version 15.0-15.2";  // 14.10
                else if (sCompilerBuildVersion == "25019") ssTool.sVersion = "2017";                    // 15.2?
                else if (sCompilerBuildVersion == "25506") ssTool.sVersion = "2017 version 15.3.0";     // 14.11
                else if (sCompilerBuildVersion == "25507") ssTool.sVersion = "2017 version 15.3.3";
                else if (sCompilerBuildVersion == "25542") ssTool.sVersion = "2017 version 15.4.4";
                else if (sCompilerBuildVersion == "25547") ssTool.sVersion = "2017 version 15.4.5";
                else if (sCompilerBuildVersion == "25830") ssTool.sVersion = "2017 version 15.5.0";  // 14.12
                else if (sCompilerBuildVersion == "25831") ssTool.sVersion = "2017 version 15.5.2";
                else if (sCompilerBuildVersion == "25834") ssTool.sVersion = "2017 version 15.5.3-15.5.4";
                else if (sCompilerBuildVersion == "25835") ssTool.sVersion = "2017 version 15.5.6-15.5.7";
                else if (sCompilerBuildVersion == "26128") ssTool.sVersion = "2017 version 15.6.0-15.6.2";  // 14.13
                else if (sCompilerBuildVersion == "26129") ssTool.sVersion = "2017 version 15.6.3-15.6.4";
                else if (sCompilerBuildVersion == "26131") ssTool.sVersion = "2017 version 15.6.6";
                else if (sCompilerBuildVersion == "26132") ssTool.sVersion = "2017 version 15.6.7";
                else if (sCompilerBuildVersion == "26428") ssTool.sVersion = "2017 version 15.7.1";  // 14.14
                else if (sCompilerBuildVersion == "26429") ssTool.sVersion = "2017 version 15.7.2";
                else if (sCompilerBuildVersion == "26430") ssTool.sVersion = "2017 version 15.7.3";
                else if (sCompilerBuildVersion == "26431") ssTool.sVersion = "2017 version 15.7.4";
                else if (sCompilerBuildVersion == "26433") ssTool.sVersion = "2017 version 15.7.5";
                else if (sCompilerBuildVersion == "26726") ssTool.sVersion = "2017 version 15.8.0";  // 14.15
                else if (sCompilerBuildVersion == "26729") ssTool.sVersion = "2017 version 15.8.4";
                else if (sCompilerBuildVersion == "26730") ssTool.sVersion = "2017 version 15.8.9";
                else if (sCompilerBuildVersion == "26732") ssTool.sVersion = "2017 version 15.8.5";
                else if (sCompilerBuildVersion == "26926") ssTool.sVersion = "2017 version 15.9.0";  // 14.16
                else if (sCompilerBuildVersion == "27023") ssTool.sVersion = "2017 version 15.9.1";
                else if (sCompilerBuildVersion == "27025") ssTool.sVersion = "2017 version 15.9.4";
                else if (sCompilerBuildVersion == "27026") ssTool.sVersion = "2017 version 15.9.5";
                else if (sCompilerBuildVersion == "27027") ssTool.sVersion = "2017 version 15.9.7";
                else if (sCompilerBuildVersion == "27030") ssTool.sVersion = "2017 version 15.9.11";
                else if (sCompilerBuildVersion == "27508") ssTool.sVersion = "2019 version 16.0.0";  // 14.20
                else if (sCompilerBuildVersion == "27702") ssTool.sVersion = "2019 version 16.1.2";  // 14.21
                else if (sCompilerBuildVersion == "27905") ssTool.sVersion = "2019 version 16.2.3";  // 14.22
                else if (sCompilerBuildVersion == "28105") ssTool.sVersion = "2019 version 16.3.2";  // 14.23
                else if (sCompilerBuildVersion == "28314") ssTool.sVersion = "2019 version 16.4.0";  // 14.24
                else if (sCompilerBuildVersion == "28315") ssTool.sVersion = "2019 version 16.4.3";
                else if (sCompilerBuildVersion == "28316") ssTool.sVersion = "2019 version 16.4.4";
                else if (sCompilerBuildVersion == "28319") ssTool.sVersion = "2019 version 16.4.6";
                else if (sCompilerBuildVersion == "28610") ssTool.sVersion = "2019 version 16.5.0";  // 14.25
                else if (sCompilerBuildVersion == "28611") ssTool.sVersion = "2019 version 16.5.1";
                else if (sCompilerBuildVersion == "28612") ssTool.sVersion = "2019 version 16.5.2";
                else if (sCompilerBuildVersion == "28614") ssTool.sVersion = "2019 version 16.5.4";
                else if (sCompilerBuildVersion == "28805") ssTool.sVersion = "2019 version 16.6.0";  // 14.26
                else if (sCompilerBuildVersion == "28806") ssTool.sVersion = "2019 version 16.6.2-16.6.5";
                else if (sCompilerBuildVersion == "29110") ssTool.sVersion = "2019 version 16.7.0";  // 14.27
                else if (sCompilerBuildVersion == "29111") ssTool.sVersion = "2019 version 16.7.1-16.7.4";
                else if (sCompilerBuildVersion == "29112") ssTool.sVersion = "2019 version 16.7.5";
                else if (sCompilerBuildVersion == "29333") ssTool.sVersion = "2019 version 16.8.0";  // 14.28
                else if (sCompilerBuildVersion == "29334") ssTool.sVersion = "2019 version 16.8.2";
                else if (sCompilerBuildVersion == "29335") ssTool.sVersion = "2019 version 16.8.3";
                else if (sCompilerBuildVersion == "29336") ssTool.sVersion = "2019 version 16.8.4";
                else if (sCompilerBuildVersion == "29337") ssTool.sVersion = "2019 version 16.8.5";
                else if (sCompilerBuildVersion == "29910") ssTool.sVersion = "2019 version 16.9.0";
                else if (sCompilerBuildVersion == "29913") ssTool.sVersion = "2019 version 16.9.2";
                else if (sCompilerBuildVersion == "29914") ssTool.sVersion = "2019 version 16.9.4";
                else if (sCompilerBuildVersion == "29915") ssTool.sVersion = "2019 version 16.9.5";
                else if (sCompilerBuildVersion == "30037") ssTool.sVersion = "2019 version 16.10.0";
                else if (sCompilerBuildVersion == "30038") ssTool.sVersion = "2019 version 16.10.3";
                else if (sCompilerBuildVersion == "30040") ssTool.sVersion = "2019 version 16.10.4";
                else if (sCompilerBuildVersion == "30133") ssTool.sVersion = "2019 version 16.11.1";  // 14.29
                else if (sCompilerBuildVersion == "30136") ssTool.sVersion = "2019 version 16.11.5";
                else if (sCompilerBuildVersion == "30137") ssTool.sVersion = "2019 version 16.11.6";
                else if (sCompilerBuildVersion == "30138") ssTool.sVersion = "2019 version 16.11.8";
                else if (sCompilerBuildVersion == "30139") ssTool.sVersion = "2019 version 16.11.9";
                else if (sCompilerBuildVersion == "30140") ssTool.sVersion = "2019 version 16.11.10";
                else if (sCompilerBuildVersion == "30141") ssTool.sVersion = "2019 version 16.11.11";
                else if (sCompilerBuildVersion == "30142") ssTool.sVersion = "2019 version 16.11.12";
                else if (sCompilerBuildVersion == "30143") ssTool.sVersion = "2019 version 16.11.13";
                else if (sCompilerBuildVersion == "30144") ssTool.sVersion = "2019 version 16.11.14";
                else if (sCompilerBuildVersion == "30145") ssTool.sVersion = "2019 version 16.11.15";
                else if (sCompilerBuildVersion == "30146") ssTool.sVersion = "2019 version 16.11.17";
                else if (sCompilerBuildVersion == "30147") ssTool.sVersion = "2019 version 16.11.21";
                else if (sCompilerBuildVersion == "30148") ssTool.sVersion = "2019 version 16.11.24-16.11.26";
                else if (sCompilerBuildVersion == "30151") ssTool.sVersion = "2019 version 16.11.27";

                if (ssTool.sVersion == "") {
                    if (sCompilerBuildVersion == "30401") ssTool.sVersion = "2022 version 17.0.0 preview2";  // 14.30
                    else if (sCompilerBuildVersion == "30423") ssTool.sVersion = "2022 version 17.0.0 pre 3.1";
                    else if (sCompilerBuildVersion == "30528") ssTool.sVersion = "2022 version 17.0.0 pre 4.0";
                    else if (sCompilerBuildVersion == "30704") ssTool.sVersion = "2022 version 17.0.0 pre 5.0";
                    else if (sCompilerBuildVersion == "30705") ssTool.sVersion = "2022 version 17.0.0 pre 7.0";
                    else if (sCompilerBuildVersion == "30818") ssTool.sVersion = "2022 version 17.1.0 pre 1.0";  // 14.31
                    else if (sCompilerBuildVersion == "30919") ssTool.sVersion = "2022 version 17.1.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31103") ssTool.sVersion = "2022 version 17.1.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31104") ssTool.sVersion = "2022 version 17.1.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31114") ssTool.sVersion = "2022 version 17.2.0 pre 1.0";  // 14.32
                    else if (sCompilerBuildVersion == "31302") ssTool.sVersion = "2022 version 17.2.0 pre 2.1";
                    else if (sCompilerBuildVersion == "31326") ssTool.sVersion = "2022 version 17.2.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31328") ssTool.sVersion = "2022 version 17.2.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31329") ssTool.sVersion = "2022 version 17.2.1-17.2.4";
                    else if (sCompilerBuildVersion == "31332") ssTool.sVersion = "2022 version 17.2.5";
                    else if (sCompilerBuildVersion == "31424") ssTool.sVersion = "2022 version 17.3.0 pre 1.0";  // 14.33
                    else if (sCompilerBuildVersion == "31517") ssTool.sVersion = "2022 version 17.3.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31627") ssTool.sVersion = "2022 version 17.3.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31628") ssTool.sVersion = "2022 version 17.3.0 pre 4.0";
                    else if (sCompilerBuildVersion == "31629") ssTool.sVersion = "2022 version 17.3.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31630") ssTool.sVersion = "2022 version 17.3.4";
                    else if (sCompilerBuildVersion == "31721") ssTool.sVersion = "2022 version 17.4.0 pre 1.0";  // 14.34
                    else if (sCompilerBuildVersion == "31823") ssTool.sVersion = "2022 version 17.4.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31921") ssTool.sVersion = "2022 version 17.4.0 pre 4.0";
                    else if (sCompilerBuildVersion == "31932") ssTool.sVersion = "2022 version 17.4.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31933") ssTool.sVersion = "2022 version 17.4.0 pre 6.0";
                    else if (sCompilerBuildVersion == "31935") ssTool.sVersion = "2022 version 17.4.2";
                    else if (sCompilerBuildVersion == "31937") ssTool.sVersion = "2022 version 17.4.3";
                    else if (sCompilerBuildVersion == "31942") ssTool.sVersion = "2022 version 17.4.5";
                    else if (sCompilerBuildVersion == "32019") ssTool.sVersion = "2022 version 17.5.0 pre 1.0";  // 14.35
                    else if (sCompilerBuildVersion == "32124") ssTool.sVersion = "2022 version 17.5.0 pre 2.0";
                    else if (sCompilerBuildVersion == "32213") ssTool.sVersion = "2022 version 17.5.0 pre 4.0";
                    else if (sCompilerBuildVersion == "32215") ssTool.sVersion = "2022 version 17.5.0-17.5.2";
                    else if (sCompilerBuildVersion == "32216") ssTool.sVersion = "2022 version 17.5.3";
                    else if (sCompilerBuildVersion == "32217") ssTool.sVersion = "2022 version 17.5.4-17.5.5";
                    else if (sCompilerBuildVersion == "32323") ssTool.sVersion = "2022 version 17.6.0 pre 1.0";  // 14.36
                    else if (sCompilerBuildVersion == "32502") ssTool.sVersion = "2022 version 17.6.0 pre 2.0";
                    else if (sCompilerBuildVersion == "32522") ssTool.sVersion = "2022 version 17.6.0 pre 3.0-4.0";
                    else if (sCompilerBuildVersion == "32530") ssTool.sVersion = "2022 version 17.6.0 pre 5.0-7.0";
                    else if (sCompilerBuildVersion == "32532") ssTool.sVersion = "2022 version 17.6.0-17.6.2";
                    else if (sCompilerBuildVersion == "32534") ssTool.sVersion = "2022 version 17.6.3";
                    else if (sCompilerBuildVersion == "32535") ssTool.sVersion = "2022 version 17.6.4";
                    else if (sCompilerBuildVersion == "32705") ssTool.sVersion = "2022 version 17.7.0 pre 1.0-2.0";  // 14.37
                }
            }

            if (ssTool.sVersion == "") {
                QString sLinkerMajorVersion = ssLinker.sVersion.section(".", 0, 1);

                if (sLinkerMajorVersion != "") {
                    if (sLinkerMajorVersion == "4.00") ssTool.sVersion = "4.00";
                    else if (sLinkerMajorVersion == "4.20") ssTool.sVersion = "4.20";
                    else if (sLinkerMajorVersion == "5.00") ssTool.sVersion = "5.0";
                    else if (sLinkerMajorVersion == "6.00") ssTool.sVersion = "6.0";
                    else if (sLinkerMajorVersion == "7.00") ssTool.sVersion = "2002";
                    else if (sLinkerMajorVersion == "7.10") ssTool.sVersion = "2003";
                    else if (sLinkerMajorVersion == "8.00") ssTool.sVersion = "2005";
                    else if (sLinkerMajorVersion == "9.00") ssTool.sVersion = "2008";
                    else if (sLinkerMajorVersion == "10.00") ssTool.sVersion = "2010";
                    else if (sLinkerMajorVersion == "11.00") ssTool.sVersion = "2012";
                    else if (sLinkerMajorVersion == "12.00") ssTool.sVersion = "2013";
                    else if (sLinkerMajorVersion == "14.00") ssTool.sVersion = "2015";
                    else if (sLinkerMajorVersion == "14.10") ssTool.sVersion = "2017 version 15.0-15.2";
                    else if (sLinkerMajorVersion == "14.11") ssTool.sVersion = "2017 version 15.3";
                    else if (sLinkerMajorVersion == "14.12") ssTool.sVersion = "2017 version 15.5";
                    else if (sLinkerMajorVersion == "14.13") ssTool.sVersion = "2017 version 15.6";
                    else if (sLinkerMajorVersion == "14.14") ssTool.sVersion = "2017 version 15.7";
                    else if (sLinkerMajorVersion == "14.15") ssTool.sVersion = "2017 version 15.8";
                    else if (sLinkerMajorVersion == "14.16") ssTool.sVersion = "2017 version 15.9";
                    else if (sLinkerMajorVersion == "14.20") ssTool.sVersion = "2019 version 16.0";
                    else if (sLinkerMajorVersion == "14.21") ssTool.sVersion = "2019 version 16.1";
                    else if (sLinkerMajorVersion == "14.22") ssTool.sVersion = "2019 version 16.2";
                    else if (sLinkerMajorVersion == "14.23") ssTool.sVersion = "2019 version 16.3";
                    else if (sLinkerMajorVersion == "14.24") ssTool.sVersion = "2019 version 16.4";
                    else if (sLinkerMajorVersion == "14.25") ssTool.sVersion = "2019 version 16.5";
                    else if (sLinkerMajorVersion == "14.26") ssTool.sVersion = "2019 version 16.6";
                    else if (sLinkerMajorVersion == "14.27") ssTool.sVersion = "2019 version 16.7-16.8";
                    else if (sLinkerMajorVersion == "14.28") ssTool.sVersion = "2019 version 16.9-16.10";
                    else if (sLinkerMajorVersion == "14.29") ssTool.sVersion = "2019 version 16.11";
                    else if (sLinkerMajorVersion == "14.30") ssTool.sVersion = "2022 version 17.0";
                    else if (sLinkerMajorVersion == "14.31") ssTool.sVersion = "2022 version 17.1";
                    else if (sLinkerMajorVersion == "14.32") ssTool.sVersion = "2022 version 17.2";
                    else if (sLinkerMajorVersion == "14.33") ssTool.sVersion = "2022 version 17.3";
                    else if (sLinkerMajorVersion == "14.34") ssTool.sVersion = "2022 version 17.4";
                    else if (sLinkerMajorVersion == "14.35") ssTool.sVersion = "2022 version 17.5";
                    else if (sLinkerMajorVersion == "14.36") ssTool.sVersion = "2022 version 17.6";
                    else if (sLinkerMajorVersion == "14.37") ssTool.sVersion = "2022 version 17.7";
                }
            }

            if (ssTool.sVersion == "") {
                // TODO
            }
        } else if (ssCompilerMASM.name == SpecAbstract::RECORD_NAME_MASM) {
            QString sCompilerVersion = ssCompilerMASM.sVersion;
            QString sLinkerVersion = ssLinker.sVersion;

            if ((sLinkerVersion == "5.12.8078") && (sCompilerVersion == "6.14.8444")) {
                ssTool.type = SpecAbstract::RECORD_TYPE_TOOL;
                ssTool.name = SpecAbstract::RECORD_NAME_MASM32;
                ssTool.sVersion = "8-11";
            }
        }

        if (pe.isImportLibraryPresentI("MSVCRT.dll", &(pPEInfo->listImports))) {
            // TODO
        }

        if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pPEInfo->basic_info), &ssLinker));
        }

        if (ssCompilerCPP.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerCPP.name, scansToScan(&(pPEInfo->basic_info), &ssCompilerCPP));
        }

        if (ssCompilerMASM.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerMASM.name, scansToScan(&(pPEInfo->basic_info), &ssCompilerMASM));
        }

        if (ssCompilerVB.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerVB.name, scansToScan(&(pPEInfo->basic_info), &ssCompilerVB));
        }

        if (ssCompilerDot.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerDot.name, scansToScan(&(pPEInfo->basic_info), &ssCompilerDot));
        }

        if (ssTool.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultTools.insert(ssTool.name, scansToScan(&(pPEInfo->basic_info), &ssTool));
        }

        if (ssMFC.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(ssMFC.name, scansToScan(&(pPEInfo->basic_info), &ssMFC));
        }

        if (ssNET.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(ssNET.name, scansToScan(&(pPEInfo->basic_info), &ssNET));
        }
    }
}

void SpecAbstract::PE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    // TODO Turbo Linker
    // https://delphi.fandom.com/wiki/Determine_Delphi_Application
    // TODO if Delphi Linker -> 2.25
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};
        _SCANS_STRUCT recordCompiler = {};
        _SCANS_STRUCT recordTool = {};
        _SCANS_STRUCT recordVCL = {};

        if (pPEInfo->basic_info.mapHeaderDetects.contains(SpecAbstract::RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT recordTurboLinker = pPEInfo->basic_info.mapHeaderDetects.value(SpecAbstract::RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                recordTurboLinker.sVersion = vi.sVersion;
            } else {
                recordTurboLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
            }

            recordLinker = recordTurboLinker;
        }

        if (!pPEInfo->cliInfo.bValid) {
            qint64 nOffset_string = -1;
            qint64 nOffset_Boolean = -1;
            qint64 nOffset_String = -1;
            qint64 nOffset_TObject = -1;
            //        qint64 nOffset_AnsiString=-1;
            //        qint64 nOffset_WideString=-1;

            qint64 nOffset_BorlandCPP = -1;
            qint64 nOffset_CodegearCPP = -1;
            qint64 nOffset_EmbarcaderoCPP_old = -1;
            qint64 nOffset_EmbarcaderoCPP_new = -1;

            QList<VCL_STRUCT> listVCL;

            bool bCppExport = (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames), "__CPPdebugHook")) ||
                              (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames), "___CPPdebugHook"));

            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                qint64 _nSize = pPEInfo->osCodeSection.nSize;

                nOffset_TObject = pe.find_array(_nOffset, _nSize, "\x07\x54\x4f\x62\x6a\x65\x63\x74", 8, pPdStruct);  // TObject

                if (nOffset_TObject != -1) {
                    nOffset_Boolean = pe.find_array(_nOffset, _nSize, "\x07\x42\x6f\x6f\x6c\x65\x61\x6e", 8, pPdStruct);  // Boolean
                    nOffset_string = pe.find_array(_nOffset, _nSize, "\x06\x73\x74\x72\x69\x6e\x67", 7, pPdStruct);       // string

                    if ((nOffset_Boolean != -1) || (nOffset_string != -1)) {
                        if (nOffset_string == -1) {
                            nOffset_String = pe.find_array(_nOffset, _nSize, "\x06\x53\x74\x72\x69\x6e\x67", 7, pPdStruct);  // String
                        }

                        listVCL = PE_getVCLstruct(pDevice, pOptions, _nOffset, _nSize, pPEInfo->bIs64, pPdStruct);
                    }
                }
                //            nOffset_AnsiString=pe.find_array(_nOffset,_nSize,"\x0a\x41\x6e\x73\x69\x53\x74\x72\x69\x6e\x67",11); // AnsiString
                //            nOffset_WideString=pe.find_array(_nOffset,_nSize,"\x0a\x57\x69\x64\x65\x53\x74\x72\x69\x6e\x67",11); // WideString
            }

            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;

                nOffset_BorlandCPP = pe.find_ansiString(_nOffset, _nSize, "Borland C++ - Copyright ", pPdStruct);  // Borland C++ - Copyright 1994 Borland Intl.

                if (nOffset_BorlandCPP == -1) {
                    nOffset_CodegearCPP =
                        pe.find_ansiString(_nOffset, _nSize, "CodeGear C++ - Copyright ", pPdStruct);  // CodeGear C++ - Copyright 2008 Embarcadero TechnologiessData

                    if (nOffset_CodegearCPP == -1) {
                        nOffset_EmbarcaderoCPP_old =
                            pe.find_ansiString(_nOffset, _nSize, "Embarcadero RAD Studio - Copyright ", pPdStruct);  // Embarcadero RAD Studio - Copyright 2009
                                                                                                                     // Embarcadero Technologies, Inc.

                        if (nOffset_EmbarcaderoCPP_old == -1) {
                            nOffset_EmbarcaderoCPP_new =
                                pe.find_ansiString(_nOffset, _nSize, "Embarcadero RAD Studio 27.0 - Copyright 2020 Embarcadero Technologies, Inc.", pPdStruct);
                        }
                    }
                }
            }

            bool bPackageinfo = XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "PACKAGEINFO", &(pPEInfo->listResources));
            bool bDvcal = XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "DVCLAL", &(pPEInfo->listResources));

            if (bPackageinfo || bDvcal || pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP) || (nOffset_TObject != -1) ||
                (nOffset_BorlandCPP != -1) || (nOffset_CodegearCPP != -1) || (nOffset_EmbarcaderoCPP_old != -1) || (nOffset_EmbarcaderoCPP_new != -1) || bCppExport) {
                bool bCpp = false;
                bool bVCL = bPackageinfo;
                QString sVCLVersion;
                QString sDelphiVersion;
                QString sBuilderVersion;
                QString sObjectPascalCompilerVersion;
                QString sCppCompilerVersion;
                bool bNewVersion = false;

                enum COMPANY {
                    COMPANY_BORLAND = 0,
                    COMPANY_CODEGEAR,
                    COMPANY_EMBARCADERO
                };

                COMPANY company = COMPANY_BORLAND;

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP) || (nOffset_BorlandCPP != -1) || (nOffset_CodegearCPP != -1) ||
                    (nOffset_EmbarcaderoCPP_old != -1) || (nOffset_EmbarcaderoCPP_new != -1) || bCppExport) {
                    bCpp = true;

                    if (nOffset_BorlandCPP != -1) {
                        company = COMPANY_BORLAND;
                    } else if (nOffset_CodegearCPP != -1) {
                        company = COMPANY_CODEGEAR;
                    } else if (nOffset_EmbarcaderoCPP_old != -1) {
                        company = COMPANY_EMBARCADERO;
                    } else if (nOffset_EmbarcaderoCPP_new != -1) {
                        company = COMPANY_EMBARCADERO;
                    } else if (bCppExport) {
                        company = COMPANY_EMBARCADERO;
                    }
                }

                if (nOffset_TObject != -1) {
                    if (nOffset_string != -1) {
                        if (bDvcal || bPackageinfo) {
                            // TODO Borland Version
                            sDelphiVersion = "2005+";
                            bNewVersion = true;
                        } else {
                            sDelphiVersion = "2";
                            sObjectPascalCompilerVersion = "9.0";
                        }
                    } else if (nOffset_String != -1) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "3-7";
                    }
                }

                if (bPackageinfo) {
                    VCL_PACKAGEINFO pi = PE_getVCLPackageInfo(pDevice, pOptions, &pPEInfo->listResources, pPdStruct);

                    if (pi.listModules.count()) {
                        quint32 nProducer = (pi.nFlags >> 26) & 0x3;

                        if (nProducer == 2)  // C++
                        {
                            bCpp = true;
                        } else if (nProducer == 3)  // Pascal
                        {
                            bCpp = false;
                        }

                        //                    for(qint32 i=0;i<pi.listModules.count();i++)
                        //                    {
                        //                        qDebug(pi.listModules.at(i).sName.toLatin1().data());
                        //                    }
                    }
                }

                if (nOffset_BorlandCPP != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_BorlandCPP + 24, 4);
                }

                if (nOffset_CodegearCPP != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_CodegearCPP + 25, 4);
                }

                if (nOffset_EmbarcaderoCPP_old != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_EmbarcaderoCPP_old + 35, 4);
                }

                if (nOffset_EmbarcaderoCPP_new != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_EmbarcaderoCPP_new + 40, 4);
                }

                if (sCppCompilerVersion == "2009") {
                    sBuilderVersion = "2009";
                } else if (sCppCompilerVersion == "2015") {
                    sBuilderVersion = "2015";
                } else if (sCppCompilerVersion == "2020") {
                    sBuilderVersion = "10.4";
                }

                if (listVCL.count()) {
                    bVCL = true;
                    qint32 nVCLOffset = listVCL.at(0).nOffset;
                    qint32 nVCLValue = listVCL.at(0).nValue;

                    //                    qDebug("nVCLOffset: %d",nVCLOffset);
                    //                    qDebug("nVCLValue: %d",nVCLValue);
                    //                bVCL=true;

                    if ((nVCLOffset == 24) && (nVCLValue == 168)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2";
                        sObjectPascalCompilerVersion = "9.0";
                        //                    sVCLVersion="20";
                    } else if ((nVCLOffset == 28) && (nVCLValue == 180)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "3";
                        sObjectPascalCompilerVersion = "10.0";
                        //                    sVCLVersion="30";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 276)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "4";
                        sObjectPascalCompilerVersion = "12.0";
                        //                    sVCLVersion="40";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 288)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "5";
                        sObjectPascalCompilerVersion = "13.0";
                        //                    sVCLVersion="50";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 296)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "6 CLX";
                        sObjectPascalCompilerVersion = "14.0";
                        //                    sVCLVersion="60";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 300)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "7 CLX";
                        sObjectPascalCompilerVersion = "15.0";
                        //                    sVCLVersion="70";
                    }
                    //                else if(nVCLOffset==40)
                    //                {
                    //                    if(nVCLValue==264)
                    //                    {
                    //                        recordTool.sVersion="???TODO";
                    //                        sVCLVersion="50";
                    //                    }
                    //                }
                    else if ((nVCLOffset == 40) && (nVCLValue == 348)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "6-7";
                        sObjectPascalCompilerVersion = "14.0-15.0";
                        //                    sVCLVersion="140-150";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 356)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2005";
                        sObjectPascalCompilerVersion = "17.0";
                        //                    sVCLVersion="170";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 400)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2006";
                        sObjectPascalCompilerVersion = "18.0";
                        //                    sVCLVersion="180";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 420)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "2009";
                        sObjectPascalCompilerVersion = "20.0";
                        //                    sVCLVersion="200";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 428)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "2010-XE";
                        sObjectPascalCompilerVersion = "21.0-22.0";
                        //                    sVCLVersion="210-220";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 436)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2-XE4";
                        sObjectPascalCompilerVersion = "23.0-25.0";
                        //                    sVCLVersion="230-250";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 52) && (nVCLValue == 444)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2-XE8";
                        sObjectPascalCompilerVersion = "23.0-29.0";
                        //                    sVCLVersion="230-290";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 104) && (nVCLValue == 760))  // 64
                    {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2";
                        sObjectPascalCompilerVersion = "23.0";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 128) && (nVCLValue == 776))  // 64
                    {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE8-10 Seattle";
                        sObjectPascalCompilerVersion = "30.0";

                        bNewVersion = true;
                    }
                    // TODO more x64
                }

                // TODO Console !!!

                if (bNewVersion) {
                    if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osConstDataSection.nOffset;
                        qint64 _nSize = pPEInfo->osConstDataSection.nSize;

                        qint64 nOffset_Version = 0;

                        if (pPEInfo->bIs64) {
                            nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "Embarcadero Delphi for Win64 compiler version ", pPdStruct);
                        } else {
                            nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "Embarcadero Delphi for Win32 compiler version ", pPdStruct);
                        }

                        if (nOffset_Version != -1) {
                            company = COMPANY_EMBARCADERO;

                            sObjectPascalCompilerVersion = pe.read_ansiString(nOffset_Version + 46);

                            sDelphiVersion = _get_DelphiVersionFromCompiler(sObjectPascalCompilerVersion).sVersion;
                        }
                    }
                }

                recordCompiler.type = RECORD_TYPE_COMPILER;
                recordTool.type = RECORD_TYPE_TOOL;

                if (!bCpp) {
                    if (company == COMPANY_BORLAND) {
                        recordCompiler.name = RECORD_NAME_BORLANDOBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_BORLANDDELPHI;
                    } else if (company == COMPANY_CODEGEAR) {
                        recordCompiler.name = RECORD_NAME_CODEGEAROBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_CODEGEARDELPHI;
                    } else if (company == COMPANY_EMBARCADERO) {
                        recordCompiler.name = RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_EMBARCADERODELPHI;
                    }

                    recordCompiler.sVersion = sObjectPascalCompilerVersion;
                    recordTool.sVersion = sDelphiVersion;
                } else {
                    if (company == COMPANY_BORLAND) {
                        recordCompiler.name = RECORD_NAME_BORLANDCPP;
                        recordTool.name = RECORD_NAME_BORLANDCPPBUILDER;
                    } else if (company == COMPANY_CODEGEAR) {
                        recordCompiler.name = RECORD_NAME_CODEGEARCPP;
                        recordTool.name = RECORD_NAME_CODEGEARCPPBUILDER;
                    } else if (company == COMPANY_EMBARCADERO) {
                        recordCompiler.name = RECORD_NAME_EMBARCADEROCPP;
                        recordTool.name = RECORD_NAME_EMBARCADEROCPPBUILDER;
                    }

                    recordCompiler.sVersion = sCppCompilerVersion;
                    recordTool.sVersion = sBuilderVersion;
                }

                if (bVCL) {
                    recordVCL.type = RECORD_TYPE_LIBRARY;
                    recordVCL.name = RECORD_NAME_VCL;
                    recordVCL.sVersion = sVCLVersion;
                }

                if (recordLinker.type == RECORD_TYPE_UNKNOWN) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_TURBOLINKER, "", "", 0);
                    recordLinker = ss;
                }
            }
        } else {
            // .NET TODO: Check!!!!
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_EMBARCADERODELPHIDOTNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_EMBARCADERODELPHIDOTNET);
                recordTool = ss;
            }
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pPEInfo->basic_info), &recordLinker));
        }

        if (recordCompiler.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pPEInfo->basic_info), &recordCompiler));
        }

        if (recordVCL.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(recordVCL.name, scansToScan(&(pPEInfo->basic_info), &recordVCL));
        }

        if (recordTool.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultTools.insert(recordTool.name, scansToScan(&(pPEInfo->basic_info), &recordTool));
        }
    }
}

void SpecAbstract::PE_handle_Watcom(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT ssLinker = {};
        _SCANS_STRUCT ssCompiler = {};

        // Watcom linker
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WATCOMLINKER)) {
            ssLinker = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WATCOMLINKER);
            ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
        }

        // Watcom CPP
        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_WATCOMCCPP)) {
            // TODO Version???
            ssCompiler = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_WATCOMCCPP);
        }

        SpecAbstract::VI_STRUCT vi = get_Watcom_vi(pDevice, pOptions, pPEInfo->nEntryPointOffset, 0x100, pPdStruct);

        if (vi.bIsValid) {
            ssCompiler.fileType = XBinary::FT_PE;
            ssCompiler.type = RECORD_TYPE_COMPILER;
            ssCompiler.name = (RECORD_NAME)vi.vValue.toUInt();
            ssCompiler.sVersion = vi.sVersion;
            ssCompiler.sInfo = vi.sInfo;
        }

        if ((ssLinker.type != RECORD_TYPE_UNKNOWN) && (ssCompiler.type == RECORD_TYPE_UNKNOWN)) {
            ssCompiler = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_WATCOMCCPP, "", "", 0);
        }

        if ((ssLinker.type == RECORD_TYPE_UNKNOWN) && (ssCompiler.type != RECORD_TYPE_UNKNOWN)) {
            ssLinker = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
        }

        if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pPEInfo->basic_info), &ssLinker));
        }

        if (ssCompiler.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }
    }
}

void SpecAbstract::PE_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if ((pPEInfo->bIsTLSPresent) && (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RUST))) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = get_Rust_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ssCompiler = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RUST);

                    ssCompiler.sVersion = viStruct.sVersion;
                    ssCompiler.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pPEInfo->basic_info), &ssCompiler));
                }
            }
        }

        if (pe.isResourcePresent(XPE_DEF::S_RT_RCDATA, "SCRIPT", &(pPEInfo->listResources))) {
            _SCANS_STRUCT ssLibrary = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_AUTOIT, "3.XX", "", 0);
            // TODO Version
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, scansToScan(&(pPEInfo->basic_info), &ssLibrary));
        } else if (pe.getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)) == "Compiled AutoIt Script") {
            _SCANS_STRUCT ssLibrary = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_AUTOIT, "2.XX", "", 0);

            ssLibrary.sVersion = pe.getFileVersionMS(&(pPEInfo->resVersion));
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, scansToScan(&(pPEInfo->basic_info), &ssLibrary));
        }

        if (XPE::isImportLibraryPresentI("msvcrt.dll", &(pPEInfo->listImports)) && (pPEInfo->nMajorLinkerVersion == 6) && (pPEInfo->nMinorLinkerVersion == 0)) {
            bool bDetected = false;
            bool bDebug = false;

            if (pPEInfo->bIs64) {
                if ((pPEInfo->fileHeader.NumberOfSections == 3) || (pPEInfo->fileHeader.NumberOfSections == 5)) {
                    if ((pPEInfo->listSectionNames.at(0) == ".text") && (pPEInfo->listSectionNames.at(1) == ".data") && (pPEInfo->listSectionNames.at(2) == ".pdata")) {
                        if (pPEInfo->fileHeader.NumberOfSections == 3) {
                            bDetected = true;
                        } else if (pPEInfo->fileHeader.NumberOfSections == 5) {
                            if ((pPEInfo->listSectionNames.at(3) == ".stab") && (pPEInfo->listSectionNames.at(4) == ".stabstr")) {
                                bDebug = true;
                                bDetected = true;
                            }
                        }
                    }
                }
            } else {
                if ((pPEInfo->fileHeader.NumberOfSections == 2) || (pPEInfo->fileHeader.NumberOfSections == 4)) {
                    if ((pPEInfo->listSectionNames.at(0) == ".text") && (pPEInfo->listSectionNames.at(1) == ".data")) {
                        if (pPEInfo->fileHeader.NumberOfSections == 2) {
                            bDetected = true;
                        } else if (pPEInfo->fileHeader.NumberOfSections == 4) {
                            if ((pPEInfo->listSectionNames.at(2) == ".stab") && (pPEInfo->listSectionNames.at(3) == ".stabstr")) {
                                bDebug = true;
                                bDetected = true;
                            }
                        }
                    }
                }
            }

            if (bDetected) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_TINYC, "", "", 0);

                if (bDebug) {
                    ss.sInfo = "debug";
                }

                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_CHROMIUMCRASHPAD)) {
            XPE::SECTION_RECORD sr = XPE::getSectionRecordByName("CPADinfo", &(pPEInfo->listSectionRecords));

            if (sr.nSize) {
                quint32 nSignature = pe.read_uint32(sr.nOffset);

                if (nSignature == 0x43506164) {
                    quint32 nVersion = pe.read_uint32(sr.nOffset + 8);

                    _SCANS_STRUCT ssLibrary = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_CHROMIUMCRASHPAD, "", "", 0);
                    ssLibrary.sVersion = QString("%1.0").arg(nVersion);
                    pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, scansToScan(&(pPEInfo->basic_info), &ssLibrary));
                }
            }
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_EXCELSIORJET)) {
            // TODO Version
            _SCANS_STRUCT ssLibrary = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_JAVA, "", "Native", 0);
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, scansToScan(&(pPEInfo->basic_info), &ssLibrary));

            // TODO Version
            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_EXCELSIORJET, "", "", 0);  // mb Tool
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_GO) || pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_GO)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_GO, "1.X", "", 0);

            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = get_Go_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;
                }
            }

            pPEInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Visual Objects
        if (pe.compareSignature(&(pPEInfo->basic_info.memoryMap), "'This Visual Objects application cannot be run in DOS mode'", 0x312)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_VISUALOBJECTS, "2.XX", "", 0);
            ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // FASM
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASM)) {
            // TODO correct Version
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FASM, "", "", 0);
            ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Zig
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER) &&
            (pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GENERICLINKER).nVariant == 1)) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = get_Zig_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_ZIG, "", "", 0);

                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            VI_STRUCT viNim = get_Nim_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

            if (viNim.bIsValid) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_NIM, "", "", 0);
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Valve
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VALVE)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_STUB, RECORD_NAME_VALVE, "", "", 0);
            pPEInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // UniLink
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UNILINK)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_UNILINK, "", "", 0);
            pPEInfo->basic_info.mapResultLinkers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // DMD32 D
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DMD32)) {
            // TODO correct Version
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_DMD32, "", "", 0);
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GoLink, GoAsm
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GOLINK)) {
            _SCANS_STRUCT ssLinker = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_GOLINK, "", "", 0);
            ssLinker.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pPEInfo->basic_info), &ssLinker));

            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_GOASM, "", "", 0);
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }

        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LAYHEYFORTRAN90)) {
            QString sLFString = pe.read_ansiString(0x200);

            if (sLFString == "This program must be run under Windows 95, NT, or Win32s\r\nPress any key to exit.$") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_LAYHEYFORTRAN90, "", "", 0);
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Flex
        if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            qint64 _nOffset = pPEInfo->osDataSection.nOffset;
            qint64 _nSize = pPEInfo->osDataSection.nSize;
            // TODO FPC Version in Major and Minor linker

            qint64 nOffset_FlexLM = pe.find_ansiString(_nOffset, _nSize, "@(#) FLEXlm ", pPdStruct);

            if (nOffset_FlexLM != -1) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_FLEXLM, "", "", 0);

                ss.sVersion = pe.read_ansiString(nOffset_FlexLM + 12, 50);
                ss.sVersion = ss.sVersion.section(" ", 0, 0);

                if (ss.sVersion.left(1) == "v") {
                    ss.sVersion.remove(0, 1);
                }

                // TODO Version
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            qint64 nOffset_FlexNet = -1;

            if (nOffset_FlexLM == -1) {
                nOffset_FlexNet = pe.find_ansiString(_nOffset, _nSize, "@(#) FLEXnet Licensing v", pPdStruct);
            }

            if (nOffset_FlexNet == -1) {
                nOffset_FlexNet = pe.find_ansiString(_nOffset, _nSize, "@(#) FlexNet Licensing v", pPdStruct);
            }

            if (nOffset_FlexNet != -1) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_FLEXNET, "", "", 0);

                ss.sVersion = pe.read_ansiString(nOffset_FlexNet + 24, 50);

                if (ss.sVersion.contains("build")) {
                    ss.sVersion = ss.sVersion.section(" ", 0, 2);
                } else {
                    ss.sVersion = ss.sVersion.section(" ", 0, 0);
                }

                // TODO Version
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        if (!pPEInfo->cliInfo.bValid) {
            // Qt
            // TODO Find Strings QObject
            if (XPE::isImportLibraryPresentI("QtCore4.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "4.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("QtCored4.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "4.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt5Core.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "5.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt5Cored.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "5.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt6Core.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt6Cored.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_QT)) {
                // TODO Version!
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_QT);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;
                // TODO FPC Version in Major and Minor linker

                qint64 nOffset_FPC = pe.find_ansiString(_nOffset, _nSize, "FPC ", pPdStruct);

                if (nOffset_FPC != -1) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FPC, "", "", 0);
                    QString sFPCVersion = pe.read_ansiString(nOffset_FPC);
                    ss.sVersion = sFPCVersion.section(" ", 1, -1).section(" - ", 0, 0);

                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));

                    // Lazarus
                    qint64 nOffset_Lazarus = pe.find_ansiString(_nOffset, _nSize, "Lazarus LCL: ", pPdStruct);

                    if (nOffset_Lazarus == -1) {
                        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            _nOffset = pPEInfo->osConstDataSection.nOffset;
                            _nSize = pPEInfo->osConstDataSection.nSize;

                            nOffset_Lazarus = pe.find_ansiString(_nOffset, _nSize, "Lazarus LCL: ", pPdStruct);
                        }
                    }

                    QString sLazarusVersion;

                    if (nOffset_Lazarus != -1) {
                        sLazarusVersion = pe.read_ansiString(nOffset_Lazarus + 13);
                        sLazarusVersion = sLazarusVersion.section(" ", 0, 0);
                    }

                    if (nOffset_Lazarus != -1) {
                        _SCANS_STRUCT ssLazarus = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_TOOL, RECORD_NAME_LAZARUS, "", "", 0);

                        ssLazarus.sVersion = sLazarusVersion;

                        pPEInfo->basic_info.mapResultTools.insert(ssLazarus.name, scansToScan(&(pPEInfo->basic_info), &ssLazarus));
                    }
                } else {
                    //                    qint64 nOffset_TObject=pe.find_array(_nOffset,_nSize,"\x07\x54\x4f\x62\x6a\x65\x63\x74",8); // TObject

                    //                    if(nOffset_TObject!=-1)
                    //                    {

                    //                        SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                    //                        // TODO Version
                    //                        pPEInfo->basic_info.mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    //                    }
                    qint64 nOffset_RunTimeError = pe.find_array(_nOffset, _nSize, "\x0e\x52\x75\x6e\x74\x69\x6d\x65\x20\x65\x72\x72\x6f\x72\x20", 15,
                                                                pPdStruct);  // Runtime Error TODO: use findAnsiString

                    if (nOffset_RunTimeError != -1) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FPC, "", "", 0);

                        // TODO Version
                        pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // Python
            // TODO Create function
            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^PYTHON", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);

                            ss.sVersion = QString::number(dVersion / 10, 'f', 1);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                } else if (XBinary::isRegExpPresent("^LIBPYTHON", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d.\\d)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);

                            ss.sVersion = QString::number(dVersion);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                }
            }

            // Perl
            // TODO Create function
            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^PERL", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PERL, "", "", 0);

                            ss.sVersion = QString::number(dVersion / 100, 'f', 2);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                }
            }

            // Virtual Pascal
            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_VP =
                    pe.find_ansiString(_nOffset, _nSize, "Virtual Pascal - Copyright (C) ", pPdStruct);  // "Virtual Pascal - Copyright (C) 1996-2000 vpascal.com"

                if (nOffset_VP != -1) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_VIRTUALPASCAL, "", "", 0);

                    // TODO Version???
                    ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // PowerBASIC
            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                qint64 _nSize = pPEInfo->osCodeSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_PB = pe.find_ansiString(_nOffset, _nSize, "PowerBASIC", pPdStruct);

                if (nOffset_PB != -1) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_POWERBASIC, "", "", 0);

                    // TODO Version???
                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // PureBasic
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PUREBASIC)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PUREBASIC);

                // TODO Version???
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // lcc-win
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LCCWIN)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LCCWIN);

                // TODO Version???
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));

                if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
                    _SCANS_STRUCT ssLinker = {};
                    ssLinker.name = RECORD_NAME_LCCLNK;
                    ssLinker.type = RECORD_TYPE_LINKER;
                    ssLinker.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pPEInfo->basic_info), &ssLinker));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PETools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_VMUNPACKER)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_VMUNPACKER);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_XVOLKOLAK)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_XVOLKOLAK);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_HOODLUM)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_HOODLUM);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::PE_handle_wxWidgets(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bDynamic = false;
            bool bStatic = false;
            QString sVersion;
            QString sInfo;

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^WX", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sDllVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sDllVersion != "") {
                        double dVersion = sDllVersion.toDouble();

                        if (dVersion) {
                            // TODO a function
                            if (dVersion < 100) {
                                sVersion = QString::number(dVersion / 10, 'f', 1);
                            } else if (dVersion < 1000) {
                                sVersion = QString::number(dVersion / 100, 'f', 2);
                            }

                            bDynamic = true;
                        }
                    }

                    break;
                }
            }

            if (!bDynamic) {
                if (XPE::isResourcePresent(XPE_DEF::S_RT_MENU, "WXWINDOWMENU", &(pPEInfo->listResources))) {
                    bStatic = true;
                }
            }

            if (bDynamic || bStatic) {
                if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osConstDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osConstDataSection.nSize;
                    // TODO VP Version in Major and Minor linker

                    qint64 nOffset_Version = -1;

                    if (nOffset_Version == -1) {
                        nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "3.1.1 (wchar_t,Visual C++ 1900,wx containers)", pPdStruct);

                        if (nOffset_Version != -1) {
                            sVersion = "3.1.1";
                            sInfo = "Visual C++ 1900";
                        }
                    }

                    if (nOffset_Version == -1) {
                        nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "3.1.2 (wchar_t,Visual C++ 1900,wx containers,compatible with 3.0)", pPdStruct);

                        if (nOffset_Version != -1) {
                            sVersion = "3.1.2";
                            sInfo = "Visual C++ 1900";
                        }
                    }
                }
            }

            if (bDynamic || bStatic) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_WXWIDGETS, "", "", 0);

                if (bDynamic) {
                    ss.sInfo = "";
                } else if (bStatic) {
                    ss.sInfo = "Static";
                }

                ss.sVersion = sVersion;
                ss.sInfo = append(ss.sInfo, sInfo);

                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    _SCANS_STRUCT ssLinker = {};
    _SCANS_STRUCT ssCompiler = {};
    _SCANS_STRUCT ssTool = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bDetectGCC = false;
            bool bHeurGCC = false;

            if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
                switch (pPEInfo->nMajorLinkerVersion) {
                    case 2:
                        switch (pPEInfo->nMinorLinkerVersion)  // TODO Check MinGW versions
                        {
                            case 22:
                            case 23:
                            case 24:
                            case 25:
                            case 26:
                            case 27:
                            case 28:
                            case 29:
                            case 30:
                            case 31:
                            case 32:
                            case 33:
                            case 34:
                            case 35:
                            case 36:
                            case 56: bHeurGCC = true; break;
                        }

                        break;
                }
            }

            QString sDllLib;

            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                sDllLib = pe.read_ansiString(pPEInfo->osConstDataSection.nOffset);
            }

            if (XPE::isImportLibraryPresentI("msys-1.0.dll", &(pPEInfo->listImports)) || sDllLib.contains("msys-")) {
                // Msys 1.0
                ssTool.type = RECORD_TYPE_TOOL;
                ssTool.name = RECORD_NAME_MSYS;
                ssTool.sVersion = "1.0";
            }

            if ((sDllLib.contains("gcc")) || (sDllLib.contains("libgcj")) || (sDllLib.contains("cyggcj")) || (sDllLib == "_set_invalid_parameter_handler") ||
                XPE::isImportLibraryPresentI("libgcc_s_dw2-1.dll", &(pPEInfo->listImports)) || pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_MINGW) ||
                pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_GCC)) {
                bDetectGCC = true;
            }

            if (bDetectGCC || bHeurGCC) {
                // Mingw
                // Msys
                if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    VI_STRUCT viStruct = get_GCC_vi1(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                    ssCompiler.sVersion = viStruct.sVersion;

                    // TODO MinGW-w64
                    if (viStruct.sInfo.contains("MinGW")) {
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_MINGW;
                    } else if (viStruct.sInfo.contains("MSYS2")) {
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_MSYS2;
                    } else if (viStruct.sInfo.contains("Cygwin")) {
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_CYGWIN;
                    }

                    if (ssCompiler.sVersion == "") {
                        QString _sGCCVersion;

                        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            _sGCCVersion = get_GCC_vi2(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct).sVersion;

                            if (_sGCCVersion != "") {
                                ssCompiler.sVersion = _sGCCVersion;
                            }
                        }

                        if (_sGCCVersion == "") {
                            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                                _sGCCVersion = get_GCC_vi2(pDevice, pOptions, pPEInfo->osDataSection.nOffset, pPEInfo->osDataSection.nSize, pPdStruct).sVersion;

                                if (_sGCCVersion != "") {
                                    ssCompiler.sVersion = _sGCCVersion;
                                }
                            }
                        }
                    }

                    if ((ssTool.type == RECORD_TYPE_UNKNOWN) && (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_GCC))) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_GCC).sInfo.contains("MinGW")) {
                            ssTool.type = RECORD_TYPE_TOOL;
                            ssTool.name = RECORD_NAME_MINGW;
                        }
                    }
                }

                if (ssCompiler.sVersion != "") {
                    bDetectGCC = true;
                }

                if (!bDetectGCC) {
                    if (pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                        qint64 nGCC_MinGW =
                            pe.find_ansiString(pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, "Mingw-w64 runtime failure:", pPdStruct);

                        if (nGCC_MinGW != -1) {
                            ssTool.type = RECORD_TYPE_TOOL;
                            ssTool.name = RECORD_NAME_MINGW;

                            bDetectGCC = true;
                        }
                    }
                }

                if (bDetectGCC) {
                    ssCompiler.type = RECORD_TYPE_COMPILER;
                    ssCompiler.name = RECORD_NAME_GCC;
                }
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                if (XBinary::isRegExpPresent("^CYGWIN", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            ssTool.sVersion = QString::number(dVersion, 'f', 2);
                        }
                    }

                    ssTool.type = RECORD_TYPE_TOOL;
                    ssTool.name = RECORD_NAME_CYGWIN;

                    break;
                }
            }

            if (ssCompiler.type == RECORD_TYPE_UNKNOWN) {
                if (XPE::isSectionNamePresent(".stabstr", &(pPEInfo->listSectionRecords)))  // TODO
                {
                    XPE::SECTION_RECORD sr = XPE::getSectionRecordByName(".stabstr", &(pPEInfo->listSectionRecords));

                    if (sr.nSize) {
                        qint64 _nOffset = sr.nOffset;
                        qint64 _nSize = sr.nSize;

                        bool bSuccess = false;

                        if (!bSuccess) {
                            qint64 nGCC_MinGW = pe.find_ansiString(_nOffset, _nSize, "/gcc/mingw32/", pPdStruct);

                            if (nGCC_MinGW != -1) {
                                ssTool.type = RECORD_TYPE_TOOL;
                                ssTool.name = RECORD_NAME_MINGW;

                                bSuccess = true;
                            }
                        }

                        if (!bSuccess) {
                            qint64 nCygwin = pe.find_ansiString(_nOffset, _nSize, "/gcc/i686-pc-cygwin/", pPdStruct);

                            if (nCygwin != -1) {
                                ssTool.type = RECORD_TYPE_TOOL;
                                ssTool.name = RECORD_NAME_CYGWIN;

                                bSuccess = true;
                            }
                        }
                    }
                }
            }

            if (ssCompiler.type == RECORD_TYPE_UNKNOWN) {
                if ((ssTool.name == RECORD_NAME_MINGW) || (ssTool.name == RECORD_NAME_MSYS) || (ssTool.name == RECORD_NAME_MSYS2) ||
                    (ssTool.name == RECORD_NAME_CYGWIN)) {
                    ssCompiler.type = RECORD_TYPE_COMPILER;
                    ssCompiler.name = RECORD_NAME_GCC;
                }
            }

            if ((ssCompiler.name == RECORD_NAME_GCC) && (ssTool.type == RECORD_TYPE_UNKNOWN)) {
                ssTool.type = RECORD_TYPE_TOOL;
                ssTool.name = RECORD_NAME_MINGW;
            }

            if ((ssCompiler.name == RECORD_NAME_GCC) && (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
                ssLinker.type = RECORD_TYPE_LINKER;
                ssLinker.name = RECORD_NAME_GNULINKER;
                ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            }

            if (ssTool.name == RECORD_NAME_MINGW) {
                if (ssTool.sVersion == "") {
                    switch (pPEInfo->nMajorLinkerVersion) {
                        case 2:
                            switch (pPEInfo->nMinorLinkerVersion) {
                                case 23: ssTool.sVersion = "4.7.0-4.8.0"; break;
                                case 24: ssTool.sVersion = "4.8.2-4.9.2"; break;
                                case 25: ssTool.sVersion = "5.3.0"; break;
                                case 29: ssTool.sVersion = "7.3.0"; break;
                                case 30: ssTool.sVersion = "7.3.0"; break;  // TODO Check
                            }
                            break;
                    }
                }
            }

            // TODO Check overlay debug

            if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pPEInfo->basic_info), &ssLinker));
            }
            if (ssCompiler.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pPEInfo->basic_info), &ssCompiler));
            }
            if (ssTool.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultTools.insert(ssTool.name, scansToScan(&(pPEInfo->basic_info), &ssTool));
            }
        }
    }
}

void SpecAbstract::PE_handle_Signtools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pe.isSignPresent()) {
            // TODO image
            XPE_DEF::IMAGE_DATA_DIRECTORY dd = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY);

            QList<XPE::CERT> listCerts = pe.getCertList(dd.VirtualAddress, dd.Size);

            if (listCerts.count()) {
                if ((listCerts.at(0).record.wRevision == 0x200) && (listCerts.at(0).record.wCertificateType == 2)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SIGNTOOL, RECORD_NAME_WINAUTH, "2.0", "PKCS #7", 0);
                    pPEInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Installers(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            // Inno Setup
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INNOSETUP) || pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INNOSETUP, "", "", 0);

                if ((pe.read_uint32(0x30) == 0x6E556E49))  // Uninstall
                {
                    ss.sInfo = "Uninstall";

                    if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                        qint64 _nSize = pPEInfo->osCodeSection.nSize;

                        qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Setup version: Inno Setup version ", pPdStruct);

                        if (nOffsetVersion != -1) {
                            QString sVersionString = pe.read_ansiString(nOffsetVersion + 34);
                            ss.sVersion = sVersionString.section(" ", 0, 0);
                            QString sEncodes = sVersionString.section(" ", 1, 1);

                            if (sEncodes == "(a)") {
                                ss.sInfo = append(ss.sInfo, "ANSI");
                            } else if (sEncodes == "(u)") {
                                ss.sInfo = append(ss.sInfo, "Unicode");
                            }
                        }
                    }
                } else if (pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_INNOSETUP).sInfo == "Uninstall") {
                    ss.sInfo = "Uninstall";
                    qint64 _nOffset = pPEInfo->nOverlayOffset;
                    qint64 _nSize = pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Inno Setup Messages (", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion + 21);
                        ss.sVersion = sVersionString.section(" ", 0, 0);
                        ss.sVersion = ss.sVersion.remove(")");
                        QString sEncodes = sVersionString.section(" ", 1, 1);

                        // TODO Check
                        if (sEncodes == "(a))") {
                            ss.sInfo = append(ss.sInfo, "ANSI");
                        } else if (sEncodes == "(u))") {
                            ss.sInfo = append(ss.sInfo, "Unicode");
                        }
                    }
                } else {
                    qint64 nLdrTableOffset = -1;

                    if (pe.read_uint32(0x30) == 0x6F6E6E49) {
                        ss.sVersion = "1.XX-5.1.X";
                        ss.sInfo = "Install";
                        nLdrTableOffset = pe.read_uint32(0x30 + 4);
                    } else  // New versions
                    {
                        XPE::RESOURCE_RECORD resHeader = XPE::getResourceRecord(XPE_DEF::S_RT_RCDATA, 11111, &(pPEInfo->listResources));

                        nLdrTableOffset = resHeader.nOffset;

                        if (nLdrTableOffset != -1) {
                            ss.sVersion = "5.1.X-X.X.X";
                            ss.sInfo = "Install";
                        }
                    }

                    if (nLdrTableOffset != -1) {
                        // TODO 1 function
                        QString sSignature = pe.getSignature(nLdrTableOffset + 0, 12);

                        if (sSignature.left(12) == "72446C507453")  // rDlPtS
                        {
                            //                    result.nLdrTableVersion=read_uint32(nLdrTableOffset+12+0);
                            //                    result.nTotalSize=read_uint32(nLdrTableOffset+12+4);
                            //                    result.nSetupE32Offset=read_uint32(nLdrTableOffset+12+8);
                            //                    result.nSetupE32UncompressedSize=read_uint32(nLdrTableOffset+12+12);
                            //                    result.nSetupE32CRC=read_uint32(nLdrTableOffset+12+16);
                            //                    result.nSetupBin0Offset=read_uint32(nLdrTableOffset+12+20);
                            //                    result.nSetupBin1Offset=read_uint32(nLdrTableOffset+12+24);
                            //                    result.nTableCRC=read_uint32(nLdrTableOffset+12+28);

                            QString sSetupDataString = pe.read_ansiString(pe.read_uint32(nLdrTableOffset + 12 + 20));

                            if (!sSetupDataString.contains("(")) {
                                sSetupDataString = pe.read_ansiString(pe.read_uint32(nLdrTableOffset + 12 + 24));
                                // TODO
                                //                                ss.sInfo=append(ss.sInfo,"OLD.TODO");
                            }

                            QString sVersion = XBinary::regExp("\\((.*?)\\)", sSetupDataString, 1);
                            QString sOptions = XBinary::regExp("\\) \\((.*?)\\)", sSetupDataString, 1);

                            if (sVersion != "") {
                                ss.sVersion = sVersion;
                            }

                            if (sOptions != "") {
                                QString sEncode = sOptions;

                                if (sEncode == "a") {
                                    ss.sInfo = append(ss.sInfo, "ANSI");
                                } else if (sEncode == "u") {
                                    ss.sInfo = append(ss.sInfo, "Unicode");
                                }
                            }
                        }
                    }
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_CAB)) {
                // Wix Tools
                if (XPE::isSectionNamePresent(".wixburn", &(pPEInfo->listSectionRecords)))  // TODO
                {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WIXTOOLSET, "", "", 0);
                    ss.sVersion = "3.X";  // TODO check "E:\delivery\Dev\wix37\build\ship\x86\burn.pdb"
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_NOSINSTALLER)) {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_NOSINSTALLER)) {
                    // TODO Version from resources!
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_NOSINSTALLER, "", "", 0);
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // CAB SFX
            if (pPEInfo->sResourceManifest.contains("sfxcab.exe")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_CAB, "", "", 0);

                if (pe.checkOffsetSize(pPEInfo->osResourcesSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 nSectionOffset = pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).PointerToRawData +
                                            pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).Misc.VirtualSize;

                    qint64 nVersionOffset = pe.find_signature(&(pPEInfo->basic_info.memoryMap), nSectionOffset - 0x600, 0x600, "BD04EFFE00000100", nullptr, pPdStruct);
                    if (nVersionOffset != -1) {
                        ss.sVersion = QString("%1.%2.%3.%4")
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 2))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 0))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 6))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 4));
                    }
                }

                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Install Anywhere
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALLANYWHERE)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)) == "InstallAnywhere") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLANYWHERE, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_GHOSTINSTALLER)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GHOSTINSTALLER, "", "", 0);
                ss.sVersion = "1.0";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_QTINSTALLER)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_QTINSTALLER, "", "", 0);
                // ss.sVersion="";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALL4J)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALL4J, "", "", 0);
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SMARTINSTALLMAKER)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SMARTINSTALLMAKER, "", "", 0);
                ss.sVersion = XBinary::hexToString(pPEInfo->sOverlaySignature.mid(46, 14));  // TODO make 1 function
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_TARMAINSTALLER)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_TARMAINSTALLER, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_CLICKTEAM)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_CLICKTEAM, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // NSIS
            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_NSIS)) || (pPEInfo->sResourceManifest.contains("Nullsoft.NSIS"))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_NSIS, "", "", 0);

                QString _sInfo = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_NSIS).sInfo;

                if (_sInfo != "") {
                    ss.sInfo = _sInfo;
                }

                //                QRegularExpression rxVersion("Null[sS]oft Install System v?(.*?)<");
                //                QRegularExpressionMatch matchVersion=rxVersion.match(pPEInfo->sResourceManifest);

                //                if(matchVersion.hasMatch())
                //                {
                //                    ss.sVersion=matchVersion.captured(1);
                //                }

                QString sVersion = XBinary::regExp("Null[sS]oft Install System v?(.*?)<", pPEInfo->sResourceManifest, 1);

                if (sVersion != "") {
                    ss.sVersion = sVersion;
                }

                // TODO options
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // InstallShield
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("InstallShield")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->sResourceManifest.contains("InstallShield")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);

                if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osDataSection.nSize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "SOFTWARE\\InstallShield\\1", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion);
                        ss.sVersion = sVersionString.section("\\", 2, 2);
                    }
                }

                if (ss.sVersion == "") {
                    // TODO unicode
                    ss.sVersion = XPE::getResourcesVersionValue("ISInternalVersion", &(pPEInfo->resVersion));
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALLSHIELD)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "PackageForTheWeb", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("InstallShield")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);

                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));

                if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("PackageForTheWeb")) {
                    ss.sInfo = "PackageForTheWeb";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("AdvancedInstallerSetup")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ADVANCEDINSTALLER, "", "", 0);

                if ((pPEInfo->nOverlayOffset) && (pPEInfo->nOverlaySize) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->nOverlayOffset;
                    qint64 _nSize = pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Advanced Installer ", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion);
                        ss.sVersion = sVersionString.section(" ", 2, 2);
                    }
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("Illustrate.Spoon.Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SPOONINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("DeployMaster Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_DEPLOYMASTER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((pPEInfo->sResourceManifest.contains("Gentee.Installer.Install")) || (pPEInfo->sResourceManifest.contains("name=\"gentee\""))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            } else {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_GENTEEINSTALLER)) {
                    if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "SETUP_TEMP", &(pPEInfo->listResources))) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            if (pPEInfo->sResourceManifest.contains("BitRock Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_BITROCKINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("GP-Install") &&
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("TASPro6-Install")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GPINSTALL, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Total Commander Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_TOTALCOMMANDERINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Actual Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ACTUALINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Avast Antivirus")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_AVASTANTIVIRUS, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Opera Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_OPERA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Yandex Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_YANDEX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Google Update")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GOOGLE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Visual Studio Installer")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTVISUALSTUDIO, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Dropbox Update Setup")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_DROPBOX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("VeraCrypt")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_VERACRYPT, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft .NET Framework")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTDOTNETFRAMEWORK, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("LegalTrademarks", &(pPEInfo->resVersion)).contains("Setup Factory")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SETUPFACTORY, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion.contains(",")) {
                    ss.sVersion = ss.sVersion.remove(" ");
                    ss.sVersion = ss.sVersion.replace(",", ".");
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("This installation was built with InstallAware")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLAWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft Office")) {
                if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Bootstrapper.exe")) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTOFFICE, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion)).trimmed();

                    if (ss.sVersion.contains(",")) {
                        ss.sVersion = ss.sVersion.remove(" ");
                        ss.sVersion = ss.sVersion.replace(",", ".");
                    }

                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // Squirrel Installer
            if (XPE::getResourcesVersionValue("SquirrelAwareVersion", &(pPEInfo->resVersion)) != "") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SQUIRRELINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("SquirrelAwareVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion == "1") {
                    ss.sVersion = "1.0.0-1.9.1";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Java") &&
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Setup Launcher")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_JAVA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_VMWARE) ||
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("VMware installation")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_VMWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Windows Installer
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND)) {
                VI_STRUCT vi = get_WindowsInstaller_vi(pDevice, pOptions, pPEInfo->nOverlayOffset, pPEInfo->nOverlaySize, pPdStruct);

                if (vi.sVersion != "") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

                    ss.sVersion = vi.sVersion;
                    ss.sInfo = vi.sInfo;

                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // Alchemy Mindworks
            if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 4001, &(pPEInfo->listResources)) &&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 5001, &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ALCHEMYMINDWORKS, "", "", 0);
                // TODO versions

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (!pPEInfo->basic_info.mapResultInstallers.contains(RECORD_NAME_WINDOWSINSTALLER)) {
                qint32 nNumberOfResources = pPEInfo->listResources.count();

                for (qint32 i = 0; (i < nNumberOfResources) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    qint64 _nOffset = pPEInfo->listResources.at(i).nOffset;
                    qint64 _nSize = pPEInfo->listResources.at(i).nSize;
                    qint64 _nSignatureSize = qMin(_nSize, (qint64)8);

                    if (_nSignatureSize) {
                        QString sSignature = pe.getSignature(_nOffset, _nSignatureSize);

                        if (sSignature == "D0CF11E0A1B11AE1")  // DOC File TODO move to signatures
                        {
                            VI_STRUCT vi = get_WindowsInstaller_vi(pDevice, pOptions, _nOffset, _nSize, pPdStruct);

                            if (vi.sVersion != "") {
                                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

                                ss.sVersion = vi.sVersion;
                                ss.sInfo = vi.sInfo;

                                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));

                                break;
                            }
                        }
                    }
                }
            }

            // WISE Installer
            if (pPEInfo->exportHeader.sName == "STUB32.EXE") {
                if (pPEInfo->exportHeader.listPositions.count() == 2) {
                    if ((pPEInfo->exportHeader.listPositions.at(0).sFunctionName == "_MainWndProc@16") ||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName == "_StubFileWrite@12")) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                } else if (pPEInfo->exportHeader.listPositions.count() == 6) {
                    if ((pPEInfo->exportHeader.listPositions.at(0).sFunctionName == "_LanguageDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName == "_PasswordDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(2).sFunctionName == "_ProgressDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(3).sFunctionName == "_UpdateCRC@8") ||
                        (pPEInfo->exportHeader.listPositions.at(4).sFunctionName == "_t1@40") || (pPEInfo->exportHeader.listPositions.at(5).sFunctionName == "_t2@12")) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_RAR)) {
                if (XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "STARTDLG", &(pPEInfo->listResources)) &&
                    XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "LICENSEDLG", &(pPEInfo->listResources))) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_WINRAR)) || (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ZIP))) {
                if (pPEInfo->sResourceManifest.contains("WinRAR")) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ZIP)) {
                if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osDataSection.nSize;

                    qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "ZIP self-extractor", pPdStruct);
                    if (nOffset_Version != -1) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_ZIP, "", "", 0);
                        // TODO Version
                        pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // 7z SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("7-Zip")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_7Z, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((!pPEInfo->basic_info.mapResultSFX.contains(RECORD_NAME_7Z)) && (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_7Z))) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_7Z, "", "", 0);
                ss.sInfo = "Modified";
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // SQUEEZ SFX
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SQUEEZSFX)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Squeez")) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SQUEEZSFX, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // WinACE
            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinACE") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinAce") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("UNACE")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINACE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // WinZip
            if ((pPEInfo->sResourceManifest.contains("WinZipComputing.WinZip")) || (XPE::isSectionNamePresent("_winzip_", &(pPEInfo->listSectionRecords))))  // TODO
            {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINZIP, "", "", 0);

                QString _sManifest = pPEInfo->sResourceManifest.section("assemblyIdentity", 1, 1);
                ss.sVersion = XBinary::regExp("version=\"(.*?)\"", _sManifest, 1);
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Cab
            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Self-Extracting Cabinet")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_CAB, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // GkSetup SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("GkSetup Self extractor")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_GKSETUPSFX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_PolyMorph(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPEInfo)
    Q_UNUSED(pPdStruct)
    // ExeSax
}

void SpecAbstract::PE_handle_DongleProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pPEInfo->listImports.count() == 1) {
        if (XBinary::isRegExpPresent("^NOVEX", pPEInfo->listImports.at(0).sName.toUpper())) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DONGLEPROTECTION, RECORD_NAME_GUARDIANSTEALTH, "", "", 0);
            pPEInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

// void SpecAbstract::PE_handle_AnslymPacker(QIODevice *pDevice,XScanEngine::SCAN_OPTIONS *pOptions,SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//     XPE pe(pDevice,pOptions->bIsImage);

//    if(pe.isValid(pPdStruct))
//    {
//        if(!pPEInfo->cliInfo.bInit)
//        {
//            if((pPEInfo->nImportHash64==0xaf2e74867b)&&(pPEInfo->nImportHash32==0x51a4c42b))
//            {
//                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_ANSLYMPACKER,"","",0);
//                pPEInfo->basic_info.mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//            }
//        }
//    }
//}

void SpecAbstract::PE_handle_NeoLite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->nEntryPointSection != 0) {
                if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                    qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                    qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "NeoLite Executable File Compressor", pPdStruct);

                    if (nOffset_Version != -1) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PACKER, RECORD_NAME_NEOLITE, "1.0", "", 0);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PrivateEXEProtector(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                 XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bKernel32ExitProcess = false;
            bool bKernel32 = false;
            bool bUser32 = false;
            bool bCharacteristics = false;
            bool bPEPLinker = false;
            bool bTurboLinker = false;

            if (pPEInfo->listImports.count() >= 1) {
                if (pPEInfo->listImports.at(0).sName == "KERNEL32.DLL") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        bKernel32 = true;

                        if (pPEInfo->listImports.at(0).listPositions.at(0).sName == "ExitProcess") {
                            bKernel32ExitProcess = true;
                        }
                    }
                }
            }

            if (pPEInfo->listImports.count() == 2) {
                if (pPEInfo->listImports.at(1).sName == "USER32.DLL") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        bUser32 = true;
                    }
                }
            }

            qint32 nNumberOfSections = pPEInfo->listSectionHeaders.count();

            for (qint32 i = 0; (i < nNumberOfSections) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if ((pPEInfo->listSectionHeaders.at(i).Characteristics & 0xFFFF) == 0) {
                    bCharacteristics = true;
                    break;
                }
            }

            bPEPLinker = pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PRIVATEEXEPROTECTOR);
            bTurboLinker = pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER);

            if (bKernel32ExitProcess && bCharacteristics && bPEPLinker) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PRIVATEEXEPROTECTOR);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (bKernel32 && bCharacteristics && bTurboLinker) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PRIVATEEXEPROTECTOR, "2.25", "", 0);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (bKernel32 && bUser32 && bCharacteristics && bTurboLinker) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PRIVATEEXEPROTECTOR, "2.30-2.70", "", 0);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_VisualBasicCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                 XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // 1337 Exe Crypter
        if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_1337EXECRYPTER)) {
            if (XPE::isImportLibraryPresentI("MSVBVM60.DLL", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_1337EXECRYPTER);
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_1337EXECRYPTER, ssOverlay.sVersion, ssOverlay.sInfo, 0);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // AGAINNATIVITYCRYPTER
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // AR Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ARCRYPT)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ARCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // WingsCrypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WINGSCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WINGSCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Crypt R.Roads
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTRROADS))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTRROADS);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Whitell Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WHITELLCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WHITELLCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // ZeldaCrypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ZELDACRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ZELDACRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Biohazard Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BIOHAZARDCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_BIOHAZARDCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cryptable seducation
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTABLESEDUCATION))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTABLESEDUCATION);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cryptic
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTIC))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTIC);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // CRyptOZ
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTOZ))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTOZ);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Dirty Cryptor
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DIRTYCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DIRTYCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Fakus Cryptor
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FAKUSCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FAKUSCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Fast file Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FASTFILECRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FASTFILECRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // FileShield
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FILESHIELD))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FILESHIELD);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GhaZza CryPter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_GHAZZACRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_GHAZZACRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_H4CKY0UORGCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_H4CKY0UORGCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HACCREWCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HACCREWCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HALVCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HALVCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KGBCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KGBCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KIAMSCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KIAMSCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KRATOSCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KRATOSCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KUR0KX2TO))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KUR0KX2TO);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LUCYPHER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LUCYPHER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MONEYCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MONEYCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER2))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER2);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NOXCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NOXCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PUSSYCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PUSSYCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SMOKESCREENCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SMOKESCREENCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SNOOPCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SNOOPCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_STASFODIDOCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_STASFODIDOCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TSTCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TSTCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TURKISHCYBERSIGNATURE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TURKISHCYBERSIGNATURE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TURKOJANCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TURKOJANCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNDOCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNDOCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WLCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WLCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ROGUEPACK))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ROGUEPACK);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::PE_handle_DelphiCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Ass Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ASSCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ASSCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Aase
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AASE))  // TODO more checks!
        {
            //                    if(pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AASE))
            //                    {
            //                        _SCANS_STRUCT ss=pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AASE);
            //                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            //                    }

            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AASE);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Anskya Polymorphic Packer
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ANSKYAPOLYMORPHICPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ANSKYAPOLYMORPHICPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // AnslymPacker
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ANSLYMPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ANSLYMPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cigicigi Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CIGICIGICRYPTER))  // TODO more checks!
        {
            if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "AYARLAR", &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CIGICIGICRYPTER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // fEaRz Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FEARZCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FEARZCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // fEaRz Packer
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FEARZPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FEARZPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GKripto
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_GKRIPTO))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_GKRIPTO);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HOUNDHACKCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HOUNDHACKCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ICRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ICRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_INFCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_INFCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MALPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MALPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MINKE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MINKE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORUKCREWCRYPTERPRIVATE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORUKCREWCRYPTERPRIVATE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MRUNDECTETABLE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MRUNDECTETABLE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NIDHOGG))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NIDHOGG);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NME))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NME);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_OPENSOURCECODECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_OPENSOURCECODECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_OSCCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_OSCCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_P0KESCRAMBLER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_P0KESCRAMBLER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PANDORA))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PANDORA);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PFECX))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PFECX);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PICRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PICRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_POKECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_POKECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PUBCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PUBCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SIMCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SIMCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SEXECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SEXECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SIMPLECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SIMPLECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TGRCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TGRCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_THEZONECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_THEZONECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNDERGROUNDCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNDERGROUNDCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNKOWNCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNKOWNCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WINDOFCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WINDOFCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WLGROUPCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WLGROUPCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        //        if(pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DCRYPTPRIVATE)) // TODO more checks!
        //        {
        //            _SCANS_STRUCT ss=pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DCRYPTPRIVATE);

        //            pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //        }

        //        if(pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
        //        {
        //            _SCANS_STRUCT ss=pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DALKRYPT);

        //            pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //        }
    }
}

void SpecAbstract::PE_handle_Joiners(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Blade Joiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BLADEJOINER)) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BLADEJOINER)) {
                if (pPEInfo->nOverlaySize) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BLADEJOINER);
                    pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }
        }

        // ExeJoiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXEJOINER)) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXEJOINER)) {
                if (pPEInfo->nOverlaySize) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXEJOINER);
                    pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }
        }

        // Celesty File Binder
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CELESTYFILEBINDER)) {
            if (pe.isResourcePresent("RBIND", -1, &(pPEInfo->listResources))) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CELESTYFILEBINDER);
                pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        // N-Joiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NJOINER)) {
            if (pe.isResourcePresent("NJ", -1, &(pPEInfo->listResources)) || pe.isResourcePresent("NJOY", -1, &(pPEInfo->listResources))) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NJOINER);
                pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }
    }
}

void SpecAbstract::PE_handle_DebugData(QIODevice *pDevice, SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // if (pELFInfo->nSymTabOffset > 0) {
        //     qint32 nNumberOfSymbols = XELF::getNumberOfSymbols(pELFInfo->nSymTabOffset);

        //     if (nNumberOfSymbols) {
        //         _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_DEBUGDATA, RECORD_NAME_SYMBOLTABLE, "", "", 0);

        //         ss.sInfo = pELFInfo->listSectionRecords.at(pELFInfo->nSymTabSection).sName;
        //         ss.sInfo = append(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));

        //         pELFInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        //     }
        // }

        if (XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".stab", pPdStruct) &&
            XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".stabstr", pPdStruct)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DEBUGDATA, RECORD_NAME_STABSDEBUGINFO, "", "", 0);
            pPEInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".debug_info", pPdStruct)) {
            XPE::SECTION_RECORD sr = pe.getSectionRecordByName(".debug_info", &(pPEInfo->listSectionRecords));

            if (sr.nOffset && sr.nSize) {
                VI_STRUCT viStruct = get_DWRAF_vi(pDevice, pOptions, sr.nOffset, sr.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ssDebugInfo = getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                    ssDebugInfo.sVersion = viStruct.sVersion;

                    pPEInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, scansToScan(&(pPEInfo->basic_info), &ssDebugInfo));
                }
            }
        }
    }
}

bool SpecAbstract::PE_isProtectionPresent(SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    return (pPEInfo->basic_info.mapResultPackers.count() || pPEInfo->basic_info.mapResultProtectors.count() || pPEInfo->basic_info.mapResultSFX.count() ||
            pPEInfo->basic_info.mapResultInstallers.count() || pPEInfo->basic_info.mapResultNETObfuscators.count() ||
            pPEInfo->basic_info.mapResultDongleProtection.count());
}

void SpecAbstract::PE_handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                               XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
#ifdef QT_DEBUG
        //        qint32 i=pPEInfo->listImportPositionHashes.count()-1;

        //        if(i>0)
        //        {
        //            if(pPEInfo->listImports.at(i).listPositions.count()>1)
        //            {
        //                _SCANS_STRUCT ss={};

        //                ss.type=RECORD_TYPE_PROTECTOR;
        //                ss.name=(SpecAbstract::RECORD_NAME)(RECORD_NAME_UNKNOWN0+i);
        //                ss.sVersion=QString("%1").arg(pPEInfo->listImportPositionHashes.at(i),0,16);
        //                ss.bIsHeuristic=true;

        //                pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //            }
        //        }

#endif

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            if (pPEInfo->listSectionRecords.count()) {
                if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                    if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UPX) && (pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UPX).nVariant == 0)) {
                        _SCANS_STRUCT ss = {};

                        ss.type = RECORD_TYPE_PACKER;
                        ss.name = RECORD_NAME_UNK_UPXLIKE;
                        ss.bIsHeuristic = true;

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            QMapIterator<RECORD_NAME, _SCANS_STRUCT> i(pPEInfo->basic_info.mapEntryPointDetects);

            while (i.hasNext() && (XBinary::isPdStructNotCanceled(pPdStruct))) {
                i.next();

                _SCANS_STRUCT recordSS = i.value();

                if (recordSS.name != RECORD_NAME_GENERIC) {
                    recordSS.bIsHeuristic = true;

                    if (recordSS.type == RECORD_TYPE_PACKER) {
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    } else if (recordSS.type == RECORD_TYPE_PROTECTOR) {
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }
            }
        }

        if ((!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_UPX)) && (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_UNK_UPXLIKE))) {
            VI_STRUCT viUPX = get_UPX_vi(pDevice, pOptions, pPEInfo->osHeader.nOffset, pPEInfo->osHeader.nSize, XBinary::FT_PE, pPdStruct);

            if ((viUPX.bIsValid)) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_UPX;
                recordSS.sVersion = viUPX.sVersion;
                recordSS.sInfo = viUPX.sInfo;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_ASPACK)) {
            if (XPE::isSectionNamePresent(".aspack", &(pPEInfo->listSectionRecords)) && XPE::isSectionNamePresent(".adata", &(pPEInfo->listSectionRecords))) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_ASPACK;
                recordSS.sVersion = "2.12-2.XX";
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_PECOMPACT)) {
            VI_STRUCT viPECompact = PE_get_PECompact_vi(pDevice, pOptions, pPEInfo);

            if (viPECompact.bIsValid) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_PECOMPACT;
                recordSS.sVersion = viPECompact.sVersion;
                recordSS.sInfo = viPECompact.sInfo;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_KKRUNCHY)) {
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_KKRUNCHY) &&
                (pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_KKRUNCHY).nVariant == 0)) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_KKRUNCHY;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            bool bLastSectionEntryPoint = false;
            bool bEmptyFirstSection = false;
            bool bHighEntropyFirstSection = false;
            bool bHighEntropy = false;

            qint32 nNumberOfSections = pPEInfo->listSectionRecords.count();

            if (nNumberOfSections >= 2) {
                if (pPEInfo->nEntryPointSection == nNumberOfSections - 1) {
                    bLastSectionEntryPoint = true;
                }
            }

            if (nNumberOfSections > 0) {
                if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                    bEmptyFirstSection = 0;
                }
            }

            if (pe.isPacked(pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, 0, -1, pPdStruct))) {
                bHighEntropy = true;
            } else if (nNumberOfSections > 0) {
                double dEntropy =
                    pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, pPEInfo->listSectionRecords.at(0).nOffset, pPEInfo->listSectionRecords.at(0).nSize, pPdStruct);

                if (pe.isPacked(dEntropy)) {
                    bHighEntropyFirstSection = true;
                }
            }

            if (bLastSectionEntryPoint || bEmptyFirstSection || bHighEntropyFirstSection || bHighEntropy) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PROTECTOR;
                recordSS.name = RECORD_NAME_GENERIC;
                recordSS.bIsHeuristic = true;

                if (bLastSectionEntryPoint) {
                    recordSS.sInfo = append(recordSS.sInfo, "Last section entry point");  // mb TODO translate
                }

                if (bEmptyFirstSection) {
                    recordSS.sInfo = append(recordSS.sInfo, "Empty first section");  // mb TODO translate
                }

                if (bHighEntropy) {
                    recordSS.sInfo = append(recordSS.sInfo, "High entropy");  // mb TODO translate
                } else if (bHighEntropyFirstSection) {
                    recordSS.sInfo = append(recordSS.sInfo, "High entropy first section");  // mb TODO translate
                }

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (pPEInfo->basic_info.scanOptions.bIsTest && pPEInfo->basic_info.scanOptions.bIsVerbose) {
            // TODO names of note sections

            qint32 nIndex = 1;

            {
                qint32 nNumberOfRecords = pPEInfo->listImportRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_LIBRARY;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("LIBRARY_") + pPEInfo->listImportRecords.at(i).sLibrary;

                    pPEInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pPEInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_RLPACK) || pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR)) {
        pPEInfo->basic_info.mapResultLinkers.remove(RECORD_NAME_MICROSOFTLINKER);
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_MASM);
        pPEInfo->basic_info.mapResultTools.remove(RECORD_NAME_MASM32);
    }

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_AHPACKER) || pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_EPEXEPACK)) {
        pPEInfo->basic_info.mapResultPackers.remove(RECORD_NAME_AHPACKER);
    }

    // Check SafeEngine
    if (pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_VISUALCCPP) &&
        pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_BORLANDOBJECTPASCALDELPHI)) {
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_BORLANDOBJECTPASCALDELPHI);
    }

    if (pPEInfo->basic_info.mapResultLinkers.contains(RECORD_NAME_MICROSOFTLINKER) && pPEInfo->basic_info.mapResultLinkers.contains(RECORD_NAME_TURBOLINKER)) {
        pPEInfo->basic_info.mapResultLinkers.remove(RECORD_NAME_TURBOLINKER);
    }

    if (pPEInfo->basic_info.mapResultTools.contains(RECORD_NAME_MICROSOFTVISUALSTUDIO) && pPEInfo->basic_info.mapResultTools.contains(RECORD_NAME_BORLANDDELPHI)) {
        pPEInfo->basic_info.mapResultTools.remove(RECORD_NAME_BORLANDDELPHI);
    }

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_SIMPLEPACK) && pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_FASM)) {
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_FASM);
    }
}

void SpecAbstract::Binary_handle_Texts(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                       XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->bIsPlainText) || (pBinaryInfo->unicodeType != XBinary::UNICODE_TYPE_NONE) || (pBinaryInfo->bIsUTF8)) {
        qint32 nSignaturesCount = sizeof(_TEXT_Exp_records) / sizeof(STRING_RECORD);

        for (qint32 i = 0; (i < nSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++)  // TODO move to an own function !!!
        {
            if (XBinary::isRegExpPresent(_TEXT_Exp_records[i].pszString, pBinaryInfo->sHeaderText)) {
                _SCANS_STRUCT record = {};
                record.nVariant = _TEXT_Exp_records[i].basicInfo.nVariant;
                record.fileType = _TEXT_Exp_records[i].basicInfo.fileType;
                record.type = _TEXT_Exp_records[i].basicInfo.type;
                record.name = _TEXT_Exp_records[i].basicInfo.name;
                record.sVersion = _TEXT_Exp_records[i].basicInfo.pszVersion;
                record.sInfo = _TEXT_Exp_records[i].basicInfo.pszInfo;
                record.nOffset = 0;

                pBinaryInfo->basic_info.mapTextHeaderDetects.insert(record.name, record);
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_CCPP)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_CCPP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PYTHON)) {
            if ((pBinaryInfo->sHeaderText.contains("class")) && (pBinaryInfo->sHeaderText.contains("self"))) {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PYTHON);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_HTML)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_HTML);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_XML)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_XML);
            ss.sVersion = XBinary::regExp("version=['\"](.*?)['\"]", pBinaryInfo->sHeaderText, 1);

            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PHP)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PHP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        //        if(pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PERL))
        //        {
        //            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PERL);
        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_SHELL)) {
            QString sInterpreter;

            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/local\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);  // #!/usr/local/bin/ruby
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/env (\\w+)", pBinaryInfo->sHeaderText, 1);      // #!/usr/bin/env perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);          // #!/usr/bin/perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);                // #!/bin/sh
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!(\\w+)", pBinaryInfo->sHeaderText, 1);                         // #!perl

            if (sInterpreter == "perl") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_PERL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "sh") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_SHELL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "ruby") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_RUBY, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "python") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_PYTHON, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_SHELL, sInterpreter, "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        //        if(pBinaryInfo->basic_info.mapResultTexts.count()==0)
        //        {
        //            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_FORMAT,RECORD_NAME_PLAIN,"","",0);

        //            if(pBinaryInfo->unicodeType!=XBinary::UNICODE_TYPE_NONE)
        //            {
        //                ss.name=RECORD_NAME_UNICODE;

        //                if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_BE)
        //                {
        //                    ss.sVersion="Big Endian";
        //                }
        //                else if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_LE)
        //                {
        //                    ss.sVersion="Little Endian";
        //                }
        //            }
        //            else if(pBinaryInfo->bIsUTF8)
        //            {
        //                ss.name=RECORD_NAME_UTF8;
        //            }
        //            else if(pBinaryInfo->bIsPlainText)
        //            {
        //                ss.name=RECORD_NAME_PLAIN;
        //            }

        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }
    }
}

void SpecAbstract::COM_handle_OperationSystem(QIODevice *pDevice, SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XCOM xcom(pDevice, pOptions->bIsImage);

    if (xcom.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(xcom.getFileFormatInfo(pPdStruct));

        pCOMInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pCOMInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::COM_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, COMINFO_STRUCT *pCOMInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    // XCOM com(pDevice, pOptions->bIsImage);

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PKLITE)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PKLITE);
        pCOMInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UPX)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_UPX);
        pCOMInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_HACKSTOP)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HACKSTOP);
        pCOMInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYPTDISMEMBER)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYPTDISMEMBER);
        pCOMInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPIRIT)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPIRIT);
        pCOMInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ICE)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ICE);
        pCOMInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DIET)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DIET);
        pCOMInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }

    if (pCOMInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYPTCOM)) {
        pCOMInfo->basic_info.id.fileType = XBinary::FT_COM;
        _SCANS_STRUCT ss = pCOMInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYPTCOM);
        pCOMInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pCOMInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Archives(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                          XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // 7-Zip
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        //        // TODO more options
        //        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        //        if(ss.type==RECORD_TYPE_ARCHIVE)
        //        {
        //            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
        //            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        XSevenZip xsevenzip(pDevice);

        if (xsevenzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

            ss.sVersion = xsevenzip.getVersion();
#ifdef QT_DEBUG
            qint32 nNumberOfRecords = xsevenzip.getNumberOfRecords(pPdStruct);
            Q_UNUSED(nNumberOfRecords)
#endif
            //            ss.sInfo=QString("%1 records").arg(xsevenzip.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // ZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZIP)) && (pBinaryInfo->basic_info.id.nSize >= 64))  // TODO min size
    {
        XZip xzip(pDevice);

        if (xzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZIP);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = append(ss.sInfo, "Encrypted");
            }

            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // GZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GZIP)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO type gzip
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // xar
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XAR)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XAR);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LZFSE
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZFSE)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZFSE);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // CAB
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CAB)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XCab xcab(pDevice);

        if (xcab.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

            ss.sVersion = xcab.getVersion();
            ss.sInfo = QString("%1 records").arg(xcab.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // MAch-O FAT
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MACHOFAT)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XMACHOFat xmachofat(pDevice);

        if (xmachofat.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MACHOFAT);

            ss.sVersion = xmachofat.getVersion();
            ss.sInfo = QString("%1 records").arg(xmachofat.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // RAR
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RAR)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        XRar xrar(pDevice);

        if (xrar.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RAR);

            ss.sVersion = xrar.getVersion();
            ss.sInfo = QString("%1 records").arg(xrar.getNumberOfRecords(pPdStruct));
            // TODO options

            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // zlib
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZLIB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // XZ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XZ)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XZ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // ARJ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARJ)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARJ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LHA
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHA)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHA);

        bool bDetected = false;

        switch (binary.read_uint8(0x5)) {
            case 0x30: bDetected = 1; break;
            case 0x31: bDetected = 1; break;
            case 0x32: bDetected = 1; break;
            case 0x33: bDetected = 1; break;
            case 0x34: bDetected = 1; break;
            case 0x35: bDetected = 1; break;
            case 0x36: bDetected = 1; break;
            case 0x64: bDetected = 1; break;
            case 0x73: bDetected = 1; break;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // BZIP2
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BZIP2)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BZIP2);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // TAR
    else if ((pBinaryInfo->basic_info.id.nSize >= 500) && (binary.getSignature(0x100, 6) == "007573746172"))  // "00'ustar'"
    {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_TAR, "", "", 0);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Certificates(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Windows Authenticode Portable Executable Signature Format
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINAUTH)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        quint32 nLength = XBinary::hexToUint32(pBinaryInfo->basic_info.sHeaderSignature.mid(0, 8));

        if (nLength >= pBinaryInfo->basic_info.id.nSize) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINAUTH);
            pBinaryInfo->basic_info.mapResultCertificates.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MINGW)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MinGW debug data
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MINGW);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDBFILELINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PDB File Link
        // TODO more infos
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDBFILELINK);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BORLANDDEBUGINFO)) && (pBinaryInfo->basic_info.id.nSize >= 16)) {
        quint16 nSignature = binary.read_uint16(0);

        if (nSignature == 0x52FB) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_BORLANDDEBUGINFO, "", "", 0);

            quint8 nMajor = binary.read_uint8(3);
            quint8 nMinor = binary.read_uint8(2);
            quint16 nNumberOfSymbols = binary.read_uint16(0xE);
            double dVersion = nMajor + (double)nMinor / 100.0;

            ss.type = RECORD_TYPE_DEBUGDATA;
            ss.name = RECORD_NAME_BORLANDDEBUGINFO;
            ss.sVersion = QString::number(dVersion, 'f', 2);
            ss.sInfo = "TDS";

            if (nNumberOfSymbols) {
                ss.sInfo = append(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));
            }

            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        } else {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BORLANDDEBUGINFO);
            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    if (binary.getSize() > 16) {
        // unsigned_16     signature;      /* == 0x8386                    */
        // unsigned_8      exe_major_ver;  /* == 2 or 3                    */
        // unsigned_8      exe_minor_ver;  /* == 0                         */
        // unsigned_8      obj_major_ver;  /* == 1                         */
        // unsigned_8      obj_minor_ver;  /* == 1                         */
        // unsigned_16     lang_size;
        // unsigned_16     segment_size;
        // unsigned_32     debug_size;
        // TODO more
        if (binary.read_uint16(binary.getSize() - 14) == 0x8386) {
            qint64 nHeaderOffset = binary.getSize() - 14;
            quint8 exe_major_ver = binary.read_uint16(nHeaderOffset + 2);
            quint8 exe_minor_ver = binary.read_uint16(nHeaderOffset + 3);
            // quint8 obj_major_ver = binary.read_uint16(nHeaderOffset + 4);
            // quint8 obj_minor_ver = binary.read_uint16(nHeaderOffset + 5);
            // quint16 nLangSize = binary.read_uint16(nHeaderOffset + 6);
            // quint16 nSegmentSize = binary.read_uint16(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 10);

            qint64 nDebugOffset = binary.getSize() - nDebugSize;

            if (nDebugOffset >= 0) {
                // TODO Language
                // https://github.com/open-watcom/open-watcom-v2/blob/e7d0bef544987dd0429f547a2119e0c9d9472770/bld/exedump/c/wdwarf.c#L132
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_WATCOMDEBUGINFO, "", "", 0);
                ss.sVersion = QString("%1.%2").arg(QString::number(exe_major_ver), QString::number(exe_minor_ver));
                ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint16(binary.getSize() - 8) == 0x424E) {
            QString sSignature = binary.read_ansiString(binary.getSize() - 8, 4);

            if ((sSignature == "NB05") || (sSignature == "NB07") || (sSignature == "NB08") || (sSignature == "NB09") || (sSignature == "NB10") ||
                (sSignature == "NB11")) {
                qint64 nHeaderOffset = binary.getSize() - 8;
                quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 4);

                qint64 nDebugOffset = binary.getSize() - nDebugSize;

                if (nDebugOffset >= 0) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_CODEVIEWDEBUGINFO, "", "", 0);
                    ss.sVersion = "4.0";
                    ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                    pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
                }
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint32(binary.getSize() - 16) == 0x534954) {
            // typedef struct {
            //     unsigned_32 signature;
            //     unsigned_32 vendor;
            //     unsigned_32 type;
            //     unsigned_32 size;
            // } TISTrailer;

            qint64 nHeaderOffset = binary.getSize() - 16;

            quint32 nVendor = binary.read_uint32(nHeaderOffset + 4);
            quint32 nType = binary.read_uint32(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 12);

            if ((nVendor == 0) && (nType == 0)) {
                qint64 nDebugOffset = nHeaderOffset - nDebugSize;

                if (nDebugOffset >= 0) {
                    VI_STRUCT viStruct = get_DWRAF_vi(pDevice, pOptions, nDebugOffset, binary.getSize() - nDebugOffset, pPdStruct);

                    if (viStruct.bIsValid) {
                        _SCANS_STRUCT ssDebugInfo = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                        ssDebugInfo.sVersion = viStruct.sVersion;
                        ssDebugInfo.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));
                        ssDebugInfo.sInfo = append(ssDebugInfo.sInfo, "Watcom");

                        pBinaryInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, scansToScan(&(pBinaryInfo->basic_info), &ssDebugInfo));
                    }
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if (pBinaryInfo->basic_info.id.nSize == 0) {
        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_EMPTYFILE, "", "", 0);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TODO move to own type
        // PDF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDF);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5 * 2, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compound
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPOUND);

        quint16 nSub1 = binary.read_uint16(0x200);
        quint16 nSub2 = binary.read_uint16(0x1000);

        // TODO More
        if ((nSub1 == 0) && (nSub2 == 0xFFFD)) {
            ss.type = RECORD_TYPE_INSTALLER;  // TODO mapResultInstallers
            ss.name = RECORD_NAME_MICROSOFTINSTALLER;
            ss.sVersion = "";
            ss.sInfo = "";
        } else if (nSub1 == 0xA5EC) {
            ss.type = RECORD_TYPE_FORMAT;
            ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.sVersion = "97-2003";
            ss.sInfo = "";
        }

        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compiled HTML Help
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AUTOIT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AutoIt Compiled Script
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AUTOIT);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // RTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RTF);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LUACOMPILED)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Lua
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LUACOMPILED);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JAVACOMPILEDCLASS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // java
        quint16 nMinor = binary.read_uint16(4, true);
        quint16 nMajor = binary.read_uint16(6, true);

        if (nMajor) {
            QString sVersion = XJavaClass::_getJDKVersion(nMajor, nMinor);

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JAVACOMPILEDCLASS);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_COFF)) && (pBinaryInfo->basic_info.id.nSize >= 76)) {
        // COFF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_COFF);

        bool bDetected = false;

        qint64 nOffset = binary.read_uint32(72, true) + 58;

        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEX)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // dex
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEX);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(8, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SWF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // SWF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SWF);
        ss.sVersion = QString("%1").arg(binary.read_uint8(3));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTWINHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft WinHelp
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTWINHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP3)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP3
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP3);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP4)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP4
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP4);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSMEDIA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Windows Media
        // TODO WMV/WMA
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSMEDIA);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FLASHVIDEO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Flash Video
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FLASHVIDEO);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WAV)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // VAW
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WAV);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AU
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AU);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEB)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DEB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEB);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVI)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVI);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WEBP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WEBP);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TTF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDARSC)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDARSC);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDXML)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDXML);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AR)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AR
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AR);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if (pBinaryInfo->basic_info.id.nSize >= 0x8010) {
        if (binary.compareSignature("01'CD001'01", 0x8000)) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_ISO9660, "", "", 0);
            // TODO Version
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Databases(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // PDB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDB);
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKERDATABASE)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // Microsoft Linker Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTLINKERDATABASE);
        //        ss.sVersion=QString("%1.%2").arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(32*2,4))).arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(34*2,4)));
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTACCESS)) && (pBinaryInfo->basic_info.id.nSize >= 128)) {
        // Microsoft Access Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTACCESS);

        quint32 nVersion = binary.read_int32(0x14);

        switch (nVersion) {
            case 0x0000: ss.sVersion = "JET3"; break;  // TODO
            case 0x0001: ss.sVersion = "JET4"; break;  // TODO
            case 0x0002: ss.sVersion = "2007"; break;
            case 0x0103: ss.sVersion = "2010"; break;
        }

        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Images(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JPEG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // JPEG
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JPEG);
        quint32 nMajor = pBinaryInfo->basic_info.sHeaderSignature.mid(11 * 2, 2).toUInt(nullptr, 16);
        quint32 nMinor = pBinaryInfo->basic_info.sHeaderSignature.mid(12 * 2, 2).toUInt(nullptr, 16);
        ss.sVersion = QString("%1.%2").arg(nMajor).arg(nMinor, 2, 10, QChar('0'));
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GIF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // GIF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GIF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TIFF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TIFF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TIFF);
        // More information
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSICON)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Icon
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSICON);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSCURSOR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Cursor
        // TODO more information
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSCURSOR);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSBITMAP)) && (pBinaryInfo->basic_info.id.nSize >= 40)) {
        // Windows Bitmap
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        quint32 _nSize = qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(2 * 2, 8).toUInt(nullptr, 16));
        if (pBinaryInfo->basic_info.id.nSize >= _nSize) {
            QString sVersion;

            switch (qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(14 * 2, 8).toUInt(nullptr, 16))) {
                case 40: sVersion = "3"; break;
                case 108: sVersion = "4"; break;
                case 124: sVersion = "5"; break;
            }

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSBITMAP);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PNG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PNG
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PNG);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(16, true)).arg(binary.read_uint32(20, true));

        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DJVU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DJVU
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DJVU);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_InstallerData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Inno Setup
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INNOSETUP);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLANYWHERE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLANYWHERE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GHOSTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GHOSTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSIS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSIS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SIXXPACK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SIXXPACK);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_THINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_THINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SMARTINSTALLMAKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SMARTINSTALLMAKER);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(46, 14));
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TARMAINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TARMAINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CLICKTEAM)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CLICKTEAM);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ADVANCEDINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ADVANCEDINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_OPERA)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_OPERA);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GPINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GPINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVASTANTIVIRUS)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVASTANTIVIRUS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLSHIELD)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLSHIELD);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SETUPFACTORY)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SETUPFACTORY);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTUALINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTUALINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALL4J)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALL4J);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VMWARE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_VMWARE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOSINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_SFXData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINRAR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINRAR);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SQUEEZSFX)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SQUEEZSFX);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        if (ss.type == RECORD_TYPE_SFXDATA) {
            pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_ProtectorData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FISHNET)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Inno Setup
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FISHNET);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XENOCODE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Xenocode
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XENOCODE);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MOLEBOXULTRA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MOLEBOXULTRA);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_1337EXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_1337EXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTIVEMARK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTIVEMARK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOXCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOXCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASTFILECRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FASTFILECRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZELDACRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZELDACRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WLCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WLCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DOTNETSHRINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DOTNETSHRINK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPOONSTUDIO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPOONSTUDIO);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SECUROM)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SECUROM);
        ss.sVersion = binary.read_ansiString(8);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SERGREENAPPACKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SERGREENAPPACKER);
        // TODO Version
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_LibraryData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SHELL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        QString sString = binary.read_ansiString(0);

        if (sString.contains("python")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);
            pBinaryInfo->basic_info.mapResultLibraryData.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Resources(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_VERSIONINFO)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_VERSIONINFO);
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BITMAPINFOHEADER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BITMAPINFOHEADER);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(4)).arg(binary.read_uint32(8));
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_STRINGTABLE)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_STRINGTABLE);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_DIALOG)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_DIALOG);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_ICON)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_ICON);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_CURSOR)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_CURSOR);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_MENU)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_MENU);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Zip_handle_Microsoftoffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("docProps/app.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                QString sData = xzip.decompress(&record, pPdStruct).data();
                QString sApplication = XBinary::regExp("<Application>(.*?)</Application>", sData, 1);

                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_MICROSOFTOFFICE, "", "", 0);

                if (sApplication == "Microsoft Office Word") {
                    ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
                } else if (sApplication == "Microsoft Excel") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                } else if (sApplication == "Microsoft Visio") {
                    ss.name = RECORD_NAME_MICROSOFTVISIO;
                } else if (sApplication == "SheetJS") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                    ss.sInfo = "SheetJS";
                }

                ss.sVersion = XBinary::regExp("<AppVersion>(.*?)</AppVersion>", sData, 1);
                pZipInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_OpenOffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("meta.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                QString sData = xzip.decompress(&record, pPdStruct).data();

                // TODO
                if (sData.contains(":opendocument:")) {
                    pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_OPENDOCUMENT, "", "", 0);

                    pZipInfo->basic_info.mapResultFormats.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::Zip_handle_Metainfos(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BASIC_INFO *pBasicInfo, QList<XArchive::RECORD> *pListArchiveRecords,
                                        XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pListArchiveRecords, pPdStruct)) {
        QString sDataManifest = xjar.decompress(pListArchiveRecords, "META-INF/MANIFEST.MF", pPdStruct).data();

        if (sDataManifest != "") {
            QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sAntVersion = XBinary::regExp("Ant-Version: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltJdk = XBinary::regExp("Build-Jdk: (.*?)\n", sDataManifest, 1).remove("\r");

            if (sCreatedBy.contains("Android Gradle")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDGRADLE, "", "", 0);
                ss.sVersion = XBinary::regExp("Android Gradle (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("MOTODEV Studio for Android") || sCreatedBy.contains("MOTODEV Studio for ANDROID")) {
                // TODO Check "MOTODEV Studio for ANDROID" version
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_MOTODEVSTUDIOFORANDROID, "", "", 0);
                ss.sVersion = XBinary::regExp("MOTODEV Studio for Android v(.*?).release", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("Android Maven") || sCreatedBy.contains("Apache Maven Bundle Plugin")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDMAVENPLUGIN, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Radialix")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_RADIALIX, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Radialix", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("AntiLVL")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_ANTILVL, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkEditor")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_APKEDITOR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("d2j-apk-sign")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_D2JAPKSIGN, "", "", 0);
                ss.sVersion = XBinary::regExp("d2j-apk-sign (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("singlejar")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_SINGLEJAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("PseudoApkSigner")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_PSEUDOAPKSIGNER, "", "", 0);
                ss.sVersion = XBinary::regExp("PseudoApkSigner (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkSigner")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNER, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("www.HiAPK.com")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_HIAPKCOM, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("com.haibison.apksigner") || sCreatedBy.contains("com.haibison.apksigner")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APK_SIGNER, "", "", 0);

                if (sBuiltBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sBuiltBy, 1);
                } else if (sCreatedBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sCreatedBy, 1);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("BundleTool") || sCreatedBy.contains("BundleTool")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_BUNDLETOOL, "", "", 0);

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(COMEX SignApk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_COMEXSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (COMEX SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(NetEase ApkSigner)"))  // TODO Check " " !!!
            {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_NETEASEAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (NetEase ApkSigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signatory)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNATORY, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signatory)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signupdate)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNUPDATE, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signupdate)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android SignApk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(KT Android SignApk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (KT Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(abc SignApk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (abc SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(dotools sign apk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_DOTOOLSSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (dotools sign apk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android apksigner)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android apksigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(ApkModifier SignApk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKMODIFIERSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (ApkModifier SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Baidu Signature platform)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_BAIDUSIGNATUREPLATFORM, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Baidu Signature platform)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("tiny-sign")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_TINYSIGN, "", "", 0);
                ss.sVersion = sCreatedBy.section("tiny-sign-", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("DexGuard, version")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);
                ss.sVersion = XBinary::regExp("DexGuard, version (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkProtector")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_APKPROTECTOR, "", "", 0);

                if (sCreatedBy.section(" ", 0, 0) == "ApkProtector") {
                    ss.sVersion = sCreatedBy.section(" ", 1, 1).remove(")").remove("(");
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Sun Microsystems Inc.)") || sCreatedBy.contains("(BEA Systems, Inc.)") || sCreatedBy.contains("(The FreeBSD Foundation)") ||
                       sCreatedBy.contains("(d2j-null)") || sCreatedBy.contains("(d2j-2.1-SNAPSHOT)") || sCreatedBy.contains("(Oracle Corporation)") ||
                       sCreatedBy.contains("(Apple Inc.)") || sCreatedBy.contains("(Google Inc.)") || sCreatedBy.contains("(Jeroen Frijters)") ||
                       sCreatedBy.contains("(IBM Corporation)") || sCreatedBy.contains("(JetBrains s.r.o)") || sCreatedBy.contains("(Alibaba)") ||
                       sCreatedBy.contains("(AdoptOpenJdk)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);

                if (sCreatedBy.contains("(Apple Inc.)")) {
                    ss.name = RECORD_NAME_APPLEJDK;
                } else if (sCreatedBy.contains("(IBM Corporation)")) {
                    ss.name = RECORD_NAME_IBMJDK;
                } else if (sCreatedBy.contains("(AdoptOpenJdk)")) {
                    ss.name = RECORD_NAME_OPENJDK;
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy == "1.6.0_21") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(JetBrains s.r.o)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JETBRAINS, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-null)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-2.1-SNAPSHOT)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "2.1", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Jeroen Frijters)")) {
                // Check OpenJDK
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_IKVMDOTNET, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(BEA Systems, Inc.)")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_BEAWEBLOGIC, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("dx ")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_COMPILER, RECORD_NAME_DX, "", "", 0);
                ss.sVersion = sCreatedBy.section("dx ", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sAntVersion.contains("Apache Ant")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_APACHEANT, "", "", 0);
                ss.sVersion = XBinary::regExp("Apache Ant (.*?)$", sAntVersion, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltBy.contains("Generated-by-ADT")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ECLIPSE, "", "ADT", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltJdk != "") {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sBuiltJdk;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sProtectedBy.contains("DexProtector")) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXPROTECTOR, "", "", 0);

                if (sProtectedBy.section(" ", 0, 0) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 1, 1).remove(")").remove("(");
                } else if (sProtectedBy.section(" ", 1, 1) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 0, 0);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (XBinary::regExp("^\\d+(\\.\\d+)*$", sCreatedBy, 0) != "")  // 0.0.0
            {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(d8)") || sCreatedBy.contains("(dx)"))  // Dexguard
            {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            // TODO heur if String contains add to heur
        }
    }
}

void SpecAbstract::Zip_handle_JAR(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(xjar.getFileFormatInfo(pPdStruct));

        pZipInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pZipInfo->basic_info), &ssOperationSystem));

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APPLEJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APPLEJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IBMJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IBMJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_OPENJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_OPENJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JETBRAINS)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JETBRAINS);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IKVMDOTNET)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IKVMDOTNET);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BEAWEBLOGIC)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BEAWEBLOGIC);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APACHEANT)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APACHEANT);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SINGLEJAR)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SINGLEJAR);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(&(pApkInfo->listArchiveRecords), pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(xapk.getFileFormatInfo(pPdStruct));

        pApkInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pApkInfo->basic_info), &ssOperationSystem));

        // 0x7109871a APK_SIGNATURE_SCHEME_V2_BLOCK_ID
        // TODO Check 0x7109871f
        // https://github.com/18598925736/ApkChannelPackageJavaCore/blob/9342d57a1fc5f9271d569612df6028758f6ee42d/src/channel/data/Constants.java#L38
        // 0xf05368c0 APK_SIGNATURE_SCHEME_V3_BLOCK_ID
        // 0x42726577 padding
        // 0x504b4453 DEPENDENCY_INFO_BLOCK_ID;
        // https://github.com/jomof/CppBuildCacheWorkInProgress/blob/148b94d712d14b6f2a13ab37a526c7795e2215b3/agp-7.1.0-alpha01/tools/base/signflinger/src/com/android/signflinger/SignedApk.java#L56
        // 0x71777777 Walle
        // https://github.com/Meituan-Dianping/walle/blob/f78edcf1117a0aa858a3d04bb24d86bf9ad51bb2/payload_reader/src/main/java/com/meituan/android/walle/ApkUtil.java#L40
        // 0x6dff800d SOURCE_STAMP_BLOCK_ID
        // 0x2146444e Google Play

        QList<XAPK::APK_SIG_BLOCK_RECORD> listApkSignaturesBlockRecords = xapk.getAPKSignaturesBlockRecordsList();

        _SCANS_STRUCT ssSignTool = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNATURESCHEME, "", "", 0);

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x7109871a)) {
            ssSignTool.sVersion = "v2";
        } else if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0xf05368c0)) {
            ssSignTool.sVersion = "v3";
        }

        // TODO V4

        if (ssSignTool.sVersion != "") {
            pApkInfo->basic_info.mapResultSigntools.insert(ssSignTool.name, scansToScan(&(pApkInfo->basic_info), &ssSignTool));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x71777777)) {
            _SCANS_STRUCT ssWalle = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_WALLE, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssWalle.name, scansToScan(&(pApkInfo->basic_info), &ssWalle));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x2146444e)) {
            _SCANS_STRUCT ssGooglePlay = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_GOOGLEPLAY, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssGooglePlay.name, scansToScan(&(pApkInfo->basic_info), &ssGooglePlay));
        }

        if (pApkInfo->bIsKotlin) {
            _SCANS_STRUCT ssKotlin = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_KOTLIN, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssKotlin.name, scansToScan(&(pApkInfo->basic_info), &ssKotlin));
        } else {
            _SCANS_STRUCT ssJava = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_JAVA, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssJava.name, scansToScan(&(pApkInfo->basic_info), &ssJava));
        }

        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_UNKNOWN, "", "", 0);

            qint32 nNumberOfRecords = listApkSignaturesBlockRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listApkSignaturesBlockRecords.at(i).nID > 0xFFFF) {
                    if ((listApkSignaturesBlockRecords.at(i).nID != 0x7109871a) && (listApkSignaturesBlockRecords.at(i).nID != 0xf05368c0) &&
                        (listApkSignaturesBlockRecords.at(i).nID != 0x42726577)) {
                        ss.name = (RECORD_NAME)((int)RECORD_NAME_UNKNOWN0 + i);
                        ss.sVersion = XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nID);
                        // ss.sInfo=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nDataSize);
                        pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
                    }
                }
            }
        }

        QByteArray baAndroidManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "AndroidManifest.xml", pPdStruct);

        if (baAndroidManifest.size() > 0) {
            QString sAndroidManifest = XAndroidBinary::getDecoded(&baAndroidManifest, pPdStruct);

            QString sCompileSdkVersion = XBinary::regExp("android:compileSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sCompileSdkVersionCodename = XBinary::regExp("android:compileSdkVersionCodename=\"(.*?)\"", sAndroidManifest, 1);
            QString sTargetSdkVersion = XBinary::regExp("android:targetSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sMinSdkVersion = XBinary::regExp("android:minSdkVersion=\"(.*?)\"", sAndroidManifest, 1);

            // Check
            if (!XBinary::checkStringNumber(sCompileSdkVersion, 1, 40)) sCompileSdkVersion = "";
            if (!XBinary::checkStringNumber(sTargetSdkVersion, 1, 40)) sTargetSdkVersion = "";
            if (!XBinary::checkStringNumber(sMinSdkVersion, 1, 40)) sMinSdkVersion = "";

            if (!XBinary::checkStringNumber(sCompileSdkVersionCodename.section(".", 0, 0), 1, 15)) sCompileSdkVersionCodename = "";

            if ((sCompileSdkVersion != "") || (sCompileSdkVersionCodename != "") || (sTargetSdkVersion != "") || (sMinSdkVersion != "")) {
                _SCANS_STRUCT ssAndroidSDK = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);

                QString _sVersion;
                QString _sAndroidVersion;

                _sVersion = sCompileSdkVersion;
                _sAndroidVersion = sCompileSdkVersionCodename;

                if (_sVersion == "") _sVersion = sMinSdkVersion;
                if (_sVersion == "") _sVersion = sTargetSdkVersion;

                if (_sVersion != "") {
                    ssAndroidSDK.sVersion = QString("API %1").arg(_sVersion);

                    pApkInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, scansToScan(&(pApkInfo->basic_info), &ssAndroidSDK));
                }
            }

            QString sJetpack = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/androidx.core_core.version").data();
            if (sJetpack != "") {
                QString sJetpackVersion = XBinary::regExp("(.*?)\n", sJetpack, 1).remove("\r");

                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LIBRARY, RECORD_NAME_ANDROIDJETPACK, "", "", 0);
                ss.sVersion = sJetpackVersion;
                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDGRADLE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDGRADLE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDMAVENPLUGIN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDMAVENPLUGIN);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_RADIALIX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_RADIALIX);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_MOTODEVSTUDIOFORANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANTILVL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANTILVL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKEDITOR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKEDITOR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BUNDLETOOL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BUNDLETOOL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEX2JAR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEX2JAR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_D2JAPKSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_D2JAPKSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_PSEUDOAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_PSEUDOAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APK_SIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APK_SIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_NETEASEAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_NETEASEAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DOTOOLSSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DOTOOLSSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNATORY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNATORY);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNUPDATE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNUPDATE);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKMODIFIERSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKMODIFIERSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BAIDUSIGNATUREPLATFORM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_TINYSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_TINYSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_COMEXSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_COMEXSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ECLIPSE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ECLIPSE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_HIAPKCOM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_HIAPKCOM);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DX);
                pApkInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECSHELL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECSHELL);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_JIAGU)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_JIAGU);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IJIAMI)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IJIAMI);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTPROTECTION);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU) ||
                pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTLEGU);
                } else if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MOBILETENCENTPROTECT);
                }

                qint32 nNumberOfRecords = pApkInfo->listArchiveRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/arm64-v8a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/arm64-v8a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi-v7a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi-v7a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/x86/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/x86/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    }
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppGuard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Kiro
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_KIRO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_KIRO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DxShield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DXSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DXSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // qdbh
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QDBH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QDBH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Bangcle Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BANGCLEPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BANGCLEPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Qihoo 360 Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QIHOO360PROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QIHOO360PROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Alibaba Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_ALIBABAPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_ALIBABAPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Baidu Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BAIDUPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BAIDUPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // NQ Shield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NQSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NQSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Nagapt Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NAGAPTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NAGAPTPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SecNeo
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECNEO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECNEO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // LIAPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_LIAPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_LIAPP);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // yidun
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_YIDUN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_YIDUN);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // PangXie
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PANGXIE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PANGXIE);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Hdus-Wjus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_HDUS_WJUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_HDUS_WJUS);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Medusah
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MEDUSAH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MEDUSAH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppSolid
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPSOLID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPSOLID);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Proguard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PROGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PROGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // VDog
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_VDOG)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_VDOG);

                QString sVersion = xapk.decompress(&(pApkInfo->listArchiveRecords), "assets/version").data();

                if (sVersion != "") {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion = sVersion.section("VDOG-", 1, 1).section("_", 0, 0);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // APKProtect
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECT)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECT);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ollvm-tll
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_OLLVMTLL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_OLLVMTLL);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DexGuard
            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD) ||
                pApkInfo->dexInfoClasses.basic_info.mapResultProtectors.contains(RECORD_NAME_DEXGUARD)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXGUARD).sVersion;
                } else if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_GENERIC)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_GENERIC).sVersion;
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DEXPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DEXPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SandHook
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SANDHOOK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SANDHOOK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unicom SDK
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNICOMSDK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNICOMSDK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unity
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNITY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNITY);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // IL2CPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IL2CPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IL2CPP);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Basic4Android
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BASIC4ANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BASIC4ANDROID);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ApkToolPlus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKTOOLPLUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKTOOLPLUS);

                pApkInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // QML
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QML)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QML);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pApkInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_IPA(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->bIsIPA) {
            _SCANS_STRUCT ssFormat = getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_IPA, "", "", 0);

            ssFormat.sVersion = xzip.getVersion();
            ssFormat.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.listDetects.append(scansToScan(&(pZipInfo->basic_info), &ssFormat));
        }
    }
}

void SpecAbstract::Zip_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->basic_info.id.fileType == XBinary::FT_ZIP) {
            pZipInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = append(ss.sInfo, "Encrypted");
            }

            // TODO files
            pZipInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        } else if (pZipInfo->basic_info.id.fileType == XBinary::FT_APKS) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.mapResultArchives.insert(ss.name, scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle_FixDetects(QIODevice *pDevice, SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(pPdStruct)) {
        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            if (pApkInfo->basic_info.mapMetainfosDetects.count() == 0) {
                QString sDataManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/MANIFEST.MF").data();

                QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");

                if (sProtectedBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                    recordSS.sVersion = "Protected: " + sProtectedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sCreatedBy != "") && (sCreatedBy != "1.0 (Android)")) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion = "Created: " + sCreatedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if (sBuiltBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion = "Built: " + sBuiltBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sProtectedBy != "") && (sCreatedBy != "") && (sBuiltBy != "")) {
                    if (sDataManifest.contains("-By")) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_PROTECTOR;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                        recordSS.sVersion = "CHECK";

                        pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, scansToScan(&(pApkInfo->basic_info), &recordSS));
                    }
                }
            }
        }
    }
}

void SpecAbstract::AmigaHunk_handle_OperationSystem(QIODevice *pDevice, SCAN_OPTIONS *pOptions, AMIGAHUNKINFO_STRUCT *pAmigaHunkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XAmigaHunk amigaHunk(pDevice);

    if (amigaHunk.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(amigaHunk.getFileFormatInfo(pPdStruct));

        pAmigaHunkInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pAmigaHunkInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::PDF_handle_Formats(QIODevice *pDevice, SCAN_OPTIONS *pOptions, PDFINFO_STRUCT *pPDFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XPDF pdf(pDevice);

    if (pdf.isValid(pPdStruct)) {
        _SCANS_STRUCT ssFormat = getFormatScansStruct(pdf.getFileFormatInfo(pPdStruct));

        pPDFInfo->basic_info.mapResultFormats.insert(ssFormat.name, scansToScan(&(pPDFInfo->basic_info), &ssFormat));
    }
}

void SpecAbstract::PDF_handle_Tags(QIODevice *pDevice, SCAN_OPTIONS *pOptions, PDFINFO_STRUCT *pPDFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XPDF pdf(pDevice);

    if (pdf.isValid(pPdStruct)) {
        {
            QList<XBinary::XVARIANT> listVariants = pdf.getValuesByKey(&(pPDFInfo->listObjects), "/Producer");

            qint32 nNumberOfRecords = listVariants.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listVariants.at(i).varType == XBinary::VT_STRING) {
                    _SCANS_STRUCT ss =
                        getScansStruct(0, XBinary::FT_PDF, RECORD_TYPE_TOOL, (RECORD_NAME)((qint32)RECORD_NAME_UNKNOWN0 + i), listVariants.at(i).var.toString(), "", 0);

                    pPDFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pPDFInfo->basic_info), &ss));
                }
            }
        }

        {
            QList<XBinary::XVARIANT> listVariants = pdf.getValuesByKey(&(pPDFInfo->listObjects), "/Creator");

            qint32 nNumberOfRecords = listVariants.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listVariants.at(i).varType == XBinary::VT_STRING) {
                    _SCANS_STRUCT ss =
                        getScansStruct(0, XBinary::FT_PDF, RECORD_TYPE_TOOL, (RECORD_NAME)((qint32)RECORD_NAME_UNKNOWN0 + i), listVariants.at(i).var.toString(), "", 0);

                    pPDFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pPDFInfo->basic_info), &ss));
                }
            }
        }

        // {
        //     QList<QVariant> listVariants = pdf.getValuesByKey(&(pPDFInfo->listObjects), "/Author");
        // }
    }
}

void SpecAbstract::Jpeg_handle_Formats(QIODevice *pDevice, SCAN_OPTIONS *pOptions, JPEGINFO_STRUCT *pJpegInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJpeg jpeg(pDevice);

    if (jpeg.isValid(pPdStruct)) {
        _SCANS_STRUCT ssFormat = getFormatScansStruct(jpeg.getFileFormatInfo(pPdStruct));

        pJpegInfo->basic_info.mapResultFormats.insert(ssFormat.name, scansToScan(&(pJpegInfo->basic_info), &ssFormat));
    }
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::APKINFO_STRUCT *pApkInfo,
                                                        XBinary::PDSTRUCT *pPdStruct, const QString &sFileName)
{
    Q_UNUSED(pOptions)

    DEXINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        QByteArray baRecordData = xzip.decompress(&(pApkInfo->listArchiveRecords), sFileName, pPdStruct);

        QBuffer buffer(&baRecordData);

        if (buffer.open(QIODevice::ReadOnly)) {
            result = getDEXInfo(&buffer, pApkInfo->basic_info.id, pOptions, 0, pPdStruct);

            buffer.close();
        }
    }

    return result;
}

void SpecAbstract::Binary_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    if (pBinaryInfo->basic_info.mapResultFormats.contains(RECORD_NAME_PDF)) {
        pBinaryInfo->basic_info.mapResultTexts.clear();

        pBinaryInfo->basic_info.mapResultFormats[RECORD_NAME_PDF].id.fileType = XBinary::FT_BINARY;
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_BINARY;
    }
}

void SpecAbstract::MSDOS_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo,
                                                XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(msdos.getFileFormatInfo(pPdStruct));

        pMSDOSInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pMSDOSInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::MSDOS_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        // IBM PC Pascal
        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_IBMPCPASCAL)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_IBMPCPASCAL);
            pMSDOSInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        // WATCOM C
        SpecAbstract::VI_STRUCT vi = get_Watcom_vi(pDevice, pOptions, pMSDOSInfo->nEntryPointOffset, 0x300, pPdStruct);

        if (vi.bIsValid) {
            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_COMPILER, (RECORD_NAME)vi.vValue.toUInt(), vi.sVersion, vi.sInfo, 0);
            pMSDOSInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pMSDOSInfo->basic_info), &ssCompiler));

            _SCANS_STRUCT ssLinker = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
            pMSDOSInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pMSDOSInfo->basic_info), &ssLinker));
        }

        // BAT2EXEC
        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BAT2EXEC)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BAT2EXEC);
            pMSDOSInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::MSDOS_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        _SCANS_STRUCT ssLinker = {};
        _SCANS_STRUCT ssCompiler = {};

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                ss.sVersion = vi.sVersion;
            }

            ssLinker = ss;
        }

        if (pMSDOSInfo->basic_info.scanOptions.bIsDeepScan) {
            qint64 _nOffset = 0;
            qint64 _nSize = pMSDOSInfo->basic_info.id.nSize;

            if (pMSDOSInfo->nOverlayOffset != -1) {
                _nSize = pMSDOSInfo->nOverlayOffset;
            }

            qint64 nOffsetTurboC = -1;
            qint64 nOffsetTurboCPP = -1;
            qint64 nOffsetBorlandCPP = -1;

            nOffsetTurboC = msdos.find_ansiString(_nOffset, _nSize, "Turbo-C - ", pPdStruct);

            if (nOffsetTurboC != -1) {
                QString sBorlandString = msdos.read_ansiString(nOffsetTurboC);
                // TODO version
                _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_COMPILER, RECORD_NAME_TURBOC, "", "", 0);

                if (sBorlandString == "Turbo-C - Copyright (c) 1987 Borland Intl.") {
                    ssCompiler.sVersion = "1987";
                } else if (sBorlandString == "Turbo-C - Copyright (c) 1988 Borland Intl.") {
                    ssCompiler.sVersion = "1988";
                }

                pMSDOSInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pMSDOSInfo->basic_info), &ssCompiler));
            }

            if (nOffsetTurboC == -1) {
                nOffsetTurboCPP = msdos.find_ansiString(_nOffset, _nSize, "Turbo C++ - ", pPdStruct);
            }

            if (nOffsetTurboCPP != -1) {
                QString sBorlandString = msdos.read_ansiString(nOffsetTurboCPP);
                // TODO version
                _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_COMPILER, RECORD_NAME_TURBOCPP, "", "", 0);

                if (sBorlandString == "Turbo C++ - Copyright 1990 Borland Intl.") {
                    ssCompiler.sVersion = "1990";
                }

                pMSDOSInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pMSDOSInfo->basic_info), &ssCompiler));
            }

            if ((nOffsetTurboC == -1) && (nOffsetTurboCPP == -1)) {
                nOffsetBorlandCPP = msdos.find_ansiString(_nOffset, _nSize, "Borland C++", pPdStruct);
            }

            if (nOffsetBorlandCPP != -1) {
                QString sBorlandString = msdos.read_ansiString(nOffsetBorlandCPP);
                // TODO version
                _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_COMPILER, RECORD_NAME_BORLANDCPP, "", "", 0);

                if (sBorlandString == "Borland C++ - Copyright 1991 Borland Intl.") {
                    ssCompiler.sVersion = "1991";
                } else if (sBorlandString == "Borland C++ - Copyright 1993 Borland Intl.") {
                    ssCompiler.sVersion = "1993";
                } else if (sBorlandString == "Borland C++ - Copyright 1994 Borland Intl.") {
                    ssCompiler.sVersion = "1994";
                } else if (sBorlandString == "Borland C++ - Copyright 1995 Borland Intl.") {
                    ssCompiler.sVersion = "1995";
                }

                pMSDOSInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pMSDOSInfo->basic_info), &ssCompiler));
            }
        }

        if (ssCompiler.type == RECORD_TYPE_UNKNOWN) {
            if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_TURBOCPP)) {
                ssCompiler = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_TURBOCPP);
            }
        }

        if (ssLinker.type == RECORD_TYPE_UNKNOWN) {
            if ((ssCompiler.name == RECORD_NAME_TURBOC) || (ssCompiler.name == RECORD_NAME_TURBOCPP) || (ssCompiler.name == RECORD_NAME_BORLANDCPP)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_LINKER, RECORD_NAME_TURBOLINKER, "", "", 0);

                // TODO Version
                // Turbo-C 1987 1.0
                // Turbo-C 1988 2.0
                // Borland C++ 1991 3.0-7.00?

                ssLinker = ss;
            }
        }

        if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
            pMSDOSInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pMSDOSInfo->basic_info), &ssLinker));
        }

        if (ssCompiler.type != RECORD_TYPE_UNKNOWN) {
            pMSDOSInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pMSDOSInfo->basic_info), &ssCompiler));
        }
    }
}

void SpecAbstract::MSDOS_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYEXE)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYEXE);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LSCRYPRT)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LSCRYPRT);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PACKWIN) || pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PACKWIN)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PACKWIN);

            if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PACKWIN)) {
                pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PACKWIN);
            }

            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PKLITE)) {
            // TODO more options
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PKLITE);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WWPACK)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WWPACK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZEXE) || pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LZEXE)) {
            bool bHeader = pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZEXE);
            bool bEP = pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LZEXE);

            _SCANS_STRUCT ss = {};

            if (bHeader && bEP) {
                ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZEXE);
            } else if (bEP) {
                ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LZEXE);
                ss.sInfo = append(ss.sInfo, "modified header");
            } else if (bHeader) {
                ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZEXE);
                ss.sInfo = append(ss.sInfo, "modified entrypoint");
            }

            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RJCRUSH) || pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RJCRUSH)) {
            bool bHeader = pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RJCRUSH);
            bool bEP = pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RJCRUSH);

            _SCANS_STRUCT ss = {};

            if (bHeader && bEP) {
                ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RJCRUSH);
            } else if (bEP) {
                ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RJCRUSH);
                ss.sInfo = append(ss.sInfo, "modified header");
            } else if (bHeader) {
                ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RJCRUSH);
                ss.sInfo = append(ss.sInfo, "modified entrypoint");
            }

            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AINEXE)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AINEXE);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PGMPAK)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PGMPAK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_JAM)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_JAM);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LOCKTITE)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LOCKTITE);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PCOM)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PCOM);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AVPACK)) {
            // TODO Check
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AVPACK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LGLZ)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LGLZ);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PROPACK)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PROPACK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RELPACK)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RELPACK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_SCRNCH)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_SCRNCH);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_TINYPROG)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_TINYPROG);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_UCEXE)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_UCEXE);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_APACK)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_APACK);
            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CCBYVORONTSOV)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CCBYVORONTSOV);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRYPTCOM)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRYPTCOM);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CRYPTORBYDISMEMBER)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CRYPTORBYDISMEMBER);
            pMSDOSInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_UPX)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_UPX);

            VI_STRUCT viUPX = get_UPX_vi(pDevice, pOptions, 0, pMSDOSInfo->basic_info.id.nSize, XBinary::FT_MSDOS, pPdStruct);

            if (viUPX.bIsValid) {
                if (viUPX.sVersion != "") {
                    ss.sVersion = viUPX.sVersion;
                }

                ss.sInfo = viUPX.sInfo;
            }

            pMSDOSInfo->basic_info.mapResultPackers.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::MSDOS_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        if (pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHASSFX)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHASSFX);
            pMSDOSInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        } else if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_ICE)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_ICE);
            pMSDOSInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        } else if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PKZIPMINISFX)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PKZIPMINISFX);
            pMSDOSInfo->basic_info.mapResultSFX.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::MSDOS_handle_DosExtenders(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo,
                                             XBinary::PDSTRUCT *pPdStruct)
{
    XMSDOS msdos(pDevice, pOptions->bIsImage);

    if (msdos.isValid(pPdStruct)) {
        if (pMSDOSInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CAUSEWAY)) {
            _SCANS_STRUCT ss = pMSDOSInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CAUSEWAY);

            if (pMSDOSInfo->basic_info.scanOptions.bIsDeepScan) {
                qint64 nVersionOffset = msdos.find_ansiString(0, pMSDOSInfo->basic_info.id.nSize, "CauseWay DOS Extender v", pPdStruct);

                if (nVersionOffset != -1) {
                    QString sVersion = msdos.read_ansiString(nVersionOffset + 23);
                    sVersion = sVersion.section(" ", 0, 0);

                    if (sVersion != "") {
                        ss.sVersion = sVersion;
                    }
                }
            }

            pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        // CWSDPMI
        if (pMSDOSInfo->basic_info.scanOptions.bIsDeepScan) {
            qint64 nVersionOffset = msdos.find_ansiString(0, 0x100, "CWSDPMI", pPdStruct);

            if (nVersionOffset != -1) {
                QString sCWSDPMI = msdos.read_ansiString(nVersionOffset);

                if (sCWSDPMI.section(" ", 0, 0) == "CWSDPMI") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_DOSEXTENDER, RECORD_NAME_CWSDPMI, "", "", 0);

                    ss.sVersion = sCWSDPMI.section(" ", 1, 1);

                    pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
                }
            }
        }
        // PMODE/W
        QString sPMODEW = msdos.read_ansiString(0x55);
        QString sPMODE_W = sPMODEW.section(" ", 0, 0);
        if ((sPMODE_W == "PMODE/W") || (sPMODE_W == "PMODE\\W")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_DOSEXTENDER, RECORD_NAME_PMODEW, "", "", 0);

            ss.sVersion = sPMODEW.section(" ", 1, 1).remove("v");

            pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        QString sWDOSX = msdos.read_ansiString(0x34);

        if (sWDOSX.section(" ", 0, 0) == "WDOSX") {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_DOSEXTENDER, RECORD_NAME_WDOSX, "", "", 0);

            ss.sVersion = sWDOSX.section(" ", 1, 1);

            pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
        }

        // DOS/16M
        if (pMSDOSInfo->basic_info.scanOptions.bIsDeepScan) {
            qint64 nVersionOffset =
                msdos.find_ansiString(0, qMin(pMSDOSInfo->basic_info.id.nSize, (qint64)0x1000), "DOS/16M Copyright (C) Tenberry Software Inc", pPdStruct);

            if (nVersionOffset != -1) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_DOSEXTENDER, RECORD_NAME_DOS16M, "", "", 0);
                // TODO Version
                pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
            }
        }

        // DOS/4G
        if (pMSDOSInfo->basic_info.scanOptions.bIsDeepScan) {
            // TODO vi
            qint64 nVersionOffset = msdos.find_ansiString(0, qMin(pMSDOSInfo->basic_info.id.nSize, (qint64)0x1000), "DOS/4G", pPdStruct);

            if (nVersionOffset != -1) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_DOSEXTENDER, RECORD_NAME_DOS4G, "", "", 0);
                // TODO Version
                pMSDOSInfo->basic_info.mapResultDosExtenders.insert(ss.name, scansToScan(&(pMSDOSInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::ELF_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo,
                                              XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(elf.getFileFormatInfo(pPdStruct));

        pELFInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pELFInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::ELF_handle_CommentSection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo,
                                             XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    qint32 nNumberOfComments = pELFInfo->listComments.count();

    for (qint32 i = 0; (i < nNumberOfComments) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        QString sComment = pELFInfo->listComments.at(i);

        VI_STRUCT vi = {};
        _SCANS_STRUCT ss = {};

        // Apple LLVM / clang
        if (!vi.bIsValid) {
            vi = _get_ByteGuard_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_BYTEGUARD, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_GCC_string(sComment);  // TODO Max version

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_GCC, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AppleLLVM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_APPLELLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AndroidClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ANDROIDCLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AlipayClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ALIPAYCLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AlpineClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ALPINECLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AlibabaClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ALIBABACLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_PlexClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_PLEXCLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_UbuntuClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_UBUNTUCLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_DebianClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_DEBIANCLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ApportableClang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_APPORTABLECLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMAssembler_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMASSEMBLER, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMLinker_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LINKER, RECORD_NAME_ARMLINKER, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMC_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMC, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMCCPP_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMCCPP, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMNEONCCPP_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMNEONCCPP, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMThumbCCPP_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMTHUMBCCPP, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ARMThumbMacroAssembler_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ARMTHUMBMACROASSEMBLER, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ThumbC_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_THUMBC, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_clang_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_CLANG, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_DynASM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_DYNASM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_Delphi_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_LLD_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LINKER, RECORD_NAME_LLD, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_mold_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LINKER, RECORD_NAME_MOLD, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_OracleSolarisLinkEditors_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LINKER, RECORD_NAME_ORACLESOLARISLINKEDITORS, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_SunWorkShop_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_SUNWORKSHOP, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_SunWorkShopCompilers_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_SUNWORKSHOPCOMPILERS, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_SnapdragonLLVMARM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_SNAPDRAGONLLVMARM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_NASM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_NASM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_TencentLegu_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_TENCENTLEGU, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_AlipayObfuscator_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_ALIPAYOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_wangzehuaLLVM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_WANGZEHUALLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_ObfuscatorLLVM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_OBFUSCATORLLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_NagainLLVM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_NAGAINLLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_iJiami_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_IJIAMILLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_SafeengineLLVM_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_SAFEENGINELLVM, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_TencentObfuscation_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_TENCENTPROTECTION, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (!vi.bIsValid) {
            vi = _get_AppImage_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_APPIMAGE, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_HikariObfuscator_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_HIKARIOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_SnapProtect_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_SNAPPROTECT, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_ByteDanceSecCompiler_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_BYTEDANCESECCOMPILER, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_DingbaozengNativeObfuscator_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_OllvmTll_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_OLLVMTLL, vi.sVersion, vi.sInfo, 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_SourceryCodeBench_string(sComment);

            if (vi.bIsValid) {
                if (vi.sInfo == "lite") {
                    ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_SOURCERYCODEBENCHLITE, vi.sVersion, "", 0);
                } else {
                    ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_SOURCERYCODEBENCH, vi.sVersion, "", 0);
                }

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        {
            vi = _get_Rust_string(sComment);

            if (vi.bIsValid) {
                ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_RUST, vi.sVersion, "", 0);

                pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
            }
        }

        if (pELFInfo->basic_info.scanOptions.bIsTest && pELFInfo->basic_info.scanOptions.bIsVerbose) {
            if (ss.name == RECORD_NAME_UNKNOWN) {
                if ((!vi.bIsValid) && (!XBinary::isRegExpPresent(".o$", sComment)) && (!XBinary::isRegExpPresent(".c$", sComment)) &&
                    (!XBinary::isRegExpPresent(".S22$", sComment)) && (!XBinary::isRegExpPresent(".s$", sComment)) && (!XBinary::isRegExpPresent(".S$", sComment))) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + (RECORD_NAME)(i + 1));
                    recordSS.sVersion = "COMMENT:" + sComment;

                    pELFInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
                }
            }
        }
    }
}

void SpecAbstract::ELF_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        // Qt
        if (XELF::isSectionNamePresent(".qtversion", &(pELFInfo->listSectionRecords))) {
            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name = SpecAbstract::RECORD_NAME_QT;

            XELF::SECTION_RECORD record = elf._getSectionRecords(&(pELFInfo->listSectionRecords), ".qtversion").at(0);

            quint64 nVersion = 0;

            if (pELFInfo->bIs64) {
                if (record.nSize == 16) {
                    nVersion = elf.read_uint64(record.nOffset + 8, pELFInfo->bIsBigEndian);
                }
            } else {
                if (record.nSize == 8) {
                    nVersion = elf.read_uint32(record.nOffset + 4, pELFInfo->bIsBigEndian);
                }
            }

            if (nVersion) {
                recordSS.sVersion = XBinary::get_uint32_full_version(nVersion);
            }

            pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        } else if (XELF::isSectionNamePresent(".qtplugin", &(pELFInfo->listSectionRecords))) {
            XELF::SECTION_RECORD record = elf._getSectionRecords(&(pELFInfo->listSectionRecords), ".qtplugin").at(0);

            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name = SpecAbstract::RECORD_NAME_QT;

            QString sVersionString = elf.read_ansiString(record.nOffset);
            recordSS.sVersion = XBinary::regExp("version=(.*?)\\\n", sVersionString, 1);

            pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        } else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt5Core.so.5", pPdStruct)) {
            _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "5.X", "", 0);

            pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        } else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt6Core_x86.so", pPdStruct)) {
            _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "", 0);

            pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        } else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt6Core.so.6", pPdStruct)) {
            _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "", 0);

            pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        }

        if (XELF::isNotePresent(&(pELFInfo->listNotes), "Android")) {
            XELF::NOTE note = XELF::getNote(&(pELFInfo->listNotes), "Android");

            _SCANS_STRUCT ssAndroidSDK = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);
            _SCANS_STRUCT ssAndroidNDK = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDNDK, "", "", 0);

            if (note.nSize >= 4) {
                quint32 nSDKVersion = elf.read_uint32(note.nDataOffset);
                ssAndroidSDK.sVersion = QString("API %1(Android %2)").arg(QString::number(nSDKVersion), XBinary::getAndroidVersionFromApi(nSDKVersion));  // TODO
            }

            if (note.nSize >= 4 + 64 * 2) {
                QString sNdkVersion = elf.read_ansiString(note.nDataOffset + 4);
                QString sNdkBuild = elf.read_ansiString(note.nDataOffset + 4 + 64);

                ssAndroidNDK.sVersion = QString("%1(%2)").arg(sNdkVersion).arg(sNdkBuild);
            }

            pELFInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, scansToScan(&(pELFInfo->basic_info), &ssAndroidSDK));
            pELFInfo->basic_info.mapResultTools.insert(ssAndroidNDK.name, scansToScan(&(pELFInfo->basic_info), &ssAndroidNDK));
        }

        if (XELF::isNotePresent(&(pELFInfo->listNotes), "Go")) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_GO, "", "", 0);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // gold
        if (XELF::isSectionNamePresent(".note.gnu.gold-version", &(pELFInfo->listSectionRecords))) {
            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LINKER;
            recordSS.name = SpecAbstract::RECORD_NAME_GOLD;

            XELF::SECTION_RECORD record = elf._getSectionRecords(&(pELFInfo->listSectionRecords), ".note.gnu.gold-version").at(0);

            SpecAbstract::VI_STRUCT vi = get_gold_vi(pDevice, pOptions, record.nOffset, record.nSize, pPdStruct);

            if (vi.bIsValid) {
                recordSS.sVersion = vi.sVersion;
            }

            pELFInfo->basic_info.mapResultLinkers.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        }

        // dotnet
        if (pELFInfo->sRunPath == "$ORIGIN/netcoredeps") {
            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LOADER;
            recordSS.name = SpecAbstract::RECORD_NAME_DOTNET;

            pELFInfo->basic_info.mapResultTools.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        }

        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SOURCERYCODEBENCH)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SOURCERYCODEBENCH);

            pELFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        } else if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SOURCERYCODEBENCHLITE)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SOURCERYCODEBENCHLITE);

            pELFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_RUST)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_RUST);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_APPLELLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_APPLELLVM);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Android clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ANDROIDCLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ANDROIDCLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Alipay clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ALIPAYCLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ALIPAYCLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Alpine clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ALPINECLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ALPINECLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Alibaba clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ALIBABACLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ALIBABACLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Plex clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_PLEXCLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_PLEXCLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Ubuntu clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_UBUNTUCLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_UBUNTUCLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Debian clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_DEBIANCLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_DEBIANCLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Apportable clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_APPORTABLECLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_APPORTABLECLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM Assembler
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMASSEMBLER)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMASSEMBLER);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM C
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMC)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMC);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM C/C++
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMCCPP)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMCCPP);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM NEON C/C++
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMNEONCCPP)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMNEONCCPP);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM/Thumb C/C++
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMTHUMBCCPP)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMTHUMBCCPP);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Thumb C
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_THUMBC)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_THUMBC);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM/Thumb Macro Assembler
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMTHUMBMACROASSEMBLER)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMTHUMBMACROASSEMBLER);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ARM Linker
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ARMLINKER)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ARMLINKER);

            pELFInfo->basic_info.mapResultLinkers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // clang
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_CLANG)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_CLANG);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // DynASM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_DYNASM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_DYNASM);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Delphi
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI)) {
            _SCANS_STRUCT ssCompiler = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI);

            pELFInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pELFInfo->basic_info), &ssCompiler));

            _SCANS_STRUCT ssTool =
                getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_TOOL, RECORD_NAME_EMBARCADERODELPHI, _get_DelphiVersionFromCompiler(ssCompiler.sVersion).sVersion, "", 0);

            pELFInfo->basic_info.mapResultTools.insert(ssTool.name, scansToScan(&(pELFInfo->basic_info), &ssTool));
        }

        // LLD
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_LLD)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_LLD);

            pELFInfo->basic_info.mapResultLinkers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Oracle Solaris Link Editors
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ORACLESOLARISLINKEDITORS)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ORACLESOLARISLINKEDITORS);

            pELFInfo->basic_info.mapResultLinkers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Sun WorkShop
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SUNWORKSHOP)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SUNWORKSHOP);

            pELFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Sun WorkShop Compilers
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SUNWORKSHOPCOMPILERS)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SUNWORKSHOPCOMPILERS);

            pELFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Snapdragon LLVM ARM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SNAPDRAGONLLVMARM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SNAPDRAGONLLVMARM);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // NASM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_NASM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_NASM);

            pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        if (XELF::isSectionNamePresent(".rodata", &(pELFInfo->listSectionRecords))) {
            qint32 nIndex = XELF::getSectionNumber(".rodata", &(pELFInfo->listSectionRecords));

            qint64 nDataOffset = XELF::getElf_Shdr_offset(nIndex, &(pELFInfo->listSectionHeaders));
            qint64 nDataSize = XELF::getElf_Shdr_size(nIndex, &(pELFInfo->listSectionHeaders));

            VI_STRUCT viStruct = get_Zig_vi(pDevice, pOptions, nDataOffset, nDataSize, pPdStruct);

            if (viStruct.bIsValid) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_COMPILER, RECORD_NAME_ZIG, "", "", 0);

                ss.sVersion = viStruct.sVersion;
                ss.sInfo = viStruct.sInfo;

                pELFInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::ELF_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        _SCANS_STRUCT recordCompiler = {};
        // GCC
        if (XELF::isSectionNamePresent(".gcc_except_table", &(pELFInfo->listSectionRecords)))  // TODO
        {
            recordCompiler.type = SpecAbstract::RECORD_TYPE_COMPILER;
            recordCompiler.name = SpecAbstract::RECORD_NAME_GCC;
        }

        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_GCC)) {
            recordCompiler = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_GCC);
        }

        if (recordCompiler.type != SpecAbstract::RECORD_TYPE_UNKNOWN) {
            pELFInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pELFInfo->basic_info), &recordCompiler));
        }
    }
}

void SpecAbstract::ELF_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        if (pELFInfo->nSymTabOffset > 0) {
            qint32 nNumberOfSymbols = elf.getNumberOfSymbols(pELFInfo->nSymTabOffset);

            if (nNumberOfSymbols) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_DEBUGDATA, RECORD_NAME_SYMBOLTABLE, "", "", 0);

                ss.sInfo = pELFInfo->listSectionRecords.at(pELFInfo->nSymTabSection).sName;
                ss.sInfo = append(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));

                pELFInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
            }
        }

        if (elf.isSectionNamePresent(".stab", &(pELFInfo->listSectionRecords)) && elf.isSectionNamePresent(".stabstr", &(pELFInfo->listSectionRecords))) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_DEBUGDATA, RECORD_NAME_STABSDEBUGINFO, "", "", 0);
            pELFInfo->basic_info.mapResultDebugData.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        if (pELFInfo->nDWARFDebugOffset > 0) {
            VI_STRUCT viStruct = get_DWRAF_vi(pDevice, pOptions, pELFInfo->nDWARFDebugOffset, pELFInfo->nDWARFDebugSize, pPdStruct);

            if (viStruct.bIsValid) {
                _SCANS_STRUCT ssDebugInfo = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                ssDebugInfo.sVersion = viStruct.sVersion;

                pELFInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, scansToScan(&(pELFInfo->basic_info), &ssDebugInfo));
            }
        }
    }
}

void SpecAbstract::ELF_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pELFInfo)

    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        // UPX
        VI_STRUCT viUPXEnd = _get_UPX_vi(pDevice, pOptions, pELFInfo->basic_info.id.nSize - 0x24, 0x24, XBinary::FT_ELF);
        VI_STRUCT viUPX = get_UPX_vi(pDevice, pOptions, 0, pELFInfo->basic_info.id.nSize, XBinary::FT_ELF, pPdStruct);

        if ((viUPXEnd.bIsValid) || (viUPX.bIsValid)) {
            _SCANS_STRUCT recordSS = {};

            recordSS.type = RECORD_TYPE_PACKER;
            recordSS.name = RECORD_NAME_UPX;

            if (viUPXEnd.sVersion != "") recordSS.sVersion = viUPXEnd.sVersion;
            if (viUPX.sVersion != "") recordSS.sVersion = viUPX.sVersion;

            if (viUPXEnd.sInfo != "") recordSS.sInfo = viUPXEnd.sInfo;
            if (viUPX.sInfo != "") recordSS.sInfo = viUPX.sInfo;

            pELFInfo->basic_info.mapResultPackers.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));
        }

        if (viUPXEnd.vValue.toUInt() == 0x21434553)  // SEC!
        {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_SECNEO, "Old", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        } else if (viUPXEnd.vValue.toUInt() == 0x00010203) {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_SECNEO, "", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        } else if (viUPXEnd.vValue.toUInt() == 0x214d4a41)  // "AJM!"
        {
            _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_IJIAMI, "", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Burneye
        if (pELFInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BURNEYE)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BURNEYE);

            qint64 _nOffset = 0x1000;
            qint64 _nSize = 0x200;

            qint64 nOffset_Id = elf.find_ansiString(_nOffset, _nSize, "TEEE burneye - TESO ELF Encryption Engine", pPdStruct);

            if (nOffset_Id == -1) {
                ss.sInfo = "Modified";
            }

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Obfuscator-LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_OBFUSCATORLLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_OBFUSCATORLLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // wangzehua LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_WANGZEHUALLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_WANGZEHUALLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Byteguard
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_BYTEGUARD)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_BYTEGUARD);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Alipay Obfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_ALIPAYOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_ALIPAYOBFUSCATOR);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Tencent Legu
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_TENCENTLEGU)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_TENCENTLEGU);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Safeengine LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SAFEENGINELLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SAFEENGINELLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Tencent-Obfuscation
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_TENCENTPROTECTION)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_TENCENTPROTECTION);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // AppImage
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_APPIMAGE))  // Check overlay
        {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_APPIMAGE);
            pELFInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // HikariObfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_HIKARIOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_HIKARIOBFUSCATOR);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // SnapProtect
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_SNAPPROTECT)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_SNAPPROTECT);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ByteDance-SecCompiler
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_BYTEDANCESECCOMPILER)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_BYTEDANCESECCOMPILER);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Dingbaozeng native obfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Nagain LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_NAGAINLLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_NAGAINLLVM);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // iJiami LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_IJIAMILLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_IJIAMILLVM);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // LLVM 6.0 + Ollvm + Armariris
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(RECORD_NAME_OLLVMTLL)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(RECORD_NAME_OLLVMTLL);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
        }

        {
            // Virbox Protector
            QList<XELF_DEF::Elf_Phdr> listNotes = elf._getPrograms(&(pELFInfo->listProgramHeaders), XELF_DEF::S_PT_NOTE);

            qint32 nNumberOfNotes = listNotes.count();

            for (qint32 i = 0; (i < nNumberOfNotes) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                qint64 nOffset = 0;

                if (pOptions->bIsImage) {
                    nOffset = listNotes.at(i).p_vaddr;  // TODO Check
                } else {
                    nOffset = listNotes.at(i).p_offset;
                }

                qint64 nSize = listNotes.at(i).p_filesz;

                QString sString = elf.read_ansiString(nOffset, nSize);

                if (sString == "Virbox Protector") {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_PROTECTOR, RECORD_NAME_VIRBOXPROTECTOR, "", "", 0);

                    pELFInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pELFInfo->basic_info), &ss));
                }

                break;
            }
        }
    }
}

void SpecAbstract::ELF_handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo,
                                                XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pELFInfo)

    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        if (pELFInfo->basic_info.scanOptions.bIsTest && pELFInfo->basic_info.scanOptions.bIsVerbose) {
            // TODO names of note sections

            qint32 nIndex = 1;

            {
                qint32 nNumberOfRecords = pELFInfo->listLibraries.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_LIBRARY;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("LIBRARY_") + pELFInfo->listLibraries.at(i);

                    pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }

            {
                XBinary::OS_STRING asInterpeter = elf.getProgramInterpreterName();

                if (asInterpeter.nSize) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_LIBRARY;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("Interpreter_") + asInterpeter.sString;

                    pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }

            {
                QSet<QString> stRecords;

                qint32 nNumberOfRecords = pELFInfo->listComments.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (!stRecords.contains(pELFInfo->listComments.at(i))) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_LIBRARY;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("COMMENT_") + pELFInfo->listComments.at(i);

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                        stRecords.insert(pELFInfo->listComments.at(i));

                        nIndex++;
                    }
                }
            }

            {
                QSet<QString> stRecords;

                qint32 nNumberOfRecords = pELFInfo->listNotes.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (!stRecords.contains(pELFInfo->listNotes.at(i).sName)) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_LIBRARY;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("NOTE_") + pELFInfo->listNotes.at(i).sName;

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                        stRecords.insert(pELFInfo->listNotes.at(i).sName);

                        nIndex++;
                    }
                }
            }

            {
                QSet<quint32> stRecords;

                qint32 nNumberOfRecords = pELFInfo->listNotes.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (!stRecords.contains(pELFInfo->listNotes.at(i).nType)) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_LIBRARY;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("NOTE_TYPE_%1").arg(pELFInfo->listNotes.at(i).nType);

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                        stRecords.insert(pELFInfo->listNotes.at(i).nType);

                        nIndex++;
                    }
                }
            }

            {
                QSet<QString> stRecords;

                qint32 nNumberOfRecords = pELFInfo->listSectionRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (!stRecords.contains(pELFInfo->listSectionRecords.at(i).sName)) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_LIBRARY;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("SECTION_") + pELFInfo->listSectionRecords.at(i).sName;

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pELFInfo->basic_info), &recordSS));

                        stRecords.insert(pELFInfo->listSectionRecords.at(i).sName);

                        nIndex++;
                    }
                }
            }
        }
    }
}

void SpecAbstract::ELF_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pELFInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_GCC) || pELFInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_APPORTABLECLANG)) {
        if (pELFInfo->basic_info.mapResultCompilers.value(RECORD_NAME_GCC).sVersion == "") {
            pELFInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_GCC);
        }
    }
}

void SpecAbstract::MACHO_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        QList<XMACH_DEF::build_tool_version> listBTV;

        _SCANS_STRUCT recordSDK = {};
        recordSDK.type = SpecAbstract::RECORD_TYPE_TOOL;
        recordSDK.name = SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordXcode = {};

        recordXcode.type = SpecAbstract::RECORD_TYPE_TOOL;
        recordXcode.name = SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordGCC = {};
        recordGCC.type = SpecAbstract::RECORD_TYPE_COMPILER;

        _SCANS_STRUCT recordCLANG = {};
        recordCLANG.type = SpecAbstract::RECORD_TYPE_COMPILER;

        _SCANS_STRUCT recordSwift = {};
        recordSwift.type = SpecAbstract::RECORD_TYPE_COMPILER;
        recordSwift.name = SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordZig = {};
        recordZig.type = SpecAbstract::RECORD_TYPE_COMPILER;
        recordZig.name = SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordLD = {};
        recordLD.type = SpecAbstract::RECORD_TYPE_LINKER;
        recordLD.name = SpecAbstract::RECORD_NAME_UNKNOWN;

        XBinary::FILEFORMATINFO fileFormatInfo = mach.getFileFormatInfo(pPdStruct);

        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(fileFormatInfo);

        pMACHInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pMACHInfo->basic_info), &ssOperationSystem));

        if (mach.isCommandPresent(XMACH_DEF::S_LC_CODE_SIGNATURE, &(pMACHInfo->listCommandRecords))) {
            _SCANS_STRUCT recordSS = getScansStruct(0, XBinary::FT_MACHO, RECORD_TYPE_SIGNTOOL, RECORD_NAME_CODESIGN, "", "", 0);
            // TODO more info
            pMACHInfo->basic_info.mapResultSigntools.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }

        // Foundation
        if (XMACH::isLibraryRecordNamePresent("Foundation", &(pMACHInfo->listLibraryRecords))) {
            _SCANS_STRUCT recordFoundation = {};

            recordFoundation.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordFoundation.name = SpecAbstract::RECORD_NAME_FOUNDATION;

            quint32 nVersion = XMACH::getLibraryCurrentVersion("Foundation", &(pMACHInfo->listLibraryRecords));

            if ((fileFormatInfo.osName == XBinary::OSNAME_MAC_OS_X) || (fileFormatInfo.osName == XBinary::OSNAME_OS_X) ||
                (fileFormatInfo.osName == XBinary::OSNAME_MACOS)) {
                recordSDK.name = RECORD_NAME_MACOSSDK;

                // https://developer.apple.com/documentation/foundation/object_runtime/foundation_framework_version_numbers
                if ((nVersion >= S_FULL_VERSION(397, 40, 0)) && (nVersion < S_FULL_VERSION(425, 0, 0))) recordSDK.sVersion = "10.0.0";
                else if (nVersion < S_FULL_VERSION(462, 0, 0)) recordSDK.sVersion = "10.1.0";
                else if (nVersion < S_FULL_VERSION(462, 70, 0)) recordSDK.sVersion = "10.2.0";
                else if (nVersion < S_FULL_VERSION(500, 0, 0)) recordSDK.sVersion = "10.2.7";
                else if (nVersion < S_FULL_VERSION(500, 30, 0)) recordSDK.sVersion = "10.3.0";
                else if (nVersion < S_FULL_VERSION(500, 54, 0)) recordSDK.sVersion = "10.3.2";
                else if (nVersion < S_FULL_VERSION(500, 56, 0)) recordSDK.sVersion = "10.3.3";
                else if (nVersion < S_FULL_VERSION(500, 58, 0)) recordSDK.sVersion = "10.3.4";
                else if (nVersion < S_FULL_VERSION(567, 0, 0)) recordSDK.sVersion = "10.3.9";
                else if (nVersion < S_FULL_VERSION(567, 12, 0)) recordSDK.sVersion = "10.4.0";
                else if (nVersion < S_FULL_VERSION(567, 21, 0)) recordSDK.sVersion = "10.4.2";
                else if (nVersion < S_FULL_VERSION(567, 25, 0)) recordSDK.sVersion = "10.4.4";
                else if (nVersion < S_FULL_VERSION(567, 26, 0)) recordSDK.sVersion = "10.4.5";
                else if (nVersion < S_FULL_VERSION(567, 27, 0)) recordSDK.sVersion = "10.4.6";
                else if (nVersion < S_FULL_VERSION(567, 28, 0)) recordSDK.sVersion = "10.4.7";
                else if (nVersion < S_FULL_VERSION(567, 29, 0)) recordSDK.sVersion = "10.4.8";
                else if (nVersion < S_FULL_VERSION(567, 36, 0)) recordSDK.sVersion = "10.4.9";
                else if (nVersion < S_FULL_VERSION(677, 0, 0)) recordSDK.sVersion = "10.4.11";
                else if (nVersion < S_FULL_VERSION(677, 10, 0)) recordSDK.sVersion = "10.5.0";
                else if (nVersion < S_FULL_VERSION(677, 15, 0)) recordSDK.sVersion = "10.5.1";
                else if (nVersion < S_FULL_VERSION(677, 19, 0)) recordSDK.sVersion = "10.5.2";
                else if (nVersion < S_FULL_VERSION(677, 21, 0)) recordSDK.sVersion = "10.5.3";
                else if (nVersion < S_FULL_VERSION(677, 22, 0)) recordSDK.sVersion = "10.5.5";
                else if (nVersion < S_FULL_VERSION(677, 24, 0)) recordSDK.sVersion = "10.5.6";
                else if (nVersion < S_FULL_VERSION(677, 26, 0)) recordSDK.sVersion = "10.5.7";
                else if (nVersion < S_FULL_VERSION(751, 0, 0)) recordSDK.sVersion = "10.5.8";
                else if (nVersion < S_FULL_VERSION(751, 14, 0)) recordSDK.sVersion = "10.6.0";
                else if (nVersion < S_FULL_VERSION(751, 21, 0)) recordSDK.sVersion = "10.6.2";
                else if (nVersion < S_FULL_VERSION(751, 29, 0)) recordSDK.sVersion = "10.6.3";
                else if (nVersion < S_FULL_VERSION(751, 42, 0)) recordSDK.sVersion = "10.6.4";
                else if (nVersion < S_FULL_VERSION(751, 53, 0)) recordSDK.sVersion = "10.6.5";
                else if (nVersion < S_FULL_VERSION(751, 62, 0)) recordSDK.sVersion = "10.6.6";
                else if (nVersion < S_FULL_VERSION(833, 10, 0)) recordSDK.sVersion = "10.6.8";
                else if (nVersion < S_FULL_VERSION(833, 10, 0)) recordSDK.sVersion = "10.7.0";
                else if (nVersion < S_FULL_VERSION(833, 20, 0)) recordSDK.sVersion = "10.7.1";
                else if (nVersion < S_FULL_VERSION(833, 24, 0)) recordSDK.sVersion = "10.7.2";
                else if (nVersion < S_FULL_VERSION(833, 25, 0)) recordSDK.sVersion = "10.7.3";
                else if (nVersion < S_FULL_VERSION(945, 0, 0)) recordSDK.sVersion = "10.7.4";
                else if (nVersion < S_FULL_VERSION(945, 11, 0)) recordSDK.sVersion = "10.8.0";
                else if (nVersion < S_FULL_VERSION(945, 16, 0)) recordSDK.sVersion = "10.8.2";
                else if (nVersion < S_FULL_VERSION(945, 18, 0)) recordSDK.sVersion = "10.8.3";
                else if (nVersion < S_FULL_VERSION(1056, 0, 0)) recordSDK.sVersion = "10.8.4";
                else if (nVersion < S_FULL_VERSION(1056, 13, 0)) recordSDK.sVersion = "10.9.0";
                else if (nVersion < S_FULL_VERSION(1151, 16, 0)) recordSDK.sVersion = "10.9.2";
                else if (nVersion < S_FULL_VERSION(1152, 14, 0)) recordSDK.sVersion = "10.10.0";
                else if (nVersion < S_FULL_VERSION(1153, 20, 0)) recordSDK.sVersion = "10.10.2";
                else if (nVersion < S_FULL_VERSION(1154, 0, 0)) recordSDK.sVersion = "10.10.3";
                else if (nVersion < S_FULL_VERSION(1199, 0, 0)) recordSDK.sVersion = "10.10.5";
                else if (nVersion < S_FULL_VERSION(1252, 0, 0)) recordSDK.sVersion = "10.10 Max";
                else if (nVersion < S_FULL_VERSION(1255, 10, 0)) recordSDK.sVersion = "10.11.0";
                else if (nVersion < S_FULL_VERSION(1256, 10, 0)) recordSDK.sVersion = "10.11.1";
                else if (nVersion < S_FULL_VERSION(1258, 0, 0)) recordSDK.sVersion = "10.11.3";
                else if (nVersion < S_FULL_VERSION(1299, 0, 0)) recordSDK.sVersion = "10.11.4";
                else if (nVersion < S_FULL_VERSION(1400, 10, 0))  // TODO Check
                    recordSDK.sVersion = "10.11 Max";
            } else if ((fileFormatInfo.osName == XBinary::OSNAME_IPHONEOS) || (fileFormatInfo.osName == XBinary::OSNAME_IOS) ||
                       (fileFormatInfo.osName == XBinary::OSNAME_IPADOS)) {
                recordSDK.name = RECORD_NAME_IOSSDK;

                if (nVersion < S_FULL_VERSION(678, 24, 0)) recordSDK.sVersion = "1.0.0";
                else if (nVersion < S_FULL_VERSION(678, 26, 0)) recordSDK.sVersion = "2.0.0";
                else if (nVersion < S_FULL_VERSION(678, 29, 0)) recordSDK.sVersion = "2.1.0";
                else if (nVersion < S_FULL_VERSION(678, 47, 0)) recordSDK.sVersion = "2.2.0";
                else if (nVersion < S_FULL_VERSION(678, 51, 0)) recordSDK.sVersion = "3.0.0";
                else if (nVersion < S_FULL_VERSION(678, 60, 0)) recordSDK.sVersion = "3.1.0";
                else if (nVersion < S_FULL_VERSION(751, 32, 0)) recordSDK.sVersion = "3.2.0";
                else if (nVersion < S_FULL_VERSION(751, 37, 0)) recordSDK.sVersion = "4.0.0";
                else if (nVersion < S_FULL_VERSION(751, 49, 0)) recordSDK.sVersion = "4.1.0";
                else if (nVersion < S_FULL_VERSION(881, 0, 0)) recordSDK.sVersion = "4.2.0";
                else if (nVersion < S_FULL_VERSION(890, 10, 0)) recordSDK.sVersion = "5.0.0";
                else if (nVersion < S_FULL_VERSION(992, 0, 0)) recordSDK.sVersion = "5.1.0";
                else if (nVersion < S_FULL_VERSION(993, 0, 0)) recordSDK.sVersion = "6.0.0";
                else if (nVersion < S_FULL_VERSION(1047, 20, 0)) recordSDK.sVersion = "6.1.0";
                else if (nVersion < S_FULL_VERSION(1047, 25, 0)) recordSDK.sVersion = "7.0.0";
                else if (nVersion < S_FULL_VERSION(1140, 11, 0)) recordSDK.sVersion = "7.1.0";
                else if (nVersion < S_FULL_VERSION(1141, 1, 0)) recordSDK.sVersion = "8.0.0";
                else if (nVersion < S_FULL_VERSION(1142, 14, 0)) recordSDK.sVersion = "8.1.0";
                else if (nVersion < S_FULL_VERSION(1144, 17, 0)) recordSDK.sVersion = "8.2.0";
                else if (nVersion < S_FULL_VERSION(1200, 0, 0)) recordSDK.sVersion = "8.3.0";  // TODO Check
                // TODO
            }

            QString sVersion = XBinary::get_uint32_full_version(nVersion);

            recordFoundation.sVersion = sVersion;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordFoundation.name, scansToScan(&(pMACHInfo->basic_info), &recordFoundation));
        }

        // GCC
        if (XMACH::isLibraryRecordNamePresent("libgcc_s.1.dylib", &(pMACHInfo->listLibraryRecords))) {
            recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
        }

        // Swift
        if (XMACH::isSectionNamePresent("__swift5_proto", &(pMACHInfo->listSectionRecords)) ||
            XMACH::isSectionNamePresent("__swift5_types", &(pMACHInfo->listSectionRecords))) {  // TODO Check
            recordSwift.name = SpecAbstract::RECORD_NAME_SWIFT;
            recordSwift.sVersion = "5.XX";
        } else if (XMACH::isSectionNamePresent("__swift2_proto", &(pMACHInfo->listSectionRecords)) ||
                   XMACH::isLibraryRecordNamePresent("libswiftCore.dylib", &(pMACHInfo->listLibraryRecords)))  // TODO
        {
            recordSwift.name = SpecAbstract::RECORD_NAME_SWIFT;
        }

        if (XMACH::isSectionNamePresent("__objc_selrefs", &(pMACHInfo->listSectionRecords)) || XMACH::isSegmentNamePresent("__OBJC", &(pMACHInfo->listSegmentRecords)) ||
            XMACH::isLibraryRecordNamePresent("libobjc.A.dylib", &(pMACHInfo->listLibraryRecords))) {
            recordGCC.sInfo = "Objective-C";
            recordCLANG.sInfo = "Objective-C";
        }

        // XCODE
        qint64 nVersionMinOffset = -1;
        qint64 nBuildVersionOffset = -1;

        if (mach.isCommandPresent(XMACH_DEF::S_LC_BUILD_VERSION, &(pMACHInfo->listCommandRecords))) {
            nBuildVersionOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_BUILD_VERSION, 0, &(pMACHInfo->listCommandRecords));
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_IPHONEOS, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_IPHONEOS, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = RECORD_NAME_IOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_MACOSX, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_MACOSX, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = RECORD_NAME_MACOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_TVOS, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_TVOS, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = RECORD_NAME_TVOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = RECORD_NAME_WATCHOSSDK;
        }

        if (nBuildVersionOffset != -1) {
            XMACH_DEF::build_version_command build_version = mach._read_build_version_command(nBuildVersionOffset);

            if (build_version.platform == XMACH_DEF::S_PLATFORM_MACOS) recordSDK.name = RECORD_NAME_MACOSSDK;
            else if (build_version.platform == XMACH_DEF::S_PLATFORM_BRIDGEOS) recordSDK.name = RECORD_NAME_BRIDGEOS;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_IOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_IOSSIMULATOR))
                recordSDK.name = RECORD_NAME_IOSSDK;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_TVOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_TVOSSIMULATOR))
                recordSDK.name = RECORD_NAME_TVOSSDK;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_WATCHOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_WATCHOSSIMULATOR))
                recordSDK.name = RECORD_NAME_WATCHOSSDK;

            if (build_version.sdk) {
                recordSDK.sVersion = XBinary::get_uint32_full_version(build_version.sdk);
            }

            if ((build_version.cmdsize - sizeof(XMACH_DEF::build_version_command)) && (build_version.ntools > 0)) {
                nBuildVersionOffset += sizeof(XMACH_DEF::build_version_command);

                quint32 nNumberOfTools =
                    qMin(build_version.ntools, (quint32)((build_version.cmdsize - sizeof(XMACH_DEF::build_version_command) / sizeof(XMACH_DEF::build_tool_version))));

                for (quint32 i = 0; i < nNumberOfTools; i++) {
                    XMACH_DEF::build_tool_version btv = mach._read_build_tool_version(nBuildVersionOffset);

                    listBTV.append(btv);

                    nBuildVersionOffset += sizeof(XMACH_DEF::build_tool_version);
                }
            }

        } else if (nVersionMinOffset != -1) {
            XMACH_DEF::version_min_command version_min = mach._read_version_min_command(nVersionMinOffset);

            if (version_min.sdk) {
                recordSDK.sVersion = XBinary::get_uint32_full_version(version_min.sdk);
            }
        }

        // https://xcodereleases.com/
        // https://en.wikipedia.org/wiki/Xcode
        if (recordSDK.name != RECORD_NAME_UNKNOWN) {
            recordXcode.name = SpecAbstract::RECORD_NAME_XCODE;

            if (recordSDK.name == SpecAbstract::RECORD_NAME_MACOSSDK) {
                if (recordSDK.sVersion == "10.3.0") {
                    recordXcode.sVersion = "1.0-3.1.4";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion == "10.4.0") {
                    recordXcode.sVersion = "2.0-3.2.6";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.0.2-1.7";
                } else if (recordSDK.sVersion == "10.5.0") {
                    recordXcode.sVersion = "2.5-3.2.6";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.0.2-1.7";
                } else if (recordSDK.sVersion == "10.6.0") {
                    recordXcode.sVersion = "3.2-4.3.3";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.0.2-3.0";
                } else if (recordSDK.sVersion == "10.7.0") {
                    recordXcode.sVersion = "4.1-4.6.3";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "2.1-4.2";
                } else if (recordSDK.sVersion == "10.8.0") {
                    recordXcode.sVersion = "4.4-5.1.1";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "4.0-5.1";
                } else if (recordSDK.sVersion == "10.9.0") {
                    recordXcode.sVersion = "5.0.1-6.4";
                    recordCLANG.sVersion = "5.0-6.1.0";
                    recordSwift.sVersion = "1.0-1.2";
                } else if (recordSDK.sVersion == "10.10.0") {
                    recordXcode.sVersion = "6.1-6.4";
                    recordCLANG.sVersion = "6.0-6.1.0";
                    recordSwift.sVersion = "1.0-1.2";
                } else if (recordSDK.sVersion == "10.11.0") {
                    recordXcode.sVersion = "7.0-7.1.1";
                    recordCLANG.sVersion = "7.0.0";
                    recordSwift.sVersion = "2.0-2.1";
                } else if (recordSDK.sVersion == "10.11.2") {
                    recordXcode.sVersion = "7.2-7.2.1";
                    recordCLANG.sVersion = "7.0.2";
                    recordSwift.sVersion = "2.1.1";
                } else if (recordSDK.sVersion == "10.11.4") {
                    recordXcode.sVersion = "7.3-7.3.1";
                    recordCLANG.sVersion = "7.3.0";
                    recordSwift.sVersion = "2.2";
                } else if (recordSDK.sVersion == "10.12.0") {
                    recordXcode.sVersion = "8.0";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0";
                } else if (recordSDK.sVersion == "10.12.1") {
                    recordXcode.sVersion = "8.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.1";
                } else if (recordSDK.sVersion == "10.12.2") {
                    recordXcode.sVersion = "8.2-8.2.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.2";
                } else if (recordSDK.sVersion == "10.12.4") {
                    recordXcode.sVersion = "8.3-8.3.3";
                    recordCLANG.sVersion = "8.1.0";
                    recordSwift.sVersion = "3.1";
                } else if (recordSDK.sVersion == "10.13.0") {
                    recordXcode.sVersion = "9.0-9.0.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0";
                } else if (recordSDK.sVersion == "10.13.1") {
                    recordXcode.sVersion = "9.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.2";
                } else if (recordSDK.sVersion == "10.13.2") {
                    recordXcode.sVersion = "9.2";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.3";
                } else if (recordSDK.sVersion == "10.13.4") {
                    recordXcode.sVersion = "9.3-9.4.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1-4.1.2";
                } else if (recordSDK.sVersion == "10.14.0") {
                    recordXcode.sVersion = "10.0";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2";
                } else if (recordSDK.sVersion == "10.14.1") {
                    recordXcode.sVersion = "10.1";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2.1";
                } else if (recordSDK.sVersion == "10.14.4") {
                    recordXcode.sVersion = "10.2-10.2.1";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0-5.0.1";
                } else if (recordSDK.sVersion == "10.14.6") {
                    recordXcode.sVersion = "10.3";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0.1";
                } else if (recordSDK.sVersion == "10.15.0") {
                    recordXcode.sVersion = "11.0-11.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1";
                } else if (recordSDK.sVersion == "10.15.1") {
                    recordXcode.sVersion = "11.2-11.2.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1.2";
                } else if (recordSDK.sVersion == "10.15.2") {
                    recordXcode.sVersion = "11.3-11.3.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1.3";
                } else if (recordSDK.sVersion == "10.15.4") {
                    recordXcode.sVersion = "11.4-11.5";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2-5.2.4";
                } else if (recordSDK.sVersion == "10.15.6") {
                    recordXcode.sVersion = "11.6-12.1.1";
                    recordCLANG.sVersion = "11.0.3-12.0.0";
                    recordSwift.sVersion = "5.2.4-5.3";
                } else if (recordSDK.sVersion == "11.0.0") {
                    recordXcode.sVersion = "12.2";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.1";
                } else if (recordSDK.sVersion == "11.1.0") {
                    recordXcode.sVersion = "12.3-12.4";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.2";
                } else if (recordSDK.sVersion == "11.3.0") {
                    recordXcode.sVersion = "12.5-13.0";
                    recordCLANG.sVersion = "12.0.5-13.0.0";
                    recordSwift.sVersion = "5.4-5.5";
                } else if (recordSDK.sVersion == "12.0.0") {
                    recordXcode.sVersion = "13.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.1";
                } else if (recordSDK.sVersion == "12.1.0") {
                    recordXcode.sVersion = "13.2-13.2.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.2";
                } else if (recordSDK.sVersion == "12.3.0") {
                    recordXcode.sVersion = "13.3-14.0.1";
                    recordCLANG.sVersion = "13.1.6-14.0.0";
                    recordSwift.sVersion = "5.6-5.7";
                } else if (recordSDK.sVersion == "13.0.0") {
                    recordXcode.sVersion = "14.1";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.1";
                } else if (recordSDK.sVersion == "13.1.0") {
                    recordXcode.sVersion = "14.2";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.2";
                } else if (recordSDK.sVersion == "13.3.0") {
                    recordXcode.sVersion = "14.3-14.3.1";
                    recordCLANG.sVersion = "14.0.3";
                    recordSwift.sVersion = "5.8-5.81";
                } else if (recordSDK.sVersion == "14.0.0") {
                    recordXcode.sVersion = "15.0-15.0.1";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9";
                } else if (recordSDK.sVersion == "14.2.0") {
                    recordXcode.sVersion = "15.1-15.2";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9.2";
                }
            } else if (recordSDK.name == SpecAbstract::RECORD_NAME_IOSSDK) {
                if (recordSDK.sVersion == "1.0.0") {
                    recordXcode.sVersion = "1.0.0-2.0.0";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion.section(".", 0, 0) == "1")  // TODO
                {
                    recordXcode.sVersion = "1.0.0-2.0.0";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion == "2.0.0") {
                    recordXcode.sVersion = "3.0.0-3.2.1";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion.section(".", 0, 0) == "2")  // TODO
                {
                    recordXcode.sVersion = "3.0.0-3.2.1";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion.section(".", 0, 0) == "3")  // TODO
                {
                    recordXcode.sVersion = "3.0.0-3.2.1";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion == "3.1.3") {
                    recordXcode.sVersion = "3.1.3-3.2.1";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                } else if (recordSDK.sVersion == "3.2.0") {
                    recordXcode.sVersion = "3.2.2-3.2.4";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.0.2-1.5";
                } else if (recordSDK.sVersion == "4.0.0") {
                    recordXcode.sVersion = "3.2.3";
                    recordGCC.name = SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.5";
                } else if (recordSDK.sVersion == "4.1.0") {
                    recordXcode.sVersion = "3.2.4";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.5";
                } else if (recordSDK.sVersion == "4.2.0") {
                    recordXcode.sVersion = "3.2.5";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.6";
                } else if (recordSDK.sVersion == "4.3.0") {
                    recordXcode.sVersion = "3.2.6-4.0.1";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "1.7-2.0";
                } else if (recordSDK.sVersion == "4.3.2") {
                    recordXcode.sVersion = "4.0.2-4.1.1";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "2.0-2.1";
                } else if (recordSDK.sVersion == "4.5.0") {
                    recordXcode.sVersion = "4.2-4.3";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "2.0-3.1";
                } else if (recordSDK.sVersion == "5.1.0") {
                    recordXcode.sVersion = "4.3.1-4.4.1";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "3.1-4.0";
                } else if (recordSDK.sVersion == "6.0.0") {
                    recordXcode.sVersion = "4.5-4.5.2";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "4.1";
                } else if (recordSDK.sVersion == "6.1.0") {
                    recordXcode.sVersion = "4.6-4.6.3";
                    recordGCC.sVersion = "4.0-4.2";
                    recordCLANG.sVersion = "4.2";
                } else if (recordSDK.sVersion == "7.0.0") {
                    recordXcode.sVersion = "5.0";
                    recordCLANG.sVersion = "5.0";
                } else if (recordSDK.sVersion == "7.0.3") {
                    recordXcode.sVersion = "5.0.1-5.0.2";
                    recordCLANG.sVersion = "5.0";
                } else if (recordSDK.sVersion == "7.1.0") {
                    recordXcode.sVersion = "5.1-5.1.1";
                    recordCLANG.sVersion = "5.1";
                } else if (recordSDK.sVersion == "8.0.0") {
                    recordXcode.sVersion = "6.0.1";
                    recordCLANG.sVersion = "6.0";
                    recordSwift.sVersion = "1.0";
                } else if (recordSDK.sVersion == "8.1.0") {
                    recordXcode.sVersion = "6.1-6.1.1";
                    recordCLANG.sVersion = "6.0";
                    recordSwift.sVersion = "1.1";
                } else if (recordSDK.sVersion == "8.2.0") {
                    recordXcode.sVersion = "6.2";
                    recordCLANG.sVersion = "6.0";
                    recordSwift.sVersion = "1.1";
                } else if (recordSDK.sVersion == "8.3.0") {
                    recordXcode.sVersion = "6.3-6.3.2";
                    recordCLANG.sVersion = "6.1.0";
                    recordSwift.sVersion = "1.2";
                } else if (recordSDK.sVersion == "8.4.0") {
                    recordXcode.sVersion = "6.4";
                    recordCLANG.sVersion = "6.1.0";
                    recordSwift.sVersion = "1.2";
                } else if (recordSDK.sVersion == "9.0.0") {
                    recordXcode.sVersion = "7.0-7.0.1";
                    recordCLANG.sVersion = "7.0.0";
                    recordSwift.sVersion = "2.0";
                } else if (recordSDK.sVersion == "9.1.0") {
                    recordXcode.sVersion = "7.1-7.1.1";
                    recordCLANG.sVersion = "7.0.0";
                    recordSwift.sVersion = "2.1";
                } else if (recordSDK.sVersion == "9.2.0") {
                    recordXcode.sVersion = "7.2-7.2.1";
                    recordCLANG.sVersion = "7.0.2";
                    recordSwift.sVersion = "2.1.1";
                } else if (recordSDK.sVersion == "9.3.0") {
                    recordXcode.sVersion = "7.3-7.3.1";
                    recordCLANG.sVersion = "7.3.0";
                    recordSwift.sVersion = "2.2";
                } else if (recordSDK.sVersion == "10.0.0") {
                    recordXcode.sVersion = "8.0";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0";
                } else if (recordSDK.sVersion == "10.1.0") {
                    recordXcode.sVersion = "8.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.1";
                } else if (recordSDK.sVersion == "10.2.0") {
                    recordXcode.sVersion = "8.2-8.2.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.2";
                } else if (recordSDK.sVersion == "10.3.0") {
                    recordXcode.sVersion = "8.3-8.3.2";
                    recordCLANG.sVersion = "8.1.0";
                    recordSwift.sVersion = "3.1";
                } else if (recordSDK.sVersion == "10.3.1") {
                    recordXcode.sVersion = "8.3.3";
                    recordCLANG.sVersion = "8.1.0";
                    recordSwift.sVersion = "3.1";
                } else if (recordSDK.sVersion == "11.0.0") {
                    recordXcode.sVersion = "9.0-9.0.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0";
                } else if (recordSDK.sVersion == "11.1.0") {
                    recordXcode.sVersion = "9.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.2";
                } else if (recordSDK.sVersion == "11.2.0") {
                    recordXcode.sVersion = "9.2";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.3";
                } else if (recordSDK.sVersion == "11.3.0") {
                    recordXcode.sVersion = "9.3-9.3.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1";
                } else if (recordSDK.sVersion == "11.4.0") {
                    recordXcode.sVersion = "9.4-9.4.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1.2";
                } else if (recordSDK.sVersion == "12.0.0") {
                    recordXcode.sVersion = "10.0";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2";
                } else if (recordSDK.sVersion == "12.1.0") {
                    recordXcode.sVersion = "10.1";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2.1";
                } else if (recordSDK.sVersion == "12.2.0") {
                    recordXcode.sVersion = "10.2-10.2.1";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0-5.0.1";
                } else if (recordSDK.sVersion == "12.4.0") {
                    recordXcode.sVersion = "10.3";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0.1";
                } else if (recordSDK.sVersion == "13.0.0") {
                    recordXcode.sVersion = "11.0";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1";
                } else if (recordSDK.sVersion == "13.1.0") {
                    recordXcode.sVersion = "11.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1";
                } else if (recordSDK.sVersion == "13.2.0") {
                    recordXcode.sVersion = "11.2-11.3.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1.2-5.1.3";
                } else if (recordSDK.sVersion == "13.4.0") {
                    recordXcode.sVersion = "11.4-11.4.1";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2-5.2.2";
                } else if (recordSDK.sVersion == "13.5.0") {
                    recordXcode.sVersion = "11.5";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2.4";
                } else if (recordSDK.sVersion == "13.6.0") {
                    recordXcode.sVersion = "11.6";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2.4";
                } else if (recordSDK.sVersion == "13.7.0") {
                    recordXcode.sVersion = "11.7";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2.4";
                } else if (recordSDK.sVersion == "14.0.0") {
                    recordXcode.sVersion = "12.0-12.0.1";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3";
                } else if (recordSDK.sVersion == "14.1.0") {
                    recordXcode.sVersion = "12.1";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3";
                } else if (recordSDK.sVersion == "14.2.0") {
                    recordXcode.sVersion = "12.1.1-12.2";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3-5.3.1";
                } else if (recordSDK.sVersion == "14.3.0") {
                    recordXcode.sVersion = "12.3";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.2";
                } else if (recordSDK.sVersion == "14.4.0") {
                    recordXcode.sVersion = "12.4";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.2";
                } else if (recordSDK.sVersion == "14.5.0") {
                    recordXcode.sVersion = "12.5-12.5.1";
                    recordCLANG.sVersion = "12.0.5";
                    recordSwift.sVersion = "5.4-5.4.2";
                } else if (recordSDK.sVersion == "15.0.0") {
                    recordXcode.sVersion = "13.0-13.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5-5.5.1";
                } else if (recordSDK.sVersion == "15.2.0") {
                    recordXcode.sVersion = "13.2-13.2.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.2";
                } else if (recordSDK.sVersion == "15.4.0") {
                    recordXcode.sVersion = "13.3-13.3.1";
                    recordCLANG.sVersion = "13.1.6";
                    recordSwift.sVersion = "5.6";
                } else if (recordSDK.sVersion == "15.5.0") {
                    recordXcode.sVersion = "13.4-13.4.1";
                    recordCLANG.sVersion = "13.1.6";
                    recordSwift.sVersion = "5.6.1";
                } else if (recordSDK.sVersion == "16.0.0") {
                    recordXcode.sVersion = "14.0-14.0.1";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7";
                } else if (recordSDK.sVersion == "16.1.0") {
                    recordXcode.sVersion = "14.1";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.1";
                } else if (recordSDK.sVersion == "16.2.0") {
                    recordXcode.sVersion = "14.2";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.2";
                } else if (recordSDK.sVersion == "16.4.0") {
                    recordXcode.sVersion = "14.3-14.3.1";
                    recordCLANG.sVersion = "14.0.3";
                    recordSwift.sVersion = "5.8-5.81";
                } else if (recordSDK.sVersion == "17.0.0") {
                    recordXcode.sVersion = "15.0-15.0.1";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9";
                } else if (recordSDK.sVersion == "17.2.0") {
                    recordXcode.sVersion = "15.1-15.2";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9.2";
                }
            } else if (recordSDK.name == SpecAbstract::RECORD_NAME_WATCHOSSDK) {
                if (recordSDK.sVersion == "2.0.0") {
                    recordXcode.sVersion = "7.0-7.1.1";
                    recordCLANG.sVersion = "7.0.0";
                    recordSwift.sVersion = "2.0-2.1";
                } else if (recordSDK.sVersion == "2.1.0") {
                    recordXcode.sVersion = "7.2-7.2.1";
                    recordCLANG.sVersion = "7.0.2";
                    recordSwift.sVersion = "2.1.1";
                } else if (recordSDK.sVersion == "2.2.0") {
                    recordXcode.sVersion = "7.3-7.3.1";
                    recordCLANG.sVersion = "7.3.0";
                    recordSwift.sVersion = "2.2";
                } else if (recordSDK.sVersion == "3.0.0") {
                    recordXcode.sVersion = "8.0";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0";
                } else if (recordSDK.sVersion == "3.1.0") {
                    recordXcode.sVersion = "8.1-8.2.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.1-3.0.2";
                } else if (recordSDK.sVersion == "3.2.0") {
                    recordXcode.sVersion = "8.3-8.3.3";
                    recordCLANG.sVersion = "8.1.0";
                    recordSwift.sVersion = "3.1";
                } else if (recordSDK.sVersion == "4.0.0") {
                    recordXcode.sVersion = "9.0-9.0.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0";
                } else if (recordSDK.sVersion == "4.1.0") {
                    recordXcode.sVersion = "9.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.2";
                } else if (recordSDK.sVersion == "4.2.0") {
                    recordXcode.sVersion = "9.2";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.3";
                } else if (recordSDK.sVersion == "4.3.0") {
                    recordXcode.sVersion = "9.3-9.4.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1-4.1.2";
                } else if (recordSDK.sVersion == "5.0.0") {
                    recordXcode.sVersion = "10.0";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2";
                } else if (recordSDK.sVersion == "5.1.0") {
                    recordXcode.sVersion = "10.1";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2.1";
                } else if (recordSDK.sVersion == "5.2.0") {
                    recordXcode.sVersion = "10.2-10.2.1";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0-5.0.1";
                } else if (recordSDK.sVersion == "5.3.0") {
                    recordXcode.sVersion = "10.3";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0.1";
                } else if (recordSDK.sVersion == "6.0.0") {
                    recordXcode.sVersion = "11.0-11.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1";
                } else if (recordSDK.sVersion == "6.1.0") {
                    recordXcode.sVersion = "11.2-11.3.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1.2-5.1.3";
                } else if (recordSDK.sVersion == "6.2.0") {
                    recordXcode.sVersion = "11.4-11.7";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2-5.2.4";
                } else if (recordSDK.sVersion == "7.0.0") {
                    recordXcode.sVersion = "12.0-12.1";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3";
                } else if (recordSDK.sVersion == "7.1.0") {
                    recordXcode.sVersion = "12.1.1-12.2";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3-5.3.1";
                } else if (recordSDK.sVersion == "7.2.0") {
                    recordXcode.sVersion = "12.3-12.4";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.2";
                } else if (recordSDK.sVersion == "7.4.0") {
                    recordXcode.sVersion = "12.5-12.5.1";
                    recordCLANG.sVersion = "12.0.5";
                    recordSwift.sVersion = "5.4-5.4.2";
                } else if (recordSDK.sVersion == "8.0.0") {
                    recordXcode.sVersion = "13.0";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5";
                } else if (recordSDK.sVersion == "8.0.1") {
                    recordXcode.sVersion = "13.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.1";
                } else if (recordSDK.sVersion == "8.3.0") {
                    recordXcode.sVersion = "13.2-13.2.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.2";
                } else if (recordSDK.sVersion == "8.5.0") {
                    recordXcode.sVersion = "13.3-13.4.1";
                    recordCLANG.sVersion = "13.1.6";
                    recordSwift.sVersion = "5.6-5.6.1";
                } else if (recordSDK.sVersion == "9.0.0") {
                    recordXcode.sVersion = "14.0-14.0.1";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7";
                } else if (recordSDK.sVersion == "9.1.0") {
                    recordXcode.sVersion = "14.1-14.2";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.1-5.7.2";
                } else if (recordSDK.sVersion == "9.4.0") {
                    recordXcode.sVersion = "14.3-14.3.1";
                    recordCLANG.sVersion = "14.0.3";
                    recordSwift.sVersion = "5.8-5.81";
                } else if (recordSDK.sVersion == "10.0.0") {
                    recordXcode.sVersion = "15.0-15.0.1";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9";
                } else if (recordSDK.sVersion == "10.2.0") {
                    recordXcode.sVersion = "15.1-15.2";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9.2";
                }
            } else if (recordSDK.name == SpecAbstract::RECORD_NAME_TVOS) {
                if (recordSDK.sVersion == "9.0.0") {
                    recordXcode.sVersion = "7.1-7.1.1";
                    recordCLANG.sVersion = "7.0.0";
                    recordSwift.sVersion = "2.1";
                } else if (recordSDK.sVersion == "9.1.0") {
                    recordXcode.sVersion = "7.2-7.2.1";
                    recordCLANG.sVersion = "7.0.2";
                    recordSwift.sVersion = "2.1.1";
                } else if (recordSDK.sVersion == "9.2.0") {
                    recordXcode.sVersion = "7.3-7.3.1";
                    recordCLANG.sVersion = "7.3.0";
                    recordSwift.sVersion = "2.2";
                } else if (recordSDK.sVersion == "10.0.0") {
                    recordXcode.sVersion = "8.0-8.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0-3.0.1";
                } else if (recordSDK.sVersion == "10.1.0") {
                    recordXcode.sVersion = "8.2-8.2.1";
                    recordCLANG.sVersion = "8.0.0";
                    recordSwift.sVersion = "3.0.2";
                } else if (recordSDK.sVersion == "10.2.0") {
                    recordXcode.sVersion = "8.3-8.3.3";
                    recordCLANG.sVersion = "8.1.0";
                    recordSwift.sVersion = "3.1";
                } else if (recordSDK.sVersion == "11.0.0") {
                    recordXcode.sVersion = "9.0-9.0.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0";
                } else if (recordSDK.sVersion == "11.1.0") {
                    recordXcode.sVersion = "9.1";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.2";
                } else if (recordSDK.sVersion == "11.2.0") {
                    recordXcode.sVersion = "9.2";
                    recordCLANG.sVersion = "9.0.0";
                    recordSwift.sVersion = "4.0.3";
                } else if (recordSDK.sVersion == "11.3.0") {
                    recordXcode.sVersion = "9.3-9.3.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1";
                } else if (recordSDK.sVersion == "11.4.0") {
                    recordXcode.sVersion = "9.4-9.4.1";
                    recordCLANG.sVersion = "9.1.0";
                    recordSwift.sVersion = "4.1.2";
                } else if (recordSDK.sVersion == "12.0.0") {
                    recordXcode.sVersion = "10.0";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2";
                } else if (recordSDK.sVersion == "12.1.0") {
                    recordXcode.sVersion = "10.1";
                    recordCLANG.sVersion = "10.0.0";
                    recordSwift.sVersion = "4.2.1";
                } else if (recordSDK.sVersion == "12.2.0") {
                    recordXcode.sVersion = "10.2-10.2.1";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0-5.0.1";
                } else if (recordSDK.sVersion == "12.4.0") {
                    recordXcode.sVersion = "10.3";
                    recordCLANG.sVersion = "10.0.1";
                    recordSwift.sVersion = "5.0.1";
                } else if (recordSDK.sVersion == "13.0.0") {
                    recordXcode.sVersion = "11.0-11.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1";
                } else if (recordSDK.sVersion == "13.2.0") {
                    recordXcode.sVersion = "11.2-11.3.1";
                    recordCLANG.sVersion = "11.0.0";
                    recordSwift.sVersion = "5.1.2-5.1.3";
                } else if (recordSDK.sVersion == "13.4.0") {
                    recordXcode.sVersion = "11.4-11.7";
                    recordCLANG.sVersion = "11.0.3";
                    recordSwift.sVersion = "5.2-5.2.4";
                } else if (recordSDK.sVersion == "14.0.0") {
                    recordXcode.sVersion = "12.0-12.1";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3";
                } else if (recordSDK.sVersion == "14.2.0") {
                    recordXcode.sVersion = "12.1.1-12.2";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3-5.3.1";
                } else if (recordSDK.sVersion == "14.3.0") {
                    recordXcode.sVersion = "12.3-12.4";
                    recordCLANG.sVersion = "12.0.0";
                    recordSwift.sVersion = "5.3.2";
                } else if (recordSDK.sVersion == "14.5.0") {
                    recordXcode.sVersion = "12.5-12.5.1";
                    recordCLANG.sVersion = "12.0.5";
                    recordSwift.sVersion = "5.4-5.4.2";
                } else if (recordSDK.sVersion == "15.0.0") {
                    recordXcode.sVersion = "13.0-13.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5-5.5.1";
                } else if (recordSDK.sVersion == "15.2.0") {
                    recordXcode.sVersion = "13.2-13.2.1";
                    recordCLANG.sVersion = "13.0.0";
                    recordSwift.sVersion = "5.5.2";
                } else if (recordSDK.sVersion == "15.4.0") {
                    recordXcode.sVersion = "13.3-13.4.1";
                    recordCLANG.sVersion = "13.1.6";
                    recordSwift.sVersion = "5.6-5.6.1";
                } else if (recordSDK.sVersion == "16.0.0") {
                    recordXcode.sVersion = "14.0-14.0.1";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7";
                } else if (recordSDK.sVersion == "16.1.0") {
                    recordXcode.sVersion = "14.1-14.2";
                    recordCLANG.sVersion = "14.0.0";
                    recordSwift.sVersion = "5.7.1-5.7.2";
                } else if (recordSDK.sVersion == "16.4.0") {
                    recordXcode.sVersion = "14.3-14.3.1";
                    recordCLANG.sVersion = "14.0.3";
                    recordSwift.sVersion = "5.8-5.81";
                } else if (recordSDK.sVersion == "17.0.0") {
                    recordXcode.sVersion = "15.0-15.0.1";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9";
                } else if (recordSDK.sVersion == "17.2.0") {
                    recordXcode.sVersion = "15.1-15.2";
                    recordCLANG.sVersion = "15.0.0";
                    recordSwift.sVersion = "5.9.2";
                }
            }
        }

        // Qt
        if (XMACH::isLibraryRecordNamePresent("QtCore", &(pMACHInfo->listLibraryRecords))) {
            XMACH::LIBRARY_RECORD lr = XMACH::getLibraryRecordByName("QtCore", &(pMACHInfo->listLibraryRecords));

            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name = SpecAbstract::RECORD_NAME_QT;
            recordSS.sVersion = XBinary::get_uint32_full_version(lr.current_version);

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
        // Carbon
        if (XMACH::isLibraryRecordNamePresent("Carbon", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Carbon");

            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name = SpecAbstract::RECORD_NAME_CARBON;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
        // Cocoa
        if (XMACH::isLibraryRecordNamePresent("Cocoa", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Cocoa");

            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name = SpecAbstract::RECORD_NAME_COCOA;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }

        if (XMACH::isSectionNamePresent("__cstring", &(pMACHInfo->listSectionRecords))) {
            qint32 nIndex = XMACH::getSectionNumber("__cstring", &(pMACHInfo->listSectionRecords));

            qint64 nDataOffset = XMACH::getSectionFileOffset(nIndex, &(pMACHInfo->listSectionRecords));
            qint64 nDataSize = XMACH::getSectionFileSize(nIndex, &(pMACHInfo->listSectionRecords));

            VI_STRUCT viStruct = get_Zig_vi(pDevice, pOptions, nDataOffset, nDataSize, pPdStruct);

            if (viStruct.bIsValid) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_MACHO, RECORD_TYPE_COMPILER, RECORD_NAME_ZIG, "", "", 0);

                ss.sVersion = viStruct.sVersion;
                ss.sInfo = viStruct.sInfo;

                pMACHInfo->basic_info.mapResultCompilers.insert(ss.name, scansToScan(&(pMACHInfo->basic_info), &ss));
            }
        }

        qint32 nNumberOfBT = listBTV.count();

        for (qint32 i = 0; i < nNumberOfBT; i++) {
            QString _sVersion = XBinary::get_uint32_full_version(listBTV.at(i).version);
            if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_SWIFT) {
                recordSwift.name = SpecAbstract::RECORD_NAME_SWIFT;
                recordSwift.sVersion = _sVersion;
            } else if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_CLANG) {
                recordCLANG.name = SpecAbstract::RECORD_NAME_CLANG;
                recordCLANG.sVersion = _sVersion;
            } else if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_LD) {
                recordLD.name = SpecAbstract::RECORD_NAME_XCODELINKER;
                recordLD.sVersion = _sVersion;
            }
        }

        if (recordLD.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultLinkers.insert(recordLD.name, scansToScan(&(pMACHInfo->basic_info), &recordLD));
        }

        if ((recordGCC.name == SpecAbstract::RECORD_NAME_UNKNOWN) && (recordCLANG.name == SpecAbstract::RECORD_NAME_UNKNOWN)) {
            recordCLANG.name = SpecAbstract::RECORD_NAME_CLANG;  // Default
        }

        if (recordGCC.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordGCC.name, scansToScan(&(pMACHInfo->basic_info), &recordGCC));
        }

        if (recordCLANG.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordCLANG.name, scansToScan(&(pMACHInfo->basic_info), &recordCLANG));
        }

        if (recordSwift.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordSwift.name, scansToScan(&(pMACHInfo->basic_info), &recordSwift));
        }

        if (recordZig.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordZig.name, scansToScan(&(pMACHInfo->basic_info), &recordZig));
        }

        if (recordSDK.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultTools.insert(recordSDK.name, scansToScan(&(pMACHInfo->basic_info), &recordSDK));
        }

        if (recordXcode.name != SpecAbstract::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultTools.insert(recordXcode.name, scansToScan(&(pMACHInfo->basic_info), &recordXcode));
        }
    }
}

void SpecAbstract::MACHO_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        // VMProtect
        if (XMACH::isLibraryRecordNamePresent("libVMProtectSDK.dylib", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"libVMProtectSDK.dylib");

            _SCANS_STRUCT recordSS = {};

            recordSS.type = SpecAbstract::RECORD_TYPE_PROTECTOR;
            recordSS.name = SpecAbstract::RECORD_NAME_VMPROTECT;

            pMACHInfo->basic_info.mapResultProtectors.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
    }
}

void SpecAbstract::MACHO_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        if (pMACHInfo->basic_info.mapResultLanguages.contains(RECORD_NAME_OBJECTIVEC) || pMACHInfo->basic_info.mapResultLanguages.contains(RECORD_NAME_CCPP)) {
            pMACHInfo->basic_info.mapResultLanguages.remove(RECORD_NAME_CCPP);
        }

        if (pMACHInfo->basic_info.scanOptions.bIsTest && pMACHInfo->basic_info.scanOptions.bIsVerbose) {
            //            QMap<quint64,QString> mapCommands=XMACH::getLoadCommandTypesS();

            //            QList<XMACH::COMMAND_RECORD> list=mach.getCommandRecords();

            //            QSet<quint32> stRecords;

            //            for(qint32 i=0;i<list.count();i++)
            //            {
            //                if(!stRecords.contains(list.at(i).nType))
            //                {
            //                    _SCANS_STRUCT recordSS={};

            //                    recordSS.type=RECORD_TYPE_LIBRARY;
            //                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN9+i+1);
            //                    recordSS.sVersion=mapCommands.value(list.at(i).nType);

            //                    pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));

            //                    stRecords.insert(list.at(i).nType);
            //                }
            //            }

            QSet<QString> stRecords;

            qint32 nNumberOfRecords = pMACHInfo->listLibraryRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (!stRecords.contains(pMACHInfo->listLibraryRecords.at(i).sName)) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_LIBRARY;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + i + 1);
                    recordSS.sVersion = pMACHInfo->listLibraryRecords.at(i).sName;
                    recordSS.sInfo = XBinary::get_uint32_full_version(pMACHInfo->listLibraryRecords.at(i).current_version);

                    pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, scansToScan(&(pMACHInfo->basic_info), &recordSS));

                    stRecords.insert(pMACHInfo->listLibraryRecords.at(i).sName);
                }
            }
        }
    }
}

void SpecAbstract::LE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(le.getFileFormatInfo(pPdStruct));

        pLEInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pLEInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::LE_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};
        _SCANS_STRUCT recordCompiler = {};

        if ((pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)) && (!pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
            recordLinker.type = RECORD_TYPE_LINKER;
            recordLinker.name = RECORD_NAME_MICROSOFTLINKER;
        }

        // Rich
        qint32 nRichSignaturesCount = pLEInfo->listRichSignatures.count();

        if (nRichSignaturesCount) {
            recordLinker.name = RECORD_NAME_MICROSOFTLINKER;
            recordLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
        }

        QList<_SCANS_STRUCT> listRichDescriptions;

        for (qint32 i = 0; (i < nRichSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            listRichDescriptions.append(MSDOS_richScan(pLEInfo->listRichSignatures.at(i).nId, pLEInfo->listRichSignatures.at(i).nVersion,
                                                       pLEInfo->listRichSignatures.at(i).nCount, _MS_rich_records, sizeof(_MS_rich_records),
                                                       pLEInfo->basic_info.id.fileType, XBinary::FT_MSDOS, &(pLEInfo->basic_info), DETECTTYPE_RICH, pPdStruct));
        }

        qint32 nRichDescriptionsCount = listRichDescriptions.count();

        for (qint32 i = nRichDescriptionsCount - 1; (i >= 0) && XBinary::isPdStructNotCanceled(pPdStruct); i--) {
            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_LINKER) {
                recordLinker.name = listRichDescriptions.at(i).name;
                recordLinker.sVersion = listRichDescriptions.at(i).sVersion;
                recordLinker.sInfo = listRichDescriptions.at(i).sInfo;
                recordLinker.type = listRichDescriptions.at(i).type;
            }

            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_COMPILER) {
                if (listRichDescriptions.at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) {
                    recordCompiler.name = RECORD_NAME_VISUALCCPP;
                    recordCompiler.sVersion = listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo = listRichDescriptions.at(i).sInfo;
                    recordCompiler.type = listRichDescriptions.at(i).type;
                } else {
                    recordCompiler.name = listRichDescriptions.at(i).name;
                    recordCompiler.sVersion = listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo = listRichDescriptions.at(i).sInfo;
                    recordCompiler.type = listRichDescriptions.at(i).type;
                }
            }
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pLEInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pLEInfo->basic_info), &recordLinker));
        }

        if (recordCompiler.type != RECORD_TYPE_UNKNOWN) {
            pLEInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pLEInfo->basic_info), &recordCompiler));
        }
    }
}

void SpecAbstract::LE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};

        if (pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT ss = pLEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                ss.sVersion = vi.sVersion;
            }

            recordLinker = ss;
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pLEInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pLEInfo->basic_info), &recordLinker));
        }
    }
}

void SpecAbstract::LE_handle_Tools(QIODevice *pDevice, SCAN_OPTIONS *pOptions, LEINFO_STRUCT *pLEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE xle(pDevice, pOptions->bIsImage);

    if (xle.isValid(pPdStruct)) {
        // WATCOM C
        SpecAbstract::VI_STRUCT vi = get_Watcom_vi(pDevice, pOptions, pLEInfo->nEntryPointOffset, 0x100, pPdStruct);

        if (vi.bIsValid) {
            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_LX, RECORD_TYPE_COMPILER, (RECORD_NAME)vi.vValue.toUInt(), vi.sVersion, vi.sInfo, 0);
            pLEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pLEInfo->basic_info), &ssCompiler));

            _SCANS_STRUCT ssLinker = getScansStruct(0, XBinary::FT_LX, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
            pLEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pLEInfo->basic_info), &ssLinker));
        }
    }
}

void SpecAbstract::LX_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE lx(pDevice, pOptions->bIsImage);

    if (lx.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(lx.getFileFormatInfo(pPdStruct));

        pLXInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pLXInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::LX_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE lx(pDevice, pOptions->bIsImage);

    if (lx.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};
        _SCANS_STRUCT recordCompiler = {};

        if ((pLXInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)) && (!pLXInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
            recordLinker.type = RECORD_TYPE_LINKER;
            recordLinker.name = RECORD_NAME_MICROSOFTLINKER;
        }

        // Rich
        qint32 nRichSignaturesCount = pLXInfo->listRichSignatures.count();

        if (nRichSignaturesCount) {
            recordLinker.name = RECORD_NAME_MICROSOFTLINKER;
            recordLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
        }

        QList<_SCANS_STRUCT> listRichDescriptions;

        for (qint32 i = 0; (i < nRichSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            listRichDescriptions.append(MSDOS_richScan(pLXInfo->listRichSignatures.at(i).nId, pLXInfo->listRichSignatures.at(i).nVersion,
                                                       pLXInfo->listRichSignatures.at(i).nCount, _MS_rich_records, sizeof(_MS_rich_records),
                                                       pLXInfo->basic_info.id.fileType, XBinary::FT_MSDOS, &(pLXInfo->basic_info), DETECTTYPE_RICH, pPdStruct));
        }

        qint32 nRichDescriptionsCount = listRichDescriptions.count();

        for (qint32 i = nRichDescriptionsCount - 1; (i >= 0) && (XBinary::isPdStructNotCanceled(pPdStruct)); i--) {
            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_LINKER) {
                recordLinker.name = listRichDescriptions.at(i).name;
                recordLinker.sVersion = listRichDescriptions.at(i).sVersion;
                recordLinker.sInfo = listRichDescriptions.at(i).sInfo;
                recordLinker.type = listRichDescriptions.at(i).type;
            }

            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_COMPILER) {
                if (listRichDescriptions.at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) {
                    recordCompiler.name = RECORD_NAME_VISUALCCPP;
                    recordCompiler.sVersion = listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo = listRichDescriptions.at(i).sInfo;
                    recordCompiler.type = listRichDescriptions.at(i).type;
                } else {
                    recordCompiler.name = listRichDescriptions.at(i).name;
                    recordCompiler.sVersion = listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo = listRichDescriptions.at(i).sInfo;
                    recordCompiler.type = listRichDescriptions.at(i).type;
                }
            }
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pLXInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pLXInfo->basic_info), &recordLinker));
        }

        if (recordCompiler.type != RECORD_TYPE_UNKNOWN) {
            pLXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pLXInfo->basic_info), &recordCompiler));
        }
    }
}

void SpecAbstract::LX_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE le(pDevice, pOptions->bIsImage);

    if (le.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};

        if (pLXInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT ss = pLXInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                ss.sVersion = vi.sVersion;
            }

            recordLinker = ss;
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pLXInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pLXInfo->basic_info), &recordLinker));
        }
    }
}

void SpecAbstract::LX_handle_Tools(QIODevice *pDevice, SCAN_OPTIONS *pOptions, LXINFO_STRUCT *pLXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XLE xle(pDevice, pOptions->bIsImage);

    if (xle.isValid(pPdStruct)) {
        // WATCOM C
        SpecAbstract::VI_STRUCT vi = get_Watcom_vi(pDevice, pOptions, pLXInfo->nEntryPointOffset, 0x100, pPdStruct);

        if (vi.bIsValid) {
            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_LX, RECORD_TYPE_COMPILER, (RECORD_NAME)vi.vValue.toUInt(), vi.sVersion, vi.sInfo, 0);
            pLXInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pLXInfo->basic_info), &ssCompiler));

            _SCANS_STRUCT ssLinker = getScansStruct(0, XBinary::FT_LX, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
            pLXInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pLXInfo->basic_info), &ssLinker));
        }
    }
}

void SpecAbstract::NE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XNE ne(pDevice, pOptions->bIsImage);

    if (ne.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(ne.getFileFormatInfo(pPdStruct));

        pNEInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pNEInfo->basic_info), &ssOperationSystem));
    }
}

void SpecAbstract::NE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XNE ne(pDevice, pOptions->bIsImage);

    if (ne.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};

        if (pNEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT ss = pNEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                ss.sVersion = vi.sVersion;
            }

            recordLinker = ss;
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pNEInfo->basic_info.mapResultLinkers.insert(recordLinker.name, scansToScan(&(pNEInfo->basic_info), &recordLinker));
        }
    }
}

void SpecAbstract::NE_handle_Tools(QIODevice *pDevice, SCAN_OPTIONS *pOptions, NEINFO_STRUCT *pNEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XNE xne(pDevice, pOptions->bIsImage);

    if (xne.isValid(pPdStruct)) {
        // WATCOM C
        SpecAbstract::VI_STRUCT vi = get_Watcom_vi(pDevice, pOptions, pNEInfo->nEntryPointOffset, 0x100, pPdStruct);

        if (vi.bIsValid) {
            _SCANS_STRUCT ssCompiler = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_COMPILER, (RECORD_NAME)vi.vValue.toUInt(), vi.sVersion, vi.sInfo, 0);
            pNEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, scansToScan(&(pNEInfo->basic_info), &ssCompiler));

            _SCANS_STRUCT ssLinker = getScansStruct(0, XBinary::FT_MSDOS, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
            pNEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, scansToScan(&(pNEInfo->basic_info), &ssLinker));
        }
    }
}

void SpecAbstract::DEX_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);

    if (dex.isValid(pPdStruct)) {
        _SCANS_STRUCT recordAndroidSDK = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);

        QString sDDEXVersion = dex.getVersion();

        // https://source.android.com/devices/tech/dalvik/dex-format
        if (sDDEXVersion == "035") {
            recordAndroidSDK.sVersion = "API 14";
        }
        //        else if (sDDEXVersion=="036")
        //        {
        //            // Due to a Dalvik bug present in older versions of Android, Dex version 036 has been skipped.
        //            // Dex version 036 is not valid for any version of Android and never will be.
        //        }
        else if (sDDEXVersion == "037") {
            recordAndroidSDK.sVersion = "API 24";
        } else if (sDDEXVersion == "038") {
            recordAndroidSDK.sVersion = "API 26";
        } else if (sDDEXVersion == "039") {
            recordAndroidSDK.sVersion = "API 28";
        } else {
            recordAndroidSDK.sVersion = sDDEXVersion;
        }

        pDEXInfo->basic_info.mapResultTools.insert(recordAndroidSDK.name, scansToScan(&(pDEXInfo->basic_info), &recordAndroidSDK));

        _SCANS_STRUCT ssOperationSystem = getOperationSystemScansStruct(dex.getFileFormatInfo(pPdStruct));

        pDEXInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, scansToScan(&(pDEXInfo->basic_info), &ssOperationSystem));

        //        qint32 nNumberOfMapItems=listMaps.count();

        // dx
        // https://github.com/aosp-mirror/platform_dalvik/blob/master/dx/src/com/android/dx/dex/file/DexFile.java#L122
        //        QList<quint16> listDx;
        //        listDx.append(XDEX_DEF::TYPE_HEADER_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);  // Optional API 26+
        //        listDx.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM); // Optional API 26+
        //        listDx.append(XDEX_DEF::TYPE_CODE_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_TYPE_LIST);
        //        listDx.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        //        listDx.append(XDEX_DEF::TYPE_MAP_LIST);
        QList<quint16> listDx;
        listDx.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDx.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDx.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);   // Optional API 26+
        listDx.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM);  // Optional API 26+
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDx.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDx.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDx.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDx.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDx.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDx.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDx.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDx.append(XDEX_DEF::TYPE_MAP_LIST);

        // DexLib
        // https://android.googlesource.com/platform/external/smali/+/9a12fbef9912a824a4824e392f0d2fdd5319f580/dexlib/src/main/java/org/jf/dexlib/DexFile.java?autodive=0%2F#210
        QList<quint16> listDexLib;
        listDexLib.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexLib.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_MAP_LIST);

        // dexlib2
        // https://github.com/JesusFreke/smali/blob/master/dexlib2/src/main/java/org/jf/dexlib2/writer/DexWriter.java#L1465
        QList<quint16> listDexLib2;
        listDexLib2.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexLib2.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_HIDDENAPI_CLASS_DATA_ITEM);  // Optional
        listDexLib2.append(XDEX_DEF::TYPE_MAP_LIST);

        QList<quint16> listDexLib2heur;
        listDexLib2heur.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);

        // r8
        // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/FileWriter.java#752
        QList<quint16> listR8;
        listR8.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listR8.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listR8.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);   // Optional
        listR8.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM);  // Optional
        listR8.append(XDEX_DEF::TYPE_CODE_ITEM);
        listR8.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listR8.append(XDEX_DEF::TYPE_TYPE_LIST);
        listR8.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listR8.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listR8.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);  // Check
        listR8.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listR8.append(XDEX_DEF::TYPE_MAP_LIST);

        // DexMerge
        // https://github.com/aosp-mirror/platform_dalvik/blob/master/dx/src/com/android/dx/merge/DexMerger.java#L95
        QList<quint16> listDexMerge;
        listDexMerge.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_MAP_LIST);
        listDexMerge.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);  // Check
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);

        // fast-proxy
        // https://github.com/int02h/fast-proxy/blob/master/fastproxy/src/main/java/com/dpforge/fastproxy/dex/writer/DexWriter.java#L57
        // TODO more researches
        QList<quint16> listFastProxy;
        listFastProxy.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_TYPE_LIST);
        listFastProxy.append(XDEX_DEF::TYPE_CODE_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_MAP_LIST);

        // TODO Check https://github.com/facebookexperimental/r8
        // TODO https://github.com/davidbrazdil/dexter-backup/blob/e09c9397aa727f6180799254fb08e15955c1a89e/src/org/jf/dexlib/DexFromMemory.java
        // TODO https://github.com/rchiossi/dexterity/blob/ce66ca62a6df4c6d913bdde1d7d91f5fa90ff916/dx/dxlib.py#L505
        // TODO https://github.com/rchiossi/dexterity/blob/ce66ca62a6df4c6d913bdde1d7d91f5fa90ff916/lib/dex_builder.c#L404
        // TODO redex https://github.com/lzoghbi/thesis
        // TODO https://github.com/zyq8709/DexHunter/tree/master/dalvik/dx

        // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java
        // Example: X~~D8{"compilation-mode":"release","has-checksums":false,"min-api":14,"version":"2.0.88"}

        VI_STRUCT viR8 = get_R8_marker_vi(pDevice, pOptions, 0, pDEXInfo->basic_info.id.nSize, pPdStruct);
        bool bR8_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listR8);
        bool bDX_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDx);
        //        bool bDexLib_map=XDEX::compareMapItems(&listMaps,&listDexLib);
        bool bDexLib2_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexLib2);
        bool bDexLib2heur_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexLib2heur);
        bool bDexMerge_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexMerge);
        bool bFastProxy_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listFastProxy);

        if (viR8.bIsValid) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_R8, "", "", 0);
            recordCompiler.sVersion = viR8.sVersion;
            recordCompiler.sInfo = viR8.sInfo;
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (!(pDEXInfo->bIsStringPoolSorted)) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_DEXLIB, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (bDX_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_DX, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (bDexLib2_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_DEXLIB2, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (bR8_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_R8, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (bDexLib2heur_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_DEXLIB2, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        } else if (bFastProxy_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_FASTPROXY, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        }

        if (bDexMerge_map) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_DEXMERGE, "", "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        }

        if (viR8.bIsValid && (!bR8_map)) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_R8, "", "", 0);
            recordCompiler.sVersion = viR8.sVersion;
            recordCompiler.sInfo = append(recordCompiler.sInfo, "CHECK !!!");
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        }

        if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
            qint32 nJackIndex = dex.getStringNumberFromListExp(&(pDEXInfo->listStrings), "^emitter: jack");

            if (nJackIndex != -1) {
                _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_JACK, "", "", 0);
                recordCompiler.sVersion = pDEXInfo->listStrings.at(nJackIndex).section("-", 1, -1);
                pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
            }
        }

        if (pDEXInfo->basic_info.mapResultCompilers.size() == 0) {
            _SCANS_STRUCT recordCompiler = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_COMPILER, RECORD_NAME_UNKNOWN,
                                                          QString("%1").arg(dex.getMapItemsHash(&(pDEXInfo->mapItems), pPdStruct)), "", 0);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_APKTOOLPLUS)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_APKTOOLPLUS);
            pDEXInfo->basic_info.mapResultTools.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_UNICOMSDK)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_UNICOMSDK);
            pDEXInfo->basic_info.mapResultLibraries.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
            bool bInvalidHeaderSize = (pDEXInfo->header.header_size != 0x70);
            bool bLink = (pDEXInfo->header.link_off || pDEXInfo->header.link_size);

            QString sOverlay;

            if (pDEXInfo->basic_info.scanOptions.bIsVerbose) {
                bool bIsFieldNamesUnicode = dex.isFieldNamesUnicode(&(pDEXInfo->listFieldIDs), &(pDEXInfo->listStrings), pPdStruct);
                bool bIsMethodNamesUnicode = dex.isMethodNamesUnicode(&(pDEXInfo->listMethodIDs), &(pDEXInfo->listStrings), pPdStruct);

                sOverlay = QString("Maps %1").arg(dex.getMapItemsHash(&(pDEXInfo->mapItems), pPdStruct));

                if (pDEXInfo->bIsOverlayPresent) {
                    sOverlay = append(sOverlay, "Overlay");
                }

                if (bInvalidHeaderSize) {
                    sOverlay = append(sOverlay, "Invalid header size");
                }

                if (bLink) {
                    sOverlay = append(sOverlay, QString("Invalid Link(%1,%2)").arg(pDEXInfo->header.link_size).arg(pDEXInfo->header.link_off));
                }

                if (bIsFieldNamesUnicode) {
                    sOverlay = append(sOverlay, "bIsFieldNamesUnicode");
                }

                if (bIsMethodNamesUnicode) {
                    sOverlay = append(sOverlay, "bIsMethodNamesUnicode");
                }

                if (viR8.bIsValid) {
                    if (bDX_map) {
                        sOverlay = append(sOverlay, "DX");
                    }

                    if (bDexLib2_map) {
                        sOverlay = append(sOverlay, "DexLib2");
                    }

                    if (!(pDEXInfo->bIsStringPoolSorted)) {
                        sOverlay = append(sOverlay, "DexLib");
                    }

                    if (bDexMerge_map) {
                        sOverlay = append(sOverlay, "DexMerge");
                    }
                }
            }

            qint32 nNumberOfRecords = pDEXInfo->listStrings.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (pDEXInfo->basic_info.scanOptions.bIsTest && pDEXInfo->basic_info.scanOptions.bIsVerbose) {
                    // TODO find!
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_UNKNOWN, "", "", 0);

                    if (pDEXInfo->listStrings.at(i).contains("agconfig") || pDEXInfo->listStrings.at(i).contains("AntiSkid") ||
                        pDEXInfo->listStrings.at(i).contains("ALLATORI") || pDEXInfo->listStrings.at(i).contains("AppSuit") ||
                        pDEXInfo->listStrings.at(i).contains("appsuit") || pDEXInfo->listStrings.at(i).contains("gemalto") ||
                        pDEXInfo->listStrings.at(i).contains("WapperApplication") || pDEXInfo->listStrings.at(i).contains("AppSealing") ||
                        pDEXInfo->listStrings.at(i).contains("whitecryption") || pDEXInfo->listStrings.at(i).contains("ModGuard") ||
                        pDEXInfo->listStrings.at(i).contains("InjectedActivity")) {
                        ss.sVersion = pDEXInfo->listStrings.at(i);
                        pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
                        ss.sInfo = append(ss.sInfo, sOverlay);

                        break;
                    }
                }
            }
        }
        // Check Ljava/lang/ClassLoader;
    }
}

void SpecAbstract::DEX_handle_Dexguard(QIODevice *pDevice, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);

    if (dex.isValid(pPdStruct)) {
        if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
            if (XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "dexguard\\/", pPdStruct)) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);
                pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
            }

            // if (!pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_DEXGUARD)) {
            //     qint32 nNumberOfTypes = pDEXInfo->listTypeItemStrings.count();

            //     for (qint32 i = 0; (i < nNumberOfTypes) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            //         QString sType = pDEXInfo->listTypeItemStrings.at(i);

            //         // TODO Check!
            //         if (sType.size() <= 7) {
            //             if (XBinary::isRegExpPresent("^Lo/", sType)) {
            //                 _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);
            //                 pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));

            //                 break;
            //             }
            //         }
            //     }
            // }
        }
    }
}

void SpecAbstract::DEX_handle_Protection(QIODevice *pDevice, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);

    if (dex.isValid(pPdStruct)) {
        // DexProtect
        // 070002000000020083dc63003e000000120113000e0048000500e0000010011239022a001232d563ff0048030503d533ff00e1040608d544ff0048040504d544ff00e0040408b643e1040610d544ff0048040504d544ff00e0040410b643e1040618d544ff0048000504e0000018b6300f000d023901feff1221dd02067f48000502e100000828f50d0328cb0d000000
        if (pDEXInfo->bIsOverlayPresent) {
            if (dex.getOverlaySize(&(pDEXInfo->basic_info.memoryMap), pPdStruct) == 0x60) {
                _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXPROTECTOR, "", "", 0);
                pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
            }
        } else {
            if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
                if (XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "\\/dexprotector\\/", pPdStruct)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXPROTECTOR, "", "", 0);
                    pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
                }
            }
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_EASYPROTECTOR)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_EASYPROTECTOR);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_QDBH)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_QDBH);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_JIAGU)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_JIAGU);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_BANGCLEPROTECTION)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_BANGCLEPROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_ALLATORIOBFUSCATOR)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_ALLATORIOBFUSCATOR);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_PANGXIE)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_PANGXIE);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_NAGAPTPROTECTION)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_NAGAPTPROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_MODGUARD)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_MODGUARD);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_KIWIVERSIONOBFUSCATOR)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_KIWIVERSIONOBFUSCATOR);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_APKPROTECT)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_APKPROTECT);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        } else {
            if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
                if (XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings), "http://www.apkprotect.net/", pPdStruct)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_APKPROTECT, "", "", 0);
                    pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
                }
            }
        }

        if (pDEXInfo->basic_info.scanOptions.bIsHeuristicScan) {
            if (pDEXInfo->basic_info.mapStringDetects.contains(RECORD_NAME_AESOBFUSCATOR)) {
                _SCANS_STRUCT ss = pDEXInfo->basic_info.mapStringDetects.value(RECORD_NAME_AESOBFUSCATOR);
                pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
            } else {
                if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
                    if (XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings), "licensing/AESObfuscator;", pPdStruct)) {
                        _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_AESOBFUSCATOR, "", "", 0);
                        pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
                    }
                }
            }
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_BTWORKSCODEGUARD)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_BTWORKSCODEGUARD);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_QIHOO360PROTECTION))  // Check overlay
        {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_QIHOO360PROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_ALIBABAPROTECTION))  // Check overlay
        {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_ALIBABAPROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_BAIDUPROTECTION))  // Check overlay
        {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_BAIDUPROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_TENCENTPROTECTION))  // Check overlay
        {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_TENCENTPROTECTION);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_SECNEO)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_SECNEO);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_LIAPP)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_LIAPP);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_VDOG)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_VDOG);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_APPSOLID)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_APPSOLID);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_MEDUSAH)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_MEDUSAH);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_NQSHIELD)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_NQSHIELD);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_YIDUN)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_YIDUN);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_APKENCRYPTOR)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_APKENCRYPTOR);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        }

        if (pDEXInfo->basic_info.mapTypeDetects.contains(RECORD_NAME_PROGUARD)) {
            _SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(RECORD_NAME_PROGUARD);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
        } else {
            if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
                if (XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "\\/proguard\\/", pPdStruct)) {
                    _SCANS_STRUCT ss = getScansStruct(0, XBinary::FT_DEX, RECORD_TYPE_PROTECTOR, RECORD_NAME_PROGUARD, "", "", 0);
                    pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, scansToScan(&(pDEXInfo->basic_info), &ss));
                }
            }
        }
    }
}

// void SpecAbstract::fixDetects(SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//     if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
//     {
//         pPEInfo->basic_info.mapHeaderDetects.remove(RECORD_NAME_MICROSOFTLINKER);
//     }

//    if(pPEInfo->_mapImportDetects.contains(RECORD_NAME_C)&&pPEInfo->_mapImportDetects.contains(RECORD_NAME_VISUALCPP))
//    {
//        pPEInfo->_mapImportDetects.remove(RECORD_NAME_VISUALCPP);
//    }

//    if(pPEInfo->basic_info.mapSpecialDetects.contains(RECORD_NAME_ENIGMA))
//    {
//        pPEInfo->basic_info.mapEntryPointDetects.remove(RECORD_NAME_BORLANDCPP);
//    }
//}

void SpecAbstract::updateVersion(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, const QString &sVersion)
{
    if (pMap->contains(name)) {
        SpecAbstract::SCAN_STRUCT record = pMap->value(name);
        record.sVersion = sVersion;
        pMap->insert(name, record);
    }
}

void SpecAbstract::updateInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, const QString &sInfo)
{
    if (pMap->contains(name)) {
        SpecAbstract::SCAN_STRUCT record = pMap->value(name);
        record.sInfo = sInfo;
        pMap->insert(name, record);
    }
}

void SpecAbstract::updateVersionAndInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, const QString &sVersion,
                                        const QString &sInfo)
{
    if (pMap->contains(name)) {
        SpecAbstract::SCAN_STRUCT record = pMap->value(name);
        record.sVersion = sVersion;
        record.sInfo = sInfo;
        pMap->insert(name, record);
    }
}

bool SpecAbstract::isScanStructPresent(QList<XScanEngine::SCANSTRUCT> *pListScanStructs, XBinary::FT fileType, SpecAbstract::RECORD_TYPE type,
                                       SpecAbstract::RECORD_NAME name, const QString &sVersion, const QString &sInfo)
{
    bool bResult = false;

    qint32 nNumberOfRecords = pListScanStructs->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        if (((pListScanStructs->at(i).id.fileType == fileType) || (fileType == XBinary::FT_UNKNOWN)) &&
            ((pListScanStructs->at(i).nType == type) || (type == SpecAbstract::RECORD_TYPE_UNKNOWN)) &&
            ((pListScanStructs->at(i).nName == name) || (name == SpecAbstract::RECORD_NAME_UNKNOWN)) &&
            ((pListScanStructs->at(i).sVersion == sVersion) || (sVersion == "")) && ((pListScanStructs->at(i).sInfo == sInfo) || (sInfo == ""))) {
            bResult = true;
            break;
        }
    }

    return bResult;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType,
                                                 XBinary::PDSTRUCT *pPdStruct)
{
    // TODO unknown version
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO make both
    qint64 nStringOffset1 = binary.find_ansiString(nOffset, nSize, "$Id: UPX", pPdStruct);
    qint64 nStringOffset2 = binary.find_ansiString(nOffset, nSize, "UPX!", pPdStruct);

    if (nStringOffset1 != -1) {
        result.bIsValid = true;

        result.sVersion = binary.read_ansiString(nStringOffset1 + 9, 10);
        result.sVersion = result.sVersion.section(" ", 0, 0);

        if (!XBinary::checkVersionString(result.sVersion)) {
            result.sVersion = "";
        }

        // NRV
        qint64 nNRVStringOffset1 = binary.find_array(nOffset, nSize, "\x24\x49\x64\x3a\x20\x4e\x52\x56\x20", 9, pPdStruct);

        if (nNRVStringOffset1 != -1) {
            QString sNRVVersion = binary.read_ansiString(nNRVStringOffset1 + 9, 10);
            sNRVVersion = sNRVVersion.section(" ", 0, 0);

            if (XBinary::checkVersionString(sNRVVersion)) {
                result.sInfo = QString("NRV %1").arg(sNRVVersion);
            }
        }
    }

    if (nStringOffset2 != -1) {
        VI_STRUCT viUPX = _get_UPX_vi(pDevice, pOptions, nStringOffset2, 0x24, fileType);

        if (viUPX.bIsValid) {
            result.sInfo = append(result.sInfo, viUPX.sInfo);

            if (result.sVersion == "") {
                result.sVersion = viUPX.sVersion;
            }
        }

        result.bIsValid = true;  // TODO Check
        // TODO 1 function

        if (result.sVersion == "") {
            result.sVersion = binary.read_ansiString(nStringOffset2 - 5, 4);
        }
    }

    if (!XBinary::checkVersionString(result.sVersion)) {
        result.sVersion = "";
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_UPX_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::FT fileType)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.isOffsetAndSizeValid(nOffset, nSize)) {
        if (nSize >= 22) {
            result.bIsValid = true;

            quint8 nVersion = binary.read_uint8(nOffset + 4);
            quint8 nFormat = binary.read_uint8(nOffset + 5);
            quint8 nMethod = binary.read_uint8(nOffset + 6);
            quint8 nLevel = binary.read_uint8(nOffset + 7);

            quint32 nULen = 0;
            quint32 nCLen = 0;
            quint32 nUAdler = 0;
            quint32 nCAdler = 0;
            quint32 nFileSize = 0;
            quint8 nFilter = 0;
            quint8 nFilterCTO = 0;
            quint8 nMRU = 0;
            quint8 nHeaderChecksum = 0;

            if (nFormat < 128) {
                if ((nFormat == 1) || (nFormat == 2))  // UPX_F_DOS_COM, UPX_F_DOS_SYS
                {
                    if (nSize >= 22) {
                        nULen = binary.read_uint16(nOffset + 16);
                        nCLen = binary.read_uint16(nOffset + 18);
                        nFilter = binary.read_uint8(nOffset + 20);
                        nHeaderChecksum = binary.read_uint8(nOffset + 21);
                    } else {
                        result.bIsValid = false;
                    }
                } else if (nFormat == 3)  // UPX_F_DOS_EXE
                {
                    if (nSize >= 27) {
                        nULen = binary.read_uint24(nOffset + 16);
                        nCLen = binary.read_uint24(nOffset + 19);
                        nFileSize = binary.read_uint24(nOffset + 22);
                        nFilter = binary.read_uint8(nOffset + 25);
                        nHeaderChecksum = binary.read_uint8(nOffset + 26);
                    } else {
                        result.bIsValid = false;
                    }
                } else {
                    if (nSize >= 32) {
                        nULen = binary.read_uint32(nOffset + 16);
                        nCLen = binary.read_uint32(nOffset + 20);
                        nFileSize = binary.read_uint32(nOffset + 24);
                        nFilter = binary.read_uint8(nOffset + 28);
                        nFilterCTO = binary.read_uint8(nOffset + 29);
                        nMRU = binary.read_uint8(nOffset + 30);
                        nHeaderChecksum = binary.read_uint8(nOffset + 31);
                    } else {
                        result.bIsValid = false;
                    }
                }

                if (result.bIsValid) {
                    nUAdler = binary.read_uint32(nOffset + 8);
                    nCAdler = binary.read_uint32(nOffset + 12);
                }
            } else {
                if (nSize >= 32) {
                    nULen = binary.read_uint32(nOffset + 8, true);
                    nCLen = binary.read_uint32(nOffset + 12, true);
                    nUAdler = binary.read_uint32(nOffset + 16, true);
                    nCAdler = binary.read_uint32(nOffset + 20, true);
                    nFileSize = binary.read_uint32(nOffset + 24, true);
                    nFilter = binary.read_uint8(nOffset + 28);
                    nFilterCTO = binary.read_uint8(nOffset + 29);
                    nMRU = binary.read_uint8(nOffset + 30);
                    nHeaderChecksum = binary.read_uint8(nOffset + 31);
                } else {
                    result.bIsValid = false;
                }
            }

            Q_UNUSED(nUAdler)
            Q_UNUSED(nCAdler)
            Q_UNUSED(nFileSize)
            Q_UNUSED(nFilter)
            Q_UNUSED(nFilterCTO)
            Q_UNUSED(nMRU)
            Q_UNUSED(nHeaderChecksum)

            if (result.bIsValid) {
                // Check Executable formats
                if (nFormat == 0) result.bIsValid = false;
                if ((nFormat > 42) && (nFormat < 129)) result.bIsValid = false;
                if (nFormat > 142) result.bIsValid = false;
                if (nFormat == 7) result.bIsValid = false;    // UPX_F_DOS_EXEH        OBSOLETE
                if (nFormat == 6) result.bIsValid = false;    // UPX_F_VXD_LE NOT      IMPLEMENTED
                if (nFormat == 11) result.bIsValid = false;   // UPX_F_WIN16_NE NOT    IMPLEMENTED
                if (nFormat == 13) result.bIsValid = false;   // UPX_F_LINUX_SEP_i386  NOT IMPLEMENTED
                if (nFormat == 17) result.bIsValid = false;   // UPX_F_ELKS_8086 NOT   IMPLEMENTED
                if (nFormat == 130) result.bIsValid = false;  // UPX_F_SOLARIS_SPARC   NOT IMPLEMENTED

                if (fileType == XBinary::FT_COM) {
                    if ((nFormat != 1) &&  // UPX_F_DOS_COM
                        (nFormat != 2))    // UPX_F_DOS_SYS
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_MSDOS) {
                    if ((nFormat != 3))  // UPX_F_DOS_EXE
                    {
                        result.bIsValid = false;
                    }
                } else if ((fileType == XBinary::FT_LE) || (fileType == XBinary::FT_LX)) {
                    if ((nFormat != 5))  // UPX_F_WATCOM_LE
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_PE) {
                    if ((nFormat != 9) &&   // UPX_F_WIN32_PE
                        (nFormat != 21) &&  // UPX_F_WINCE_ARM_PE
                        (nFormat != 36))    // UPX_F_WIN64_PEP
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_MACHO) {
                    if ((nFormat != 29) &&   // UPX_F_MACH_i386
                        (nFormat != 32) &&   // UPX_F_MACH_ARMEL
                        (nFormat != 33) &&   // UPX_F_DYLIB_i386
                        (nFormat != 34) &&   // UPX_F_MACH_AMD64
                        (nFormat != 35) &&   // UPX_F_DYLIB_AMD64
                        (nFormat != 37) &&   // UPX_F_MACH_ARM64EL
                        (nFormat != 38) &&   // UPX_F_MACH_PPC64LE
                        (nFormat != 41) &&   // UPX_F_DYLIB_PPC64LE
                        (nFormat != 131) &&  // UPX_F_MACH_PPC32
                        (nFormat != 134) &&  // UPX_F_MACH_FAT
                        (nFormat != 138) &&  // UPX_F_DYLIB_PPC32
                        (nFormat != 139) &&  // UPX_F_MACH_PPC64
                        (nFormat != 142))    // UPX_F_DYLIB_PPC64
                    {
                        result.bIsValid = false;
                    }
                } else if (fileType == XBinary::FT_ELF) {
                    if ((nFormat != 10) &&   // UPX_F_LINUX_i386
                        (nFormat != 12) &&   // UPX_F_LINUX_ELF_i386
                        (nFormat != 14) &&   // UPX_F_LINUX_SH_i386
                        (nFormat != 15) &&   // UPX_F_VMLINUZ_i386
                        (nFormat != 16) &&   // UPX_F_BVMLINUZ_i386
                        (nFormat != 19) &&   // UPX_F_VMLINUX_i386
                        (nFormat != 20) &&   // UPX_F_LINUX_ELFI_i386
                        (nFormat != 22) &&   // UPX_F_LINUX_ELF64_AMD
                        (nFormat != 23) &&   // UPX_F_LINUX_ELF32_ARMEL
                        (nFormat != 24) &&   // UPX_F_BSD_i386
                        (nFormat != 25) &&   // UPX_F_BSD_ELF_i386
                        (nFormat != 26) &&   // UPX_F_BSD_SH_i386
                        (nFormat != 27) &&   // UPX_F_VMLINUX_AMD64
                        (nFormat != 28) &&   // UPX_F_VMLINUX_ARMEL
                        (nFormat != 30) &&   // UPX_F_LINUX_ELF32_MIPSEL
                        (nFormat != 31) &&   // UPX_F_VMLINUZ_ARMEL
                        (nFormat != 39) &&   // UPX_F_LINUX_ELFPPC64LE
                        (nFormat != 40) &&   // UPX_F_VMLINUX_PPC64LE
                        (nFormat != 42) &&   // UPX_F_LINUX_ELF64_ARM
                        (nFormat != 132) &&  // UPX_F_LINUX_ELFPPC32
                        (nFormat != 133) &&  // UPX_F_LINUX_ELF32_ARMEB
                        (nFormat != 135) &&  // UPX_F_VMLINUX_ARMEB
                        (nFormat != 136) &&  // UPX_F_VMLINUX_PPC32
                        (nFormat != 137) &&  // UPX_F_LINUX_ELF32_MIPSEB
                        (nFormat != 140) &&  // UPX_F_LINUX_ELFPPC64
                        (nFormat != 141))    // UPX_F_VMLINUX_PPC64
                    {
                        result.bIsValid = false;
                    }
                }

                // Check Version
                if (nVersion > 14) {
                    result.bIsValid = false;
                }

                // Check Methods
                if ((nMethod < 2) || (nMethod > 15)) {
                    result.bIsValid = false;
                }

                // Check Level
                // https://github.com/upx/upx/blob/d7ba31cab8ce8d95d2c10e88d2ec787ac52005ef/src/compress_lzma.cpp#L137
                if (nLevel > 10) {
                    result.bIsValid = false;
                }

                // Check size
                if (nCLen > nULen) {
                    result.bIsValid = false;
                }
            }

            if (result.bIsValid) {
                // TODO
                //                switch(nVersion)
                //                {
                //                    case 11:    result.sVersion="1.10-";                break;
                //                    case 12:    result.sVersion="1.10-";                break;
                //                    case 13:    result.sVersion="1.90+";                break;
                //                }

                switch (nMethod)  // From https://github.com/upx/upx/blob/master/src/conf.h
                {
                    // #define M_CL1B_LE32     11
                    // #define M_CL1B_8        12
                    // #define M_CL1B_LE16     13
                    case 2: result.sInfo = append(result.sInfo, "NRV2B_LE32"); break;
                    case 3: result.sInfo = append(result.sInfo, "NRV2B_8"); break;
                    case 4: result.sInfo = append(result.sInfo, "NRV2B_LE16"); break;
                    case 5: result.sInfo = append(result.sInfo, "NRV2D_LE32"); break;
                    case 6: result.sInfo = append(result.sInfo, "NRV2D_8"); break;
                    case 7: result.sInfo = append(result.sInfo, "NRV2D_LE16"); break;
                    case 8: result.sInfo = append(result.sInfo, "NRV2E_LE32"); break;
                    case 9: result.sInfo = append(result.sInfo, "NRV2E_8"); break;
                    case 10: result.sInfo = append(result.sInfo, "NRV2E_LE16"); break;
                    case 14: result.sInfo = append(result.sInfo, "LZMA"); break;
                    case 15: result.sInfo = append(result.sInfo, "zlib"); break;
                }

                if (result.sInfo != "") {
                    if (nLevel == 8) {
                        result.sInfo = append(result.sInfo, "best");
                    } else {
                        result.sInfo = append(result.sInfo, "brute");
                    }
                }

                result.vValue = binary.read_uint32(nOffset);

                if (result.vValue.toUInt() != 0x21585055)  // UPX!
                {
                    result.sInfo = append(result.sInfo, QString("Modified(%1)").arg(XBinary::valueToHex((quint32)result.vValue.toUInt())));
                }
            }
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_GCC_vi1(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "GCC:", pPdStruct);

    if (nOffset_Version != -1) {
        QString sVersionString = binary.read_ansiString(nOffset_Version);

        result = _get_GCC_string(sVersionString);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_GCC_vi2(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "gcc-", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        QString sVersionString = binary.read_ansiString(nOffset_Version);
        result.sVersion = sVersionString.section("-", 1, 1).section("/", 0, 0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Nim_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO false positives in die.exe
    if ((binary.find_ansiString(nOffset, nSize, "io.nim", pPdStruct) != -1) || (binary.find_ansiString(nOffset, nSize, "fatal.nim", pPdStruct) != -1)) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Zig_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((binary.find_unicodeString(nOffset, nSize, "ZIG_DEBUG_COLOR", false, pPdStruct) != -1) ||
        (binary.find_ansiString(nOffset, nSize, "ZIG_DEBUG_COLOR", pPdStruct) != -1)) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Watcom_vi(QIODevice *pDevice, SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.find_ansiString(nOffset, nSize, "Open Watcom", pPdStruct) != -1) {
        result.bIsValid = true;
        result.vValue = RECORD_NAME_OPENWATCOMCCPP;

        qint64 nVersionOffset = binary.find_ansiString(nOffset, nSize, " 2002-", pPdStruct);

        if (nVersionOffset != -1) {
            result.sVersion = binary.read_ansiString(nVersionOffset + 6, 4);
        } else {
            result.sVersion = "2002";
        }
    } else if (binary.find_ansiString(nOffset, nSize, "WATCOM", pPdStruct) != -1) {
        result.bIsValid = true;
        result.vValue = RECORD_NAME_WATCOMCCPP;

        qint64 nVersionOffset = binary.find_ansiString(nOffset, nSize, ". 1988-", pPdStruct);

        if (nVersionOffset != -1) {
            result.sVersion = binary.read_ansiString(nVersionOffset + 7, 4);
        } else {
            result.sVersion = "1988";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_PyInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                         XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "PyInstaller: FormatMessageW failed.", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_DWRAF_vi(QIODevice *pDevice, SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (nSize > 8) {
        qint16 nVersion = binary.read_int16(nOffset + 4);

        if ((nVersion >= 0) && (nVersion <= 7)) {
            result.sVersion = QString::number(nVersion) + ".0";
            result.bIsValid = true;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_GCC_string(const QString &sString)
{
    VI_STRUCT result = {};

    if (sString.contains("GCC:")) {
        result.bIsValid = true;

        // TODO MinGW-w64
        if (sString.contains("MinGW")) {
            result.sInfo = "MinGW";
        } else if (sString.contains("MSYS2")) {
            result.sInfo = "MSYS2";
        } else if (sString.contains("Cygwin")) {
            result.sInfo = "Cygwin";
        }

        if ((sString.contains("(experimental)")) || (sString.contains("(prerelease)"))) {
            result.sVersion = sString.section(" ", -3, -1);  // TODO Check
        } else if (sString.contains("(GNU) c ")) {
            result.sVersion = sString.section("(GNU) c ", 1, -1);
        } else if (sString.contains("GNU")) {
            result.sVersion = sString.section(" ", 2, -1);
        } else if (sString.contains("Rev1, Built by MSYS2 project")) {
            result.sVersion = sString.section(" ", -2, -1);
        } else if (sString.contains("(Ubuntu ")) {
            result.sVersion = sString.section(") ", 1, 1).section(" ", 0, 0);
        } else if (sString.contains("StartOS)")) {
            result.sVersion = sString.section(")", 1, 1).section(" ", 0, 0);
        } else if (sString.contains("GCC: (c) ")) {
            result.sVersion = sString.section("GCC: (c) ", 1, 1);
        } else {
            result.sVersion = sString.section(" ", -1, -1);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_WindowsInstaller_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                                                              XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    qint64 nStringOffset = binary.find_ansiString(nOffset, nSize, "Windows Installer", pPdStruct);

    if (nStringOffset != -1) {
        result.bIsValid = true;

        QString _sString = binary.read_ansiString(nStringOffset);

        if (_sString.contains("xml", Qt::CaseInsensitive)) {
            result.sInfo = "XML";
        }

        QString sVersion = XBinary::regExp("\\((.*?)\\)", _sString, 1);

        if (sVersion != "") {
            result.sVersion = sVersion;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_gold_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, XBinary::PDSTRUCT *pPdStruct)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    // TODO get max version
    qint64 nOffset_Version = binary.find_ansiString(nOffset, nSize, "gold ", pPdStruct);

    if (nOffset_Version != -1) {
        result.bIsValid = true;
        QString sVersionString = binary.read_ansiString(nOffset_Version, nSize - (nOffset_Version - nOffset));
        result.sVersion = sVersionString.section(" ", 1, 1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_TurboLinker_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions)
{
    VI_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);

    if (binary.read_uint8(0x1E) == 0xFB) {
        result.bIsValid = true;

        result.sVersion = QString::number((double)binary.read_uint8(0x1F) / 16, 'f', 1);
    }

    return result;
}

bool SpecAbstract::PE_isValid_UPX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    bool bResult = false;

    if (pPEInfo->listSectionHeaders.count() >= 3) {
        // pPEInfo->listSections.at(0).SizeOfRawData!=0 dump file
        if ((pPEInfo->listSectionHeaders.at(0).SizeOfRawData == 0) && ((pPEInfo->nResourcesSection == -1) || (pPEInfo->nResourcesSection == 2))) {
            bResult = true;
        }
    }

    return bResult;
}

void SpecAbstract::PE_x86Emul(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    XADDR nAddress = pPEInfo->nImageBaseAddress + pPEInfo->nEntryPointAddress;

    QString sSignature;

    bool bSuccess = true;
    bool bVMProtect = true;

    qint32 nCount = 10;

    for (qint32 i = 0; (i < nCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        qint64 nOffset = XBinary::addressToOffset(&(pPEInfo->basic_info.memoryMap), nAddress);

        if (nOffset == -1) {
            bSuccess = false;
            break;
        }

        quint8 nByte = binary.read_uint8(nOffset);
        nAddress++;
        nOffset++;

        if (nByte == 0x9c)  // pushf
        {
            sSignature += "9C";
        } else if (nByte == 0x60)  // pusha
        {
            sSignature += "60";
        } else if (nByte == 0xe9)  // jmp ..
        {
            sSignature += "E9$$$$$$$$";
            nAddress += (4 + binary.read_int32(nOffset));
        } else if (nByte == 0xe8)  // call ..
        {
            sSignature += "E8$$$$$$$$";
            nAddress += (4 + binary.read_int32(nOffset));
        } else if (nByte == 0x68)  // push ..
        {
            sSignature += "68........";
            nAddress += 4;
        } else if (nByte == 0x53)  // push ebx
        {
            sSignature += "53";
        } else if (nByte == 0xC7)  // mov DWORD PTR [reg+],imm
        {
            sSignature += "C7";
            quint8 nMODRM = binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if ((nMODRM == 0x04) || (nMODRM == 0x44)) {
                sSignature += XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB = binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if (nSIB == 0x24)  // ESP+
                {
                    sSignature += "24";

                    if (nMODRM == 0x44) {
                        //                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature += "..";

                        nAddress++;
                        nOffset++;
                    }

                    sSignature += "........";

                    nAddress += 4;
                    nOffset += 4;
                } else {
                    bVMProtect = false;
                }
            } else {
                bVMProtect = false;
            }
        } else if (nByte == 0x8D)  // lea esp,dword ptr[esp+]
        {
            sSignature += "8D";
            quint8 nMODRM = binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if (nMODRM == 0x64) {
                sSignature += XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB = binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if (nSIB == 0x24)  // ESP+
                {
                    sSignature += "24";

                    if (nMODRM == 0x64) {
                        //                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature += "..";

                        nAddress++;
                        nOffset++;
                    }
                } else {
                    bVMProtect = false;
                }
            } else {
                bVMProtect = false;
            }
        } else {
            bVMProtect = false;
        }

        if (!bVMProtect) {
            break;
        }
    }

    if (!bSuccess) {
        bVMProtect = false;
    }
}

SpecAbstract::VI_STRUCT SpecAbstract::PE_get_PECompact_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    VI_STRUCT result = {};

    if (pPEInfo->listSectionHeaders.count() >= 2) {
        if (pPEInfo->listSectionHeaders.at(0).PointerToRelocations == 0x32434550) {
            result.bIsValid = true;

            quint32 nBuildNumber = pPEInfo->listSectionHeaders.at(0).PointerToLinenumbers;

            // TODO !!! more build versions
            switch (nBuildNumber) {
                case 20206: result.sVersion = "2.70"; break;
                case 20240: result.sVersion = "2.78a"; break;
                case 20243: result.sVersion = "2.79b1"; break;
                case 20245: result.sVersion = "2.79bB"; break;
                case 20247: result.sVersion = "2.79bD"; break;
                case 20252: result.sVersion = "2.80b1"; break;
                case 20256: result.sVersion = "2.80b5"; break;
                case 20261: result.sVersion = "2.82"; break;
                case 20285: result.sVersion = "2.92.0"; break;
                case 20288: result.sVersion = "2.93b3"; break;
                case 20294: result.sVersion = "2.96.2"; break;
                case 20295: result.sVersion = "2.97b1"; break;
                case 20296: result.sVersion = "2.98"; break;
                case 20300: result.sVersion = "2.98.04"; break;
                case 20301: result.sVersion = "2.98.05"; break;
                case 20302: result.sVersion = "2.98.06"; break;
                case 20303: result.sVersion = "2.99b"; break;
                case 20308: result.sVersion = "3.00.2"; break;
                case 20312: result.sVersion = "3.01.3"; break;
                case 20317: result.sVersion = "3.02.1"; break;
                case 20318: result.sVersion = "3.02.2"; break;
                case 20323: result.sVersion = "3.03.5b"; break;
                case 20327: result.sVersion = "3.03.9b"; break;
                case 20329: result.sVersion = "3.03.10b"; break;
                case 20334: result.sVersion = "3.03.12b"; break;
                case 20342: result.sVersion = "3.03.18b"; break;
                case 20343: result.sVersion = "3.03.19b"; break;
                case 20344: result.sVersion = "3.03.20b"; break;
                case 20345: result.sVersion = "3.03.21b"; break;
                case 20348: result.sVersion = "3.03.23b"; break;
                default: {
                    if (nBuildNumber > 20308) {
                        result.sVersion = QString("3.X(build %1)").arg(nBuildNumber);
                    } else if (nBuildNumber == 0) {
                        result.sVersion = "2.20-2.68";
                    } else {
                        result.sVersion = QString("2.X(build %1)").arg(nBuildNumber);
                    }
                }
            }

            //                            qDebug("nVersion: %d",nVersion);
        }
    }

    return result;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::scansToScan(SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::_SCANS_STRUCT *pScansStruct)
{
    SCAN_STRUCT result = {};

    result.id = pBasicInfo->id;
    result.parentId = pBasicInfo->parentId;
    result.bIsHeuristic = pScansStruct->bIsHeuristic;
    result.bIsUnknown = pScansStruct->bIsUnknown;
    result.type = pScansStruct->type;
    result.name = pScansStruct->name;
    result.sVersion = pScansStruct->sVersion;
    result.sInfo = pScansStruct->sInfo;

    //    result.sArch=pBasicInfo->memoryMap.sArch;

    return result;
}

void SpecAbstract::memoryScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMmREcords, QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize,
                              SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                              DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    if (nSize) {
        XBinary binary(pDevice, pOptions->bIsImage);

        qint32 nSignaturesCount = nRecordsSize / sizeof(SIGNATURE_RECORD);

        for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
                if ((!pMmREcords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                    qint64 _nOffset = binary.find_signature(&(pBasicInfo->memoryMap), nOffset, nSize, (char *)pRecords[i].pszSignature, nullptr, pPdStruct);

                    if (_nOffset != -1) {
                        if (!pMmREcords->contains(pRecords[i].basicInfo.name)) {
                            _SCANS_STRUCT record = {};
                            record.nVariant = pRecords[i].basicInfo.nVariant;
                            record.fileType = pRecords[i].basicInfo.fileType;
                            record.type = pRecords[i].basicInfo.type;
                            record.name = pRecords[i].basicInfo.name;
                            record.sVersion = pRecords[i].basicInfo.pszVersion;
                            record.sInfo = pRecords[i].basicInfo.pszInfo;
                            record.nOffset = _nOffset;

                            pMmREcords->insert(record.name, record);
                        }

                        if (pBasicInfo->scanOptions.bShowInternalDetects) {
                            DETECT_RECORD heurRecord = {};

                            heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                            heurRecord.fileType = pRecords[i].basicInfo.fileType;
                            heurRecord.type = pRecords[i].basicInfo.type;
                            heurRecord.name = pRecords[i].basicInfo.name;
                            heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                            heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                            heurRecord.nOffset = _nOffset;
                            heurRecord.filepart = pBasicInfo->id.filePart;
                            heurRecord.detectType = detectType;
                            heurRecord.sValue = pRecords[i].pszSignature;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::signatureScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, const QString &sSignature, SpecAbstract::SIGNATURE_RECORD *pRecords, qint32 nRecordsSize,
                                 XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(SIGNATURE_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                if (XBinary::compareSignatureStrings(sSignature, pRecords[i].pszSignature)) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        _SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;

                        record.nOffset = 0;

                        pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                        qDebug("SIGNATURE SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};

                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_resourcesScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources,
                                    PE_RESOURCES_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                                    DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / sizeof(PE_RESOURCES_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                bool bSuccess = false;

                QString sValue;

                if (pRecords[i].bIsString1) {
                    if (pRecords[i].bIsString2) {
                        bSuccess = XPE::isResourcePresent(pRecords[i].pszName1, pRecords[i].pszName2, pListResources);

                        sValue = QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].pszName2);
                    } else {
                        bSuccess = XPE::isResourcePresent(pRecords[i].pszName1, pRecords[i].nID2, pListResources);

                        sValue = QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].nID2);
                    }
                } else {
                    if (pRecords[i].bIsString2) {
                        bSuccess = XPE::isResourcePresent(pRecords[i].nID1, pRecords[i].pszName2, pListResources);

                        sValue = QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].pszName2);
                    } else {
                        bSuccess = XPE::isResourcePresent(pRecords[i].nID1, pRecords[i].nID2, pListResources);

                        sValue = QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].nID2);
                    }
                }

                if (bSuccess) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        _SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;
                        record.nOffset = 0;

                        pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                        qDebug("RESOURCES SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};

                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = sValue;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::stringScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings,
                              SpecAbstract::STRING_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                              DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    qint32 nNumberOfStrings = pListStrings->count();
    qint32 nNumberOfSignatures = nRecordsSize / sizeof(STRING_RECORD);

    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfStrings);

        for (qint32 i = 0; (i < nNumberOfStrings) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nCRC = XBinary::getStringCustomCRC32(pListStrings->at(i));
            listStringCRC.append(nCRC);
            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }

        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }
    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfStrings);

        for (qint32 i = 0; (i < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nCRC = XBinary::getStringCustomCRC32(pRecords[i].pszString);
            listSignatureCRC.append(nCRC);
            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }

        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    {
        qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
        XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nNumberOfStrings);

        for (qint32 i = 0; (i < nNumberOfStrings) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            for (qint32 j = 0; j < nNumberOfSignatures; j++) {
                if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                    if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                        quint32 nCRC1 = listStringCRC[i];
                        quint32 nCRC2 = listSignatureCRC[j];

                        if (nCRC1 == nCRC2) {
                            if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                                _SCANS_STRUCT record = {};
                                record.nVariant = pRecords[j].basicInfo.nVariant;
                                record.fileType = pRecords[j].basicInfo.fileType;
                                record.type = pRecords[j].basicInfo.type;
                                record.name = pRecords[j].basicInfo.name;
                                record.sVersion = pRecords[j].basicInfo.pszVersion;
                                record.sInfo = pRecords[j].basicInfo.pszInfo;

                                record.nOffset = 0;

                                pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                                qDebug("STRING SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                            }

                            if (pBasicInfo->scanOptions.bShowInternalDetects) {
                                DETECT_RECORD heurRecord = {};

                                heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                                heurRecord.fileType = pRecords[j].basicInfo.fileType;
                                heurRecord.type = pRecords[j].basicInfo.type;
                                heurRecord.name = pRecords[j].basicInfo.name;
                                heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                                heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                                heurRecord.nOffset = 0;
                                heurRecord.filepart = pBasicInfo->id.filePart;
                                heurRecord.detectType = detectType;
                                heurRecord.sValue = pRecords[j].pszString;

                                pBasicInfo->listHeurs.append(heurRecord);
                            }
                        }
                    }
                }
            }

            XBinary::setPdStructCurrentIncrement(pPdStruct, _nFreeIndex);
        }

        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }
}

void SpecAbstract::constScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2,
                             SpecAbstract::CONST_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                             DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(CONST_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects) || (pRecords[i].nConst1 == 0xFFFFFFFF)) {
                bool bSuccess = false;

                bSuccess =
                    ((pRecords[i].nConst1 == nCost1) || (pRecords[i].nConst1 == 0xFFFFFFFF)) && ((pRecords[i].nConst2 == nCost2) || (pRecords[i].nConst2 == 0xFFFFFFFF));

                if (bSuccess) {
                    if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pRecords[i].nConst1 == 0xFFFFFFFF)) {
                        _SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;

                        record.nOffset = 0;

                        pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                        qDebug("CONST SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};

                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nConst1)).arg(XBinary::valueToHex(pRecords[i].nConst2));

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::MSDOS_richScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, quint32 nCount,
                                  SpecAbstract::MSRICH_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo,
                                  DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(MSRICH_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
            _SCANS_STRUCT record = {};

            if (MSDOS_compareRichRecord(&record, &(pRecords[i]), nID, nBuild, nCount, fileType1, fileType2)) {
                if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                    pMapRecords->insert(record.name, record);
                }

                if (pBasicInfo->scanOptions.bShowInternalDetects) {
                    DETECT_RECORD heurRecord = {};

                    heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                    heurRecord.fileType = pRecords[i].basicInfo.fileType;
                    heurRecord.type = pRecords[i].basicInfo.type;
                    heurRecord.name = pRecords[i].basicInfo.name;
                    heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                    heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                    heurRecord.nOffset = 0;
                    heurRecord.filepart = pBasicInfo->id.filePart;
                    heurRecord.detectType = detectType;
                    heurRecord.sValue = QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID)).arg(XBinary::valueToHex(pRecords[i].nBuild));

                    pBasicInfo->listHeurs.append(heurRecord);
                }
            }
        }
    }
}

void SpecAbstract::archiveScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords,
                               SpecAbstract::STRING_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2,
                               SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    qint32 nNumberOfArchives = pListArchiveRecords->count();
    qint32 nNumberOfSignatures = nRecordsSize / sizeof(STRING_RECORD);

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        //        qDebug("%s",pListArchiveRecords->at(i).sFileName.toLatin1().data());
        quint32 nCRC = XBinary::getStringCustomCRC32(pListArchiveRecords->at(i).spInfo.sRecordName);
        listStringCRC.append(nCRC);
    }

    for (qint32 i = 0; (i < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        //        qDebug("%s",pRecords[i].pszString);
        quint32 nCRC = XBinary::getStringCustomCRC32(pRecords[i].pszString);
        listSignatureCRC.append(nCRC);
    }

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        for (qint32 j = 0; (j < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); j++) {
            if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                    quint32 nCRC1 = listStringCRC[i];
                    quint32 nCRC2 = listSignatureCRC[j];

                    if (nCRC1 == nCRC2) {
                        if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                            _SCANS_STRUCT record = {};
                            record.nVariant = pRecords[j].basicInfo.nVariant;
                            record.fileType = pRecords[j].basicInfo.fileType;
                            record.type = pRecords[j].basicInfo.type;
                            record.name = pRecords[j].basicInfo.name;
                            record.sVersion = pRecords[j].basicInfo.pszVersion;
                            record.sInfo = pRecords[j].basicInfo.pszInfo;

                            record.nOffset = 0;

                            pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }

                        if (pBasicInfo->scanOptions.bShowInternalDetects) {
                            DETECT_RECORD heurRecord = {};

                            heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType = pRecords[j].basicInfo.fileType;
                            heurRecord.type = pRecords[j].basicInfo.type;
                            heurRecord.name = pRecords[j].basicInfo.name;
                            heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset = 0;
                            heurRecord.filepart = pBasicInfo->id.filePart;
                            heurRecord.detectType = detectType;
                            heurRecord.sValue = pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::archiveExpScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords,
                                  SpecAbstract::STRING_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2,
                                  SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nNumberOfArchives = pListArchiveRecords->count();
    qint32 nNumberOfSignatures = nRecordsSize / sizeof(STRING_RECORD);

    for (qint32 i = 0; (i < nNumberOfArchives) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        for (qint32 j = 0; (j < nNumberOfSignatures) && XBinary::isPdStructNotCanceled(pPdStruct); j++) {
            if ((pRecords[j].basicInfo.fileType == fileType1) || (pRecords[j].basicInfo.fileType == fileType2)) {
                if ((!pMapRecords->contains(pRecords[j].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                    if (XBinary::isRegExpPresent(pRecords[j].pszString, pListArchiveRecords->at(i).spInfo.sRecordName)) {
                        if (!pMapRecords->contains(pRecords[j].basicInfo.name)) {
                            _SCANS_STRUCT record = {};
                            record.nVariant = pRecords[j].basicInfo.nVariant;
                            record.fileType = pRecords[j].basicInfo.fileType;
                            record.type = pRecords[j].basicInfo.type;
                            record.name = pRecords[j].basicInfo.name;
                            record.sVersion = pRecords[j].basicInfo.pszVersion;
                            record.sInfo = pRecords[j].basicInfo.pszInfo;

                            record.nOffset = 0;

                            pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }

                        if (pBasicInfo->scanOptions.bShowInternalDetects) {
                            DETECT_RECORD heurRecord = {};

                            heurRecord.nVariant = pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType = pRecords[j].basicInfo.fileType;
                            heurRecord.type = pRecords[j].basicInfo.type;
                            heurRecord.name = pRecords[j].basicInfo.name;
                            heurRecord.sVersion = pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo = pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset = 0;
                            heurRecord.filepart = pBasicInfo->id.filePart;
                            heurRecord.detectType = detectType;
                            heurRecord.sValue = pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords,
                                    qint64 nOffset, SpecAbstract::SIGNATURE_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2,
                                    BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(SIGNATURE_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if ((pRecords[i].basicInfo.fileType == fileType1) || (pRecords[i].basicInfo.fileType == fileType2)) {
            if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
                if (pXBinary->compareSignature(pMemoryMap, pRecords[i].pszSignature, nOffset)) {
                    if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
                        _SCANS_STRUCT record = {};
                        record.nVariant = pRecords[i].basicInfo.nVariant;
                        record.fileType = pRecords[i].basicInfo.fileType;
                        record.type = pRecords[i].basicInfo.type;
                        record.name = pRecords[i].basicInfo.name;
                        record.sVersion = pRecords[i].basicInfo.pszVersion;
                        record.sInfo = pRecords[i].basicInfo.pszInfo;

                        record.nOffset = 0;

                        pMapRecords->insert(record.name, record);

#ifdef QT_DEBUG
                        qDebug("SIGNATURE EXP SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if (pBasicInfo->scanOptions.bShowInternalDetects) {
                        DETECT_RECORD heurRecord = {};

                        heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType = pRecords[i].basicInfo.fileType;
                        heurRecord.type = pRecords[i].basicInfo.type;
                        heurRecord.name = pRecords[i].basicInfo.name;
                        heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset = 0;
                        heurRecord.filepart = pBasicInfo->id.filePart;
                        heurRecord.detectType = detectType;
                        heurRecord.sValue = pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

QList<SpecAbstract::_SCANS_STRUCT> SpecAbstract::MSDOS_richScan(quint16 nID, quint32 nBuild, quint32 nCount, SpecAbstract::MSRICH_RECORD *pRecords, qint32 nRecordsSize,
                                                                XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType,
                                                                XBinary::PDSTRUCT *pPdStruct)
{
    QList<_SCANS_STRUCT> listResult;

    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(MSRICH_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        _SCANS_STRUCT record = {};

        if (MSDOS_compareRichRecord(&record, &(pRecords[i]), nID, nBuild, nCount, fileType1, fileType2)) {
            listResult.append(record);

            if (pBasicInfo->scanOptions.bShowInternalDetects) {
                DETECT_RECORD heurRecord = {};

                heurRecord.nVariant = pRecords[i].basicInfo.nVariant;
                heurRecord.fileType = pRecords[i].basicInfo.fileType;
                heurRecord.type = pRecords[i].basicInfo.type;
                heurRecord.name = pRecords[i].basicInfo.name;
                heurRecord.sVersion = pRecords[i].basicInfo.pszVersion;
                heurRecord.sInfo = pRecords[i].basicInfo.pszInfo;
                heurRecord.nOffset = 0;
                heurRecord.filepart = pBasicInfo->id.filePart;
                heurRecord.detectType = detectType;
                heurRecord.sValue = QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID), XBinary::valueToHex(pRecords[i].nBuild));

                pBasicInfo->listHeurs.append(heurRecord);
            }
        }
    }

    return listResult;
}

QByteArray SpecAbstract::serializeScanStruct(const SCAN_STRUCT &scanStruct, bool bIsHeader)
{
    QByteArray baResult;

    QDataStream ds(baResult);

    ds << scanStruct.id.sUuid;
    ds << (quint32)scanStruct.id.fileType;
    ds << (quint32)scanStruct.id.filePart;
    ds << scanStruct.parentId.sUuid;
    ds << (quint32)scanStruct.parentId.fileType;
    ds << (quint32)scanStruct.parentId.filePart;
    ds << (quint32)scanStruct.type;
    ds << (quint32)scanStruct.name;
    ds << scanStruct.sVersion;
    ds << scanStruct.sInfo;
    ds << bIsHeader;

    return baResult;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::deserializeScanStruct(const QByteArray &baData, bool *pbIsHeader)
{
    SCAN_STRUCT ssResult = {};

    QDataStream ds(baData);

    quint32 nTemp = 0;

    ds >> ssResult.id.sUuid;
    ds >> nTemp;
    ssResult.id.fileType = (XBinary::FT)nTemp;
    ds >> nTemp;
    ssResult.id.filePart = (XBinary::FILEPART)nTemp;
    ds >> ssResult.parentId.sUuid;
    ds >> nTemp;
    ssResult.parentId.fileType = (XBinary::FT)nTemp;
    ds >> nTemp;
    ssResult.parentId.filePart = (XBinary::FILEPART)nTemp;
    ds >> nTemp;
    ssResult.type = (RECORD_TYPE)nTemp;
    ds >> nTemp;
    ssResult.name = (RECORD_NAME)nTemp;
    ds >> ssResult.sVersion;
    ds >> ssResult.sInfo;
    ds >> *pbIsHeader;

    return ssResult;
}

void SpecAbstract::getLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages, XBinary::PDSTRUCT *pPdStruct)
{
    QMapIterator<RECORD_NAME, SCAN_STRUCT> i(*pMapDetects);
    while (i.hasNext() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        i.next();

        SCAN_STRUCT ssDetect = i.value();
        _SCANS_STRUCT ssLanguage = getScansStruct(0, ssDetect.id.fileType, RECORD_TYPE_LANGUAGE, RECORD_NAME_UNKNOWN, "", "", 0);

        // TODO Libraries like MFC
        switch (ssDetect.name) {
            case RECORD_NAME_C:
            case RECORD_NAME_ARMC:
            case RECORD_NAME_LCCLNK:
            case RECORD_NAME_LCCWIN:
            case RECORD_NAME_MICROSOFTC:
            case RECORD_NAME_THUMBC:
            case RECORD_NAME_TINYC:
            case RECORD_NAME_TURBOC:
            case RECORD_NAME_WATCOMC: ssLanguage.name = RECORD_NAME_C; break;
            case RECORD_NAME_CCPP:
            case RECORD_NAME_ARMCCPP:
            case RECORD_NAME_ARMNEONCCPP:
            case RECORD_NAME_ARMTHUMBCCPP:
            case RECORD_NAME_BORLANDCCPP:
            case RECORD_NAME_MINGW:
            case RECORD_NAME_MSYS:
            case RECORD_NAME_MSYS2:
            case RECORD_NAME_VISUALCCPP:
            case RECORD_NAME_OPENWATCOMCCPP:
            case RECORD_NAME_WATCOMCCPP: ssLanguage.name = RECORD_NAME_CCPP; break;
            case RECORD_NAME_CLANG:
            case RECORD_NAME_GCC:
            case RECORD_NAME_ALIPAYCLANG:
            case RECORD_NAME_ANDROIDCLANG:
            case RECORD_NAME_APPORTABLECLANG:
            case RECORD_NAME_PLEXCLANG:
            case RECORD_NAME_UBUNTUCLANG:
            case RECORD_NAME_DEBIANCLANG:
                if (ssDetect.sInfo.contains("Objective-C")) {
                    ssLanguage.name = RECORD_NAME_OBJECTIVEC;
                } else {
                    ssLanguage.name = RECORD_NAME_CCPP;
                }
                break;
            case RECORD_NAME_CPP:
            case RECORD_NAME_BORLANDCPP:
            case RECORD_NAME_BORLANDCPPBUILDER:
            case RECORD_NAME_CODEGEARCPP:
            case RECORD_NAME_CODEGEARCPPBUILDER:
            case RECORD_NAME_EMBARCADEROCPP:
            case RECORD_NAME_EMBARCADEROCPPBUILDER:
            case RECORD_NAME_MICROSOFTCPP:
            case RECORD_NAME_TURBOCPP: ssLanguage.name = RECORD_NAME_CPP; break;
            case RECORD_NAME_ASSEMBLER:
            case RECORD_NAME_ARMTHUMBMACROASSEMBLER:
            case RECORD_NAME_GNUASSEMBLER:
                ssLanguage.name = RECORD_NAME_ASSEMBLER;  // TODO Check architecture if X86 -> RECORD_NAME_X86ASSEMBLER
                break;
            case RECORD_NAME_FASM:
            case RECORD_NAME_GOASM:
            case RECORD_NAME_MASM:
            case RECORD_NAME_MASM32:
            case RECORD_NAME_NASM: ssLanguage.name = RECORD_NAME_X86ASSEMBLER; break;
            case RECORD_NAME_AUTOIT: ssLanguage.name = RECORD_NAME_AUTOIT; break;
            case RECORD_NAME_OBJECTPASCAL:
            case RECORD_NAME_LAZARUS:
            case RECORD_NAME_FPC:
            case RECORD_NAME_VIRTUALPASCAL:
            case RECORD_NAME_IBMPCPASCAL: ssLanguage.name = RECORD_NAME_OBJECTPASCAL; break;
            case RECORD_NAME_BORLANDDELPHI:
            case RECORD_NAME_BORLANDDELPHIDOTNET:
            case RECORD_NAME_BORLANDOBJECTPASCALDELPHI:
            case RECORD_NAME_CODEGEARDELPHI:
            case RECORD_NAME_CODEGEAROBJECTPASCALDELPHI:
            case RECORD_NAME_EMBARCADERODELPHI:
            case RECORD_NAME_EMBARCADERODELPHIDOTNET:
            case RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI: ssLanguage.name = RECORD_NAME_OBJECTPASCALDELPHI; break;
            case RECORD_NAME_D:
            case RECORD_NAME_DMD:
            case RECORD_NAME_DMD32:
            case RECORD_NAME_LDC: ssLanguage.name = RECORD_NAME_D; break;
            case RECORD_NAME_CSHARP:
            case RECORD_NAME_DOTNET: ssLanguage.name = RECORD_NAME_CSHARP; break;
            case RECORD_NAME_GO: ssLanguage.name = RECORD_NAME_GO; break;
            case RECORD_NAME_JAVA:
            case RECORD_NAME_JVM:
            case RECORD_NAME_JDK:
            case RECORD_NAME_OPENJDK:
            case RECORD_NAME_IBMJDK:
            case RECORD_NAME_APPLEJDK:
                // case RECORD_NAME_DX:
                ssLanguage.name = RECORD_NAME_JAVA;
                break;
            case RECORD_NAME_JSCRIPT: ssLanguage.name = RECORD_NAME_ECMASCRIPT; break;
            case RECORD_NAME_KOTLIN: ssLanguage.name = RECORD_NAME_KOTLIN; break;
            case RECORD_NAME_FORTRAN:
            case RECORD_NAME_LAYHEYFORTRAN90: ssLanguage.name = RECORD_NAME_FORTRAN; break;
            case RECORD_NAME_NIM: ssLanguage.name = RECORD_NAME_NIM; break;
            case RECORD_NAME_OBJECTIVEC: ssLanguage.name = RECORD_NAME_OBJECTIVEC; break;
            case RECORD_NAME_BASIC:
            case RECORD_NAME_BASIC4ANDROID:
            case RECORD_NAME_POWERBASIC:
            case RECORD_NAME_PUREBASIC:
            case RECORD_NAME_TURBOBASIC:
            case RECORD_NAME_VBNET:
            case RECORD_NAME_VISUALBASIC: ssLanguage.name = RECORD_NAME_BASIC; break;
            case RECORD_NAME_RUST: ssLanguage.name = RECORD_NAME_RUST; break;
            case RECORD_NAME_RUBY: ssLanguage.name = RECORD_NAME_RUBY; break;
            case RECORD_NAME_PYTHON:
            case RECORD_NAME_PYINSTALLER: ssLanguage.name = RECORD_NAME_PYTHON; break;
            case RECORD_NAME_SWIFT: ssLanguage.name = RECORD_NAME_SWIFT; break;
            case RECORD_NAME_PERL: ssLanguage.name = RECORD_NAME_PERL; break;
            case RECORD_NAME_ZIG: ssLanguage.name = RECORD_NAME_ZIG; break;
            case RECORD_NAME_QML: ssLanguage.name = RECORD_NAME_QML; break;
            default: ssLanguage.name = RECORD_NAME_UNKNOWN;
        }

        if (ssLanguage.name != RECORD_NAME_UNKNOWN) {
            SCAN_STRUCT ss = ssDetect;
            ss.type = ssLanguage.type;
            ss.name = ssLanguage.name;
            ss.sInfo = "";
            ss.sVersion = "";

            pMapLanguages->insert((RECORD_NAME)ss.name, ss);
        }
    }
}

void SpecAbstract::fixLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages)
{
    if (pMapLanguages->contains(RECORD_NAME_C) && pMapLanguages->contains(RECORD_NAME_CPP)) {
        SCAN_STRUCT ss = pMapLanguages->value(RECORD_NAME_C);
        ss.name = RECORD_NAME_CCPP;
        pMapLanguages->insert((RECORD_NAME)ss.name, ss);
    }

    if (pMapLanguages->contains(RECORD_NAME_C) && pMapLanguages->contains(RECORD_NAME_CCPP)) {
        pMapLanguages->remove(RECORD_NAME_C);
    }

    if (pMapLanguages->contains(RECORD_NAME_CPP) && pMapLanguages->contains(RECORD_NAME_CCPP)) {
        pMapLanguages->remove(RECORD_NAME_CPP);
    }

    //    if(pMapLanguages->contains(RECORD_NAME_OBJECTIVEC)&&pMapLanguages->contains(RECORD_NAME_CCPP))
    //    {
    //        pMapLanguages->remove(RECORD_NAME_CCPP);
    //    }
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::getFormatScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    _SCANS_STRUCT result = {};
    result.type = RECORD_TYPE_FORMAT;

    if (fileFormatInfo.fileType == XBinary::FT_PDF) result.name = RECORD_NAME_PDF;
    else if (fileFormatInfo.fileType == XBinary::FT_JPEG) result.name = RECORD_NAME_JPEG;

    result.sVersion = fileFormatInfo.sVersion;
    result.sInfo = XBinary::getFileFormatInfoString(&fileFormatInfo);

    return result;
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::getOperationSystemScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    _SCANS_STRUCT result = {};

    if (fileFormatInfo.bIsVM) {
        result.type = RECORD_TYPE_VIRTUALMACHINE;
    } else {
        result.type = RECORD_TYPE_OPERATIONSYSTEM;
    }

    // TODO reactOS
    if (fileFormatInfo.osName == XBinary::OSNAME_MSDOS) result.name = RECORD_NAME_MSDOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_POSIX) result.name = RECORD_NAME_POSIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UNIX) result.name = RECORD_NAME_UNIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_LINUX) result.name = RECORD_NAME_LINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWS) result.name = RECORD_NAME_WINDOWS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWSCE) result.name = RECORD_NAME_WINDOWSCE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_XBOX) result.name = RECORD_NAME_XBOX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS2) result.name = RECORD_NAME_OS2;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS) result.name = RECORD_NAME_MAC_OS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS_X) result.name = RECORD_NAME_MAC_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS_X) result.name = RECORD_NAME_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACOS) result.name = RECORD_NAME_MACOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPHONEOS) result.name = RECORD_NAME_IPHONEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPADOS) result.name = RECORD_NAME_IPADOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IOS) result.name = RECORD_NAME_IOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WATCHOS) result.name = RECORD_NAME_WATCHOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TVOS) result.name = RECORD_NAME_TVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BRIDGEOS) result.name = RECORD_NAME_BRIDGEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ANDROID) result.name = RECORD_NAME_ANDROID;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FREEBSD) result.name = RECORD_NAME_FREEBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENBSD) result.name = RECORD_NAME_OPENBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NETBSD) result.name = RECORD_NAME_NETBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HPUX) result.name = RECORD_NAME_HPUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SOLARIS) result.name = RECORD_NAME_SOLARIS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AIX) result.name = RECORD_NAME_AIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IRIX) result.name = RECORD_NAME_IRIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TRU64) result.name = RECORD_NAME_TRU64;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MODESTO) result.name = RECORD_NAME_MODESTO;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVMS) result.name = RECORD_NAME_OPENVMS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FENIXOS) result.name = RECORD_NAME_FENIXOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BORLANDOSSERVICES) result.name = RECORD_NAME_BORLANDOSSERVICES;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NSK) result.name = RECORD_NAME_NSK;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AROS) result.name = RECORD_NAME_AROS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UBUNTULINUX) result.name = RECORD_NAME_UBUNTULINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_DEBIANLINUX) result.name = RECORD_NAME_DEBIANLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_STARTOSLINUX) result.name = RECORD_NAME_STARTOSLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_GENTOOLINUX) result.name = RECORD_NAME_GENTOOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ALPINELINUX) result.name = RECORD_NAME_ALPINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDRIVERLINUX) result.name = RECORD_NAME_WINDRIVERLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUSELINUX) result.name = RECORD_NAME_SUSELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MANDRAKELINUX) result.name = RECORD_NAME_MANDRAKELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ASPLINUX) result.name = RECORD_NAME_ASPLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_REDHATLINUX) result.name = RECORD_NAME_REDHATLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HANCOMLINUX) result.name = RECORD_NAME_HANCOMLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TURBOLINUX) result.name = RECORD_NAME_TURBOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_VINELINUX) result.name = RECORD_NAME_VINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUNOS) result.name = RECORD_NAME_SUNOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVOS) result.name = RECORD_NAME_OPENVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MCLINUX) result.name = RECORD_NAME_MCLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_QNX) result.name = RECORD_NAME_QNX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SYLLABLE) result.name = RECORD_NAME_SYLLABLE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MINIX) result.name = RECORD_NAME_MINIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_JVM) result.name = RECORD_NAME_JVM;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AMIGA) result.name = RECORD_NAME_AMIGA;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACCATALYST) result.name = RECORD_NAME_MACCATALYST;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACDRIVERKIT) result.name = RECORD_NAME_MACDRIVERKIT;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACFIRMWARE) result.name = RECORD_NAME_MACFIRMWARE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SEPOS) result.name = RECORD_NAME_SEPOS;
    else result.name = RECORD_NAME_UNKNOWN;

    result.sVersion = fileFormatInfo.sOsVersion;
    result.sInfo = QString("%1, %2, %3").arg(fileFormatInfo.sArch, XBinary::modeIdToString(fileFormatInfo.mode), fileFormatInfo.sType);

    if (fileFormatInfo.endian == XBinary::ENDIAN_BIG) {
        result.sInfo.append(QString(", %1").arg(XBinary::endianToString(XBinary::ENDIAN_BIG)));
    }

    return result;
}

QString SpecAbstract::getMsRichString(quint16 nId, quint16 nBuild, quint32 nCount, XBinary::PDSTRUCT *pPdStruct)
{
    QString sResult;

    MSRICH_RECORD *pRecords = _MS_rich_records;
    qint32 nRecordsSize = sizeof(_MS_rich_records);

    qint32 nSignaturesCount = nRecordsSize / (int)sizeof(MSRICH_RECORD);

    for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        _SCANS_STRUCT record = {};

        if (MSDOS_compareRichRecord(&record, &(pRecords[i]), nId, nBuild, nCount, XBinary::FT_PE, XBinary::FT_MSDOS)) {
            sResult = _SCANS_STRUCT_toString(&record);
        }
    }

    return sResult;
}

QList<XScanEngine::SCANSTRUCT> SpecAbstract::convert(QList<SCAN_STRUCT> *pListScanStructs)
{
    QList<XScanEngine::SCANSTRUCT> listResult;

    qint32 nNumberOfRecords = pListScanStructs->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::SCANSTRUCT record = {};

        record.bIsHeuristic = pListScanStructs->at(i).bIsHeuristic;
        record.bIsUnknown = pListScanStructs->at(i).bIsUnknown;
        record.id = pListScanStructs->at(i).id;
        record.parentId = pListScanStructs->at(i).parentId;
        record.nType = pListScanStructs->at(i).type;
        record.nName = pListScanStructs->at(i).name;
        record.sType = recordTypeIdToString(pListScanStructs->at(i).type);
        record.sName = recordNameIdToString(pListScanStructs->at(i).name);
        record.sVersion = pListScanStructs->at(i).sVersion;
        record.sInfo = pListScanStructs->at(i).sInfo;

        record.globalColorRecord = typeToGlobalColorRecord(record.sType);
        record.nPrio = typeToPrio(record.sType);
        record.bIsProtection = isProtection(record.sType);
        record.sType = translateType(record.sType);

        listResult.append(record);
    }

    // XFormats::sortRecords(&listResult); // TODO Check

    return listResult;
}

QList<XScanEngine::DEBUG_RECORD> SpecAbstract::convertHeur(QList<DETECT_RECORD> *pListDetectRecords)
{
    QList<XScanEngine::DEBUG_RECORD> listResult;

    qint32 nNumberOfRecords = pListDetectRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::DEBUG_RECORD record = {};

        record.sType = heurTypeIdToString(pListDetectRecords->at(i).detectType);
        record.sName = QString("%1(%2)[%3]")
                           .arg(SpecAbstract::recordNameIdToString(pListDetectRecords->at(i).name), pListDetectRecords->at(i).sVersion, pListDetectRecords->at(i).sInfo);
        record.sValue = pListDetectRecords->at(i).sValue;

        listResult.append(record);
    }

    return listResult;
}

bool SpecAbstract::MSDOS_compareRichRecord(_SCANS_STRUCT *pResult, SpecAbstract::MSRICH_RECORD *pRecord, quint16 nID, quint32 nBuild, quint32 nCount,
                                           XBinary::FT fileType1, XBinary::FT fileType2)
{
    bool bResult = false;

    if ((pRecord->basicInfo.fileType == fileType1) || (pRecord->basicInfo.fileType == fileType2)) {
        bool bCheck = false;

        bCheck = ((pRecord->nID == nID) || (pRecord->nID == (quint16)-1)) && ((pRecord->nBuild == nBuild) || (pRecord->nBuild == (quint32)-1));

        if (bCheck) {
            _SCANS_STRUCT record = {};
            record.nVariant = pRecord->basicInfo.nVariant;
            record.fileType = pRecord->basicInfo.fileType;
            record.type = pRecord->basicInfo.type;
            record.name = pRecord->basicInfo.name;
            record.sVersion = pRecord->basicInfo.pszVersion;
            record.sInfo = pRecord->basicInfo.pszInfo;

            if (pRecord->nBuild == (quint32)-1) {
                record.sVersion += QString(".%1").arg(nBuild);
            }

            record.varExtra = nCount;

            record.nOffset = 0;

#ifdef QT_DEBUG
            qDebug("Rich SCAN: %s", _SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
            *pResult = record;

            bResult = true;
        }
    }

    return bResult;
}

void SpecAbstract::filterResult(QList<SpecAbstract::SCAN_STRUCT> *pListRecords, const QSet<SpecAbstract::RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct)
{
    QList<SpecAbstract::SCAN_STRUCT> listRecords;
    qint32 nNumberOfRecords = pListRecords->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        if (stRecordTypes.contains((RECORD_TYPE)pListRecords->at(i).type)) {
            listRecords.append(pListRecords->at(i));
        }
    }

    *pListRecords = listRecords;
}

void SpecAbstract::_fixRichSignatures(QList<_SCANS_STRUCT> *pListRichSignatures, qint32 nMajorLinkerVersion, qint32 nMinorLinkerVersion, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(nMajorLinkerVersion)

    qint32 nNumberOfRecords = pListRichSignatures->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        QString sMajor = pListRichSignatures->at(i).sVersion.section(".", 0, 0);
        QString sBuild = pListRichSignatures->at(i).sVersion.section(".", 2, 2);

        qint32 nBuild = sBuild.toInt();
        qint32 nMinorVersion = 0;

        bool bFix = false;

        if (nBuild > 25000) {
            if ((pListRichSignatures->at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) && (sMajor.toInt() >= 19)) {
                bFix = true;  // C++
            } else if (sMajor.toInt() >= 14) {
                if (pListRichSignatures->at(i).name == RECORD_NAME_MICROSOFTLINKER) {
                    if ((nMinorLinkerVersion >= 10) && (nMinorLinkerVersion <= 40)) {
                        nMinorVersion = nMinorLinkerVersion;
                    }
                }

                bFix = true;  // Linker, MASM ...
            }
        }

        if (bFix) {
            if (nMinorVersion == 0) {
                if (nBuild < 25506) nMinorVersion = 10;
                else if (nBuild < 25830) nMinorVersion = 11;
                else if (nBuild < 26128) nMinorVersion = 12;
                else if (nBuild < 26428) nMinorVersion = 13;
                else if (nBuild < 26726) nMinorVersion = 14;
                else if (nBuild < 26926) nMinorVersion = 15;
                else if (nBuild < 27508) nMinorVersion = 16;
                else if (nBuild < 27702) nMinorVersion = 20;
                else if (nBuild < 27905) nMinorVersion = 21;
                else if (nBuild < 28105) nMinorVersion = 22;
                else if (nBuild < 28314) nMinorVersion = 23;
                else if (nBuild < 28610) nMinorVersion = 24;
                else if (nBuild < 28805) nMinorVersion = 25;
                else if (nBuild < 29110) nMinorVersion = 26;
                else if (nBuild < 29333) nMinorVersion = 27;
                else if (nBuild < 30133) nMinorVersion = 28;
                else if (nBuild < 30401) nMinorVersion = 29;
                else if (nBuild < 30818) nMinorVersion = 30;
                else if (nBuild < 31114) nMinorVersion = 31;
                else if (nBuild < 31424) nMinorVersion = 32;
                else if (nBuild < 31721) nMinorVersion = 33;
                else if (nBuild < 32019) nMinorVersion = 34;
                else if (nBuild < 32323) nMinorVersion = 35;
                else if (nBuild >= 32323) nMinorVersion = 36;
            }

            (*pListRichSignatures)[i].sVersion = QString("%1.%2.%3").arg(sMajor, QString::number(nMinorVersion), sBuild);
        }
    }
}

void SpecAbstract::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                  XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO basic_info = {};

    if ((fileType == XBinary::FT_PE32) || (fileType == XBinary::FT_PE64)) {
        SpecAbstract::PEINFO_STRUCT pe_info = SpecAbstract::getPEInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pe_info.basic_info;
    } else if ((fileType == XBinary::FT_ELF32) || (fileType == XBinary::FT_ELF64)) {
        SpecAbstract::ELFINFO_STRUCT elf_info = SpecAbstract::getELFInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = elf_info.basic_info;
    } else if ((fileType == XBinary::FT_MACHO32) || (fileType == XBinary::FT_MACHO64)) {
        SpecAbstract::MACHOINFO_STRUCT mach_info = SpecAbstract::getMACHOInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = mach_info.basic_info;
    } else if (fileType == XBinary::FT_LE) {
        SpecAbstract::LEINFO_STRUCT le_info = SpecAbstract::getLEInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = le_info.basic_info;
    } else if (fileType == XBinary::FT_LX) {
        SpecAbstract::LXINFO_STRUCT lx_info = SpecAbstract::getLXInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = lx_info.basic_info;
    } else if (fileType == XBinary::FT_NE) {
        SpecAbstract::NEINFO_STRUCT ne_info = SpecAbstract::getNEInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = ne_info.basic_info;
    } else if (fileType == XBinary::FT_MSDOS) {
        SpecAbstract::MSDOSINFO_STRUCT msdos_info = SpecAbstract::getMSDOSInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = msdos_info.basic_info;
    } else if (fileType == XBinary::FT_JAR) {
        SpecAbstract::JARINFO_STRUCT jar_info = SpecAbstract::getJARInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jar_info.basic_info;
    } else if (fileType == XBinary::FT_APK) {
        SpecAbstract::APKINFO_STRUCT apk_info = SpecAbstract::getAPKInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = apk_info.basic_info;
    } else if ((fileType == XBinary::FT_ZIP) || (fileType == XBinary::FT_IPA)) {
        // mb TODO split detects
        SpecAbstract::ZIPINFO_STRUCT zip_info = SpecAbstract::getZIPInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = zip_info.basic_info;
    } else if (fileType == XBinary::FT_RAR) {
        SpecAbstract::RARINFO_STRUCT rar_info = SpecAbstract::getRARInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = rar_info.basic_info;
    } else if (fileType == XBinary::FT_JAVACLASS) {
        SpecAbstract::JAVACLASSINFO_STRUCT javaclass_info = SpecAbstract::getJavaClassInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = javaclass_info.basic_info;
    } else if (fileType == XBinary::FT_DEX) {
        SpecAbstract::DEXINFO_STRUCT dex_info = SpecAbstract::getDEXInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = dex_info.basic_info;
    } else if (fileType == XBinary::FT_AMIGAHUNK) {
        SpecAbstract::AMIGAHUNKINFO_STRUCT amigaHunk_info = SpecAbstract::getAmigaHunkInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = amigaHunk_info.basic_info;
    } else if (fileType == XBinary::FT_PDF) {
        SpecAbstract::PDFINFO_STRUCT pdf_info = SpecAbstract::getPDFInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pdf_info.basic_info;
    } else if (fileType == XBinary::FT_JPEG) {
        SpecAbstract::JPEGINFO_STRUCT jpeg_info = SpecAbstract::getJpegInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jpeg_info.basic_info;
    } else if (fileType == XBinary::FT_COM) {
        SpecAbstract::COMINFO_STRUCT com_info = SpecAbstract::getCOMInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = com_info.basic_info;
    } else {
        SpecAbstract::BINARYINFO_STRUCT binary_info = SpecAbstract::getBinaryInfo(pDevice, fileType, parentId, pScanOptions, 0, pPdStruct);
        basic_info = binary_info.basic_info;
    }

    if (bAddUnknown) {
        if (!basic_info.listDetects.count()) {
            _SCANS_STRUCT ssUnknown = {};

            ssUnknown.type = SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name = SpecAbstract::RECORD_NAME_UNKNOWN;
            ssUnknown.bIsUnknown = true;

            basic_info.listDetects.append(scansToScan(&basic_info, &ssUnknown));
        }
    }

    QList<XScanEngine::SCANSTRUCT> listScanStructs = convert(&(basic_info.listDetects));

    if (pScanOptions->bIsSort) {
        sortRecords(&listScanStructs);
    }

    pScanResult->listRecords.append(listScanStructs);
    pScanResult->listDebugRecords.append(convertHeur(&(basic_info.listHeurs)));

    if (pScanID) {
        *pScanID = basic_info.id;
    }
}

QList<SpecAbstract::VCL_STRUCT> SpecAbstract::PE_getVCLstruct(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, bool bIs64,
                                                              XBinary::PDSTRUCT *pPdStruct)
{
    QList<VCL_STRUCT> listResult;

    XPE pe(pDevice, pOptions->bIsImage);

    qint64 _nOffset = nOffset;
    qint64 _nSize = nSize;

    qint32 nAddressSize = bIs64 ? 8 : 4;

    while ((_nSize > 0) && (XBinary::isPdStructNotCanceled(pPdStruct))) {
        qint64 nClassOffset = pe.find_array(_nOffset, _nSize, "\x07\x08\x54\x43\x6f\x6e\x74\x72\x6f\x6c", 10, pPdStruct);  // 0708'TControl'

        if (nClassOffset == -1) {
            break;
        }

        quint32 nDword = pe.read_uint32(nClassOffset + 10);
        qint64 nClassOffset2 = pe.addressToOffset(nDword);

        if (nClassOffset2 != -1) {
            for (qint32 i = 0; (i < 20) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                quint32 nValue = pe.read_uint32(nClassOffset2 - nAddressSize * (i + 1));

                if (nValue <= 0xFFFF) {
                    VCL_STRUCT record = {};

                    record.nValue = nValue;
                    record.nOffset = nAddressSize * (i + 1);
                    record.bIs64 = bIs64;

                    listResult.append(record);

                    break;
                }
            }
        }

        qint64 nDelta = (nClassOffset - _nOffset) + 1;

        _nOffset += nDelta;
        _nSize -= nDelta;
    }

    return listResult;
}

SpecAbstract::VCL_PACKAGEINFO SpecAbstract::PE_getVCLPackageInfo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, QList<XPE::RESOURCE_RECORD> *pListResources,
                                                                 XBinary::PDSTRUCT *pPdStruct)
{
    VCL_PACKAGEINFO result = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        XPE::RESOURCE_RECORD rh = pe.getResourceRecord(10, "PACKAGEINFO", pListResources);

        if ((rh.nOffset != -1) && (rh.nSize)) {
            qint64 nOffset = rh.nOffset;
            quint32 nFlags = pe.read_uint32(nOffset);

            quint32 _nFlags = nFlags & 0xFF00;

            if (_nFlags == 0) {
                result.nFlags = nFlags;
                nOffset += 4;
                result.nUnknown = pe.read_uint32(nOffset);

                if (result.nUnknown == 0) {
                    nOffset += 4;
                    result.nRequiresCount = pe.read_uint32(nOffset);
                    nOffset += 4;
                } else {
                    nOffset += 3;
                }

                qint32 nCount = result.nRequiresCount ? result.nRequiresCount : 1000;

                for (qint32 i = 0; (i < nCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (nOffset - rh.nOffset > rh.nSize) {
                        break;
                    }

                    VCL_PACKAGEINFO_MODULE vpm = VCL_PACKAGEINFO_MODULE();
                    vpm.nFlags = pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.nHashCode = pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.sName = pe.read_ansiString(nOffset);
                    nOffset += vpm.sName.length() + 1;

                    result.listModules.append(vpm);
                }
            }
        }
    }

    return result;
}
