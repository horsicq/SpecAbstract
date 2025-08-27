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
#include "nfd_binary.h"
#include "xscanengine.h"
#include "specabstract.h"

NFD_Binary::NFD_Binary(XBinary *pBinary, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Binary_Script(pBinary, filePart, pOptions, pPdStruct)
{
}

QString NFD_Binary::_SCANS_STRUCT_toString(const SCANS_STRUCT *pScanStruct, bool bShowType)
{
    QString sResult;

    if (pScanStruct->bIsHeuristic) {
        sResult += "(Heur)";
    }

    if (bShowType) {
        sResult += QString("%1: ").arg(XScanEngine::translateType(XScanEngine::recordTypeIdToString(pScanStruct->type)));
    }

    sResult += QString("%1").arg(XScanEngine::recordNameIdToString(pScanStruct->name));

    if (pScanStruct->sVersion != "") {
        sResult += QString("(%1)").arg(pScanStruct->sVersion);
    }

    if (pScanStruct->sInfo != "") {
        sResult += QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

NFD_Binary::SCAN_STRUCT NFD_Binary::scansToScan(NFD_Binary::BASIC_INFO *pBasicInfo, NFD_Binary::SCANS_STRUCT *pScansStruct)
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

    return result;
}

NFD_Binary::SCANS_STRUCT NFD_Binary::detectOperationSystem(XBinary *pBinary, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pBinary) {
        SCANS_STRUCT unknown = {};
        unknown.type = XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;
        unknown.name = XScanEngine::RECORD_NAME_UNKNOWN;
        unknown.bIsUnknown = true;
        return unknown;
    }

    XBinary::FILEFORMATINFO ffi = pBinary->getFileFormatInfo(pPdStruct);

    SCANS_STRUCT result = {};

    // Type: OS vs VM
    result.type = ffi.bIsVM ? XScanEngine::RECORD_TYPE_VIRTUALMACHINE : XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;

    // File type context
    result.fileType = ffi.fileType;

    // Map known OS names (extendable)
    if (ffi.osName == XBinary::OSNAME_AMIGA) {
        result.name = XScanEngine::RECORD_NAME_AMIGA;
    } else if (ffi.osName == XBinary::OSNAME_AROS) {
        result.name = XScanEngine::RECORD_NAME_AROS;
    } else {
        result.name = XScanEngine::RECORD_NAME_UNKNOWN;
        result.bIsUnknown = true;
    }

    // Version and info
    result.sVersion = ffi.sOsVersion;
    result.sInfo = QString("%1, %2, %3").arg(ffi.sArch, XBinary::modeIdToString(ffi.mode), ffi.sType);
    if (ffi.endian == XBinary::ENDIAN_BIG) {
        result.sInfo.append(QString(", %1").arg(XBinary::endianToString(XBinary::ENDIAN_BIG)));
    }

    // Flags
    result.bIsHeuristic = false;

    return result;
}

// Moved helpers from SpecAbstract into NFD_Binary (static)
NFD_Binary::BASIC_INFO NFD_Binary::_initBasicInfo(XBinary *pBinary, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                  XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)
    NFD_Binary::BASIC_INFO result = {};

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

void NFD_Binary::_handleResult(NFD_Binary::BASIC_INFO *pBasic_info, XBinary::PDSTRUCT *pPdStruct)
{
    // Aggregate languages from multiple maps
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

void NFD_Binary::getLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages,
                             XBinary::PDSTRUCT *pPdStruct)
{
    QMapIterator<XScanEngine::RECORD_NAME, SCAN_STRUCT> i(*pMapDetects);
    while (i.hasNext() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        i.next();

        SCAN_STRUCT ssDetect = i.value();
        SCANS_STRUCT ssLanguage = {};
        ssLanguage.type = XScanEngine::RECORD_TYPE_LANGUAGE;
        ssLanguage.name = XScanEngine::RECORD_NAME_UNKNOWN;

        switch (ssDetect.name) {
            case XScanEngine::RECORD_NAME_C:
            case XScanEngine::RECORD_NAME_ARMC:
            case XScanEngine::RECORD_NAME_LCCLNK:
            case XScanEngine::RECORD_NAME_LCCWIN:
            case XScanEngine::RECORD_NAME_MICROSOFTC:
            case XScanEngine::RECORD_NAME_THUMBC:
            case XScanEngine::RECORD_NAME_TINYC:
            case XScanEngine::RECORD_NAME_TURBOC:
            case XScanEngine::RECORD_NAME_WATCOMC: ssLanguage.name = XScanEngine::RECORD_NAME_C; break;
            case XScanEngine::RECORD_NAME_CCPP:
            case XScanEngine::RECORD_NAME_ARMCCPP:
            case XScanEngine::RECORD_NAME_ARMNEONCCPP:
            case XScanEngine::RECORD_NAME_ARMTHUMBCCPP:
            case XScanEngine::RECORD_NAME_BORLANDCCPP:
            case XScanEngine::RECORD_NAME_MINGW:
            case XScanEngine::RECORD_NAME_MSYS:
            case XScanEngine::RECORD_NAME_MSYS2:
            case XScanEngine::RECORD_NAME_VISUALCCPP:
            case XScanEngine::RECORD_NAME_OPENWATCOMCCPP:
            case XScanEngine::RECORD_NAME_WATCOMCCPP: ssLanguage.name = XScanEngine::RECORD_NAME_CCPP; break;
            case XScanEngine::RECORD_NAME_CLANG:
            case XScanEngine::RECORD_NAME_GCC:
            case XScanEngine::RECORD_NAME_ALIPAYCLANG:
            case XScanEngine::RECORD_NAME_ANDROIDCLANG:
            case XScanEngine::RECORD_NAME_APPORTABLECLANG:
            case XScanEngine::RECORD_NAME_PLEXCLANG:
            case XScanEngine::RECORD_NAME_UBUNTUCLANG:
            case XScanEngine::RECORD_NAME_DEBIANCLANG:
                if (ssDetect.sInfo.contains("Objective-C")) {
                    ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTIVEC;
                } else {
                    ssLanguage.name = XScanEngine::RECORD_NAME_CCPP;
                }
                break;
            case XScanEngine::RECORD_NAME_CPP:
            case XScanEngine::RECORD_NAME_BORLANDCPP:
            case XScanEngine::RECORD_NAME_BORLANDCPPBUILDER:
            case XScanEngine::RECORD_NAME_CODEGEARCPP:
            case XScanEngine::RECORD_NAME_CODEGEARCPPBUILDER:
            case XScanEngine::RECORD_NAME_EMBARCADEROCPP:
            case XScanEngine::RECORD_NAME_EMBARCADEROCPPBUILDER:
            case XScanEngine::RECORD_NAME_MICROSOFTCPP:
            case XScanEngine::RECORD_NAME_TURBOCPP: ssLanguage.name = XScanEngine::RECORD_NAME_CPP; break;
            case XScanEngine::RECORD_NAME_ASSEMBLER:
            case XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER:
            case XScanEngine::RECORD_NAME_GNUASSEMBLER: ssLanguage.name = XScanEngine::RECORD_NAME_ASSEMBLER; break;
            case XScanEngine::RECORD_NAME_FASM:
            case XScanEngine::RECORD_NAME_GOASM:
            case XScanEngine::RECORD_NAME_MASM:
            case XScanEngine::RECORD_NAME_MASM32:
            case XScanEngine::RECORD_NAME_NASM: ssLanguage.name = XScanEngine::RECORD_NAME_X86ASSEMBLER; break;
            case XScanEngine::RECORD_NAME_AUTOIT: ssLanguage.name = XScanEngine::RECORD_NAME_AUTOIT; break;
            case XScanEngine::RECORD_NAME_OBJECTPASCAL:
            case XScanEngine::RECORD_NAME_LAZARUS:
            case XScanEngine::RECORD_NAME_FPC:
            case XScanEngine::RECORD_NAME_VIRTUALPASCAL:
            case XScanEngine::RECORD_NAME_IBMPCPASCAL: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTPASCAL; break;
            case XScanEngine::RECORD_NAME_BORLANDDELPHI:
            case XScanEngine::RECORD_NAME_BORLANDDELPHIDOTNET:
            case XScanEngine::RECORD_NAME_BORLANDOBJECTPASCALDELPHI:
            case XScanEngine::RECORD_NAME_CODEGEARDELPHI:
            case XScanEngine::RECORD_NAME_CODEGEAROBJECTPASCALDELPHI:
            case XScanEngine::RECORD_NAME_EMBARCADERODELPHI:
            case XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET:
            case XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTPASCALDELPHI; break;
            case XScanEngine::RECORD_NAME_D:
            case XScanEngine::RECORD_NAME_DMD:
            case XScanEngine::RECORD_NAME_DMD32:
            case XScanEngine::RECORD_NAME_LDC: ssLanguage.name = XScanEngine::RECORD_NAME_D; break;
            case XScanEngine::RECORD_NAME_CSHARP:
            case XScanEngine::RECORD_NAME_DOTNET: ssLanguage.name = XScanEngine::RECORD_NAME_CSHARP; break;
            case XScanEngine::RECORD_NAME_GO: ssLanguage.name = XScanEngine::RECORD_NAME_GO; break;
            case XScanEngine::RECORD_NAME_JAVA:
            case XScanEngine::RECORD_NAME_JVM:
            case XScanEngine::RECORD_NAME_JDK:
            case XScanEngine::RECORD_NAME_OPENJDK:
            case XScanEngine::RECORD_NAME_IBMJDK:
            case XScanEngine::RECORD_NAME_APPLEJDK: ssLanguage.name = XScanEngine::RECORD_NAME_JAVA; break;
            case XScanEngine::RECORD_NAME_JSCRIPT: ssLanguage.name = XScanEngine::RECORD_NAME_ECMASCRIPT; break;
            case XScanEngine::RECORD_NAME_KOTLIN: ssLanguage.name = XScanEngine::RECORD_NAME_KOTLIN; break;
            case XScanEngine::RECORD_NAME_FORTRAN:
            case XScanEngine::RECORD_NAME_LAYHEYFORTRAN90: ssLanguage.name = XScanEngine::RECORD_NAME_FORTRAN; break;
            case XScanEngine::RECORD_NAME_NIM: ssLanguage.name = XScanEngine::RECORD_NAME_NIM; break;
            case XScanEngine::RECORD_NAME_OBJECTIVEC: ssLanguage.name = XScanEngine::RECORD_NAME_OBJECTIVEC; break;
            case XScanEngine::RECORD_NAME_BASIC:
            case XScanEngine::RECORD_NAME_BASIC4ANDROID:
            case XScanEngine::RECORD_NAME_POWERBASIC:
            case XScanEngine::RECORD_NAME_PUREBASIC:
            case XScanEngine::RECORD_NAME_TURBOBASIC:
            case XScanEngine::RECORD_NAME_VBNET:
            case XScanEngine::RECORD_NAME_VISUALBASIC: ssLanguage.name = XScanEngine::RECORD_NAME_BASIC; break;
            case XScanEngine::RECORD_NAME_RUST: ssLanguage.name = XScanEngine::RECORD_NAME_RUST; break;
            case XScanEngine::RECORD_NAME_RUBY: ssLanguage.name = XScanEngine::RECORD_NAME_RUBY; break;
            case XScanEngine::RECORD_NAME_PYTHON:
            case XScanEngine::RECORD_NAME_PYINSTALLER: ssLanguage.name = XScanEngine::RECORD_NAME_PYTHON; break;
            case XScanEngine::RECORD_NAME_SWIFT: ssLanguage.name = XScanEngine::RECORD_NAME_SWIFT; break;
            case XScanEngine::RECORD_NAME_PERL: ssLanguage.name = XScanEngine::RECORD_NAME_PERL; break;
            case XScanEngine::RECORD_NAME_ZIG: ssLanguage.name = XScanEngine::RECORD_NAME_ZIG; break;
            case XScanEngine::RECORD_NAME_QML: ssLanguage.name = XScanEngine::RECORD_NAME_QML; break;
            default: ssLanguage.name = XScanEngine::RECORD_NAME_UNKNOWN;
        }

        if (ssLanguage.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            SCAN_STRUCT ss = ssDetect;
            ss.type = ssLanguage.type;
            ss.name = ssLanguage.name;
            ss.sInfo = "";
            ss.sVersion = "";
            pMapLanguages->insert(ss.name, ss);
        }
    }
}

void NFD_Binary::fixLanguage(QMap<XScanEngine::RECORD_NAME, SCAN_STRUCT> *pMapLanguages)
{
    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_C) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CPP)) {
        SCAN_STRUCT ss = pMapLanguages->value(XScanEngine::RECORD_NAME_C);
        ss.name = XScanEngine::RECORD_NAME_CCPP;
        pMapLanguages->insert(ss.name, ss);
    }

    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_C) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CCPP)) {
        pMapLanguages->remove(XScanEngine::RECORD_NAME_C);
    }

    if (pMapLanguages->contains(XScanEngine::RECORD_NAME_CPP) && pMapLanguages->contains(XScanEngine::RECORD_NAME_CCPP)) {
        pMapLanguages->remove(XScanEngine::RECORD_NAME_CPP);
    }
}

NFD_Binary::SCANS_STRUCT NFD_Binary::getFormatScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    SCANS_STRUCT result = {};
    result.type = XScanEngine::RECORD_TYPE_FORMAT;
    if (fileFormatInfo.fileType == XBinary::FT_PDF) result.name = XScanEngine::RECORD_NAME_PDF;
    else if (fileFormatInfo.fileType == XBinary::FT_JPEG) result.name = XScanEngine::RECORD_NAME_JPEG;
    else if (fileFormatInfo.fileType == XBinary::FT_CFBF) result.name = XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND;
    else result.name = XScanEngine::RECORD_NAME_UNKNOWN;
    result.sVersion = fileFormatInfo.sVersion;
    result.sInfo = XBinary::getFileFormatInfoString(&fileFormatInfo);
    return result;
}

NFD_Binary::SCANS_STRUCT NFD_Binary::getOperationSystemScansStruct(const XBinary::FILEFORMATINFO &fileFormatInfo)
{
    SCANS_STRUCT result = {};
    result.type = fileFormatInfo.bIsVM ? XScanEngine::RECORD_TYPE_VIRTUALMACHINE : XScanEngine::RECORD_TYPE_OPERATIONSYSTEM;
    if (fileFormatInfo.osName == XBinary::OSNAME_MSDOS) result.name = XScanEngine::RECORD_NAME_MSDOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_POSIX) result.name = XScanEngine::RECORD_NAME_POSIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UNIX) result.name = XScanEngine::RECORD_NAME_UNIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_LINUX) result.name = XScanEngine::RECORD_NAME_LINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWS) result.name = XScanEngine::RECORD_NAME_WINDOWS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDOWSCE) result.name = XScanEngine::RECORD_NAME_WINDOWSCE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_XBOX) result.name = XScanEngine::RECORD_NAME_XBOX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS2) result.name = XScanEngine::RECORD_NAME_OS2;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS) result.name = XScanEngine::RECORD_NAME_MAC_OS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MAC_OS_X) result.name = XScanEngine::RECORD_NAME_MAC_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OS_X) result.name = XScanEngine::RECORD_NAME_OS_X;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACOS) result.name = XScanEngine::RECORD_NAME_MACOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPHONEOS) result.name = XScanEngine::RECORD_NAME_IPHONEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IPADOS) result.name = XScanEngine::RECORD_NAME_IPADOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IOS) result.name = XScanEngine::RECORD_NAME_IOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WATCHOS) result.name = XScanEngine::RECORD_NAME_WATCHOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TVOS) result.name = XScanEngine::RECORD_NAME_TVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BRIDGEOS) result.name = XScanEngine::RECORD_NAME_BRIDGEOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ANDROID) result.name = XScanEngine::RECORD_NAME_ANDROID;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FREEBSD) result.name = XScanEngine::RECORD_NAME_FREEBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENBSD) result.name = XScanEngine::RECORD_NAME_OPENBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NETBSD) result.name = XScanEngine::RECORD_NAME_NETBSD;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HPUX) result.name = XScanEngine::RECORD_NAME_HPUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SOLARIS) result.name = XScanEngine::RECORD_NAME_SOLARIS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AIX) result.name = XScanEngine::RECORD_NAME_AIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_IRIX) result.name = XScanEngine::RECORD_NAME_IRIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TRU64) result.name = XScanEngine::RECORD_NAME_TRU64;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MODESTO) result.name = XScanEngine::RECORD_NAME_MODESTO;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVMS) result.name = XScanEngine::RECORD_NAME_OPENVMS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_FENIXOS) result.name = XScanEngine::RECORD_NAME_FENIXOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_BORLANDOSSERVICES) result.name = XScanEngine::RECORD_NAME_BORLANDOSSERVICES;
    else if (fileFormatInfo.osName == XBinary::OSNAME_NSK) result.name = XScanEngine::RECORD_NAME_NSK;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AROS) result.name = XScanEngine::RECORD_NAME_AROS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_UBUNTULINUX) result.name = XScanEngine::RECORD_NAME_UBUNTULINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_DEBIANLINUX) result.name = XScanEngine::RECORD_NAME_DEBIANLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_STARTOSLINUX) result.name = XScanEngine::RECORD_NAME_STARTOSLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_GENTOOLINUX) result.name = XScanEngine::RECORD_NAME_GENTOOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ALPINELINUX) result.name = XScanEngine::RECORD_NAME_ALPINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_WINDRIVERLINUX) result.name = XScanEngine::RECORD_NAME_WINDRIVERLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUSELINUX) result.name = XScanEngine::RECORD_NAME_SUSELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MANDRAKELINUX) result.name = XScanEngine::RECORD_NAME_MANDRAKELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_ASPLINUX) result.name = XScanEngine::RECORD_NAME_ASPLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_REDHATLINUX) result.name = XScanEngine::RECORD_NAME_REDHATLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_HANCOMLINUX) result.name = XScanEngine::RECORD_NAME_HANCOMLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_TURBOLINUX) result.name = XScanEngine::RECORD_NAME_TURBOLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_VINELINUX) result.name = XScanEngine::RECORD_NAME_VINELINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SUNOS) result.name = XScanEngine::RECORD_NAME_SUNOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_OPENVOS) result.name = XScanEngine::RECORD_NAME_OPENVOS;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MCLINUX) result.name = XScanEngine::RECORD_NAME_MCLINUX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_QNX) result.name = XScanEngine::RECORD_NAME_QNX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SYLLABLE) result.name = XScanEngine::RECORD_NAME_SYLLABLE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MINIX) result.name = XScanEngine::RECORD_NAME_MINIX;
    else if (fileFormatInfo.osName == XBinary::OSNAME_JVM) result.name = XScanEngine::RECORD_NAME_JVM;
    else if (fileFormatInfo.osName == XBinary::OSNAME_AMIGA) result.name = XScanEngine::RECORD_NAME_AMIGA;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACCATALYST) result.name = XScanEngine::RECORD_NAME_MACCATALYST;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACDRIVERKIT) result.name = XScanEngine::RECORD_NAME_MACDRIVERKIT;
    else if (fileFormatInfo.osName == XBinary::OSNAME_MACFIRMWARE) result.name = XScanEngine::RECORD_NAME_MACFIRMWARE;
    else if (fileFormatInfo.osName == XBinary::OSNAME_SEPOS) result.name = XScanEngine::RECORD_NAME_SEPOS;
    else result.name = XScanEngine::RECORD_NAME_UNKNOWN;
    result.sVersion = fileFormatInfo.sOsVersion;
    result.sInfo = QString("%1, %2, %3").arg(fileFormatInfo.sArch, XBinary::modeIdToString(fileFormatInfo.mode), fileFormatInfo.sType);
    if (fileFormatInfo.endian == XBinary::ENDIAN_BIG) {
        result.sInfo.append(QString(", %1").arg(XBinary::endianToString(XBinary::ENDIAN_BIG)));
    }
    return result;
}

// Options conversion implementation (static)
Binary_Script::OPTIONS NFD_Binary::toOptions(const XScanEngine::SCAN_OPTIONS *pScanOptions)
{
    Binary_Script::OPTIONS opts = {};
    opts.bIsDeepScan = pScanOptions->bIsDeepScan;
    opts.bIsHeuristicScan = pScanOptions->bIsHeuristicScan;
    opts.bIsAggressiveScan = pScanOptions->bIsAggressiveScan;
    opts.bIsVerbose = pScanOptions->bIsVerbose;
    // Profiling is a runtime tracing option; default to false here
    opts.bIsProfiling = false;
    return opts;
}
