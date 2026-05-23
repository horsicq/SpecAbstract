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
#include "nfd_mach.h"

NFD_MACH::NFD_MACH(XMACH *pMACH, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
    : MACH_Script(pMACH, filePart, scanOptions, pPdStruct)
{
}

NFD_MACH::MACHOINFO_STRUCT NFD_MACH::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                             XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    MACHOINFO_STRUCT result = {};

    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&mach, parentId, pOptions, nOffset, pPdStruct);

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

        NFD_MACH::handle_Tools(pDevice, pOptions, &result, pPdStruct);
        NFD_MACH::handle_Protection(pDevice, pOptions, &result, pPdStruct);

        NFD_MACH::handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

void NFD_MACH::handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_MACH::MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        QList<XMACH_DEF::build_tool_version> listBTV;

        NFD_Binary::SCANS_STRUCT recordSDK = {};
        recordSDK.type = XScanEngine::RECORD_TYPE_TOOL;
        recordSDK.name = XScanEngine::RECORD_NAME_UNKNOWN;

        NFD_Binary::SCANS_STRUCT recordXcode = {};

        recordXcode.type = XScanEngine::RECORD_TYPE_TOOL;
        recordXcode.name = XScanEngine::RECORD_NAME_UNKNOWN;

        NFD_Binary::SCANS_STRUCT recordGCC = {};
        recordGCC.type = XScanEngine::RECORD_TYPE_COMPILER;

        NFD_Binary::SCANS_STRUCT recordCLANG = {};
        recordCLANG.type = XScanEngine::RECORD_TYPE_COMPILER;

        NFD_Binary::SCANS_STRUCT recordSwift = {};
        recordSwift.type = XScanEngine::RECORD_TYPE_COMPILER;
        recordSwift.name = XScanEngine::RECORD_NAME_UNKNOWN;

        NFD_Binary::SCANS_STRUCT recordZig = {};
        recordZig.type = XScanEngine::RECORD_TYPE_COMPILER;
        recordZig.name = XScanEngine::RECORD_NAME_UNKNOWN;

        NFD_Binary::SCANS_STRUCT recordLD = {};
        recordLD.type = XScanEngine::RECORD_TYPE_LINKER;
        recordLD.name = XScanEngine::RECORD_NAME_UNKNOWN;

        XBinary::FILEFORMATINFO fileFormatInfo = mach.getFileFormatInfo(pPdStruct);

        NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(fileFormatInfo);

        pMACHInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &ssOperationSystem));

        if (mach.isCommandPresent(XMACH_DEF::S_LC_CODE_SIGNATURE, &(pMACHInfo->listCommandRecords))) {
            NFD_Binary::SCANS_STRUCT recordSS =
                NFD_Binary::getScansStruct(0, XBinary::FT_MACHO, XScanEngine::RECORD_TYPE_SIGNTOOL, XScanEngine::RECORD_NAME_CODESIGN, "", "", 0);
            // TODO more info
            pMACHInfo->basic_info.mapResultSigntools.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }

        // Foundation
        if (XMACH::isLibraryRecordNamePresent("Foundation", &(pMACHInfo->listLibraryRecords))) {
            NFD_Binary::SCANS_STRUCT recordFoundation = {};

            recordFoundation.type = XScanEngine::RECORD_TYPE_LIBRARY;
            recordFoundation.name = XScanEngine::RECORD_NAME_FOUNDATION;

            quint32 nVersion = XMACH::getLibraryCurrentVersion("Foundation", &(pMACHInfo->listLibraryRecords));

            if ((fileFormatInfo.osName == XBinary::OSNAME_MAC_OS_X) || (fileFormatInfo.osName == XBinary::OSNAME_OS_X) ||
                (fileFormatInfo.osName == XBinary::OSNAME_MACOS)) {
                recordSDK.name = XScanEngine::RECORD_NAME_MACOSSDK;
                recordSDK.sVersion = XMACH::getSDKVersionFromFoundation(nVersion, fileFormatInfo.osName);

                if (!recordSDK.sVersion.isEmpty()) {
                    fileFormatInfo.osName = XMACH::getExactOSName(fileFormatInfo.osName, recordSDK.sVersion);
                }
            } else if ((fileFormatInfo.osName == XBinary::OSNAME_IPHONEOS) || (fileFormatInfo.osName == XBinary::OSNAME_IOS) ||
                       (fileFormatInfo.osName == XBinary::OSNAME_IPADOS)) {
                recordSDK.name = XScanEngine::RECORD_NAME_IOSSDK;
                recordSDK.sVersion = XMACH::getSDKVersionFromFoundation(nVersion, fileFormatInfo.osName);

                if (!recordSDK.sVersion.isEmpty()) {
                    fileFormatInfo.osName = XMACH::getExactOSName(fileFormatInfo.osName, recordSDK.sVersion);
                }
            }

            QString sVersion = XBinary::get_uint32_full_version(nVersion);

            recordFoundation.sVersion = sVersion;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordFoundation.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordFoundation));
        }

        // GCC
        if (XMACH::isLibraryRecordNamePresent("libgcc_s.1.dylib", &(pMACHInfo->listLibraryRecords))) {
            recordGCC.name = XScanEngine::RECORD_NAME_GCC;
        }

        // Swift
        if (XMACH::isSectionNamePresent("__swift5_proto", &(pMACHInfo->listSectionRecords)) ||
            XMACH::isSectionNamePresent("__swift5_types", &(pMACHInfo->listSectionRecords))) {  // TODO Check
            recordSwift.name = XScanEngine::RECORD_NAME_SWIFT;
            // Version will be determined from SDK or build tools later
        } else if (XMACH::isSectionNamePresent("__swift2_proto", &(pMACHInfo->listSectionRecords)) ||
                   XMACH::isLibraryRecordNamePresent("libswiftCore.dylib", &(pMACHInfo->listLibraryRecords)))  // TODO
        {
            recordSwift.name = XScanEngine::RECORD_NAME_SWIFT;
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
            recordSDK.name = XScanEngine::RECORD_NAME_IOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_MACOSX, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_MACOSX, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = XScanEngine::RECORD_NAME_MACOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_TVOS, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_TVOS, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = XScanEngine::RECORD_NAME_TVOSSDK;
        } else if (mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS, &(pMACHInfo->listCommandRecords))) {
            nVersionMinOffset = mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS, 0, &(pMACHInfo->listCommandRecords));
            recordSDK.name = XScanEngine::RECORD_NAME_WATCHOSSDK;
        }

        if (nBuildVersionOffset != -1) {
            XMACH_DEF::build_version_command build_version = mach._read_build_version_command(nBuildVersionOffset);

            if (build_version.platform == XMACH_DEF::S_PLATFORM_MACOS) recordSDK.name = XScanEngine::RECORD_NAME_MACOSSDK;
            else if (build_version.platform == XMACH_DEF::S_PLATFORM_BRIDGEOS) recordSDK.name = XScanEngine::RECORD_NAME_BRIDGEOS;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_IOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_IOSSIMULATOR))
                recordSDK.name = XScanEngine::RECORD_NAME_IOSSDK;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_TVOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_TVOSSIMULATOR))
                recordSDK.name = XScanEngine::RECORD_NAME_TVOSSDK;
            else if ((build_version.platform == XMACH_DEF::S_PLATFORM_WATCHOS) || (build_version.platform == XMACH_DEF::S_PLATFORM_WATCHOSSIMULATOR))
                recordSDK.name = XScanEngine::RECORD_NAME_WATCHOSSDK;

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
        if (recordSDK.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            recordXcode.name = XScanEngine::RECORD_NAME_XCODE;

            // Use new SDK version lookup functions
            if (!recordSDK.sVersion.isEmpty()) {
                QString sXcodeVersion = XMACH::getXcodeVersionFromSDK(recordSDK.sVersion, fileFormatInfo.osName);
                if (!sXcodeVersion.isEmpty()) {
                    recordXcode.sVersion = sXcodeVersion;
                }

                QString sClangVersion = XMACH::getClangVersionFromSDK(recordSDK.sVersion, fileFormatInfo.osName);
                if (!sClangVersion.isEmpty()) {
                    recordCLANG.name = XScanEngine::RECORD_NAME_CLANG;
                    recordCLANG.sVersion = sClangVersion;
                }

                QString sSwiftVersion = XMACH::getSwiftVersionFromSDK(recordSDK.sVersion, fileFormatInfo.osName);
                if (!sSwiftVersion.isEmpty()) {
                    recordSwift.name = XScanEngine::RECORD_NAME_SWIFT;
                    recordSwift.sVersion = sSwiftVersion;
                }
            }
        }

        // Qt
        if (XMACH::isLibraryRecordNamePresent("QtCore", &(pMACHInfo->listLibraryRecords))) {
            XMACH::LIBRARY_RECORD lr = XMACH::getLibraryRecordByName("QtCore", &(pMACHInfo->listLibraryRecords));

            NFD_Binary::SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
            recordSS.name = XScanEngine::RECORD_NAME_QT;
            recordSS.sVersion = XBinary::get_uint32_full_version(lr.current_version);

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        } else if (XMACH::isSectionNamePresent(".qtmimedatabase", &(pMACHInfo->listSectionRecords))) {
            NFD_Binary::SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
            recordSS.name = XScanEngine::RECORD_NAME_QT;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
        // Carbon
        if (XMACH::isLibraryRecordNamePresent("Carbon", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Carbon");

            NFD_Binary::SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
            recordSS.name = XScanEngine::RECORD_NAME_CARBON;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
        // Cocoa
        if (XMACH::isLibraryRecordNamePresent("Cocoa", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Cocoa");

            NFD_Binary::SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
            recordSS.name = XScanEngine::RECORD_NAME_COCOA;

            pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }

        if (XMACH::isSectionNamePresent("__cstring", &(pMACHInfo->listSectionRecords))) {
            qint32 nIndex = XMACH::getSectionNumber("__cstring", &(pMACHInfo->listSectionRecords));

            qint64 nDataOffset = XMACH::getSectionFileOffset(nIndex, &(pMACHInfo->listSectionRecords));
            qint64 nDataSize = XMACH::getSectionFileSize(nIndex, &(pMACHInfo->listSectionRecords));

            NFD_Binary::VI_STRUCT viStruct = NFD_Binary::get_Zig_vi(pDevice, pOptions, nDataOffset, nDataSize, pPdStruct);

            if (viStruct.bIsValid) {
                NFD_Binary::SCANS_STRUCT ss =
                    NFD_Binary::getScansStruct(0, XBinary::FT_MACHO, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ZIG, "", "", 0);

                ss.sVersion = viStruct.sVersion;
                ss.sInfo = viStruct.sInfo;

                pMACHInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &ss));
            }
        }

        qint32 nNumberOfBT = listBTV.count();

        for (qint32 i = 0; i < nNumberOfBT; i++) {
            QString _sVersion = XBinary::get_uint32_full_version(listBTV.at(i).version);
            if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_SWIFT) {
                recordSwift.name = XScanEngine::RECORD_NAME_SWIFT;
                recordSwift.sVersion = _sVersion;
            } else if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_CLANG) {
                recordCLANG.name = XScanEngine::RECORD_NAME_CLANG;
                recordCLANG.sVersion = _sVersion;
            } else if (listBTV.at(i).tool == XMACH_DEF::S_TOOL_LD) {
                recordLD.name = XScanEngine::RECORD_NAME_XCODELINKER;
                recordLD.sVersion = _sVersion;
            }
        }

        if (recordLD.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultLinkers.insert(recordLD.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordLD));
        }

        if ((recordGCC.name == XScanEngine::RECORD_NAME_UNKNOWN) && (recordCLANG.name == XScanEngine::RECORD_NAME_UNKNOWN)) {
            recordCLANG.name = XScanEngine::RECORD_NAME_CLANG;  // Default
        }

        if (recordGCC.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordGCC.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordGCC));
        }

        if (recordCLANG.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordCLANG.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordCLANG));
        }

        if (recordSwift.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordSwift.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSwift));
        }

        if (recordZig.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultCompilers.insert(recordZig.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordZig));
        }

        if (recordSDK.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultTools.insert(recordSDK.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSDK));
        }

        if (recordXcode.name != XScanEngine::RECORD_NAME_UNKNOWN) {
            pMACHInfo->basic_info.mapResultTools.insert(recordXcode.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordXcode));
        }
    }
}

void NFD_MACH::handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_MACH::MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        // VMProtect
        if (XMACH::isLibraryRecordNamePresent("libVMProtectSDK.dylib", &(pMACHInfo->listLibraryRecords))) {
            //            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"libVMProtectSDK.dylib");

            NFD_Binary::SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
            recordSS.name = XScanEngine::RECORD_NAME_VMPROTECT;

            pMACHInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));
        }
    }
}

void NFD_MACH::handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_MACH::MACHOINFO_STRUCT *pMACHInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XMACH mach(pDevice, pOptions->bIsImage);

    if (mach.isValid(pPdStruct)) {
        if (pMACHInfo->basic_info.mapResultLanguages.contains(XScanEngine::RECORD_NAME_OBJECTIVEC) ||
            pMACHInfo->basic_info.mapResultLanguages.contains(XScanEngine::RECORD_NAME_CCPP)) {
            pMACHInfo->basic_info.mapResultLanguages.remove(XScanEngine::RECORD_NAME_CCPP);
        }

        if (pMACHInfo->basic_info.scanOptions.bIsTest && pMACHInfo->basic_info.scanOptions.bIsVerbose) {
            QSet<QString> stRecords;

            qint32 nNumberOfRecords = pMACHInfo->listLibraryRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (!stRecords.contains(pMACHInfo->listLibraryRecords.at(i).sName)) {
                    NFD_Binary::SCANS_STRUCT recordSS = {};

                    recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + i + 1);
                    recordSS.sVersion = pMACHInfo->listLibraryRecords.at(i).sName;
                    recordSS.sInfo = XBinary::get_uint32_full_version(pMACHInfo->listLibraryRecords.at(i).current_version);

                    pMACHInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pMACHInfo->basic_info), &recordSS));

                    stRecords.insert(pMACHInfo->listLibraryRecords.at(i).sName);
                }
            }
        }
    }
}
