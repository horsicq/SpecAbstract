/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
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

NFD_MACH::NFD_MACH(XMACH *pMACH, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : MACH_Script(pMACH, filePart, pOptions, pPdStruct)
{
}

NFD_MACH::MACHOINFO_STRUCT NFD_MACH::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
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
			NFD_Binary::SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_MACHO, XScanEngine::RECORD_TYPE_SIGNTOOL, XScanEngine::RECORD_NAME_CODESIGN, "", "", 0);
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
				recordSDK.name = XScanEngine::RECORD_NAME_IOSSDK;

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
			recordSwift.sVersion = "5.XX";
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

			if (recordSDK.name == XScanEngine::RECORD_NAME_MACOSSDK) {
				if (recordSDK.sVersion == "10.3.0") {
					recordXcode.sVersion = "1.0-3.1.4";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion == "10.4.0") {
					recordXcode.sVersion = "2.0-3.2.6";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
					recordCLANG.sVersion = "1.0.2-1.7";
				} else if (recordSDK.sVersion == "10.5.0") {
					recordXcode.sVersion = "2.5-3.2.6";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
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
			} else if (recordSDK.name == XScanEngine::RECORD_NAME_IOSSDK) {
				if (recordSDK.sVersion == "1.0.0") {
					recordXcode.sVersion = "1.0.0-2.0.0";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion.section(".", 0, 0) == "1")  // TODO
				{
					recordXcode.sVersion = "1.0.0-2.0.0";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion == "2.0.0") {
					recordXcode.sVersion = "3.0.0-3.2.1";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion.section(".", 0, 0) == "2")  // TODO
				{
					recordXcode.sVersion = "3.0.0-3.2.1";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion.section(".", 0, 0) == "3")  // TODO
				{
					recordXcode.sVersion = "3.0.0-3.2.1";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion == "3.1.3") {
					recordXcode.sVersion = "3.1.3-3.2.1";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
				} else if (recordSDK.sVersion == "3.2.0") {
					recordXcode.sVersion = "3.2.2-3.2.4";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
					recordGCC.sVersion = "4.0-4.2";
					recordCLANG.sVersion = "1.0.2-1.5";
				} else if (recordSDK.sVersion == "4.0.0") {
					recordXcode.sVersion = "3.2.3";
					recordGCC.name = XScanEngine::RECORD_NAME_GCC;
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
			} else if (recordSDK.name == XScanEngine::RECORD_NAME_WATCHOSSDK) {
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
			} else if (recordSDK.name == XScanEngine::RECORD_NAME_TVOS) {
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

			NFD_Binary::SCANS_STRUCT recordSS = {};

			recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
			recordSS.name = XScanEngine::RECORD_NAME_QT;
			recordSS.sVersion = XBinary::get_uint32_full_version(lr.current_version);

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
				NFD_Binary::SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_MACHO, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ZIG, "", "", 0);

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
		if (pMACHInfo->basic_info.mapResultLanguages.contains(XScanEngine::RECORD_NAME_OBJECTIVEC) || pMACHInfo->basic_info.mapResultLanguages.contains(XScanEngine::RECORD_NAME_CCPP)) {
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
