#include "nfd_jar.h"

NFD_JAR::NFD_JAR(XZip *pZip, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : JAR_Script(pZip, filePart, pOptions, pPdStruct)
{
}

NFD_JAR::JARINFO_STRUCT NFD_JAR::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
										  XBinary::PDSTRUCT *pPdStruct)
{
	QElapsedTimer timer;
	timer.start();

	JARINFO_STRUCT result = {};

	XZip jar(pDevice);

	if (jar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
		result.basic_info = NFD_Binary::_initBasicInfo(&jar, parentId, pOptions, nOffset, pPdStruct);

		// Populate archive records and language flags similarly to ZIP path
		result.listArchiveRecords = jar.getRecords(20000, pPdStruct);

		// Kotlin/Java hints
		result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
						   XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);
		// Java presence heuristic
		result.bIsJava = XArchive::isArchiveRecordPresent("META-INF/MANIFEST.MF", &(result.listArchiveRecords), pPdStruct) ||
						 XArchive::isArchiveRecordPresent("module-info.class", &(result.listArchiveRecords), pPdStruct);

		// Operation System (JVM) result
		{
			NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(jar.getFileFormatInfo(pPdStruct));
			result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));
		}

		// Derive tools from meta-infos if available via manifest Created-By etc.
		// Inline minimal subset of Zip_handle_Metainfos for JAR context
		{
			Binary_Script::OPTIONS binOpts = NFD_Binary::toOptions(pOptions);
			JAR_Script js(&jar, parentId.filePart, &binOpts, pPdStruct);
			QString sCreatedBy = js.getManifestRecord("Created-By");
			QString sBuiltBy = js.getManifestRecord("Built-By");
			QString sAntVersion = js.getManifestRecord("Ant-Version");
			QString sBuiltJdk = js.getManifestRecord("Build-Jdk");
			QString sProtectedBy = js.getManifestRecord("Protected-By");

			if (sCreatedBy.contains("(Apple Inc.)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_APPLEJDK;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sCreatedBy.contains("(IBM Corporation)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_IBMJDK;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sCreatedBy.contains("(AdoptOpenJdk)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_OPENJDK;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			// Generic JDK tool with version
			if (sCreatedBy.contains("(Sun Microsystems Inc.)") || sCreatedBy.contains("(BEA Systems, Inc.)") || sCreatedBy.contains("(The FreeBSD Foundation)") ||
				sCreatedBy.contains("(Oracle Corporation)") || sCreatedBy.contains("(Apple Inc.)") || sCreatedBy.contains("(Google Inc.)") ||
				sCreatedBy.contains("(Jeroen Frijters)") || sCreatedBy.contains("(IBM Corporation)") || sCreatedBy.contains("(JetBrains s.r.o)") ||
				sCreatedBy.contains("(Alibaba)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_JDK;
				ss.sVersion = sCreatedBy.section(" ", 0, 0);
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sBuiltJdk != "") {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_JDK;
				ss.sVersion = sBuiltJdk;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sAntVersion.contains("Apache Ant")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_APACHEANT;
				ss.sVersion = XBinary::regExp("Apache Ant (.*?)$", sAntVersion, 1);
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sCreatedBy.contains("(JetBrains s.r.o)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_JETBRAINS;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sCreatedBy.contains("(Jeroen Frijters)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_IKVMDOTNET;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			if (sCreatedBy.contains("(BEA Systems, Inc.)")) {
				NFD_Binary::SCANS_STRUCT ss = {};
				ss.nVariant = 0; ss.fileType = XBinary::FT_JAR; ss.type = XScanEngine::RECORD_TYPE_TOOL; ss.name = XScanEngine::RECORD_NAME_BEAWEBLOGIC;
				result.basic_info.mapMetainfosDetects.insert(ss.name, ss);
			}
			// Promotion to result tools similar to Zip_handle_JAR
			const XScanEngine::RECORD_NAME names[] = {XScanEngine::RECORD_NAME_JDK,         XScanEngine::RECORD_NAME_APPLEJDK,
													 XScanEngine::RECORD_NAME_IBMJDK,      XScanEngine::RECORD_NAME_OPENJDK,
													 XScanEngine::RECORD_NAME_JETBRAINS,   XScanEngine::RECORD_NAME_IKVMDOTNET,
													 XScanEngine::RECORD_NAME_BEAWEBLOGIC};
			for (XScanEngine::RECORD_NAME name : names) {
				if (result.basic_info.mapMetainfosDetects.contains(name)) {
					auto ss = result.basic_info.mapMetainfosDetects.value(name);
					result.basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(result.basic_info), &ss));
				}
			}
		}

		NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
	}

	result.basic_info.nElapsedTime = timer.elapsed();

	return result;
}
