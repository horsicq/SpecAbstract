#include "nfd_ne.h"

NFD_NE::NFD_NE(XNE *pNE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : NE_Script(pNE, filePart, pOptions, pPdStruct)
{
}

NFD_NE::NEINFO_STRUCT NFD_NE::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
									   XBinary::PDSTRUCT *pPdStruct)
{
	QElapsedTimer timer;
	timer.start();

	NEINFO_STRUCT result = {};

	XNE ne(pDevice, pOptions->bIsImage);

	if (ne.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
		result.basic_info = NFD_Binary::_initBasicInfo(&ne, parentId, pOptions, nOffset, pPdStruct);

		result.nEntryPointOffset = ne.getEntryPointOffset(&(result.basic_info.memoryMap));
		result.sEntryPointSignature = ne.getSignature(result.nEntryPointOffset, 150);

		result.nOverlayOffset = ne.getOverlayOffset(&(result.basic_info.memoryMap), pPdStruct);
		result.nOverlaySize = ne.getOverlaySize(&(result.basic_info.memoryMap), pPdStruct);
		if (result.nOverlaySize) {
			result.sOverlaySignature = ne.getSignature(result.nOverlayOffset, 150);
		}

		// Operation System
		{
			NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(ne.getFileFormatInfo(pPdStruct));
			result.basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(result.basic_info), &ssOperationSystem));
		}

		// Borland Turbo Linker (version from VI if available)
		{
			NFD_Binary::VI_STRUCT vi = NFD_Binary::get_TurboLinker_vi(pDevice, pOptions);
			if (vi.bIsValid) {
				NFD_Binary::SCANS_STRUCT ssLinker = {};
				ssLinker.nVariant = 0;
				ssLinker.fileType = XBinary::FT_MSDOS; // parity with previous implementation for NE block
				ssLinker.type = XScanEngine::RECORD_TYPE_LINKER;
				ssLinker.name = XScanEngine::RECORD_NAME_TURBOLINKER;
				ssLinker.sVersion = vi.sVersion;
				ssLinker.sInfo = vi.sInfo;
				result.basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(result.basic_info), &ssLinker));
			}
		}

		// Watcom C/C++ toolchain (compiler + linker)
		{
			NFD_Binary::VI_STRUCT vi = NFD_Binary::get_Watcom_vi(pDevice, pOptions, result.nEntryPointOffset, 0x100, pPdStruct);
			if (vi.bIsValid) {
				// Compiler
				NFD_Binary::SCANS_STRUCT ssCompiler = {};
				ssCompiler.nVariant = 0;
				ssCompiler.fileType = XBinary::FT_MSDOS;
				ssCompiler.type = XScanEngine::RECORD_TYPE_COMPILER;
				ssCompiler.name = static_cast<XScanEngine::RECORD_NAME>(vi.vValue.toUInt());
				ssCompiler.sVersion = vi.sVersion;
				ssCompiler.sInfo = vi.sInfo;
				result.basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(result.basic_info), &ssCompiler));

				// Linker
				NFD_Binary::SCANS_STRUCT ssLinker = {};
				ssLinker.nVariant = 0;
				ssLinker.fileType = XBinary::FT_MSDOS;
				ssLinker.type = XScanEngine::RECORD_TYPE_LINKER;
				ssLinker.name = XScanEngine::RECORD_NAME_WATCOMLINKER;
				result.basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(result.basic_info), &ssLinker));
			}
		}

		NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
	}

	result.basic_info.nElapsedTime = timer.elapsed();

	return result;
}
