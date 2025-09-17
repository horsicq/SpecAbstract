#include "nfd_elf.h"

// Add using declarations for types that were available in SpecAbstract namespace
using _SCANS_STRUCT = NFD_Binary::SCANS_STRUCT;
using VI_STRUCT = NFD_Binary::VI_STRUCT;

NFD_ELF::NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : ELF_Script(pELF, filePart, pOptions, pPdStruct)
{
}

// ELF entrypoint signature table (migrated from SpecAbstract/signatures.cpp)
static NFD_Binary::SIGNATURE_RECORD g_ELF_entrypoint_records[] = {
    {{0, XBinary::FT_ELF32, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BURNEYE, "1.00", ""}, "FF35........9C608B0D........E9"},
    };

NFD_Binary::SIGNATURE_RECORD *NFD_ELF::getEntrypointRecords()
{
    return g_ELF_entrypoint_records;
}

qint32 NFD_ELF::getEntrypointRecordsSize()
{
    return sizeof(g_ELF_entrypoint_records);
}

NFD_ELF::ELFINFO_STRUCT NFD_ELF::getELFInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
										 XBinary::PDSTRUCT *pPdStruct)
{
	QElapsedTimer timer;
	timer.start();

	ELFINFO_STRUCT result = {};

	XELF elf(pDevice, pOptions->bIsImage);

	if (elf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
		// Basic info
		result.basic_info = NFD_Binary::_initBasicInfo(&elf, parentId, pOptions, nOffset, pPdStruct);

		result.bIs64 = elf.is64();
		result.bIsBigEndian = elf.isBigEndian();
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

		// Format/OS contribution to maps via common helpers can be added by callers as needed.
		NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
	}

	result.basic_info.nElapsedTime = timer.elapsed();

	return result;
}

void NFD_ELF::handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
	XELF elf(pDevice, pOptions->bIsImage);

	if (elf.isValid(pPdStruct)) {
		_SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(elf.getFileFormatInfo(pPdStruct));

		pELFInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssOperationSystem));
	}
}

void NFD_ELF::handle_CommentSection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
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
			vi = NFD_Binary::_get_ByteGuard_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BYTEGUARD, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_GCC_string(sComment);  // TODO Max version

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_GCC, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AppleLLVM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_APPLELLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AndroidClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ANDROIDCLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AlipayClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ALIPAYCLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AlpineClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ALPINECLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AlibabaClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ALIBABACLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_PlexClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_PLEXCLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_UbuntuClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_UBUNTUCLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_DebianClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_DEBIANCLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ApportableClang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_APPORTABLECLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMAssembler_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMASSEMBLER, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMLinker_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LINKER, XScanEngine::RECORD_NAME_ARMLINKER, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMC_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMC, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMCCPP_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMCCPP, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMNEONCCPP_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMNEONCCPP, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMThumbCCPP_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMTHUMBCCPP, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ARMThumbMacroAssembler_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ThumbC_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_THUMBC, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_clang_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_CLANG, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_DynASM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_DYNASM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_Delphi_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_LLD_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LINKER, XScanEngine::RECORD_NAME_LLD, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_mold_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LINKER, XScanEngine::RECORD_NAME_MOLD, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_OracleSolarisLinkEditors_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LINKER, XScanEngine::RECORD_NAME_ORACLESOLARISLINKEDITORS, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_SunWorkShop_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_SUNWORKSHOP, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_SunWorkShopCompilers_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_SUNWORKSHOPCOMPILERS, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_SnapdragonLLVMARM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_SNAPDRAGONLLVMARM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_NASM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_NASM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_TencentLegu_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_AlipayObfuscator_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALIPAYOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_wangzehuaLLVM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_WANGZEHUALLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_ObfuscatorLLVM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_OBFUSCATORLLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_NagainLLVM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NAGAINLLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_iJiami_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMILLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_SafeengineLLVM_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SAFEENGINELLVM, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_TencentObfuscation_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTPROTECTION, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (!vi.bIsValid) {
			vi = NFD_Binary::_get_AppImage_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_APPIMAGE, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_HikariObfuscator_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HIKARIOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_SnapProtect_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SNAPPROTECT, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_ByteDanceSecCompiler_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BYTEDANCESECCOMPILER, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_DingbaozengNativeObfuscator_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_OllvmTll_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_OLLVMTLL, vi.sVersion, vi.sInfo, 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_SourceryCodeBench_string(sComment);

			if (vi.bIsValid) {
				if (vi.sInfo == "lite") {
					ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_SOURCERYCODEBENCHLITE, vi.sVersion, "", 0);
				} else {
					ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_SOURCERYCODEBENCH, vi.sVersion, "", 0);
				}

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		{
			vi = NFD_Binary::_get_Rust_string(sComment);

			if (vi.bIsValid) {
				ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_RUST, vi.sVersion, "", 0);

				pELFInfo->basic_info.mapCommentSectionDetects.insert(ss.name, ss);
			}
		}

		if (pELFInfo->basic_info.scanOptions.bIsTest && pELFInfo->basic_info.scanOptions.bIsVerbose) {
			if (ss.name == XScanEngine::RECORD_NAME_UNKNOWN) {
				if ((!vi.bIsValid) && (!XBinary::isRegExpPresent(".o$", sComment)) && (!XBinary::isRegExpPresent(".c$", sComment)) &&
					(!XBinary::isRegExpPresent(".S22$", sComment)) && (!XBinary::isRegExpPresent(".s$", sComment)) && (!XBinary::isRegExpPresent(".S$", sComment))) {
					_SCANS_STRUCT recordSS = {};

					recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
					recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + (XScanEngine::RECORD_NAME)(i + 1));
					recordSS.sVersion = "COMMENT:" + sComment;

					pELFInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
				}
			}
		}
	}
}

void NFD_ELF::handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
	XELF elf(pDevice, pOptions->bIsImage);

	if (elf.isValid(pPdStruct)) {
		// Qt
		if (XELF::isSectionNamePresent(".qtversion", &(pELFInfo->listSectionRecords))) {
			_SCANS_STRUCT recordSS = {};

			recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
			recordSS.name = XScanEngine::RECORD_NAME_QT;

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

			pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		} else if (XELF::isSectionNamePresent(".qtplugin", &(pELFInfo->listSectionRecords))) {
			XELF::SECTION_RECORD record = elf._getSectionRecords(&(pELFInfo->listSectionRecords), ".qtplugin").at(0);

			_SCANS_STRUCT recordSS = {};

			recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
			recordSS.name = XScanEngine::RECORD_NAME_QT;

			QString sVersionString = elf.read_ansiString(record.nOffset);
			recordSS.sVersion = XBinary::regExp("version=(.*?)\\\n", sVersionString, 1);

			pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		} else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt5Core.so.5", pPdStruct)) {
			_SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_QT, "5.X", "", 0);

			pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		} else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt6Core_x86.so", pPdStruct)) {
			_SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_QT, "6.X", "", 0);

			pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		} else if (XBinary::isStringInListPresent(&(pELFInfo->listLibraries), "libQt6Core.so.6", pPdStruct)) {
			_SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_QT, "6.X", "", 0);

			pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		}

		if (XELF::isNotePresent(&(pELFInfo->listNotes), "Android")) {
			XELF::NOTE note = XELF::getNote(&(pELFInfo->listNotes), "Android");

			_SCANS_STRUCT ssAndroidSDK = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_ANDROIDSDK, "", "", 0);
			_SCANS_STRUCT ssAndroidNDK = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_ANDROIDNDK, "", "", 0);

			if (note.nSize >= 4) {
				quint32 nSDKVersion = elf.read_uint32(note.nDataOffset);
				ssAndroidSDK.sVersion = QString("API %1(Android %2)").arg(QString::number(nSDKVersion), XBinary::getAndroidVersionFromApi(nSDKVersion));  // TODO
			}

			if (note.nSize >= 4 + 64 * 2) {
				QString sNdkVersion = elf.read_ansiString(note.nDataOffset + 4);
				QString sNdkBuild = elf.read_ansiString(note.nDataOffset + 4 + 64);

				ssAndroidNDK.sVersion = QString("%1(%2)").arg(sNdkVersion).arg(sNdkBuild);
			}

			pELFInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssAndroidSDK));
			pELFInfo->basic_info.mapResultTools.insert(ssAndroidNDK.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssAndroidNDK));
		}

		if (XELF::isNotePresent(&(pELFInfo->listNotes), "Go")) {
			_SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_GO, "", "", 0);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// gold
		if (XELF::isSectionNamePresent(".note.gnu.gold-version", &(pELFInfo->listSectionRecords))) {
			_SCANS_STRUCT recordSS = {};

			recordSS.type = XScanEngine::RECORD_TYPE_LINKER;
			recordSS.name = XScanEngine::RECORD_NAME_GOLD;

			XELF::SECTION_RECORD record = elf._getSectionRecords(&(pELFInfo->listSectionRecords), ".note.gnu.gold-version").at(0);

			VI_STRUCT vi = NFD_Binary::get_gold_vi(pDevice, pOptions, record.nOffset, record.nSize, pPdStruct);

			if (vi.bIsValid) {
				recordSS.sVersion = vi.sVersion;
			}

			pELFInfo->basic_info.mapResultLinkers.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		}

		// dotnet
		if (pELFInfo->sRunPath == "$ORIGIN/netcoredeps") {
			_SCANS_STRUCT recordSS = {};

			recordSS.type = XScanEngine::RECORD_TYPE_LOADER;
			recordSS.name = XScanEngine::RECORD_NAME_DOTNET;

			pELFInfo->basic_info.mapResultTools.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
		}

		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SOURCERYCODEBENCH)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SOURCERYCODEBENCH);

			pELFInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		} else if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SOURCERYCODEBENCHLITE)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SOURCERYCODEBENCHLITE);

			pELFInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_RUST)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_RUST);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_APPLELLVM)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_APPLELLVM);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Android clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ANDROIDCLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ANDROIDCLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Alipay clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ALIPAYCLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ALIPAYCLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Alpine clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ALPINECLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ALPINECLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Alibaba clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ALIBABACLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ALIBABACLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Plex clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_PLEXCLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_PLEXCLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Ubuntu clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_UBUNTUCLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_UBUNTUCLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Debian clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_DEBIANCLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_DEBIANCLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Apportable clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_APPORTABLECLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_APPORTABLECLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM Assembler
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMASSEMBLER)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMASSEMBLER);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM C
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMC)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMC);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM C/C++
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMCCPP)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMCCPP);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM NEON C/C++
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMNEONCCPP)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMNEONCCPP);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM/Thumb C/C++
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMTHUMBCCPP)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMTHUMBCCPP);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Thumb C
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_THUMBC)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_THUMBC);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM/Thumb Macro Assembler
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMTHUMBMACROASSEMBLER);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// ARM Linker
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ARMLINKER)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ARMLINKER);

			pELFInfo->basic_info.mapResultLinkers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// clang
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_CLANG)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_CLANG);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// DynASM
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_DYNASM)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_DYNASM);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Delphi
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI)) {
			_SCANS_STRUCT ssCompiler = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI);

			pELFInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssCompiler));

			_SCANS_STRUCT ssTool = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_EMBARCADERODELPHI,
												  NFD_Binary::_get_DelphiVersionFromCompiler(ssCompiler.sVersion).sVersion, "", 0);

			pELFInfo->basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssTool));
		}

		// LLD
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_LLD)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_LLD);

			pELFInfo->basic_info.mapResultLinkers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Oracle Solaris Link Editors
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ORACLESOLARISLINKEDITORS)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ORACLESOLARISLINKEDITORS);

			pELFInfo->basic_info.mapResultLinkers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Sun WorkShop
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SUNWORKSHOP)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SUNWORKSHOP);

			pELFInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Sun WorkShop Compilers
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SUNWORKSHOPCOMPILERS)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SUNWORKSHOPCOMPILERS);

			pELFInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// Snapdragon LLVM ARM
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SNAPDRAGONLLVMARM)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SNAPDRAGONLLVMARM);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		// NASM
		if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_NASM)) {
			_SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_NASM);

			pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
		}

		if (XELF::isSectionNamePresent(".rodata", &(pELFInfo->listSectionRecords))) {
			qint32 nIndex = XELF::getSectionNumber(".rodata", &(pELFInfo->listSectionRecords));

			qint64 nDataOffset = XELF::getElf_Shdr_offset(nIndex, &(pELFInfo->listSectionHeaders));
			qint64 nDataSize = XELF::getElf_Shdr_size(nIndex, &(pELFInfo->listSectionHeaders));

			VI_STRUCT viStruct = NFD_Binary::get_Zig_vi(pDevice, pOptions, nDataOffset, nDataSize, pPdStruct);

			if (viStruct.bIsValid) {
				_SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_ZIG, "", "", 0);

				ss.sVersion = viStruct.sVersion;
				ss.sInfo = viStruct.sInfo;

				pELFInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
			}
		}
	}
}

void NFD_ELF::handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        _SCANS_STRUCT recordCompiler = {};
        // GCC
        if (XELF::isSectionNamePresent(".gcc_except_table", &(pELFInfo->listSectionRecords)))  // TODO
        {
            recordCompiler.type = XScanEngine::RECORD_TYPE_COMPILER;
            recordCompiler.name = XScanEngine::RECORD_NAME_GCC;
        }

        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_GCC)) {
            recordCompiler = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_GCC);
        }

        if (recordCompiler.type != XScanEngine::RECORD_TYPE_UNKNOWN) {
            pELFInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordCompiler));
        }
    }
}

void NFD_ELF::handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        if (pELFInfo->nSymTabOffset > 0) {
            qint32 nNumberOfSymbols = elf.getNumberOfSymbols(pELFInfo->nSymTabOffset);

            if (nNumberOfSymbols) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_SYMBOLTABLE, "", "", 0);

                ss.sInfo = pELFInfo->listSectionRecords.at(pELFInfo->nSymTabSection).sName;
                ss.sInfo = XBinary::appendComma(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));

                pELFInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
            }
        }

        if (elf.isSectionNamePresent(".stab", &(pELFInfo->listSectionRecords)) && elf.isSectionNamePresent(".stabstr", &(pELFInfo->listSectionRecords))) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_STABSDEBUGINFO, "", "", 0);
            pELFInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        if (pELFInfo->nDWARFDebugOffset > 0) {
            VI_STRUCT viStruct = NFD_Binary::get_DWRAF_vi(pDevice, pOptions, pELFInfo->nDWARFDebugOffset, pELFInfo->nDWARFDebugSize, pPdStruct);

            if (viStruct.bIsValid) {
                _SCANS_STRUCT ssDebugInfo = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_DEBUGDATA, XScanEngine::RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                ssDebugInfo.sVersion = viStruct.sVersion;

                pELFInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ssDebugInfo));
            }
        }
    }
}

NFD_ELF::ELFINFO_STRUCT NFD_ELF::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                            XBinary::PDSTRUCT *pPdStruct)
{
    // Delegate the core ELF info extraction to NFD_ELF, then continue with SpecAbstract-specific handlers.
    ELFINFO_STRUCT result = NFD_ELF::getELFInfo(pDevice, parentId, pOptions, nOffset, pPdStruct);

    XELF elf(pDevice, pOptions->bIsImage);
    if (elf.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        // Keep existing SpecAbstract handlers that derive more detects from the core info
        NFD_Binary::signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, NFD_ELF::getEntrypointRecords(),
                                  NFD_ELF::getEntrypointRecordsSize(), result.basic_info.id.fileType, XBinary::FT_ELF, &(result.basic_info), DETECTTYPE_ENTRYPOINT,
                                  pPdStruct);

        NFD_ELF::handle_CommentSection(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_GCC(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_Tools(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_Protection(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_UnknownProtection(pDevice, pOptions, &result, pPdStruct);
        NFD_ELF::handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    return result;
}

void NFD_ELF::handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pELFInfo)

    XELF elf(pDevice, pOptions->bIsImage);

    if (elf.isValid(pPdStruct)) {
        // UPX
        VI_STRUCT viUPXEnd = NFD_Binary::_get_UPX_vi(pDevice, pOptions, pELFInfo->basic_info.id.nSize - 0x24, 0x24, XBinary::FT_ELF);
        VI_STRUCT viUPX = NFD_Binary::get_UPX_vi(pDevice, pOptions, 0, pELFInfo->basic_info.id.nSize, XBinary::FT_ELF, pPdStruct);

        if ((viUPXEnd.bIsValid) || (viUPX.bIsValid)) {
            _SCANS_STRUCT recordSS = {};

            recordSS.type = XScanEngine::RECORD_TYPE_PACKER;
            recordSS.name = XScanEngine::RECORD_NAME_UPX;

            if (viUPXEnd.sVersion != "") recordSS.sVersion = viUPXEnd.sVersion;
            if (viUPX.sVersion != "") recordSS.sVersion = viUPX.sVersion;

            if (viUPXEnd.sInfo != "") recordSS.sInfo = viUPXEnd.sInfo;
            if (viUPX.sInfo != "") recordSS.sInfo = viUPX.sInfo;

            pELFInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));
        }

        if (viUPXEnd.vValue.toUInt() == 0x21434553)  // SEC!
        {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "Old", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        } else if (viUPXEnd.vValue.toUInt() == 0x00010203) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        } else if (viUPXEnd.vValue.toUInt() == 0x214d4a41)  // "AJM!"
        {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", "UPX", 0);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Burneye
        if (pELFInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::RECORD_NAME_BURNEYE)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapEntryPointDetects.value(XScanEngine::RECORD_NAME_BURNEYE);

            qint64 _nOffset = 0x1000;
            qint64 _nSize = 0x200;

            qint64 nOffset_Id = elf.find_ansiString(_nOffset, _nSize, "TEEE burneye - TESO ELF Encryption Engine", pPdStruct);

            if (nOffset_Id == -1) {
                ss.sInfo = "Modified";
            }

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Obfuscator-LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_OBFUSCATORLLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_OBFUSCATORLLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // wangzehua LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_WANGZEHUALLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_WANGZEHUALLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Byteguard
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_BYTEGUARD)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_BYTEGUARD);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Alipay Obfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_ALIPAYOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_ALIPAYOBFUSCATOR);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Tencent Legu
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_TENCENTLEGU)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_TENCENTLEGU);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Safeengine LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SAFEENGINELLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SAFEENGINELLVM);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Tencent-Obfuscation
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_TENCENTPROTECTION)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_TENCENTPROTECTION);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // AppImage
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_APPIMAGE))  // Check overlay
        {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_APPIMAGE);
            pELFInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // HikariObfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_HIKARIOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_HIKARIOBFUSCATOR);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // SnapProtect
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_SNAPPROTECT)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_SNAPPROTECT);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // ByteDance-SecCompiler
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_BYTEDANCESECCOMPILER)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_BYTEDANCESECCOMPILER);
            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Dingbaozeng native obfuscator
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // Nagain LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_NAGAINLLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_NAGAINLLVM);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // iJiami LLVM
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_IJIAMILLVM)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_IJIAMILLVM);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        }

        // LLVM 6.0 + Ollvm + Armariris
        if (pELFInfo->basic_info.mapCommentSectionDetects.contains(XScanEngine::RECORD_NAME_OLLVMTLL)) {
            _SCANS_STRUCT ss = pELFInfo->basic_info.mapCommentSectionDetects.value(XScanEngine::RECORD_NAME_OLLVMTLL);

            pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
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
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VIRBOXPROTECTOR, "", "", 0);

                    pELFInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
                }

                break;
            }
        }
    }
}

void NFD_ELF::handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo,
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

                    recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("LIBRARY_") + pELFInfo->listLibraries.at(i);

                    pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }

            {
                XBinary::OS_STRING asInterpeter = elf.getProgramInterpreterName();

                if (asInterpeter.nSize) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("Interpreter_") + asInterpeter.sString;

                    pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }

            {
                QSet<QString> stRecords;

                qint32 nNumberOfRecords = pELFInfo->listComments.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (!stRecords.contains(pELFInfo->listComments.at(i))) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                        recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("COMMENT_") + pELFInfo->listComments.at(i);

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

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

                        recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                        recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("NOTE_") + pELFInfo->listNotes.at(i).sName;

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

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

                        recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                        recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("NOTE_TYPE_%1").arg(pELFInfo->listNotes.at(i).nType);

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

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

                        recordSS.type = XScanEngine::RECORD_TYPE_LIBRARY;
                        recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN9 + nIndex);
                        recordSS.sVersion = QString("SECTION_") + pELFInfo->listSectionRecords.at(i).sName;

                        pELFInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &recordSS));

                        stRecords.insert(pELFInfo->listSectionRecords.at(i).sName);

                        nIndex++;
                    }
                }
            }
        }
    }
}

void NFD_ELF::handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_ELF::ELFINFO_STRUCT *pELFInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pELFInfo->basic_info.mapResultCompilers.contains(XScanEngine::RECORD_NAME_GCC) || pELFInfo->basic_info.mapResultCompilers.contains(XScanEngine::RECORD_NAME_APPORTABLECLANG)) {
        if (pELFInfo->basic_info.mapResultCompilers.value(XScanEngine::RECORD_NAME_GCC).sVersion == "") {
            pELFInfo->basic_info.mapResultCompilers.remove(XScanEngine::RECORD_NAME_GCC);
        }
    }
}
