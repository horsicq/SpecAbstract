#include "nfd_msdos.h"

NFD_MSDOS::NFD_MSDOS(XMSDOS *pMSDOS, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : MSDOS_Script(pMSDOS, filePart, pOptions, pPdStruct)
{
}

static bool _nfd_msdos_compareRichRecord(NFD_Binary::SCANS_STRUCT *pResult, NFD_Binary::MSRICH_RECORD *pRecord, quint16 nID, quint32 nBuild, quint32 nCount,
										 XBinary::FT fileType1, XBinary::FT fileType2)
{
	bool bResult = false;

	if ((pRecord->basicInfo.fileType == fileType1) || (pRecord->basicInfo.fileType == fileType2)) {
		bool bCheck = false;

		bCheck = ((pRecord->nID == nID) || (pRecord->nID == (quint16)-1)) && ((pRecord->nBuild == nBuild) || (pRecord->nBuild == (quint32)-1));

		if (bCheck) {
			NFD_Binary::SCANS_STRUCT record = {};
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

			*pResult = record;
			bResult = true;
		}
	}

	return bResult;
}

void NFD_MSDOS::MSDOS_richScan(QMap<XScanEngine::RECORD_NAME, NFD_Binary::SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, quint32 nCount,
								NFD_Binary::MSRICH_RECORD *pRecords, qint32 nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2,
								NFD_Binary::BASIC_INFO *pBasicInfo, DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
	qint32 nSignaturesCount = nRecordsSize / (int)sizeof(NFD_Binary::MSRICH_RECORD);

	for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
		if ((!pMapRecords->contains(pRecords[i].basicInfo.name)) || (pBasicInfo->scanOptions.bShowInternalDetects)) {
			NFD_Binary::SCANS_STRUCT record = {};

			if (_nfd_msdos_compareRichRecord(&record, &(pRecords[i]), nID, nBuild, nCount, fileType1, fileType2)) {
				if (!pMapRecords->contains(pRecords[i].basicInfo.name)) {
					pMapRecords->insert(record.name, record);
				}

				if (pBasicInfo->scanOptions.bShowInternalDetects) {
					NFD_Binary::DETECT_RECORD heurRecord = {};

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

QList<NFD_Binary::SCANS_STRUCT> NFD_MSDOS::MSDOS_richScan(quint16 nID, quint32 nBuild, quint32 nCount, NFD_Binary::MSRICH_RECORD *pRecords, qint32 nRecordsSize,
														   XBinary::FT fileType1, XBinary::FT fileType2, NFD_Binary::BASIC_INFO *pBasicInfo,
														   DETECTTYPE detectType, XBinary::PDSTRUCT *pPdStruct)
{
	Q_UNUSED(pBasicInfo)
	Q_UNUSED(detectType)

	QList<NFD_Binary::SCANS_STRUCT> listResult;

	qint32 nSignaturesCount = nRecordsSize / (int)sizeof(NFD_Binary::MSRICH_RECORD);

	for (qint32 i = 0; (i < nSignaturesCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
		NFD_Binary::SCANS_STRUCT record = {};

		if (_nfd_msdos_compareRichRecord(&record, &(pRecords[i]), nID, nBuild, nCount, fileType1, fileType2)) {
			listResult.append(record);
		}
	}

	return listResult;
}

	// MSDOS linker header signature records (migrated from SpecAbstract/signatures.cpp)
	static NFD_Binary::SIGNATURE_RECORD g_MSDOS_linker_header_records[] =
	{
	{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_TURBOLINKER,                  "",                 ""},                    "'MZ'50000200000004000F00FFFF0000B80000000000000040001A000000000000000000000000000000000000000000000000000000000000000000....0000BA10000E1FB409CD21B8014CCD219090'This program must be run under Win'....'\r\n$'370000000000"},
	{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_TURBOLINKER,                  "",                 "Patched"},             "'MZ'............................................................................................................................BA10000E1FB409CD21B8014CCD219090'This program must be run under Win'....'\r\n$'370000000000"},
	//    {{1, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_TURBOLINKER,                  "",                 "MSDOS"},               "'MZ'........................................................FB..'jr'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_TURBOLINKER,                  "",                 ""},                    "'MZ'........................................................FB"},
	{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "",                 ""},                    "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000....00000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.\r\r\n$'00000000"},
	{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_GENERICLINKER,                "",                 ""},                    "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.\r\r\n$'00000000"},
	{{1, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_GENERICLINKER,                "",                 ""},                    "'MZ'78000100000004000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000780000000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.$'0000'PE'0000"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "",                 "Patched"},             "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000....000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
	};

	NFD_Binary::SIGNATURE_RECORD *NFD_MSDOS::getHeaderLinkerRecords() { return g_MSDOS_linker_header_records; }
	qint32 NFD_MSDOS::getHeaderLinkerRecordsSize() { return sizeof(g_MSDOS_linker_header_records); }

	// Generic MSDOS header signature records (migrated from SpecAbstract/signatures.cpp)
	static NFD_Binary::SIGNATURE_RECORD g_MSDOS_header_records[] =
	{
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYEXE,                       "4.0",              ""},                    "'MZ'....................................................'CryEXE 4.0 By Iosco^DaTo!'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_LSCRYPRT,                     "1.21",             ""},                    "'MZ'....................................................'L.S.    Crypt By'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_PACKWIN,                      "1.0",              ""},                    "'MZ'........................................................'YRZLITE (C) 1993 WYellow Rose'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PKLITE,                       "1.0",              ""},                    "'MZ'........................................................'PKLITE Copr. 1990 PKWARE Inc. All Rights Reserved'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PKLITE,                       "1.1",              ""},                    "'MZ'........................................................'PKLITE Copr. 1990-91 PKWARE Inc. All Rights Reserved'"}, // TODO Check Version
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PKLITE,                       "1.2",              ""},                    "'MZ'........................................................'PKLITE Copr. 1990-92 PKWARE Inc. All Rights Reserved'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_WWPACK,                       "",                 ""},                    "'MZ'....................................................'WWP'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_LZEXE,                        "0.90",             ""},                    "'MZ'....................................................'LZ09'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_LZEXE,                        "0.91",             ""},                    "'MZ'....................................................'LZ91'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_RJCRUSH,                      "1.00",             ""},                    "'MZ'....................................................'RJS1'"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_SFX,              XScanEngine::RECORD_NAME_LHASSFX,                      "2.11S",            ""},                    "'MZ'....................................................................'LHA'27's SFX 2.11S (c) Yoshi, 1991'"},
	};

	NFD_Binary::SIGNATURE_RECORD *NFD_MSDOS::getHeaderRecords() { return g_MSDOS_header_records; }
	qint32 NFD_MSDOS::getHeaderRecordsSize() { return sizeof(g_MSDOS_header_records); }

	// MSDOS entrypoint signature records (migrated from SpecAbstract/signatures.cpp)
	static NFD_Binary::SIGNATURE_RECORD g_MSDOS_entrypoint_records[]=
	{
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_IBMPCPASCAL,                  "1.00(1981)",       ""},                    "B8....8ED88C06....BA....D1EAB9....2BCAD1EA"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_IBMPCPASCAL,                  "2.00(1984)",       ""},                    "B8....8ED88C06....FA8ED0268B1E....2BD881FB....7E..BB....D1E3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_IBMPCPASCAL,                  "2.02(1987)",       ""},                    "2E8E1E....8CD08CDB2BC3D1E0"}, // TODO Check
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_IBMPCPASCAL,                  "2.05(1987)",       ""},                    "B8....8ED88BD08C06....268B1E....891E....2BD8F7C3....75..B1..D3E3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_PACKWIN,                      "1.0",              ""},                    "8CC0FA8ED0BC....FB060E1F2E8B0E....8BF14E8BFE8CDB2E031E....8EC3FDF3A453B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_WATCOMCCPP,                   "1994",             ""},                    "......'WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. '"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_WATCOMCCPP,                   "1995",             ""},                    "......'WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. '"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_WATCOMCCPP,                   "2.0",              ""},                    "EB....00'*** NULL assignment detected'00'"}, // TODO rename
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_DOSEXTENDER,      XScanEngine::RECORD_NAME_CAUSEWAY,                     "3.1X-3.4X",        ""},                    "FA161F26A1....83E8..8ED0FB061607BE....8BFEB9....F3A407368C......8BD88CCA3603......368B......FD8BC53D....76"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_LZEXE,                        "0.90",             ""},                    "060E1F8B0E....8BF14E89F78CDB03......8EC3B4..31EDFDAC01C5AAE2"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_LZEXE,                        "0.91",             ""},                    "060E1F8B0E....8BF14E89F78CDB03......8EC3FDF3A453B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_AINEXE,                       "2.1",              ""},                    "A1....2D....8ED0BC....8CD836A3....05....36A3....2EA1....8AD4B1..D2EAFEC9D3E08CD336"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_AINEXE,                       "2.3",              ""},                    "0E07B9....BE....33FFFCF3A4A1....2D....8ED0BC....8CD836......05....36......2E"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_AINEXE,                       "2.22",             ""},                    "A1....2D....8ED0BC....8CD836A3....05....36A3....2EA1....8AD4B1..D2EAD3E08CD3368B2E....2E032E....FDFECA"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PGMPAK,                       "0.13",             ""},                    "FA1E1750B430CD213C..73..B44CCD21FCBE....BF....E8....E8....BB....BA....8AC38BF3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PGMPAK,                       "0.15",             ""},                    "1E1750B430CD213C..73..B44CCD21FCBE....BF....E8....E8....BB....BA....8AC38BF3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_TURBOCPP,                     "1988",             ""},                    "BA....2E8916....B430CD218B2E....8B1E....8EDAA3....8C06....891E....892E....C43E....8BC78BD8"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_RJCRUSH,                      "1.00",             ""},                    "06FC8CC8BA....03D052BA....52BA....03C28BD805....8EDB8EC033F633FFB9"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_BAT2EXEC,                     "1.2",              ""},                    "FCBD....8B....8B......8B......B44ACD21A1....8986....8B9E....FFE3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_JAM,                          "2.21",             ""},                    "50061607BE....8BFEB9....FDFAF32EA5FB06BD....55CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_SFX,              XScanEngine::RECORD_NAME_PKZIPMINISFX,                 "1.1",              ""},                    "B8....A3....BF....B9....2BCF32C0F3AAB430CD21A3....A1....A3....E8....B8"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_SFX,              XScanEngine::RECORD_NAME_PKZIPMINISFX,                 "2.04",             ""},                    "B9....BF....2BCF32C0F3AAB430CD21A3....8926....E8....B8....E8....E8"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_AVPACK,                       "1.20",             ""},                    "501E0E1F160733F68BFEB9....FCF3A506BB....53CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_LGLZ,                         "1.04",             ""},                    "FC1E060E8CC80106....BA....03C28BD805....8EDB8EC033F633FFB9....F3A54B484A79..8EC38ED8BE....AD95B2..EA"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PROPACK,                      "2.08",             ""},                    "8CD38EC38CCA8EDA8B0E....8BF183EE..8BFED1..FDF3A553B8....508B......CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_PROPACK,                      "2.13-2.14",        ""},                    "0E8CD38EC38CCA8EDA8B......8BF183....8BFED1..FDF3A553B8....508B......03......CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_TINYPROG,                     "3.X",              ""},                    "83EC..83E4..8BEC50BE....0336....8CD28CD803....33C275..FC8EC233FF"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_UCEXE,                        "2.3",              ""},                    "501E0E1FFC33F6E8....160733F633FFB9....F3A506B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_UCEXE,                        "2.4",              ""},                    "501E0E1FFC2BF6E8....16072BF68BFEB9....F3A406B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_UCEXE,                        "3.0",              ""},                    "501E0E1FFC160733F633FFB9....F3A506B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CCBYVORONTSOV,                "1.00",             ""},                    "B8....BA....3BE073..B409BA....CD21B8....CD218BDC81EB....83E3..FCBE....8BFBB9....F3A48BC3B1..D3E88CC903C15033C050CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER,           "1.3",              ""},                    "1E8CDA83....8EDA8EC2BB....BA....85D274..B4..33FF33F6B9....AC32C4C0....02..2E........AAE2"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER,           "1.7",              ""},                    "0E179C58F6....74..E9....1EB0..E6..8CDA83....8EDA8EC2BB....BA....85D274..B4..33FF33F6B9"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER,           "2.0",              ""},                    "FA061E8CDD83C5..2E012E....2E012E....E8....E8....1F072E8E16....2E8B26....FB2EFF2E"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_UPX,                          "0.20-0.60",        ""},                    "8CCBB9....BE....89F71EA9....8D......8ED805....8EC0FDF3A5FC"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_UPX,                          "0.82-3.XX",        ""},                    "B9....BE....89F71EA9....8CC805....8ED805....8EC0FDF3A5FC2E........73..92AFAD0E0E"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_LOCKTITE,                     "",                 ""},                    "8CC88ED88CC381C3....8BC30306....8EC08B0E....8BF14E8BFEFDF3A450B8....50CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_PCOM,                         "2.8b2-2.8b3",      "-e -i"},               "BE....B9....2E8A0434..2E880446E2"},

		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_APACK,                        "0.90-0.99,XE_1.3-1.4", ""},                "1E068CCBBA....03DAFC33F633FF4B8EDB8D......8EC0B9....F3A54A75..8EC38ED833FFBE....05....0E50"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_APACK,                        "0.82",             ""},                    "1E068CCBBA....03DA8D87....FC33F633FF484B8EC08EDBB9....F3A54A75..8EC38ED833FFBE....05....0E50"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_APACK,                        "0.94",             "-m -d"},               "8CC88ED805....8EC050BE....33FFFCB2..BD....33C950A4FFD5"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_APACK,                        "0.98, 0.99",       "-t"},                  "1E060E1F0E07BE....BF....8BCFFC57F3A4C3"},
		// TODO More
	};

	static NFD_Binary::SIGNATURE_RECORD g_MSDOS_entrypointExp_records[]=
	{
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_BAT2EXEC,                     "1.5",              ""},                    "EB$$FCBD....8B....8B......8B......B44ACD21A1....8986....8B9E....FFE3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_SFX,              XScanEngine::RECORD_NAME_ICE,                          "1.0",              ""},                    "EB$$BE....8BFE8B0E....8B16....B8....50FCAD33C2AB8BD0E2"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_RELPACK,                      "1.0",              ""},                    "EB$$2E8C1E....2E8C06....8CC383C3..8CC88ED8BE....FCAD3D....75..AD3D....74..03C38EC0AD8BF826011DEB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_SCRNCH,                       "1.02",             ""},                    "EB$$BB....B44ACD2181EB....73..BA....B9....E9$$$$0E1FB440BB....CD21B8....CD21"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_TINYPROG,                     "3.X",              ""},                    "E9$$$$EB$$83EC..83E4..8BEC50BE....0336....8CD28CD803....33C275..FC8EC233FF"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_TINYPROG,                     "3.X",              ""},                    "EB$$83EC..83E4..8BEC50BE....0336....8CD28CD803....33C275..FC8EC233FF"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::RECORD_NAME_TINYPROG,                     "3.X",              ""},                    "E9$$$$2EC606......E9$$$$83EC..83E4..8BEC50BE............8CD28CD803....33C275..FC8EC233FF"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTCOM,                     "2.0",              ""},                    "E9$$$$BE....56B9....C704....C644....8134....4646E2..31F631C9C3"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER,           "1.7",              ""},                    "0E179C58F6....74..EB$$B0..E6..33C9E2..B430CD213C..73..33C00650CB"},
		{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_CRYPTORBYDISMEMBER,           "2.0",              ""},                    "E9$$$$BF....8BF7ACAD918AE157AC32C4F6D0D0C412E1AAE2"},
	};

	NFD_Binary::SIGNATURE_RECORD *NFD_MSDOS::getEntryPointRecords() { return g_MSDOS_entrypoint_records; }
	qint32 NFD_MSDOS::getEntryPointRecordsSize() { return sizeof(g_MSDOS_entrypoint_records); }
	NFD_Binary::SIGNATURE_RECORD *NFD_MSDOS::getEntryPointExpRecords() { return g_MSDOS_entrypointExp_records; }
	qint32 NFD_MSDOS::getEntryPointExpRecordsSize() { return sizeof(g_MSDOS_entrypointExp_records); }

		// Microsoft Rich signature records (migrated from SpecAbstract/signatures.cpp)
		static NFD_Binary::MSRICH_RECORD g_MS_rich_records[] =
		{
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "",                 ""},                    0x0001,         0},             // Linker generated import object version 0
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "5.10",             ""},                    0x0002,         (quint32)-1},   // LINK 5.10 (Visual Studio 97 SP3)
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "5.10",             ""},                    0x0003,         (quint32)-1},   // LINK 5.10 (Visual Studio 97 SP3) OMF to COFF conversion
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.00",             ""},                    0x0004,         (quint32)-1},   // LINK 6.00 (Visual Studio 98)
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.00",             ""},                    0x0005,         (quint32)-1},   // LINK 6.00 (Visual Studio 98) OMF to COFF conversion
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "5.00",             ""},                    0x0006,         (quint32)-1},   // CVTRES 5.00
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "11.00",            "Basic"},               0x0007,         (quint32)-1},   // VB 5.0 native code
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "11.00",            "C/C++"},               0x0008,         (quint32)-1},   // VC++ 5.0 C/C++
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "Basic"},               0x0009,         (quint32)-1},   // VB 6.0 native code
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C"},                   0x000a,         (quint32)-1},   // VC++ 6.0 C
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++"},                 0x000b,         (quint32)-1},   // VC++ 6.0 C++
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "6.00",             ""},                    0x000c,         (quint32)-1},   // ALIASOBJ.EXE (CRT Tool that builds OLDNAMES.LIB)
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_VISUALBASIC,                  "6.00",             ""},                    0x000d,         (quint32)-1},   // VB 6.0 generated object
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "6.13",             ""},                    0x000e,         (quint32)-1},   // MASM 6.13
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "7.01",             ""},                    0x000f,         (quint32)-1},   // MASM 7.01
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "5.11",             ""},                    0x0010,         (quint32)-1},   // LINK 5.11
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "5.11",             ""},                    0x0011,         (quint32)-1},   // LINK 5.11 OMF to COFF conversion
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "6.14",             "MMX2 support"},        0x0012,         (quint32)-1},   // MASM 6.14 (MMX2 support)
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "5.12",             ""},                    0x0013,         (quint32)-1},   // LINK 5.12
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "5.12",             ""},                    0x0014,         (quint32)-1},   // LINK 5.12 OMF to COFF conversion
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C/std"},               0x0015,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++/std"},             0x0016,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C/book"},              0x0017,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++/book"},            0x0018,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "7.00",             ""},                    0x0019,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "7.00",             ""},                    0x001a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "Basic"},               0x001b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C"},                   0x001c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C++"},                 0x001d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.10",             ""},                    0x001e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.10",             ""},                    0x001f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.01",             ""},                    0x0020,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.01",             ""},                    0x0021,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "Basic"},               0x0022,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "C"},                   0x0023,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "C++"},                 0x0024,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.20",             ""},                    0x0025,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.20",             ""},                    0x0026,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "7.00",             ""},                    0x0027,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.21",             ""},                    0x0028,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.21",             ""},                    0x0029,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "6.15",             ""},                    0x002a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "LTCG/C"},              0x002b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "LTCG/C++"},            0x002c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "6.20",             ""},                    0x002d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_ILASM,                        "1.00",             ""},                    0x002e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "Basic"},               0x002f,         (quint32)-1}, // 6.20 ???
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C"},                   0x0030,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++"},                 0x0031,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C/std"},               0x0032,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++/std"},             0x0033,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C/book"},              0x0034,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++/book"},            0x0035,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "6.22",             ""},                    0x0036,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.22",             ""},                    0x0037,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "5.01",             ""},                    0x0038,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C/std"},               0x0039,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C++/std"},             0x003a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "13.00",            ""},                    0x003b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.22",             ""},                    0x003c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "7.00",             ""},                    0x003d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "6.22",             ""},                    0x003e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "7.00",             ""},                    0x003f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "7.00",             ""},                    0x0040,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_I_C"},            0x0041,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_I_CPP"},          0x0042,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_O_C"},            0x0043,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_O_CPP"},          0x0044,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "7.00",             ""},                    0x0045,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "7.10p",            ""},                    0x0046,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "7.10p",            ""},                    0x0047,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "7.10p",            ""},                    0x0048,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "7.10p",            ""},                    0x0049,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "7.10p",            ""},                    0x004a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "7.10p",            ""},                    0x004b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C"},                   0x004c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C++"},                 0x004d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C/std"},               0x004e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C++/std"},             0x004f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "LTCG/C"},              0x0050,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "LTCG/C++"},            0x0051,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_I_C"},            0x0052,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_I_CPP"},          0x0053,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_O_C"},            0x0054,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_O_CPP"},          0x0055,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "6.24",             ""},                    0x0056,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "6.24",             ""},                    0x0057,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "6.24",             ""},                    0x0058,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "6.24",             ""},                    0x0059,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "7.10",             ""},                    0x005a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "7.10",             ""},                    0x005b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "7.10",             ""},                    0x005c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "7.10",             ""},                    0x005d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "7.10",             ""},                    0x005e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C"},                   0x005f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C++"},                 0x0060,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C/std"},               0x0061,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C++/std"},             0x0062,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "LTCG/C"},              0x0063,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "LTCG/C++"},            0x0064,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_I_C"},            0x0065,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_I_CPP"},          0x0066,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_O_C"},            0x0067,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_O_CPP"},          0x0068,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "7.10",             ""},                    0x0069,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "7.10p",            ""},                    0x006a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "13.10",            ""},                    0x006b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "13.10p",           ""},                    0x006c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C"},                   0x006d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C++"},                 0x006e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C/std"},               0x006f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C++/std"},             0x0070,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/C"},              0x0071,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/C++"},            0x0072,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_I_C"},            0x0073,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_I_CPP"},          0x0074,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_O_C"},            0x0075,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_O_CPP"},          0x0076,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "14.00",            ""},                    0x0077,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "8.00",             ""},                    0x0078,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTOMF,                       "8.00",             ""},                    0x0079,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "8.00",             ""},                    0x007a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "8.00",             ""},                    0x007b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "8.00",             ""},                    0x007c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "8.00",             ""},                    0x007d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "8.00",             ""},                    0x007e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "Prerelease",       ""},                    0x007f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "CVTCIL/C"},            0x0080,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "CVTCIL/C++"},          0x0081,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/MSIL"},           0x0082,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C"},                   0x0083,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C++"},                 0x0084,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C/std"},               0x0085,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C++/std"},             0x0086,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "CVTCIL/C"},            0x0087,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "CVTCIL/C++"},          0x0088,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/C"},              0x0089,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/C++"},            0x008a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/MSIL"},           0x008b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_I_C"},            0x008c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_I_CPP"},          0x008d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_O_C"},            0x008e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_O_CPP"},          0x008f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "15.00",            ""},                    0x0090,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "9.00",             ""},                    0x0091,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "9.00",             ""},                    0x0092,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "9.00",             ""},                    0x0093,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "9.00",             ""},                    0x0094,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "9.00",             ""},                    0x0095,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "9.00",             ""},                    0x0096,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_RESOURCE,                     "9.00",             ""},                    0x0097,         (quint32)-1}, // Manifest
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "10.00",            ""},                    0x0098,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "16.00",            ""},                    0x0099,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "10.00",            ""},                    0x009a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "10.00",            ""},                    0x009b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "10.00",            ""},                    0x009c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "10.00",            ""},                    0x009d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "10.00",            ""},                    0x009e,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "C"},                   0x009f,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "C++"},                 0x00a0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "CVTCIL/C"},            0x00a1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "CVTCIL/C++"},          0x00a2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/C"},              0x00a3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/C++"},            0x00a4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/MSIL"},           0x00a5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_I_C"},            0x00a6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_I_CPP"},          0x00a7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_O_C"},            0x00a8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_O_CPP"},          0x00a9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "C"},                   0x00aa,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "C++"},                 0x00ab,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "CVTCIL/C"},            0x00ac,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "CVTCIL/C++"},          0x00ad,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/C"},              0x00ae,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/C++"},            0x00af,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/MSIL"},           0x00b0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_I_C"},            0x00b1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_I_CPP"},          0x00b2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_O_C"},            0x00b3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_O_CPP"},          0x00b4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "10.10",            ""},                    0x00b5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "16.10",            ""},                    0x00b6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "10.10",            ""},                    0x00b7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "10.10",            ""},                    0x00b8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "10.10",            ""},                    0x00b9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "10.10",            ""},                    0x00ba,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "10.10",            ""},                    0x00bb,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "C"},                   0x00bc,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "C++"},                 0x00bd,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "CVTCIL/C"},            0x00be,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "CVTCIL/C++"},          0x00bf,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/C"},              0x00c0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/C++"},            0x00c1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/MSIL"},           0x00c2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_I_C"},            0x00c3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_I_CPP"},          0x00c4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_O_C"},            0x00c5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_O_CPP"},          0x00c6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "11.00",            ""},                    0x00c7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "17.00",            ""},                    0x00c8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "11.00",            ""},                    0x00c9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "11.00",            ""},                    0x00ca,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "11.00",            ""},                    0x00cb,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "11.00",            ""},                    0x00cc,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "11.00",            ""},                    0x00cd,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "C"},                   0x00ce,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "C++"},                 0x00cf,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "CVTCIL/C"},            0x00d0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "CVTCIL/C++"},          0x00d1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/C"},              0x00d2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/C++"},            0x00d3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/MSIL"},           0x00d4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_I_C"},            0x00d5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_I_CPP"},          0x00d6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_O_C"},            0x00d7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_O_CPP"},          0x00d8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "12.00",            ""},                    0x00d9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "18.00",            ""},                    0x00da,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "12.00",            ""},                    0x00db,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "12.00",            ""},                    0x00dc,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "12.00",            ""},                    0x00dd,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "12.00",            ""},                    0x00de,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "12.00",            ""},                    0x00df,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "C"},                   0x00e0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "C++"},                 0x00e1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "CVTCIL/C"},            0x00e2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "CVTCIL/C++"},          0x00e3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/C"},              0x00e4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/C++"},            0x00e5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/MSIL"},           0x00e6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_I_C"},            0x00e7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_I_CPP"},          0x00e8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_O_C"},            0x00e9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_O_CPP"},          0x00ea,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "12.10",            ""},                    0x00eb,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "18.10",            ""},                    0x00ec,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "12.10",            ""},                    0x00ed,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "12.10",            ""},                    0x00ee,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "12.10",            ""},                    0x00ef,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "12.10",            ""},                    0x00f0,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "12.10",            ""},                    0x00f1,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "C"},                   0x00f2,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "C++"},                 0x00f3,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "CVTCIL/C"},            0x00f4,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "CVTCIL/C++"},          0x00f5,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/C"},              0x00f6,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/C++"},            0x00f7,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/MSIL"},           0x00f8,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_I_C"},            0x00f9,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_I_CPP"},          0x00fa,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_O_C"},            0x00fb,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_O_CPP"},          0x00fc,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_ALIASOBJ,                     "14.00",            ""},                    0x00fd,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTPGD,                       "19.00",            ""},                    0x00fe,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_CVTRES,                       "14.00",            ""},                    0x00ff,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_EXPORT,                       "14.00",            ""},                    0x0100,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_IMPORT,                       "14.00",            ""},                    0x0101,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_LINKER,           XScanEngine::RECORD_NAME_MICROSOFTLINKER,              "14.00",            ""},                    0x0102,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_MASM,                         "14.00",            ""},                    0x0103,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "C"},                   0x0104,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "C++"},                 0x0105,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "CVTCIL/C"},            0x0106,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "CVTCIL/C++"},          0x0107,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/C"},              0x0108,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/C++"},            0x0109,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/MSIL"},           0x010a,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_I_C"},            0x010b,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_I_CPP"},          0x010c,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_O_C"},            0x010d,         (quint32)-1},
			{{0, XBinary::FT_MSDOS,     XScanEngine::RECORD_TYPE_COMPILER,         XScanEngine::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_O_CPP"},          0x010e,         (quint32)-1},
		};

		NFD_Binary::MSRICH_RECORD *NFD_MSDOS::getRichRecords() { return g_MS_rich_records; }
		qint32 NFD_MSDOS::getRichRecordsSize() { return sizeof(g_MS_rich_records); }
