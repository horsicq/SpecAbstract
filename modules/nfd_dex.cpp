#include "nfd_dex.h"

NFD_DEX::NFD_DEX(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : DEX_Script(pDex, filePart, pOptions, pPdStruct)
{
}
// Keep includes minimal; actual signature tables are defined below in this TU

// Local DEX signature tables moved from SpecAbstract/signatures.cpp
static NFD_Binary::STRING_RECORD g_DEX_string_records[]=
{
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_ALLATORIOBFUSCATOR,           "",                 "Demo"},                "ALLATORIxDEMO"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_EASYPROTECTOR,                "",                 ""},                    "com.easyprotector.android"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_QDBH,                         "",                 ""},                    "/qdbh"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_JIAGU,                        "",                 ""},                    "/.jiagu"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_BANGCLEPROTECTION,            "",                 ""},                    "apkFilePath"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_PANGXIE,                      "",                 ""},                    "PangXie"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_PANGXIE,                      "",                 ""},                    "nsecure"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_NAGAPTPROTECTION,             "",                 ""},                    "LIBRARY_DDOG"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_NAGAPTPROTECTION,             "",                 ""},                    "LIBRARY_FDOG"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_APKPROTECT,                   "",                 ""},                    "APKProtect"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_AESOBFUSCATOR,                "",                 ""},                    "AESObfuscator.java"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_MODGUARD,                     "1.2",              ""},                    "ModGuard - Protect Your Piracy v1.2 by ill420smoker"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_MODGUARD,                     "1.3",              ""},                    "ModGuard - Protect Your Piracy v1.3 by ill420smoker"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_KIWIVERSIONOBFUSCATOR,        "",                 ""},                    "Kiwi__Version__Obfuscator"},
};

static NFD_Binary::STRING_RECORD g_DEX_type_records[]=
{
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_TOOL,             XScanEngine::RECORD_NAME_APKTOOLPLUS,                  "",                 ""},                    "Lcom/linchaolong/apktoolplus/jiagu/utils/ApkToolPlus;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_LIBRARY,          XScanEngine::RECORD_NAME_UNICOMSDK,                    "",                 ""},                    "Lcom/unicom/dcLoader/Utils;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_ALIBABAPROTECTION,            "",                 ""},                    "Lcom/ali/mobisecenhance/StubApplication;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_BAIDUPROTECTION,              "",                 ""},                    "Lcom/baidu/protect/StubApplication;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_TENCENTPROTECTION,            "",                 ""},                    "Lcom/tencent/StubShell/TxAppEntry;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_SECNEO,                       "",                 ""},                    "Lcom/secneo/apkwrapper/ApplicationWrapper;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_LIAPP,                        "",                 ""},                    "Lcom/lockincomp/liapp/LiappClassLoader;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_VDOG,                         "",                 ""},                    "Lcom/vdog/Common;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_MEDUSAH,                      "",                 ""},                    "Lcom/seworks/medusah/MedusahDex;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_NQSHIELD,                     "",                 ""},                    "Lcom/nqshield/Common;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_YIDUN,                        "",                 ""},                    "La/_;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_YIDUN,                        "",                 ""},                    "Lcom/_;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_APPSOLID,                     "",                 ""},                    "Lweb/apache/sax/app;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_APKENCRYPTOR,                 "",                 ""},                    "Lcn/beingyi/sub/utils/Native;"},
	{{0, XBinary::FT_DEX,       XScanEngine::RECORD_TYPE_OBFUSCATOR,       XScanEngine::RECORD_NAME_PROGUARD,                     "",                 ""},                    "Lcom/google/android/gms/common/ProGuardCanary;"},
};

// Accessors
NFD_Binary::STRING_RECORD *NFD_DEX::getStringRecords()
{
	return g_DEX_string_records;
}

qint32 NFD_DEX::getStringRecordsSize()
{
	return sizeof(g_DEX_string_records);
}

NFD_Binary::STRING_RECORD *NFD_DEX::getTypeRecords()
{
	return g_DEX_type_records;
}

qint32 NFD_DEX::getTypeRecordsSize()
{
	return sizeof(g_DEX_type_records);
}
