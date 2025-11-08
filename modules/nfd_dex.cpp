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
#include "nfd_dex.h"

NFD_DEX::NFD_DEX(XDEX *pDex, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : DEX_Script(pDex, filePart, pOptions, pPdStruct)
{
}
// Keep includes minimal; actual signature tables are defined below in this TU

// Local DEX signature tables moved from SpecAbstract/signatures.cpp
static NFD_Binary::STRING_RECORD g_DEX_string_records[] = {
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALLATORIOBFUSCATOR, "", "Demo"}, "ALLATORIxDEMO"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_EASYPROTECTOR, "", ""}, "com.easyprotector.android"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_QDBH, "", ""}, "/qdbh"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "/.jiagu"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BANGCLEPROTECTION, "", ""}, "apkFilePath"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_PANGXIE, "", ""}, "PangXie"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_PANGXIE, "", ""}, "nsecure"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NAGAPTPROTECTION, "", ""}, "LIBRARY_DDOG"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NAGAPTPROTECTION, "", ""}, "LIBRARY_FDOG"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECT, "", ""}, "APKProtect"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_AESOBFUSCATOR, "", ""}, "AESObfuscator.java"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MODGUARD, "1.2", ""}, "ModGuard - Protect Your Piracy v1.2 by ill420smoker"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MODGUARD, "1.3", ""}, "ModGuard - Protect Your Piracy v1.3 by ill420smoker"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_KIWIVERSIONOBFUSCATOR, "", ""}, "Kiwi__Version__Obfuscator"},
};

static NFD_Binary::STRING_RECORD g_DEX_type_records[] = {
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_APKTOOLPLUS, "", ""}, "Lcom/linchaolong/apktoolplus/jiagu/utils/ApkToolPlus;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "Lcom/unicom/dcLoader/Utils;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALIBABAPROTECTION, "", ""}, "Lcom/ali/mobisecenhance/StubApplication;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "Lcom/baidu/protect/StubApplication;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTPROTECTION, "", ""}, "Lcom/tencent/StubShell/TxAppEntry;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "Lcom/secneo/apkwrapper/ApplicationWrapper;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_LIAPP, "", ""}, "Lcom/lockincomp/liapp/LiappClassLoader;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VDOG, "", ""}, "Lcom/vdog/Common;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MEDUSAH, "", ""}, "Lcom/seworks/medusah/MedusahDex;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NQSHIELD, "", ""}, "Lcom/nqshield/Common;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "La/_;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "Lcom/_;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPSOLID, "", ""}, "Lweb/apache/sax/app;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKENCRYPTOR, "", ""}, "Lcn/beingyi/sub/utils/Native;"},
    {{0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_OBFUSCATOR, XScanEngine::RECORD_NAME_PROGUARD, "", ""}, "Lcom/google/android/gms/common/ProGuardCanary;"},
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

void NFD_DEX::handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);

    if (!dex.isValid(pPdStruct)) {
        return;
    }

    NFD_Binary::SCANS_STRUCT recordAndroidSDK =
        NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_ANDROIDSDK, "", "", 0);
    QString sDDEXVersion = dex.getVersion();
    if (sDDEXVersion == "035") {
        recordAndroidSDK.sVersion = "API 14";
    } else if (sDDEXVersion == "037") {
        recordAndroidSDK.sVersion = "API 24";
    } else if (sDDEXVersion == "038") {
        recordAndroidSDK.sVersion = "API 26";
    } else if (sDDEXVersion == "039") {
        recordAndroidSDK.sVersion = "API 28";
    } else {
        recordAndroidSDK.sVersion = sDDEXVersion;
    }
    pDEXInfo->basic_info.mapResultTools.insert(recordAndroidSDK.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &recordAndroidSDK));

    NFD_Binary::SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(dex.getFileFormatInfo(pPdStruct));
    pDEXInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ssOperationSystem));

    // Compiler identification via map item patterns
    QList<quint16> listDx{XDEX_DEF::TYPE_HEADER_ITEM,
                          XDEX_DEF::TYPE_STRING_ID_ITEM,
                          XDEX_DEF::TYPE_TYPE_ID_ITEM,
                          XDEX_DEF::TYPE_PROTO_ID_ITEM,
                          XDEX_DEF::TYPE_FIELD_ID_ITEM,
                          XDEX_DEF::TYPE_METHOD_ID_ITEM,
                          XDEX_DEF::TYPE_CLASS_DEF_ITEM,
                          XDEX_DEF::TYPE_CALL_SITE_ID_ITEM,
                          XDEX_DEF::TYPE_METHOD_HANDLE_ITEM,
                          XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST,
                          XDEX_DEF::TYPE_ANNOTATION_SET_ITEM,
                          XDEX_DEF::TYPE_CODE_ITEM,
                          XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM,
                          XDEX_DEF::TYPE_TYPE_LIST,
                          XDEX_DEF::TYPE_STRING_DATA_ITEM,
                          XDEX_DEF::TYPE_DEBUG_INFO_ITEM,
                          XDEX_DEF::TYPE_ANNOTATION_ITEM,
                          XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM,
                          XDEX_DEF::TYPE_CLASS_DATA_ITEM,
                          XDEX_DEF::TYPE_MAP_LIST};

    QList<quint16> listDexLib{XDEX_DEF::TYPE_HEADER_ITEM,
                              XDEX_DEF::TYPE_STRING_ID_ITEM,
                              XDEX_DEF::TYPE_TYPE_ID_ITEM,
                              XDEX_DEF::TYPE_PROTO_ID_ITEM,
                              XDEX_DEF::TYPE_FIELD_ID_ITEM,
                              XDEX_DEF::TYPE_METHOD_ID_ITEM,
                              XDEX_DEF::TYPE_CLASS_DEF_ITEM,
                              XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST,
                              XDEX_DEF::TYPE_ANNOTATION_SET_ITEM,
                              XDEX_DEF::TYPE_CODE_ITEM,
                              XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM,
                              XDEX_DEF::TYPE_TYPE_LIST,
                              XDEX_DEF::TYPE_STRING_DATA_ITEM,
                              XDEX_DEF::TYPE_ANNOTATION_ITEM,
                              XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM,
                              XDEX_DEF::TYPE_CLASS_DATA_ITEM,
                              XDEX_DEF::TYPE_DEBUG_INFO_ITEM,
                              XDEX_DEF::TYPE_MAP_LIST};

    QList<quint16> listDexLib2{XDEX_DEF::TYPE_HEADER_ITEM,
                               XDEX_DEF::TYPE_STRING_ID_ITEM,
                               XDEX_DEF::TYPE_TYPE_ID_ITEM,
                               XDEX_DEF::TYPE_PROTO_ID_ITEM,
                               XDEX_DEF::TYPE_FIELD_ID_ITEM,
                               XDEX_DEF::TYPE_METHOD_ID_ITEM,
                               XDEX_DEF::TYPE_CLASS_DEF_ITEM,
                               XDEX_DEF::TYPE_CALL_SITE_ID_ITEM,
                               XDEX_DEF::TYPE_METHOD_HANDLE_ITEM,
                               XDEX_DEF::TYPE_STRING_DATA_ITEM,
                               XDEX_DEF::TYPE_TYPE_LIST,
                               XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM,
                               XDEX_DEF::TYPE_ANNOTATION_ITEM,
                               XDEX_DEF::TYPE_ANNOTATION_SET_ITEM,
                               XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST,
                               XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM,
                               XDEX_DEF::TYPE_DEBUG_INFO_ITEM,
                               XDEX_DEF::TYPE_CODE_ITEM,
                               XDEX_DEF::TYPE_CLASS_DATA_ITEM,
                               XDEX_DEF::TYPE_HIDDENAPI_CLASS_DATA_ITEM,
                               XDEX_DEF::TYPE_MAP_LIST};

    QList<quint16> listDexLib2heur{XDEX_DEF::TYPE_HEADER_ITEM,   XDEX_DEF::TYPE_STRING_ID_ITEM, XDEX_DEF::TYPE_TYPE_ID_ITEM,   XDEX_DEF::TYPE_PROTO_ID_ITEM,
                                   XDEX_DEF::TYPE_FIELD_ID_ITEM, XDEX_DEF::TYPE_METHOD_ID_ITEM, XDEX_DEF::TYPE_CLASS_DEF_ITEM, XDEX_DEF::TYPE_STRING_DATA_ITEM};

    QList<quint16> listR8{XDEX_DEF::TYPE_HEADER_ITEM,
                          XDEX_DEF::TYPE_STRING_ID_ITEM,
                          XDEX_DEF::TYPE_TYPE_ID_ITEM,
                          XDEX_DEF::TYPE_PROTO_ID_ITEM,
                          XDEX_DEF::TYPE_FIELD_ID_ITEM,
                          XDEX_DEF::TYPE_METHOD_ID_ITEM,
                          XDEX_DEF::TYPE_CLASS_DEF_ITEM,
                          XDEX_DEF::TYPE_CALL_SITE_ID_ITEM,
                          XDEX_DEF::TYPE_METHOD_HANDLE_ITEM,
                          XDEX_DEF::TYPE_CODE_ITEM,
                          XDEX_DEF::TYPE_DEBUG_INFO_ITEM,
                          XDEX_DEF::TYPE_TYPE_LIST,
                          XDEX_DEF::TYPE_STRING_DATA_ITEM,
                          XDEX_DEF::TYPE_ANNOTATION_ITEM,
                          XDEX_DEF::TYPE_CLASS_DATA_ITEM,
                          XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM,
                          XDEX_DEF::TYPE_ANNOTATION_SET_ITEM,
                          XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST,
                          XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM,
                          XDEX_DEF::TYPE_MAP_LIST};

    QList<quint16> listDexMerge{XDEX_DEF::TYPE_HEADER_ITEM,         XDEX_DEF::TYPE_STRING_ID_ITEM,
                                XDEX_DEF::TYPE_TYPE_ID_ITEM,        XDEX_DEF::TYPE_PROTO_ID_ITEM,
                                XDEX_DEF::TYPE_FIELD_ID_ITEM,       XDEX_DEF::TYPE_METHOD_ID_ITEM,
                                XDEX_DEF::TYPE_CLASS_DEF_ITEM,      XDEX_DEF::TYPE_MAP_LIST,
                                XDEX_DEF::TYPE_TYPE_LIST,           XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST,
                                XDEX_DEF::TYPE_ANNOTATION_SET_ITEM, XDEX_DEF::TYPE_CLASS_DATA_ITEM,
                                XDEX_DEF::TYPE_CODE_ITEM,           XDEX_DEF::TYPE_STRING_DATA_ITEM,
                                XDEX_DEF::TYPE_DEBUG_INFO_ITEM,     XDEX_DEF::TYPE_ANNOTATION_ITEM,
                                XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM,  XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM};

    QList<quint16> listFastProxy{XDEX_DEF::TYPE_HEADER_ITEM,   XDEX_DEF::TYPE_STRING_ID_ITEM, XDEX_DEF::TYPE_TYPE_ID_ITEM,    XDEX_DEF::TYPE_PROTO_ID_ITEM,
                                 XDEX_DEF::TYPE_FIELD_ID_ITEM, XDEX_DEF::TYPE_METHOD_ID_ITEM, XDEX_DEF::TYPE_CLASS_DEF_ITEM,  XDEX_DEF::TYPE_STRING_DATA_ITEM,
                                 XDEX_DEF::TYPE_TYPE_LIST,     XDEX_DEF::TYPE_CODE_ITEM,      XDEX_DEF::TYPE_CLASS_DATA_ITEM, XDEX_DEF::TYPE_MAP_LIST};

    NFD_Binary::VI_STRUCT viR8 = NFD_Binary::get_R8_marker_vi(pDevice, pOptions, 0, pDEXInfo->basic_info.id.nSize, pPdStruct);
    bool bR8_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listR8, pPdStruct);
    bool bDX_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDx, pPdStruct);
    bool bDexLib2_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexLib2, pPdStruct);
    bool bDexLib2heur_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexLib2heur, pPdStruct);
    bool bDexMerge_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listDexMerge, pPdStruct);
    bool bFastProxy_map = XDEX::compareMapItems(&(pDEXInfo->mapItems), &listFastProxy, pPdStruct);

    auto addCompiler = [&](XScanEngine::RECORD_NAME name, const NFD_Binary::VI_STRUCT *pVi = nullptr, const QString &sInfoAppend = QString()) {
        NFD_Binary::SCANS_STRUCT recordCompiler = NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_COMPILER, name, "", "", 0);
        if (pVi && pVi->bIsValid) {
            recordCompiler.sVersion = pVi->sVersion;
            recordCompiler.sInfo = pVi->sInfo;
        }
        if (!sInfoAppend.isEmpty()) {
            recordCompiler.sInfo = XBinary::appendComma(recordCompiler.sInfo, sInfoAppend);
        }
        pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
    };

    if (viR8.bIsValid) {
        addCompiler(XScanEngine::RECORD_NAME_R8, &viR8);
    } else if (!(pDEXInfo->bIsStringPoolSorted)) {
        addCompiler(XScanEngine::RECORD_NAME_DEXLIB);
    } else if (bDX_map) {
        addCompiler(XScanEngine::RECORD_NAME_DX);
    } else if (bDexLib2_map) {
        addCompiler(XScanEngine::RECORD_NAME_DEXLIB2);
    } else if (bR8_map) {
        addCompiler(XScanEngine::RECORD_NAME_R8);
    } else if (bDexLib2heur_map) {
        addCompiler(XScanEngine::RECORD_NAME_DEXLIB2);
    } else if (bFastProxy_map) {
        addCompiler(XScanEngine::RECORD_NAME_FASTPROXY);
    }

    if (bDexMerge_map) {
        addCompiler(XScanEngine::RECORD_NAME_DEXMERGE);
    }

    if (viR8.bIsValid && (!bR8_map)) {
        addCompiler(XScanEngine::RECORD_NAME_R8, &viR8, "CHECK !!!");
    }

    if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
        qint32 nJackIndex = dex.getStringNumberFromListExp(&(pDEXInfo->listStrings), "^emitter: jack");
        if (nJackIndex != -1) {
            NFD_Binary::SCANS_STRUCT recordCompiler =
                NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_JACK, "", "", 0);
            recordCompiler.sVersion = pDEXInfo->listStrings.at(nJackIndex).section("-", 1, -1);
            pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
        }
    }

    if (pDEXInfo->basic_info.mapResultCompilers.size() == 0) {
        NFD_Binary::SCANS_STRUCT recordCompiler = NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_UNKNOWN,
                                                                             QString::number(dex.getMapItemsHash(&(pDEXInfo->mapItems), pPdStruct)), "", 0);
        pDEXInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &recordCompiler));
    }

    if (pDEXInfo->basic_info.mapTypeDetects.contains(XScanEngine::RECORD_NAME_APKTOOLPLUS)) {
        NFD_Binary::SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(XScanEngine::RECORD_NAME_APKTOOLPLUS);
        pDEXInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
    }
    if (pDEXInfo->basic_info.mapTypeDetects.contains(XScanEngine::RECORD_NAME_UNICOMSDK)) {
        NFD_Binary::SCANS_STRUCT ss = pDEXInfo->basic_info.mapTypeDetects.value(XScanEngine::RECORD_NAME_UNICOMSDK);
        pDEXInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
    }

    if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
        bool bInvalidHeaderSize = (pDEXInfo->header.header_size != 0x70);
        bool bLink = (pDEXInfo->header.link_off || pDEXInfo->header.link_size);
        QString sOverlay;
        if (pDEXInfo->basic_info.scanOptions.bIsVerbose) {
            bool bIsFieldNamesUnicode = dex.isFieldNamesUnicode(&(pDEXInfo->listFieldIDs), &(pDEXInfo->listStrings), pPdStruct);
            bool bIsMethodNamesUnicode = dex.isMethodNamesUnicode(&(pDEXInfo->listMethodIDs), &(pDEXInfo->listStrings), pPdStruct);
            sOverlay = QString("Maps %1").arg(dex.getMapItemsHash(&(pDEXInfo->mapItems), pPdStruct));
            if (pDEXInfo->bIsOverlayPresent) sOverlay = XBinary::appendComma(sOverlay, "Overlay");
            if (bInvalidHeaderSize) sOverlay = XBinary::appendComma(sOverlay, "Invalid header size");
            if (bLink) sOverlay = XBinary::appendComma(sOverlay, QString("Invalid Link(%1,%2)").arg(pDEXInfo->header.link_size).arg(pDEXInfo->header.link_off));
            if (bIsFieldNamesUnicode) sOverlay = XBinary::appendComma(sOverlay, "bIsFieldNamesUnicode");
            if (bIsMethodNamesUnicode) sOverlay = XBinary::appendComma(sOverlay, "bIsMethodNamesUnicode");
            if (viR8.bIsValid) {
                if (bDX_map) sOverlay = XBinary::appendComma(sOverlay, "DX");
                if (bDexLib2_map) sOverlay = XBinary::appendComma(sOverlay, "DexLib2");
                if (!(pDEXInfo->bIsStringPoolSorted)) sOverlay = XBinary::appendComma(sOverlay, "DexLib");
                if (bDexMerge_map) sOverlay = XBinary::appendComma(sOverlay, "DexMerge");
            }
        }
        // if (pDEXInfo->basic_info.scanOptions.bIsTest && pDEXInfo->basic_info.scanOptions.bIsVerbose) {
        //     for (const QString &s : std::as_const(pDEXInfo->listStrings)) {
        //         if (XBinary::isPdStructStopped(pPdStruct)) break;
        //         if (s.contains("agconfig") || s.contains("AntiSkid") || s.contains("ALLATORI") || s.contains("AppSuit") || s.contains("appsuit") ||
        //             s.contains("gemalto") || s.contains("WapperApplication") || s.contains("AppSealing") || s.contains("whitecryption") ||
        //             s.contains("ModGuard") || s.contains("InjectedActivity")) {
        //             NFD_Binary::SCANS_STRUCT ss = _mkScan(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_UNKNOWN, s, sOverlay);
        //             pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        //             break;
        //         }
        //     }
        // }
    }
}

void NFD_DEX::handle_Dexguard(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);
    if (!dex.isValid(pPdStruct)) return;
    if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
        if (XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "dexguard\\/", pPdStruct)) {
            NFD_Binary::SCANS_STRUCT ss =
                NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXGUARD, "", "", 0);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        }
    }
}

void NFD_DEX::handle_Protection(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XDEX dex(pDevice);
    if (!dex.isValid(pPdStruct)) return;

    auto addIfPresent = [&](QMap<XScanEngine::RECORD_NAME, NFD_Binary::SCANS_STRUCT> &srcMap, XScanEngine::RECORD_NAME name) {
        if (srcMap.contains(name)) {
            auto ss = srcMap.value(name);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        }
    };

    if (pDEXInfo->bIsOverlayPresent) {
        if (dex.getOverlaySize(&(pDEXInfo->basic_info.memoryMap), pPdStruct) == 0x60) {
            NFD_Binary::SCANS_STRUCT ss =
                NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", "", 0);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        }
    } else if (pDEXInfo->basic_info.scanOptions.bIsDeepScan) {
        if (XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "\\/dexprotector\\/", pPdStruct)) {
            NFD_Binary::SCANS_STRUCT ss =
                NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", "", 0);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        }
    }

    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_EASYPROTECTOR);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_QDBH);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_JIAGU);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_BANGCLEPROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_ALLATORIOBFUSCATOR);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_PANGXIE);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_NAGAPTPROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_MODGUARD);
    addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_KIWIVERSIONOBFUSCATOR);

    if (pDEXInfo->basic_info.mapStringDetects.contains(XScanEngine::RECORD_NAME_APKPROTECT)) {
        addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_APKPROTECT);
    } else if (pDEXInfo->basic_info.scanOptions.bIsDeepScan && XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings), "http://www.apkprotect.net/", pPdStruct)) {
        NFD_Binary::SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECT, "", "", 0);
        pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
    }

    if (pDEXInfo->basic_info.scanOptions.bIsHeuristicScan) {
        if (pDEXInfo->basic_info.mapStringDetects.contains(XScanEngine::RECORD_NAME_AESOBFUSCATOR)) {
            addIfPresent(pDEXInfo->basic_info.mapStringDetects, XScanEngine::RECORD_NAME_AESOBFUSCATOR);
        } else if (pDEXInfo->basic_info.scanOptions.bIsDeepScan && XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings), "licensing/AESObfuscator;", pPdStruct)) {
            NFD_Binary::SCANS_STRUCT ss =
                NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_AESOBFUSCATOR, "", "", 0);
            pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
        }
    }

    // Type-based detections
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_BTWORKSCODEGUARD);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_QIHOO360PROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_ALIBABAPROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_BAIDUPROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_TENCENTPROTECTION);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_SECNEO);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_LIAPP);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_VDOG);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_APPSOLID);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_MEDUSAH);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_NQSHIELD);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_YIDUN);
    addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_APKENCRYPTOR);

    if (pDEXInfo->basic_info.mapTypeDetects.contains(XScanEngine::RECORD_NAME_PROGUARD)) {
        addIfPresent(pDEXInfo->basic_info.mapTypeDetects, XScanEngine::RECORD_NAME_PROGUARD);
    } else if (pDEXInfo->basic_info.scanOptions.bIsDeepScan && XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings), "\\/proguard\\/", pPdStruct)) {
        NFD_Binary::SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_DEX, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_PROGUARD, "", "", 0);
        pDEXInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pDEXInfo->basic_info), &ss));
    }
}

NFD_DEX::DEXINFO_STRUCT NFD_DEX::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    DEXINFO_STRUCT result = {};

    XDEX dex(pDevice);

    if (dex.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&dex, parentId, pOptions, nOffset, pPdStruct);

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

        NFD_Binary::stringScan(&result.basic_info.mapStringDetects, &result.listStrings, NFD_DEX::getStringRecords(), NFD_DEX::getStringRecordsSize(),
                               result.basic_info.id.fileType, XBinary::FT_DEX, &(result.basic_info), DETECTTYPE_DEXSTRING, pPdStruct);
        NFD_Binary::stringScan(&result.basic_info.mapTypeDetects, &result.listTypeItemStrings, NFD_DEX::getTypeRecords(), NFD_DEX::getTypeRecordsSize(),
                               result.basic_info.id.fileType, XBinary::FT_DEX, &(result.basic_info), DETECTTYPE_DEXTYPE, pPdStruct);

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

        NFD_DEX::handle_Tools(pDevice, pOptions, &result, pPdStruct);
        NFD_DEX::handle_Protection(pDevice, &result, pPdStruct);
        NFD_DEX::handle_Dexguard(pDevice, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

#ifdef QT_DEBUG
    qDebug("%lld msec", result.basic_info.nElapsedTime);
#endif

    return result;
}
