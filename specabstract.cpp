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
#include "modules/nfd_binary.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"
#include "modules/nfd_dex.h"
#include "modules/nfd_pe.h"
#include "modules/nfd_text.h"
#include "modules/nfd_dex.h"

#include "signatures.cpp"  // Do not include in CMAKE files!

SpecAbstract::SpecAbstract(QObject *pParent) : XScanEngine(pParent)
{
}

// JARINFO delegated to NFD_JAR::getInfo

void SpecAbstract::APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(&(pApkInfo->listArchiveRecords), pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xapk.getFileFormatInfo(pPdStruct));

        pApkInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssOperationSystem));

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

        _SCANS_STRUCT ssSignTool = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNATURESCHEME, "", "", 0);

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x7109871a)) {
            ssSignTool.sVersion = "v2";
        } else if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0xf05368c0)) {
            ssSignTool.sVersion = "v3";
        }

        // TODO V4

        if (ssSignTool.sVersion != "") {
            pApkInfo->basic_info.mapResultSigntools.insert(ssSignTool.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssSignTool));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x71777777)) {
            _SCANS_STRUCT ssWalle = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_WALLE, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssWalle.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssWalle));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x2146444e)) {
            _SCANS_STRUCT ssGooglePlay = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_GOOGLEPLAY, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssGooglePlay.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssGooglePlay));
        }

        if (pApkInfo->bIsKotlin) {
            _SCANS_STRUCT ssKotlin = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_KOTLIN, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssKotlin.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssKotlin));
        } else {
            _SCANS_STRUCT ssJava = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_JAVA, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssJava.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssJava));
        }

        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_UNKNOWN, "", "", 0);

            qint32 nNumberOfRecords = listApkSignaturesBlockRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listApkSignaturesBlockRecords.at(i).nID > 0xFFFF) {
                    if ((listApkSignaturesBlockRecords.at(i).nID != 0x7109871a) && (listApkSignaturesBlockRecords.at(i).nID != 0xf05368c0) &&
                        (listApkSignaturesBlockRecords.at(i).nID != 0x42726577)) {
                        ss.name = (RECORD_NAME)((int)RECORD_NAME_UNKNOWN0 + i);
                        ss.sVersion = XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nID);
                        // ss.sInfo=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nDataSize);
                        pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
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
                _SCANS_STRUCT ssAndroidSDK = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);

                QString _sVersion;
                QString _sAndroidVersion;

                _sVersion = sCompileSdkVersion;
                _sAndroidVersion = sCompileSdkVersionCodename;

                if (_sVersion == "") _sVersion = sMinSdkVersion;
                if (_sVersion == "") _sVersion = sTargetSdkVersion;

                if (_sVersion != "") {
                    ssAndroidSDK.sVersion = QString("API %1").arg(_sVersion);

                    pApkInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssAndroidSDK));
                }
            }

            QString sJetpack = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/androidx.core_core.version").data();
            if (sJetpack != "") {
                QString sJetpackVersion = XBinary::regExp("(.*?)\n", sJetpack, 1).remove("\r");

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LIBRARY, RECORD_NAME_ANDROIDJETPACK, "", "", 0);
                ss.sVersion = sJetpackVersion;
                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDGRADLE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDGRADLE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDMAVENPLUGIN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDMAVENPLUGIN);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_RADIALIX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_RADIALIX);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_MOTODEVSTUDIOFORANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANTILVL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANTILVL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKEDITOR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKEDITOR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BUNDLETOOL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BUNDLETOOL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEX2JAR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEX2JAR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_D2JAPKSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_D2JAPKSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_PSEUDOAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_PSEUDOAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APK_SIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APK_SIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_NETEASEAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_NETEASEAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DOTOOLSSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DOTOOLSSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNATORY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNATORY);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNUPDATE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNUPDATE);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKMODIFIERSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKMODIFIERSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BAIDUSIGNATUREPLATFORM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_TINYSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_TINYSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_COMEXSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_COMEXSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ECLIPSE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ECLIPSE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_HIAPKCOM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_HIAPKCOM);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DX);
                pApkInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECSHELL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECSHELL);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_JIAGU)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_JIAGU);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IJIAMI)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IJIAMI);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTPROTECTION);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
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

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppGuard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Kiro
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_KIRO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_KIRO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DxShield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DXSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DXSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // qdbh
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QDBH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QDBH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Bangcle Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BANGCLEPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BANGCLEPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Qihoo 360 Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QIHOO360PROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QIHOO360PROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Alibaba Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_ALIBABAPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_ALIBABAPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Baidu Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BAIDUPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BAIDUPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // NQ Shield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NQSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NQSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Nagapt Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NAGAPTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NAGAPTPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SecNeo
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECNEO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECNEO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // LIAPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_LIAPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_LIAPP);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // yidun
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_YIDUN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_YIDUN);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // PangXie
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PANGXIE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PANGXIE);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Hdus-Wjus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_HDUS_WJUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_HDUS_WJUS);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Medusah
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MEDUSAH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MEDUSAH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppSolid
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPSOLID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPSOLID);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Proguard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PROGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PROGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // VDog
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_VDOG)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_VDOG);

                QString sVersion = xapk.decompress(&(pApkInfo->listArchiveRecords), "assets/version").data();

                if (sVersion != "") {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion = sVersion.section("VDOG-", 1, 1).section("_", 0, 0);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // APKProtect
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECT)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECT);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ollvm-tll
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_OLLVMTLL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_OLLVMTLL);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DexGuard
            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD) ||
                pApkInfo->dexInfoClasses.basic_info.mapResultProtectors.contains(RECORD_NAME_DEXGUARD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXGUARD).sVersion;
                } else if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_GENERIC)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_GENERIC).sVersion;
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DEXPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DEXPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SandHook
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SANDHOOK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SANDHOOK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unicom SDK
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNICOMSDK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNICOMSDK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unity
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNITY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNITY);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // IL2CPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IL2CPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IL2CPP);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Basic4Android
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BASIC4ANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BASIC4ANDROID);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ApkToolPlus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKTOOLPLUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKTOOLPLUS);

                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // QML
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QML)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QML);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }
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

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sCreatedBy != "") && (sCreatedBy != "1.0 (Android)")) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion = "Created: " + sCreatedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if (sBuiltBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion = "Built: " + sBuiltBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sProtectedBy != "") && (sCreatedBy != "") && (sBuiltBy != "")) {
                    if (sDataManifest.contains("-By")) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_PROTECTOR;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                        recordSS.sVersion = "CHECK";

                        pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                    }
                }
            }
        }
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
            result = NFD_DEX::getInfo(&buffer, pApkInfo->basic_info.id, pOptions, 0, pPdStruct);

            buffer.close();
        }
    }

    return result;
}

// LX Microsoft-specific handling moved to NFD_LX::getInfo


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

// MSDOS_compareRichRecord moved to NFD_MSDOS

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

void SpecAbstract::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                  XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO basic_info = {};

    if ((fileType == XBinary::FT_PE32) || (fileType == XBinary::FT_PE64)) {
        NFD_PE::PEINFO_STRUCT pe_info = NFD_PE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pe_info.basic_info;
    } else if ((fileType == XBinary::FT_ELF32) || (fileType == XBinary::FT_ELF64)) {
        SpecAbstract::ELFINFO_STRUCT elf_info = NFD_ELF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = elf_info.basic_info;
    } else if ((fileType == XBinary::FT_MACHO32) || (fileType == XBinary::FT_MACHO64)) {
        SpecAbstract::MACHOINFO_STRUCT mach_info = NFD_MACH::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = mach_info.basic_info;
    } else if (fileType == XBinary::FT_LE) {
        SpecAbstract::LEINFO_STRUCT le_info = NFD_LE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = le_info.basic_info;
    } else if (fileType == XBinary::FT_LX) {
        SpecAbstract::LXINFO_STRUCT lx_info = NFD_LX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = lx_info.basic_info;
    } else if (fileType == XBinary::FT_NE) {
        SpecAbstract::NEINFO_STRUCT ne_info = NFD_NE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = ne_info.basic_info;
    } else if (fileType == XBinary::FT_MSDOS) {
        SpecAbstract::MSDOSINFO_STRUCT msdos_info = NFD_MSDOS::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = msdos_info.basic_info;
    } else if (fileType == XBinary::FT_JAR) {
        SpecAbstract::JARINFO_STRUCT jar_info = NFD_JAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jar_info.basic_info;
    } else if (fileType == XBinary::FT_APK) {
        SpecAbstract::APKINFO_STRUCT apk_info = NFD_APK::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = apk_info.basic_info;
    } else if ((fileType == XBinary::FT_ZIP) || (fileType == XBinary::FT_IPA)) {
        // mb TODO split detects
        SpecAbstract::ZIPINFO_STRUCT zip_info = NFD_ZIP::getZIPInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = zip_info.basic_info;
    } else if (fileType == XBinary::FT_RAR) {
        SpecAbstract::RARINFO_STRUCT rar_info = NFD_RAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = rar_info.basic_info;
    } else if (fileType == XBinary::FT_JAVACLASS) {
        SpecAbstract::JAVACLASSINFO_STRUCT javaclass_info = NFD_JavaClass::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = javaclass_info.basic_info;
    } else if (fileType == XBinary::FT_DEX) {
        SpecAbstract::DEXINFO_STRUCT dex_info = NFD_DEX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = dex_info.basic_info;
    } else if (fileType == XBinary::FT_AMIGAHUNK) {
        SpecAbstract::AMIGAHUNKINFO_STRUCT amigaHunk_info = NFD_Amiga::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = amigaHunk_info.basic_info;
    } else if (fileType == XBinary::FT_PDF) {
        SpecAbstract::PDFINFO_STRUCT pdf_info = NFD_PDF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pdf_info.basic_info;
    } else if (fileType == XBinary::FT_JPEG) {
        SpecAbstract::JPEGINFO_STRUCT jpeg_info = NFD_JPEG::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jpeg_info.basic_info;
    } else if (fileType == XBinary::FT_CFBF) {
        SpecAbstract::CFBFINFO_STRUCT cfbf_info = NFD_CFBF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = cfbf_info.basic_info;
    } else if (fileType == XBinary::FT_COM) {
        SpecAbstract::COMINFO_STRUCT com_info = NFD_COM::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = com_info.basic_info;
    } else {
        SpecAbstract::BINARYINFO_STRUCT binary_info = NFD_Binary::getInfo(pDevice, fileType, parentId, pScanOptions, 0, pPdStruct);
        basic_info = binary_info.basic_info;
    }

    if (bAddUnknown) {
        if (!basic_info.listDetects.count()) {
            _SCANS_STRUCT ssUnknown = {};

            ssUnknown.type = SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name = SpecAbstract::RECORD_NAME_UNKNOWN;
            ssUnknown.bIsUnknown = true;

            basic_info.listDetects.append(NFD_Binary::scansToScan(&basic_info, &ssUnknown));
        }
    }

    QList<XScanEngine::SCANSTRUCT> listScanStructs = NFD_Binary::convert(&(basic_info.listDetects));

    if (pScanOptions->bIsSort) {
        sortRecords(&listScanStructs);
    }

    pScanResult->listRecords.append(listScanStructs);
    pScanResult->listDebugRecords.append(NFD_Binary::convertHeur(&(basic_info.listHeurs)));

    if (pScanID) {
        *pScanID = basic_info.id;
    }
}
