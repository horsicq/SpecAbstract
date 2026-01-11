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
#include "nfd_apk.h"
#include "../specabstract.h"

// APK file-based signature records (migrated from SpecAbstract/signatures.cpp)
static NFD_Binary::STRING_RECORD g_APK_file_records[] = {
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECSHELL, "", ""}, "lib/armeabi/libSecShell-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECSHELL, "", ""}, "lib/armeabi/libSecShell.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECSHELL, "", ""}, "assets/secData0.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "Old", ""}, "assets/dexprotect/classes.dex.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/classes.dex.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.arm-v7.so.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.arm-v8.so.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.arm.so.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.mp3"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.x86.so.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", ""}, "assets/dp.x86_64.so.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "", "Kotlin"}, "assets/dp-lib/dp.kotlin-v1.lua.mph"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "4.9.0-4.9.5", ""}, "lib/armeabi/libdexprotector.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXPROTECTOR, "4.9.0-4.9.5", ""}, "lib/armeabi-v7a/libdexprotector.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "assets/libjiagu.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "assets/libjiagu_a64.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "assets/libjiagu_ls.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "assets/libjiagu_x64.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_JIAGU, "", ""}, "assets/libjiagu_x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", ""}, "assets/ijiami.ajm"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", ""}, "assets/ijm_lib/armeabi/libexec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", ""}, "assets/ijm_lib/armeabi/libexecmain.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", ""}, "assets/ijm_lib/x86/libexec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "", ""}, "assets/ijm_lib/x86/libexecmain.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "assets/ijiami.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/armeabi/libexec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/armeabi/libexecmain.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/armeabi-v7a/libexec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/armeabi-v7a/libexecmain.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/x86/libexec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_IJIAMI, "Old", ""}, "lib/x86/libexecmain.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTPROTECTION, "", ""}, "tencent_stub"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTPROTECTION, "", ""}, "assets/tosversion"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "assets/o0oooOO0ooOo.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "assets/0OO00l111l1l"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "assets/0OO00oo01l1l"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "assets/libshellx-super.2019.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "lib/armeabi/libshell-super.2019.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_TENCENTLEGU, "", ""}, "lib/arm64-v8a/libshell-super.2019.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPGUARD, "", ""}, "lib/armeabi-v7a/libAppGuard.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPGUARD, "", ""}, "lib/armeabi/libAppGuard.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPGUARD, "", ""}, "lib/armeabi/libAppGuard-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPGUARD, "", ""}, "assets/AppGuard0.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPGUARD, "", ""}, "assets/AppGuard.dgc"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_KIRO, "", ""}, "lib/armeabi/libkiroro.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DXSHIELD, "", ""}, "lib/armeabi/libdxbase.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECT, "", ""}, "lib/armeabi/libAPKProtect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECT, "", ""}, "lib/armeabi-v7a/libAPKProtect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECT, "", ""}, "apkprotect.com/key.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "assets/ap.others/apkprotect.bin"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "assets/ap.src/apkprotect-v1.bin"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "assets/ap.src/apkprotect-v2.bin"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "assets/ap.src/apkprotect-v3.bin"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "lib/arm64-v8a/libapkprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "lib/armeabi-v7a/libapkprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "lib/x86/libapkprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APKPROTECTOR, "", ""}, "lib/x86_64/libapkprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_QDBH, "", ""}, "assets/qdbh"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BANGCLEPROTECTION, "", ""}, "lib/armeabi/libsecexe.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BANGCLEPROTECTION, "", ""}, "lib/x86/libsecexe.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_QIHOO360PROTECTION, "", ""}, "lib/armeabi/libprotectClass.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_QIHOO360PROTECTION, "", ""}, "lib/armeabi-v7a/libprotectClass.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_QIHOO360PROTECTION, "", ""}, "lib/x86/libprotectClass.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALIBABAPROTECTION, "", ""}, "lib/armeabi/libmobisec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALIBABAPROTECTION, "", ""}, "lib/armeabi-v7a/libmobisec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_ALIBABAPROTECTION, "", ""}, "lib/x86/libmobisec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "assets/libbaiduprotect_x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "assets/baiduprotect.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "lib/armeabi-v7a/libbaiduprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "lib/armeabi/libbaiduprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "lib/mips/libbaiduprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_BAIDUPROTECTION, "", ""}, "lib/x86/libbaiduprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NQSHIELD, "", ""}, "assets/libnqshieldx86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NQSHIELD, "", ""}, "assets/nqdata"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NQSHIELD, "", ""}, "lib/armeabi/libnqshield.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NAGAPTPROTECTION, "", ""}, "lib/armeabi/libddog.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_NAGAPTPROTECTION, "", ""}, "lib/armeabi/libfdog.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/armeabi-v7a/libDexHelper.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/armeabi-v7a/libDexHelper-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/arm64-v8a/libDexHelper.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/arm64-v8a/libDexHelper-x86_64.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/armeabi/libDexHelper.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/armeabi/libDexHelper-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_SECNEO, "", ""}, "lib/x86/libDexHelper.so"},
    //    {{0, XBinary::FT_APK,       XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::RECORD_NAME_SECNEO,                       "",                 ""},
    //    "lib/armeabi/libdexjni.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_LIAPP, "", ""}, "assets/LIAPPClient.sc"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_LIAPP, "", ""}, "assets/LIAPPClient_x86.sc"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_LIAPP, "", ""}, "assets/LIAPPEgg_x86.sc"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_LIAPP, "", ""}, "assets/LIAPPEgg.sc"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_SANDHOOK, "", ""}, "lib/armeabi-v7a/libsandhook-native.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_SANDHOOK, "", ""}, "lib/armeabi-v7a/libsandhook.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_SANDHOOK, "", ""}, "lib/arm64-v8a/libsandhook-native.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_SANDHOOK, "", ""}, "lib/arm64-v8a/libsandhook.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "lib/arm64-v8a/libnesec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "lib/x86/libnesec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "lib/armeabi-v7a/libnesec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_YIDUN, "", ""}, "lib/armeabi/libnesec.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/classes.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/unicom_resource.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/arm64-v8a/libunicomSimplesdk.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/arm64-v8a/libunicomsdk.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/arm64-v8a/libdecrypt.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/armeabi-v7a/libdecrypt.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/x86/libunicomSimplesdk.dat"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/x86/libunicomsdk.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNICOMSDK, "", ""}, "assets/x86/libdecrypt.jar"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT, "", ""}, "lib/armeabi/mix.dex"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT, "", ""}, "lib/armeabi-v7a/mix.dex"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_PANGXIE, "", ""}, "lib/armeabi-v7a/libnsecure.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_PANGXIE, "", ""}, "lib/armeabi/libnsecure.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VDOG, "", ""}, "assets/main000/libhdog.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VDOG, "", ""}, "assets/main000/libhdog-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VDOG, "", ""}, "assets/main000/libvdog.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_VDOG, "", ""}, "assets/main000/libvdog-x86.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_APKTOOLPLUS, "", ""}, "lib/armeabi-v7a/libapktoolplus_jiagu.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HDUS_WJUS, "", ""}, "lib/armeabi/libhdus.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_HDUS_WJUS, "", ""}, "lib/armeabi/libwjus.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_MEDUSAH, "", ""}, "lib/armeabi-v7a/libmd.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_APPSOLID, "", ""}, "assets/high_resolution.png"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_OBFUSCATOR, XScanEngine::RECORD_NAME_PROGUARD, "", ""}, "META-INF/proguard/androidx-annotations.pro"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_UNITY, "", ""}, "lib/armeabi-v7a/libunity.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_IL2CPP, "", ""}, "lib/armeabi-v7a/libil2cpp.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_OLLVMTLL, "", ""}, "lib/armeabi-v7a/libmtprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_OLLVMTLL, "", ""}, "lib/x86/libmtprotect.so"},
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_QML, "6.X", ""}, "lib/arm64-v8a/libQt6Qml_arm64-v8a.so"},
};

static NFD_Binary::STRING_RECORD g_APK_fileExp_records[] = {
    {{0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_BASIC4ANDROID, "", ""}, "assets\\/(.*).bal"},
};

NFD_Binary::STRING_RECORD *NFD_APK::getFileRecords()
{
    return g_APK_file_records;
}

qint32 NFD_APK::getFileRecordsSize()
{
    return sizeof(g_APK_file_records);
}

NFD_Binary::STRING_RECORD *NFD_APK::getFileExpRecords()
{
    return g_APK_fileExp_records;
}

qint32 NFD_APK::getFileExpRecordsSize()
{
    return sizeof(g_APK_fileExp_records);
}

void NFD_APK::APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
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

        _SCANS_STRUCT ssSignTool =
            NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_SIGNTOOL, XScanEngine::RECORD_NAME_APKSIGNATURESCHEME, "", "", 0);

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
            _SCANS_STRUCT ssWalle = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_WALLE, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssWalle.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssWalle));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x2146444e)) {
            _SCANS_STRUCT ssGooglePlay = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_GOOGLEPLAY, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssGooglePlay.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssGooglePlay));
        }

        if (pApkInfo->bIsKotlin) {
            _SCANS_STRUCT ssKotlin = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LANGUAGE, XScanEngine::RECORD_NAME_KOTLIN, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssKotlin.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssKotlin));
        } else {
            _SCANS_STRUCT ssJava = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LANGUAGE, XScanEngine::RECORD_NAME_JAVA, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssJava.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssJava));
        }

        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_SIGNTOOL, XScanEngine::RECORD_NAME_UNKNOWN, "", "", 0);

            qint32 nNumberOfRecords = listApkSignaturesBlockRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listApkSignaturesBlockRecords.at(i).nID > 0xFFFF) {
                    if ((listApkSignaturesBlockRecords.at(i).nID != 0x7109871a) && (listApkSignaturesBlockRecords.at(i).nID != 0xf05368c0) &&
                        (listApkSignaturesBlockRecords.at(i).nID != 0x42726577)) {
                        ss.name = (XScanEngine::RECORD_NAME)((int)XScanEngine::RECORD_NAME_UNKNOWN0 + i);
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
                _SCANS_STRUCT ssAndroidSDK =
                    NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_ANDROIDSDK, "", "", 0);

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

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_ANDROIDJETPACK, "", "", 0);
                ss.sVersion = sJetpackVersion;
                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ANDROIDGRADLE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ANDROIDGRADLE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ANDROIDMAVENPLUGIN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ANDROIDMAVENPLUGIN);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_RADIALIX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_RADIALIX);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_MOTODEVSTUDIOFORANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ANTILVL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ANTILVL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APKEDITOR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_APKEDITOR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_BUNDLETOOL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_BUNDLETOOL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DEX2JAR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_DEX2JAR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_D2JAPKSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_D2JAPKSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_PSEUDOAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_PSEUDOAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_APKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APK_SIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_APK_SIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_NETEASEAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_NETEASEAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ANDROIDSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ANDROIDSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DOTOOLSSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_DOTOOLSSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_SIGNATORY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_SIGNATORY);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_SIGNUPDATE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_SIGNUPDATE);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ANDROIDAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ANDROIDAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APKMODIFIERSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_APKMODIFIERSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_BAIDUSIGNATUREPLATFORM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_TINYSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_TINYSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_COMEXSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_COMEXSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_ECLIPSE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_ECLIPSE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_HIAPKCOM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_HIAPKCOM);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_DX);
                pApkInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_SECSHELL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_SECSHELL);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_JIAGU)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_JIAGU);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_IJIAMI)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_IJIAMI);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_TENCENTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_TENCENTPROTECTION);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_TENCENTLEGU) ||
                pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_TENCENTLEGU)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_TENCENTLEGU);
                } else if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_MOBILETENCENTPROTECT);
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
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_APPGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_APPGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Kiro
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_KIRO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_KIRO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DxShield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_DXSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_DXSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // qdbh
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_QDBH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_QDBH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Bangcle Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_BANGCLEPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_BANGCLEPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Qihoo 360 Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_QIHOO360PROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_QIHOO360PROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Alibaba Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_ALIBABAPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_ALIBABAPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Baidu Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_BAIDUPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_BAIDUPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // NQ Shield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_NQSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_NQSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Nagapt Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_NAGAPTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_NAGAPTPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SecNeo
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_SECNEO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_SECNEO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // LIAPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_LIAPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_LIAPP);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // yidun
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_YIDUN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_YIDUN);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // PangXie
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_PANGXIE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_PANGXIE);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Hdus-Wjus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_HDUS_WJUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_HDUS_WJUS);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Medusah
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_MEDUSAH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_MEDUSAH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppSolid
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_APPSOLID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_APPSOLID);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Proguard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_PROGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_PROGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // VDog
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_VDOG)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_VDOG);

                QString sVersion = xapk.decompress(&(pApkInfo->listArchiveRecords), "assets/version").data();

                if (sVersion != "") {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion = sVersion.section("VDOG-", 1, 1).section("_", 0, 0);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // APKProtect
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_APKPROTECT)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_APKPROTECT);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ollvm-tll
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_OLLVMTLL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_OLLVMTLL);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DexGuard
            if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DEXGUARD) ||
                pApkInfo->dexInfoClasses.basic_info.mapResultProtectors.contains(XScanEngine::RECORD_NAME_DEXGUARD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_DEXGUARD, "", "", 0);

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DEXGUARD)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_DEXGUARD).sVersion;
                } else if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_GENERIC)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_GENERIC).sVersion;
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_DEXPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DEXPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_DEXPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_DEXPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_DEXPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_APKPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APKPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(XScanEngine::RECORD_NAME_APKPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(XScanEngine::RECORD_NAME_APKPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_APKPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SandHook
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_SANDHOOK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_SANDHOOK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unicom SDK
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_UNICOMSDK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_UNICOMSDK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unity
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_UNITY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_UNITY);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // IL2CPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_IL2CPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_IL2CPP);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Basic4Android
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_BASIC4ANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_BASIC4ANDROID);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ApkToolPlus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_APKTOOLPLUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_APKTOOLPLUS);

                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // QML
            if (pApkInfo->basic_info.mapArchiveDetects.contains(XScanEngine::RECORD_NAME_QML)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(XScanEngine::RECORD_NAME_QML);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }
        }
    }
}

void NFD_APK::APK_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
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

                    recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN0);
                    recordSS.sVersion = "Protected: " + sProtectedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sCreatedBy != "") && (sCreatedBy != "1.0 (Android)")) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion = "Created: " + sCreatedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if (sBuiltBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
                    recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion = "Built: " + sBuiltBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sProtectedBy != "") && (sCreatedBy != "") && (sBuiltBy != "")) {
                    if (sDataManifest.contains("-By")) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = XScanEngine::RECORD_TYPE_PROTECTOR;
                        recordSS.name = (XScanEngine::RECORD_NAME)(XScanEngine::RECORD_NAME_UNKNOWN0);
                        recordSS.sVersion = "CHECK";

                        pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                    }
                }
            }
        }
    }
}

NFD_DEX::DEXINFO_STRUCT NFD_APK::APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct,
                                              const QString &sFileName)
{
    Q_UNUSED(pOptions)

    NFD_DEX::DEXINFO_STRUCT result = {};

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

NFD_APK::APKINFO_STRUCT NFD_APK::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                         XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    APKINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&xzip, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.listArchiveRecords = xzip.getRecords(20000, pPdStruct);

        result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
                           XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);

        NFD_Binary::archiveScan(&(result.basic_info.mapArchiveDetects), &(result.listArchiveRecords), NFD_APK::getFileRecords(), NFD_APK::getFileRecordsSize(),
                                result.basic_info.id.fileType, XBinary::FT_APK, &(result.basic_info), DETECTTYPE_ARCHIVE, pPdStruct);
        NFD_Binary::archiveExpScan(&(result.basic_info.mapArchiveDetects), &(result.listArchiveRecords), NFD_APK::getFileExpRecords(), NFD_APK::getFileExpRecordsSize(),
                                   result.basic_info.id.fileType, XBinary::FT_APK, &(result.basic_info), DETECTTYPE_ARCHIVE, pPdStruct);

        if (XArchive::isArchiveRecordPresent("classes.dex", &(result.listArchiveRecords), pPdStruct)) {
            result.dexInfoClasses = NFD_DEX::getInfo(pDevice, parentId, pOptions, 0, pPdStruct);
        }

        NFD_ZIP::handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);

        NFD_APK::APK_handle(pDevice, pOptions, &result, pPdStruct);
        NFD_APK::APK_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}
