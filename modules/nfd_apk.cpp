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
#include "nfd_apk.h"

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
#include "nfd_apk.h"

NFD_APK::NFD_APK(XAPK *pAPK, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : APK_Script(pAPK, filePart, pOptions, pPdStruct)
{
}
