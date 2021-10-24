// copyright (c) 2017-2021 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#include "specabstract.h"
#include "signatures.cpp" // Do not include in cmake files!

SpecAbstract::SpecAbstract(QObject *pParent)
{
    Q_UNUSED(pParent)
}

void SpecAbstract::scan(QIODevice *pDevice, SpecAbstract::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, bool bInit, bool *pbIsStop)
{
    bool __bIsStop=false;

    if(pbIsStop==nullptr)
    {
        pbIsStop=&__bIsStop;
    }

    QElapsedTimer scanTimer;

    if(bInit)
    {
        scanTimer.start();
    }

    pScanResult->sFileName=XBinary::getDeviceFileName(pDevice);

    SubDevice sd(pDevice,nOffset,nSize);

    if(sd.open(QIODevice::ReadOnly)&&(!(*pbIsStop)))
    {
        QSet<XBinary::FT> stFileTypes=XBinary::getFileTypes(&sd,true);

        if((pOptions->fileType!=XBinary::FT_UNKNOWN)&&(bInit))
        {
            XBinary::filterFileTypes(&stFileTypes,pOptions->fileType);
        }

        if(stFileTypes.contains(XBinary::FT_PE32)||stFileTypes.contains(XBinary::FT_PE64))
        {
            SpecAbstract::PEINFO_STRUCT pe_info=SpecAbstract::getPEInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(pe_info.basic_info.listDetects);
            pScanResult->listHeurs.append(pe_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_ELF32)||stFileTypes.contains(XBinary::FT_ELF64))
        {
            SpecAbstract::ELFINFO_STRUCT elf_info=SpecAbstract::getELFInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(elf_info.basic_info.listDetects);
            pScanResult->listHeurs.append(elf_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_MACHO32)||stFileTypes.contains(XBinary::FT_MACHO64))
        {
            SpecAbstract::MACHOINFO_STRUCT mach_info=SpecAbstract::getMACHOInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(mach_info.basic_info.listDetects);
            pScanResult->listHeurs.append(mach_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_LE)||stFileTypes.contains(XBinary::FT_LX))
        {
            SpecAbstract::LEINFO_STRUCT le_info=SpecAbstract::getLEInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(le_info.basic_info.listDetects);
            pScanResult->listHeurs.append(le_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_NE))
        {
            SpecAbstract::NEINFO_STRUCT ne_info=SpecAbstract::getNEInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(ne_info.basic_info.listDetects);
            pScanResult->listHeurs.append(ne_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_MSDOS))
        {
            SpecAbstract::MSDOSINFO_STRUCT msdos_info=SpecAbstract::getMSDOSInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(msdos_info.basic_info.listDetects);
            pScanResult->listHeurs.append(msdos_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_ZIP))
        {
            SpecAbstract::ZIPINFO_STRUCT zip_info=SpecAbstract::getZIPInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(zip_info.basic_info.listDetects);
            pScanResult->listHeurs.append(zip_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_MACHOFAT))
        {
            SpecAbstract::MACHOFATINFO_STRUCT zip_info=SpecAbstract::getMACHOFATInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(zip_info.basic_info.listDetects);
            pScanResult->listHeurs.append(zip_info.basic_info.listHeurs);
        }
        else if(stFileTypes.contains(XBinary::FT_DEX))
        {
            SpecAbstract::DEXINFO_STRUCT dex_info=SpecAbstract::getDEXInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(dex_info.basic_info.listDetects);
            pScanResult->listHeurs.append(dex_info.basic_info.listHeurs);
        }
        else
        {
            SpecAbstract::BINARYINFO_STRUCT binary_info=SpecAbstract::getBinaryInfo(&sd,parentId,pOptions,nOffset,pbIsStop);

            pScanResult->listRecords.append(binary_info.basic_info.listDetects);
            pScanResult->listHeurs.append(binary_info.basic_info.listHeurs);
        }

        sd.close();
    }

//    if(pOptions->bIsTest)
//    {
//        QList<SpecAbstract::SCAN_STRUCT> _listDetects;

//        int nNumberOfRecords=pScanResult->listRecords.count();

//        for(qint32 i=0;i<nNumberOfRecords;i++)
//        {
//            if(pScanResult->listRecords.at(i).sInfo=="TEST")
//            {
//                _listDetects.append(pScanResult->listRecords.at(i));
//            }
//        }

//        pScanResult->listRecords=_listDetects;
//    }

    if(bInit)
    {
        pScanResult->nScanTime=scanTimer.elapsed();
    }
}

QString SpecAbstract::append(QString sResult, QString sString)
{
    return XBinary::appendText(sResult,sString,",");
}

QString SpecAbstract::recordFilePartIdToString(SpecAbstract::RECORD_FILEPART id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        // TODO more
        case RECORD_FILEPART_UNKNOWN:                           sResult=tr("Unknown");                                          break;
        case RECORD_FILEPART_HEADER:                            sResult=tr("Header");                                           break;
        case RECORD_FILEPART_OVERLAY:                           sResult=tr("Overlay");                                          break;
        case RECORD_FILEPART_ARCHIVERECORD:                     sResult=tr("Archive record");                                   break;
    }

    return sResult;
}

QString SpecAbstract::recordTypeIdToString(RECORD_TYPE id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case RECORD_TYPE_UNKNOWN:                               sResult=tr("Unknown");                                          break;
        case RECORD_TYPE_APKOBFUSCATOR:                         sResult=QString("APK %1").arg(tr("obfuscator"));                break;
        case RECORD_TYPE_APKTOOL:                               sResult=QString("APK %1").arg(tr("Tool"));                      break;
        case RECORD_TYPE_CERTIFICATE:                           sResult=tr("Certificate");                                      break;
        case RECORD_TYPE_COMPILER:                              sResult=tr("Compiler");                                         break;
        case RECORD_TYPE_CONVERTER:                             sResult=tr("Converter");                                        break;
        case RECORD_TYPE_CRYPTOR:                               sResult=tr("Cryptor");                                          break;
        case RECORD_TYPE_DATABASE:                              sResult=tr("Database");                                         break;
        case RECORD_TYPE_DEBUGDATA:                             sResult=tr("Debug data");                                       break;
        case RECORD_TYPE_DONGLEPROTECTION:                      sResult=QString("Dongle %1").arg(tr("protection"));             break;
        case RECORD_TYPE_DOSEXTENDER:                           sResult=QString("DOS %1").arg(tr("extender"));                  break;
        case RECORD_TYPE_FORMAT:                                sResult=tr("Format");                                           break;
        case RECORD_TYPE_GENERIC:                               sResult=tr("Generic");                                          break;
        case RECORD_TYPE_IMAGE:                                 sResult=tr("Image");                                            break;
        case RECORD_TYPE_INSTALLER:                             sResult=tr("Installer");                                        break;
        case RECORD_TYPE_INSTALLERDATA:                         sResult=tr("Installer data");                                   break;
        case RECORD_TYPE_JAROBFUSCATOR:                         sResult=QString("JAR %1").arg(tr("obfuscator"));                break;
        case RECORD_TYPE_JOINER:                                sResult=tr("Joiner");                                           break;
        case RECORD_TYPE_LANGUAGE:                              sResult=tr("Language");                                         break;
        case RECORD_TYPE_LIBRARY:                               sResult=tr("Library");                                          break;
        case RECORD_TYPE_LINKER:                                sResult=tr("Linker");                                           break;
        case RECORD_TYPE_NETCOMPRESSOR:                         sResult=QString(".NET %1").arg(tr("compressor"));               break;
        case RECORD_TYPE_NETOBFUSCATOR:                         sResult=QString(".NET %1").arg(tr("obfuscator"));               break;
        case RECORD_TYPE_OPERATIONSYSTEM:                       sResult=tr("Operation system");                                 break;
        case RECORD_TYPE_PACKER:                                sResult=tr("Packer");                                           break;
        case RECORD_TYPE_PETOOL:                                sResult=QString("PE %1").arg(tr("Tool"));                       break;
        case RECORD_TYPE_PROTECTOR:                             sResult=tr("Protector");                                        break;
        case RECORD_TYPE_PROTECTORDATA:                         sResult=tr("Protector data");                                   break;
        case RECORD_TYPE_SFX:                                   sResult=QString("SFX");                                         break;
        case RECORD_TYPE_SFXDATA:                               sResult=QString("SFX %1").arg(tr("data"));                      break;
        case RECORD_TYPE_SIGNTOOL:                              sResult=tr("Sign tool");                                        break;
        case RECORD_TYPE_SOURCECODE:                            sResult=tr("Source code");                                      break;
        case RECORD_TYPE_STUB:                                  sResult=tr("Stub");                                             break;
        case RECORD_TYPE_TOOL:                                  sResult=tr("Tool");                                             break;
        case RECORD_TYPE_VIRTUALMACHINE:                        sResult=tr("Virtual machine");                                  break;
    }

    return sResult;
}

QString SpecAbstract::recordNameIdToString(RECORD_NAME id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case RECORD_NAME_UNKNOWN:                               sResult=tr("Unknown");                                          break;
        case RECORD_NAME_12311134:                              sResult=QString("12311134");                                    break;
        case RECORD_NAME_1337EXECRYPTER:                        sResult=QString("1337 Exe Crypter");                            break;
        case RECORD_NAME_32LITE:                                sResult=QString("32Lite");                                      break;
        case RECORD_NAME_7Z:                                    sResult=QString("7-Zip");                                       break;
        case RECORD_NAME_AASE:                                  sResult=QString("Aase");                                        break;
        case RECORD_NAME_ABCCRYPTOR:                            sResult=QString("ABC Cryptor");                                 break;
        case RECORD_NAME_ACPROTECT:                             sResult=QString("ACProtect");                                   break;
        case RECORD_NAME_ACTIVEMARK:                            sResult=QString("ActiveMARK");                                  break;
        case RECORD_NAME_ACTUALINSTALLER:                       sResult=QString("Actual Installer");                            break;
        case RECORD_NAME_ADVANCEDINSTALLER:                     sResult=QString("Advanced Installer");                          break;
        case RECORD_NAME_ADVANCEDUPXSCRAMMBLER:                 sResult=QString("Advanced UPX Scrammbler");                     break;
        case RECORD_NAME_AESOBFUSCATOR:                         sResult=QString("AESObfuscator");                               break;
        case RECORD_NAME_AFFILLIATEEXE:                         sResult=QString("AffilliateEXE");                               break;
        case RECORD_NAME_AGAINNATIVITYCRYPTER:                  sResult=QString("Again Nativity Crypter");                      break;
        case RECORD_NAME_AGILENET:                              sResult=QString("Agile .NET");                                  break;
        case RECORD_NAME_AHPACKER:                              sResult=QString("AHPacker");                                    break;
        case RECORD_NAME_AHTEAMEPPROTECTOR:                     sResult=QString("AHTeam EP Protector");                         break;
        case RECORD_NAME_AINEXE:                                sResult=QString("AINEXE");                                      break;
        case RECORD_NAME_AIX:                                   sResult=QString("AIX");                                         break;
        case RECORD_NAME_ALCHEMYMINDWORKS:                      sResult=QString("Alchemy Mindworks");                           break;
        case RECORD_NAME_ALEXPROTECTOR:                         sResult=QString("Alex Protector");                              break;
        case RECORD_NAME_ALIASOBJ:                              sResult=QString("ALIASOBJ");                                    break;
        case RECORD_NAME_ALIBABAPROTECTION:                     sResult=QString("Alibaba Protection");                          break;
        case RECORD_NAME_ALIPAYOBFUSCATOR:                      sResult=QString("Alipay Obfuscator");                           break;
        case RECORD_NAME_ALLATORIOBFUSCATOR:                    sResult=QString("Allatori Obfuscator");                         break;
        case RECORD_NAME_ALLOY:                                 sResult=QString("Alloy");                                       break;
        case RECORD_NAME_ALPINELINUX:                           sResult=QString("Alpine Linux");                                break;
        case RECORD_NAME_ANDPAKK2:                              sResult=QString("ANDpakk2");                                    break;
        case RECORD_NAME_ANDROID:                               sResult=QString("Android");                                     break;
        case RECORD_NAME_ANDROIDAPKSIGNER:                      sResult=QString("Android apksigner");                           break;
        case RECORD_NAME_ANDROIDARSC:                           sResult=QString("Android ARSC");                                break;
        case RECORD_NAME_ANDROIDCLANG:                          sResult=QString("Android clang");                               break;
        case RECORD_NAME_ANDROIDGRADLE:                         sResult=QString("Android Gradle");                              break;
        case RECORD_NAME_ANDROIDJETPACK:                        sResult=QString("Android Jetpack");                             break;
        case RECORD_NAME_ANDROIDMAVENPLUGIN:                    sResult=QString("Android Maven Plugin");                        break;
        case RECORD_NAME_ANDROIDNDK:                            sResult=QString("Android NDK");                                 break;
        case RECORD_NAME_ANDROIDSDK:                            sResult=QString("Android SDK");                                 break;
        case RECORD_NAME_ANDROIDSIGNAPK:                        sResult=QString("Android SignApk");                             break;
        case RECORD_NAME_ANDROIDXML:                            sResult=QString("Android XML");                                 break;
        case RECORD_NAME_ANSKYAPOLYMORPHICPACKER:               sResult=QString("Anskya Polymorphic Packer");                   break;
        case RECORD_NAME_ANSLYMPACKER:                          sResult=QString("AnslymPacker");                                break;
        case RECORD_NAME_ANTIDOTE:                              sResult=QString("AntiDote");                                    break;
        case RECORD_NAME_ANTILVL:                               sResult=QString("AntiLVL");                                     break;
        case RECORD_NAME_APACHEANT:                             sResult=QString("Apache Ant");                                  break;
        case RECORD_NAME_APACK:                                 sResult=QString("aPACK");                                       break;
        case RECORD_NAME_APKEDITOR:                             sResult=QString("ApkEditor");                                   break;
        case RECORD_NAME_APKENCRYPTOR:                          sResult=QString("ApkEncryptor");                                break;
        case RECORD_NAME_APKMODIFIERSIGNAPK:                    sResult=QString("ApkModifier SignApk");                         break;
        case RECORD_NAME_APKPROTECT:                            sResult=QString("APKProtect");                                  break;
        case RECORD_NAME_APKPROTECTOR:                          sResult=QString("ApkProtector");                                break;
        case RECORD_NAME_APKSIGNATURESCHEME:                    sResult=QString("APK Signature Scheme");                        break;
        case RECORD_NAME_APKSIGNER:                             sResult=QString("ApkSigner");                                   break;
        case RECORD_NAME_APKTOOLPLUS:                           sResult=QString("ApkToolPlus");                                 break;
        case RECORD_NAME_APK_SIGNER:                            sResult=QString("apk-signer");                                  break;
        case RECORD_NAME_APPGUARD:                              sResult=QString("AppGuard");                                    break;
        case RECORD_NAME_APPIMAGE:                              sResult=QString("AppImage");                                    break;
        case RECORD_NAME_APPLEJDK:                              sResult=QString("Apple JDK");                                   break;
        case RECORD_NAME_APPLELLVM:                             sResult=QString("Apple LLVM");                                  break;
        case RECORD_NAME_APPORTABLECLANG:                       sResult=QString("Apportable clang");                            break;
        case RECORD_NAME_APPSOLID:                              sResult=QString("AppSolid");                                    break;
        case RECORD_NAME_ARCRYPT:                               sResult=QString("AR Crypt");                                    break;
        case RECORD_NAME_ARJ:                                   sResult=QString("ARJ");                                         break;
        case RECORD_NAME_ARMADILLO:                             sResult=QString("Armadillo");                                   break;
        case RECORD_NAME_ARMASSEMBLER:                          sResult=QString("ARM Assembler");                               break;
        case RECORD_NAME_ARMC:                                  sResult=QString("ARM C");                                       break;
        case RECORD_NAME_ARMCCPP:                               sResult=QString("ARM C/C++");                                   break;
        case RECORD_NAME_ARMLINKER:                             sResult=QString("ARM Linker");                                  break;
        case RECORD_NAME_ARMNEONCCPP:                           sResult=QString("ARM NEON C/C++");                              break;
        case RECORD_NAME_ARMPROTECTOR:                          sResult=QString("ARM Protector");                               break;
        case RECORD_NAME_ARMTHUMBCCPP:                          sResult=QString("ARM/Thumb C/C++");                             break;
        case RECORD_NAME_ARMTHUMBMACROASSEMBLER:                sResult=QString("ARM/Thumb Macro Assembler");                   break;
        case RECORD_NAME_AROS:                                  sResult=QString("Amiga Research OS");                           break;
        case RECORD_NAME_ASDPACK:                               sResult=QString("ASDPack");                                     break;
        case RECORD_NAME_ASPACK:                                sResult=QString("ASPack");                                      break;
        case RECORD_NAME_ASPLINUX:                              sResult=QString("ASPLinux");                                    break;
        case RECORD_NAME_ASPROTECT:                             sResult=QString("ASProtect");                                   break;
        case RECORD_NAME_ASSCRYPTER:                            sResult=QString("Ass Crypter");                                 break;
        case RECORD_NAME_ASSEMBLER:                             sResult=QString("Assembler");                                   break;
        case RECORD_NAME_ASSEMBLYINVOKE:                        sResult=QString("AssemblyInvoke");                              break;
        case RECORD_NAME_AU:                                    sResult=QString("AU");                                          break;
        case RECORD_NAME_AUTOIT:                                sResult=QString("AutoIt");                                      break;
        case RECORD_NAME_AVASTANTIVIRUS:                        sResult=QString("Avast Antivirus");                             break;
        case RECORD_NAME_AVERCRYPTOR:                           sResult=QString("AverCryptor");                                 break;
        case RECORD_NAME_AVI:                                   sResult=QString("AVI");                                         break;
        case RECORD_NAME_AVPACK:                                sResult=QString("AVPACK");                                      break;
        case RECORD_NAME_AZPROTECT:                             sResult=QString("AZProtect");                                   break;
        case RECORD_NAME_BABELNET:                              sResult=QString("Babel .NET");                                  break;
        case RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR:           sResult=QString("Backdoor PE Compress Protector");              break;
        case RECORD_NAME_BAIDUPROTECTION:                       sResult=QString("Baidu Protection");                            break;
        case RECORD_NAME_BAIDUSIGNATUREPLATFORM:                sResult=QString("Baidu Signature platform");                    break;
        case RECORD_NAME_BAMBAM:                                sResult=QString("bambam");                                      break;
        case RECORD_NAME_BANGCLEPROTECTION:                     sResult=QString("Bangcle Protection");                          break;
        case RECORD_NAME_BASIC4ANDROID:                         sResult=QString("Basic4Android");                               break;
        case RECORD_NAME_BASIC:                                 sResult=QString("BASIC");                                       break;
        case RECORD_NAME_BAT2EXEC:                              sResult=QString("BAT2EXEC");                                    break;
        case RECORD_NAME_BEAWEBLOGIC:                           sResult=QString("BEA WebLogic");                                break;
        case RECORD_NAME_BEROEXEPACKER:                         sResult=QString("BeRoEXEPacker");                               break;
        case RECORD_NAME_BIOHAZARDCRYPTER:                      sResult=QString("Biohazard Crypter");                           break;
        case RECORD_NAME_BITROCKINSTALLER:                      sResult=QString("BitRock Installer");                           break;
        case RECORD_NAME_BITSHAPEPECRYPT:                       sResult=QString("BitShape PE Crypt");                           break;
        case RECORD_NAME_BLADEJOINER:                           sResult=QString("Blade Joiner");                                break;
        case RECORD_NAME_BORLANDCCPP:                           sResult=QString("Borland C/C++");                               break;
        case RECORD_NAME_BORLANDCPP:                            sResult=QString("Borland C++");                                 break;
        case RECORD_NAME_BORLANDCPPBUILDER:                     sResult=QString("Borland C++ Builder");                         break;
        case RECORD_NAME_BORLANDDELPHI:                         sResult=QString("Borland Delphi");                              break;
        case RECORD_NAME_BORLANDDELPHIDOTNET:                   sResult=QString("Borland Delphi .NET");                         break;
        case RECORD_NAME_BORLANDOBJECTPASCALDELPHI:             sResult=QString("Borland Object Pascal(Delphi)");               break;
        case RECORD_NAME_BREAKINTOPATTERN:                      sResult=QString("Break Into Pattern");                          break;
        case RECORD_NAME_BRIDGEOS:                              sResult=QString("bridgeOS");                                    break;
        case RECORD_NAME_BRIDGEOSSDK:                           sResult=QString("bridgeOS SDK");                                break;
        case RECORD_NAME_BTWORKSCODEGUARD:                      sResult=QString("Btworks CodeGuard");                           break;
        case RECORD_NAME_BUNDLETOOL:                            sResult=QString("BundleTool");                                  break;
        case RECORD_NAME_BYTEDANCESECCOMPILER:                  sResult=QString("ByteDance-SecCompiler");                       break;
        case RECORD_NAME_BYTEGUARD:                             sResult=QString("ByteGuard");                                   break;
        case RECORD_NAME_BZIP2:                                 sResult=QString("bzip2");                                       break;
        case RECORD_NAME_C:                                     sResult=QString("C");                                           break;
        case RECORD_NAME_CAB:                                   sResult=QString("CAB");                                         break;
        case RECORD_NAME_CARBON:                                sResult=QString("Carbon");                                      break;
        case RECORD_NAME_CAUSEWAY:                              sResult=QString("CauseWay");                                    break;
        case RECORD_NAME_CCBYUNIHACKERS:                        sResult=QString("CC by UniHackers");                            break;
        case RECORD_NAME_CCBYVORONTSOV:                         sResult=QString("CC by Vorontsov");                             break;
        case RECORD_NAME_CCPP:                                  sResult=QString("C/C++");                                       break;
        case RECORD_NAME_CELESTYFILEBINDER:                     sResult=QString("Celesty File Binder");                         break;
        case RECORD_NAME_CEXE:                                  sResult=QString("CExe");                                        break;
        case RECORD_NAME_CHROMIUMCRASHPAD:                      sResult=QString("Chromium Crashpad");                           break;
        case RECORD_NAME_CIGICIGICRYPTER:                       sResult=QString("Cigicigi Crypter");                            break;
        case RECORD_NAME_CIL:                                   sResult=QString("cil");                                         break;
        case RECORD_NAME_CLANG:                                 sResult=QString("clang");                                       break;
        case RECORD_NAME_CLICKTEAM:                             sResult=QString("ClickTeam");                                   break;
        case RECORD_NAME_CLISECURE:                             sResult=QString("CliSecure");                                   break;
        case RECORD_NAME_COCOA:                                 sResult=QString("Cocoa");                                       break;
        case RECORD_NAME_CODEGEARCPP:                           sResult=QString("CodeGear C++");                                break;
        case RECORD_NAME_CODEGEARCPPBUILDER:                    sResult=QString("CodeGear C++ Builder");                        break;
        case RECORD_NAME_CODEGEARDELPHI:                        sResult=QString("CodeGear Delphi");                             break;
        case RECORD_NAME_CODEGEAROBJECTPASCALDELPHI:            sResult=QString("Codegear Object Pascal(Delphi)");              break;
        case RECORD_NAME_CODEVEIL:                              sResult=QString("CodeVeil");                                    break;
        case RECORD_NAME_CODEWALL:                              sResult=QString("CodeWall");                                    break;
        case RECORD_NAME_COFF:                                  sResult=QString("COFF");                                        break;
        case RECORD_NAME_COMEXSIGNAPK:                          sResult=QString("COMEX SignApk");                               break;
        case RECORD_NAME_COMPOUNDFILEBINARYFORMAT:              sResult=QString("Compound File Binary Format");                 break;
        case RECORD_NAME_CONFUSER:                              sResult=QString("Confuser");                                    break;
        case RECORD_NAME_CONFUSEREX:                            sResult=QString("ConfuserEx");                                  break;
        case RECORD_NAME_COPYMINDER:                            sResult=QString("CopyMinder");                                  break;
        case RECORD_NAME_CPP:                                   sResult=QString("C++");                                         break;
        case RECORD_NAME_CREATEINSTALL:                         sResult=QString("CreateInstall");                               break;
        case RECORD_NAME_CRINKLER:                              sResult=QString("Crinkler");                                    break;
        case RECORD_NAME_CRUNCH:                                sResult=QString("Crunch");                                      break;
        case RECORD_NAME_CRYEXE:                                sResult=QString("CryEXE");                                      break;
        case RECORD_NAME_CRYPTABLESEDUCATION:                   sResult=QString("Cryptable Seduction");                         break;
        case RECORD_NAME_CRYPTCOM:                              sResult=QString("CryptCom");                                    break;
        case RECORD_NAME_CRYPTDISMEMBER:                        sResult=QString("Crypt(Dismember)");                            break;
        case RECORD_NAME_CRYPTER:                               sResult=QString("Crypter");                                     break;
        case RECORD_NAME_CRYPTIC:                               sResult=QString("Cryptic");                                     break;
        case RECORD_NAME_CRYPTOCRACKPEPROTECTOR:                sResult=QString("CrypToCrack Pe Protector");                    break;
        case RECORD_NAME_CRYPTOOBFUSCATORFORNET:                sResult=QString("Crypto Obfuscator For .Net");                  break;
        case RECORD_NAME_CRYPTORBYDISMEMBER:                    sResult=QString("Cryptor by Dismember");                        break;
        case RECORD_NAME_CRYPTOZ:                               sResult=QString("CRyptOZ");                                     break;
        case RECORD_NAME_CRYPTRROADS:                           sResult=QString("Crypt R.roads");                               break;
        case RECORD_NAME_CSHARP:                                sResult=QString("C#");                                          break;
        case RECORD_NAME_CVTOMF:                                sResult=QString("CVTOMF");                                      break;
        case RECORD_NAME_CVTPGD:                                sResult=QString("Cvtpgd");                                      break;
        case RECORD_NAME_CVTRES:                                sResult=QString("CVTRES");                                      break;
        case RECORD_NAME_CWSDPMI:                               sResult=QString("CWSDPMI");                                     break;
        case RECORD_NAME_CYGWIN:                                sResult=QString("Cygwin");                                      break;
        case RECORD_NAME_D2JAPKSIGN:                            sResult=QString("d2j-apk-sign");                                break;
        case RECORD_NAME_D:                                     sResult=QString("D");                                           break;
        case RECORD_NAME_DALKRYPT:                              sResult=QString("DalKrypt");                                    break;
        case RECORD_NAME_DALVIK:                                sResult=QString("Dalvik");                                      break;
        case RECORD_NAME_DBPE:                                  sResult=QString("DBPE");                                        break;
        case RECORD_NAME_DCRYPTPRIVATE:                         sResult=QString("DCrypt Private");                              break;
        case RECORD_NAME_DEB:                                   sResult=QString("DEB");                                         break;
        case RECORD_NAME_DEBIANLINUX:                           sResult=QString("Debian Linux");                                break;
        case RECORD_NAME_DEEPSEA:                               sResult=QString("DeepSea");                                     break;
        case RECORD_NAME_DEPACK:                                sResult=QString("dePack");                                      break;
        case RECORD_NAME_DEPLOYMASTER:                          sResult=QString("DeployMaster");                                break;
        case RECORD_NAME_DEX2JAR:                               sResult=QString("dex2jar");                                     break;
        case RECORD_NAME_DEX:                                   sResult=QString("DEX");                                         break;
        case RECORD_NAME_DEXGUARD:                              sResult=QString("DexGuard");                                    break;
        case RECORD_NAME_DEXLIB2:                               sResult=QString("dexlib2");                                     break;
        case RECORD_NAME_DEXLIB:                                sResult=QString("dexlib");                                      break;
        case RECORD_NAME_DEXMERGE:                              sResult=QString("DexMerge");                                    break;
        case RECORD_NAME_DEXPROTECTOR:                          sResult=QString("DexProtector");                                break;
        case RECORD_NAME_DIET:                              	sResult=QString("DIET");                                        break;
        case RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR:           sResult=QString("Dingbaozeng native obfuscator");               break;
        case RECORD_NAME_DIRTYCRYPTOR:                          sResult=QString("DirTy Cryptor");                               break;
        case RECORD_NAME_DJVU:                                  sResult=QString("DjVu");                                        break;
        case RECORD_NAME_DMD32D:                                sResult=QString("DMD32 D");                                     break;
        case RECORD_NAME_DNGUARD:                               sResult=QString("DNGuard");                                     break;
        case RECORD_NAME_DOS16M:                                sResult=QString("DOS/16M");                                     break;
        case RECORD_NAME_DOS4G:                                 sResult=QString("DOS/4G");                                      break;
        case RECORD_NAME_DOTBJFNT:                              sResult=QString(".BJFnt");                                      break;
        case RECORD_NAME_DOTFIXNICEPROTECT:                     sResult=QString("DotFix Nice Protect");                         break;
        case RECORD_NAME_DOTFUSCATOR:                           sResult=QString("Dotfuscator");                                 break;
        case RECORD_NAME_DOTNET:                                sResult=QString(".NET");                                        break;
        case RECORD_NAME_DOTNETREACTOR:                         sResult=QString(".NET Reactor");                                break;
        case RECORD_NAME_DOTNETSHRINK:                          sResult=QString(".netshrink");                                  break;
        case RECORD_NAME_DOTNETSPIDER:                          sResult=QString(".NET Spider");                                 break;
        case RECORD_NAME_DOTNETZ:                               sResult=QString(".NETZ");                                       break;
        case RECORD_NAME_DOTOOLSSIGNAPK:                        sResult=QString("dotools sign apk");                            break;
        case RECORD_NAME_DRAGONARMOR:                           sResult=QString("DragonArmor");                                 break;
        case RECORD_NAME_DROPBOX:                               sResult=QString("Dropbox");                                     break;
        case RECORD_NAME_DVCLAL:                                sResult=QString("DVCLAL");                                      break;
        case RECORD_NAME_DX:                                    sResult=QString("dx");                                          break;
        case RECORD_NAME_DXSHIELD:                              sResult=QString("DxShield");                                    break;
        case RECORD_NAME_DYAMAR:                                sResult=QString("DYAMAR");                                      break;
        case RECORD_NAME_DYNASM:                                sResult=QString("DynASM");                                      break;
        case RECORD_NAME_EASYPROTECTOR:                         sResult=QString("EasyProtector");                               break;
        case RECORD_NAME_EAZFUSCATOR:                           sResult=QString("Eazfuscator");                                 break;
        case RECORD_NAME_ECLIPSE:                               sResult=QString("Eclipse");                                     break;
        case RECORD_NAME_EMBARCADEROCPP:                        sResult=QString("Embarcadero C++");                             break;
        case RECORD_NAME_EMBARCADEROCPPBUILDER:                 sResult=QString("Embarcadero C++ Builder");                     break;
        case RECORD_NAME_EMBARCADERODELPHI:                     sResult=QString("Embarcadero Delphi");                          break;
        case RECORD_NAME_EMBARCADERODELPHIDOTNET:               sResult=QString("Embarcadero Delphi .NET");                     break;
        case RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI:         sResult=QString("Embarcadero Object Pascal(Delphi)");           break;
        case RECORD_NAME_EMPTYFILE:                             sResult=QString("Empty File");                                  break;
        case RECORD_NAME_ENCRYPTPE:                             sResult=QString("EncryptPE");                                   break;
        case RECORD_NAME_ENIGMA:                                sResult=QString("ENIGMA");                                      break;
        case RECORD_NAME_ENIGMAVIRTUALBOX:                      sResult=QString("Enigma Virtual Box");                          break;
        case RECORD_NAME_EPEXEPACK:                             sResult=QString("!EP(EXE Pack)");                               break;
        case RECORD_NAME_EPROT:                                 sResult=QString("!EProt");                                      break;
        case RECORD_NAME_EXCELSIORJET:                          sResult=QString("Excelsior JET");                               break;
        case RECORD_NAME_EXE32PACK:                             sResult=QString("exe32pack");                                   break;
        case RECORD_NAME_EXECRYPT:                              sResult=QString("EXECrypt");                                    break;
        case RECORD_NAME_EXECRYPTOR:                            sResult=QString("EXECryptor");                                  break;
        case RECORD_NAME_EXEFOG:                                sResult=QString("ExeFog");                                      break;
        case RECORD_NAME_EXEJOINER:                             sResult=QString("ExeJoiner");                                   break;
        case RECORD_NAME_EXEMPLARINSTALLER:                     sResult=QString("Exemplar Installer");                          break;
        case RECORD_NAME_EXEPACK:                               sResult=QString("EXEPACK");                                     break;
        case RECORD_NAME_EXEPASSWORDPROTECTOR:                  sResult=QString("EXE Password Protector");                      break;
        case RECORD_NAME_EXESAX:                                sResult=QString("ExeSax");                                      break;
        case RECORD_NAME_EXESHIELD:                             sResult=QString("Exe Shield");                                  break;
        case RECORD_NAME_EXESTEALTH:                            sResult=QString("ExeStealth");                                  break;
        case RECORD_NAME_EXPORT:                                sResult=QString("Export");                                      break;
        case RECORD_NAME_EXPRESSOR:                             sResult=QString("eXPressor");                                   break;
        case RECORD_NAME_EXPRESSOR_KERNEL32:                    sResult=QString("eXPressor[Kernel32]");                         break;
        case RECORD_NAME_EXPRESSOR_USER32:                      sResult=QString("eXPressor[User32]");                           break;
        case RECORD_NAME_EZIP:                                  sResult=QString("EZIP");                                        break;
        case RECORD_NAME_FAKESIGNATURE:                         sResult=QString("Fake signature");                              break;
        case RECORD_NAME_FAKUSCRYPTOR:                          sResult=QString("Fakus Cryptor");                               break;
        case RECORD_NAME_FASM:                                  sResult=QString("FASM");                                        break;
        case RECORD_NAME_FASTFILECRYPT:                         sResult=QString("Fast File Crypt");                             break;
        case RECORD_NAME_FASTPROXY:                             sResult=QString("fast-proxy");                                  break;
        case RECORD_NAME_FEARZCRYPTER:                          sResult=QString("fEaRz Crypter");                               break;
        case RECORD_NAME_FEARZPACKER:                           sResult=QString("fEaRz Packer");                                break;
        case RECORD_NAME_FENIXOS:                               sResult=QString("FenixOS");                                     break;
        case RECORD_NAME_FILESHIELD:                            sResult=QString("FileShield");                                  break;
        case RECORD_NAME_FISHNET:                               sResult=QString("FISH .NET");                                   break;
        case RECORD_NAME_FISHPEPACKER:                          sResult=QString("Fish PE Packer");                              break; // TODO Check name
        case RECORD_NAME_FISHPESHIELD:                          sResult=QString("FishPE Shield");                               break;
        case RECORD_NAME_FLASHVIDEO:                            sResult=QString("Flash Video");                                 break;
        case RECORD_NAME_FLEXLM:                                sResult=QString("Flex License Manager");                        break;
        case RECORD_NAME_FLEXNET:                               sResult=QString("FlexNet Licensing");                           break;
        case RECORD_NAME_FORTRAN:                               sResult=QString("Fortran");                                     break;
        case RECORD_NAME_FOUNDATION:                            sResult=QString("Foundation");                                  break;
        case RECORD_NAME_FPC:                                   sResult=QString("Free Pascal");                                 break;
        case RECORD_NAME_FREEBSD:                               sResult=QString("FreeBSD");                                     break;
        case RECORD_NAME_FREECRYPTOR:                           sResult=QString("FreeCryptor");                                 break;
        case RECORD_NAME_FSG:                                   sResult=QString("FSG");                                         break;
        case RECORD_NAME_GCC:                                   sResult=QString("GCC");                                         break;
        case RECORD_NAME_GENERIC:                               sResult=QString("Generic");                                     break;
        case RECORD_NAME_GENERICLINKER:                         sResult=QString("Generic Linker");                              break;
        case RECORD_NAME_GENTEEINSTALLER:                       sResult=QString("Gentee Installer");                            break;
        case RECORD_NAME_GENTOOLINUX:                           sResult=QString("Gentoo Linux");                                break;
        case RECORD_NAME_GHAZZACRYPTER:                         sResult=QString("GhaZza CryPter");                              break; // st
        case RECORD_NAME_GHOSTINSTALLER:                        sResult=QString("Ghost Installer");                             break;
        case RECORD_NAME_GIF:                                   sResult=QString("GIF");                                         break;
        case RECORD_NAME_GIXPROTECTOR:                          sResult=QString("G!X Protector");                               break;
        case RECORD_NAME_GKRIPTO:                               sResult=QString("GKripto");                                     break;
        case RECORD_NAME_GKSETUPSFX:                            sResult=QString("GkSetup SFX");                                 break;
        case RECORD_NAME_GNUASSEMBLER:                          sResult=QString("GNU Assembler");                               break;
        case RECORD_NAME_GNULINKER:                             sResult=QString("GNU ld");                                      break;
        case RECORD_NAME_GO:                                    sResult=QString("Go");                                          break;
        case RECORD_NAME_GOASM:                                 sResult=QString("GoAsm");                                       break;
        case RECORD_NAME_GOATSPEMUTILATOR:                      sResult=QString("Goat's PE Mutilator");                         break;
        case RECORD_NAME_GOLD:                                  sResult=QString("gold");                                        break;
        case RECORD_NAME_GOLIATHNET:                            sResult=QString("Goliath .NET");                                break;
        case RECORD_NAME_GOLINK:                                sResult=QString("GoLink");                                      break;
        case RECORD_NAME_GOOGLE:                                sResult=QString("Google");                                      break;
        case RECORD_NAME_GOOGLEPLAY:                            sResult=QString("Google Play");                                 break;
        case RECORD_NAME_GPINSTALL:                             sResult=QString("GP-Install");                                  break;
        case RECORD_NAME_GUARDIANSTEALTH:                       sResult=QString("Guardian Stealth");                            break;
        case RECORD_NAME_GZIP:                                  sResult=QString("GZIP");                                        break;
        case RECORD_NAME_H4CKY0UORGCRYPTER:                     sResult=QString("H4ck-y0u.org Crypter");                        break;
        case RECORD_NAME_HACCREWCRYPTER:                        sResult=QString("HAC Crew Crypter");                            break;
        case RECORD_NAME_HACKSTOP:                              sResult=QString("HackStop");                                    break;
        case RECORD_NAME_HALVCRYPTER:                           sResult=QString("HaLV Crypter");                                break;
        case RECORD_NAME_HANCOMLINUX:                           sResult=QString("Hancom Linux");                                break;
        case RECORD_NAME_HDUS_WJUS:                             sResult=QString("Hdus-Wjus");                                   break;
        case RECORD_NAME_HIAPKCOM:                              sResult=QString("www.HiAPK.com");                               break;
        case RECORD_NAME_HIDEANDPROTECT:                        sResult=QString("Hide&Protect");                                break;
        case RECORD_NAME_HIDEPE:                                sResult=QString("HidePE");                                      break;
        case RECORD_NAME_HIKARIOBFUSCATOR:                      sResult=QString("HikariObfuscator");                            break;
        case RECORD_NAME_HMIMYSPACKER:                          sResult=QString("Hmimys Packer");                               break;
        case RECORD_NAME_HMIMYSPROTECTOR:                       sResult=QString("Hmimys's Protector");                          break;
        case RECORD_NAME_HOODLUM:                               sResult=QString("HOODLUM");                                     break;
        case RECORD_NAME_HOUNDHACKCRYPTER:                      sResult=QString("Hound Hack Crypter");                          break;
        case RECORD_NAME_HPUX:                                  sResult=QString("Hewlett-Packard HP-UX");                       break;
        case RECORD_NAME_HTML:                                  sResult=QString("HTML");                                        break;
        case RECORD_NAME_HXS:                                   sResult=QString("HXS");                                         break;
        case RECORD_NAME_IBMJDK:                                sResult=QString("IBM JDK");                                     break;
        case RECORD_NAME_IBMPCPASCAL:                           sResult=QString("IBM PC Pascal");                               break;
        case RECORD_NAME_ICE:                                   sResult=QString("ICE");                                         break;
        case RECORD_NAME_ICRYPT:                                sResult=QString("ICrypt");                                      break;
        case RECORD_NAME_IJIAMI:                                sResult=QString("iJiami");                                      break;
        case RECORD_NAME_IJIAMILLVM:                            sResult=QString("iJiami LLVM");                                 break;
        case RECORD_NAME_IKVMDOTNET:                            sResult=QString("IKVM.NET");                                    break;
        case RECORD_NAME_IL2CPP:                                sResult=QString("IL2CPP");                                      break;
        case RECORD_NAME_ILASM:                                 sResult=QString("ILAsm");                                       break;
        case RECORD_NAME_IMPORT:                                sResult=QString("Import");                                      break;
        case RECORD_NAME_INFCRYPTOR:                            sResult=QString("INF Cryptor");                                 break;
        case RECORD_NAME_INNOSETUP:                             sResult=QString("Inno Setup");                                  break;
        case RECORD_NAME_INQUARTOSOBFUSCATOR:                   sResult=QString("Inquartos Obfuscator");                        break;
        case RECORD_NAME_INSTALL4J:                             sResult=QString("install4j");                                   break;
        case RECORD_NAME_INSTALLANYWHERE:                       sResult=QString("InstallAnywhere");                             break;
        case RECORD_NAME_INSTALLSHIELD:                         sResult=QString("InstallShield");                               break;
        case RECORD_NAME_IOS:                                   sResult=QString("iOS");                                         break;
        case RECORD_NAME_IOSSDK:                                sResult=QString("iOS SDK");                                     break;
        case RECORD_NAME_IPA:                                   sResult=QString("iOS App Store Package");                       break;
        case RECORD_NAME_IPADOS:                                sResult=QString("iPadOS");                                      break;
        case RECORD_NAME_IPHONEOS:                              sResult=QString("iPhone OS");                                   break;
        case RECORD_NAME_IPBPROTECT:                            sResult=QString("iPB Protect");                                 break;
        case RECORD_NAME_IRIX:                                  sResult=QString("IRIX");                                        break;
        case RECORD_NAME_ISO9660:                               sResult=QString("ISO 9660");                                    break;
        case RECORD_NAME_JACK:                                  sResult=QString("Jack");                                        break;
        case RECORD_NAME_JAM:                                   sResult=QString("JAM");                                         break;
        case RECORD_NAME_JAR:                                   sResult=QString("JAR");                                         break;
        case RECORD_NAME_JAVA:                                  sResult=QString("Java");                                        break;
        case RECORD_NAME_JAVACOMPILEDCLASS:                     sResult=QString("Java compiled class");                         break;
        case RECORD_NAME_JDK:                                   sResult=QString("JDK");                                         break;
        case RECORD_NAME_JDPACK:                                sResult=QString("JDPack");                                      break;
        case RECORD_NAME_JETBRAINS:                             sResult=QString("JetBrains");                                   break;
        case RECORD_NAME_JIAGU:                                 sResult=QString("jiagu");                                       break;
        case RECORD_NAME_JPEG:                                  sResult=QString("JPEG");                                        break;
        case RECORD_NAME_JVM:                                   sResult=QString("JVM");                                         break;
        case RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER:         sResult=QString("KaOs PE-DLL eXecutable Undetecter");           break;
        case RECORD_NAME_KBYS:                                  sResult=QString("KByS");                                        break;
        case RECORD_NAME_KCRYPTOR:                              sResult=QString("K!Cryptor");                                   break;
        case RECORD_NAME_KGBCRYPTER:                            sResult=QString("KGB Crypter");                                 break;
        case RECORD_NAME_KIAMSCRYPTOR:                          sResult=QString("KiAms Cryptor");                               break;
        case RECORD_NAME_KIRO:                                  sResult=QString("Kiro");                                        break;
        case RECORD_NAME_KIWIVERSIONOBFUSCATOR:                 sResult=QString("Kiwi Version Obfuscator");                     break;
        case RECORD_NAME_KKRUNCHY:                              sResult=QString("kkrunchy");                                    break;
        case RECORD_NAME_KOTLIN:                                sResult=QString("Kotlin");                                      break;
        case RECORD_NAME_KRATOSCRYPTER:                         sResult=QString("Kratos Crypter");                              break;
        case RECORD_NAME_KRYPTON:                               sResult=QString("Krypton");                                     break;
        case RECORD_NAME_KUR0KX2TO:                             sResult=QString("Kur0k.X2.to");                                 break;
        case RECORD_NAME_LAMECRYPT:                             sResult=QString("LameCrypt");                                   break;
        case RECORD_NAME_LARP64:                                sResult=QString("lARP64");                                      break;
        case RECORD_NAME_LAYHEYFORTRAN90:                       sResult=QString("Lahey Fortran 90");                            break;
        case RECORD_NAME_LAZARUS:                               sResult=QString("Lazarus");                                     break;
        case RECORD_NAME_LCCLNK:                                sResult=QString("lcclnk");                                      break;
        case RECORD_NAME_LCCWIN:                                sResult=QString("lcc-win");                                     break;
        case RECORD_NAME_LGLZ:                                  sResult=QString("LGLZ");                                        break;
        case RECORD_NAME_LHA:                                   sResult=QString("LHA");                                         break;
        case RECORD_NAME_LHASSFX:                               sResult=QString("LHA's SFX");                                   break;
        case RECORD_NAME_LIAPP:                                 sResult=QString("LIAPP");                                       break;
        case RECORD_NAME_LIGHTNINGCRYPTERPRIVATE:               sResult=QString("Lightning Crypter Private");                   break;
        case RECORD_NAME_LIGHTNINGCRYPTERSCANTIME:              sResult=QString("Lightning Crypter ScanTime");                  break;
        case RECORD_NAME_LINUX:                                 sResult=QString("Linux");                                       break;
        case RECORD_NAME_LLD:                                   sResult=QString("LDD");                                         break;
        case RECORD_NAME_LOCKTITE:                              sResult=QString("LockTite+");                                   break;
        case RECORD_NAME_LSCRYPRT:                              sResult=QString("LSCRYPT");                                     break;
        case RECORD_NAME_LUACOMPILED:                           sResult=QString("Lua compiled");                                break;
        case RECORD_NAME_LUCYPHER:                              sResult=QString("LuCypher");                                    break;
        case RECORD_NAME_LZEXE:                                 sResult=QString("LZEXE");                                       break;
        case RECORD_NAME_LZFSE:                                 sResult=QString("LZFSE");                                       break;
        case RECORD_NAME_MACHOFAT:                              sResult=QString("Mach-O FAT");                                  break;
        case RECORD_NAME_MAC_OS:                                sResult=QString("Mac OS");                                      break;
        case RECORD_NAME_MAC_OS_X:                              sResult=QString("Mac OS X");                                    break;
        case RECORD_NAME_MACOS:                                 sResult=QString("macOS");                                       break;
        case RECORD_NAME_MACOSSDK:                              sResult=QString("macOS SDK");                                   break;
        case RECORD_NAME_MACROBJECT:                            sResult=QString("Macrobject");                                  break;
        case RECORD_NAME_MALPACKER:                             sResult=QString("Mal Packer");                                  break;
        case RECORD_NAME_MANDRAKELINUX:                         sResult=QString("Mandrake Linux");                              break;
        case RECORD_NAME_MASKPE:                                sResult=QString("MaskPE");                                      break;
        case RECORD_NAME_MASM32:                                sResult=QString("MASM32");                                      break;
        case RECORD_NAME_MASM:                                  sResult=QString("MASM");                                        break;
        case RECORD_NAME_MAXTOCODE:                             sResult=QString("MaxtoCode");                                   break;
        case RECORD_NAME_MEDUSAH:                               sResult=QString("Medusah");                                     break;
        case RECORD_NAME_MEW10:                                 sResult=QString("MEW10");                                       break;
        case RECORD_NAME_MEW11SE:                               sResult=QString("MEW11 SE");                                    break;
        case RECORD_NAME_MFC:                                   sResult=QString("MFC");                                         break;
        case RECORD_NAME_MICROSOFTACCESS:                       sResult=QString("Microsoft Access");                            break;
        case RECORD_NAME_MICROSOFTC:                            sResult=QString("Microsoft C");                                 break;
        case RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP:             sResult=QString("Microsoft Compiled HTML Help");                break;
        case RECORD_NAME_MICROSOFTCOMPOUND:                     sResult=QString("Microsoft Compound");                          break;
        case RECORD_NAME_MICROSOFTCPP:                          sResult=QString("Microsoft C++");                               break;
        case RECORD_NAME_MICROSOFTDOTNETFRAMEWORK:              sResult=QString("Microsoft .NET Framework");                    break;
        case RECORD_NAME_MICROSOFTEXCEL:                        sResult=QString("Microsoft Excel");                             break;
        case RECORD_NAME_MICROSOFTINSTALLER:                    sResult=QString("Microsoft Installer(MSI)");                    break;
        case RECORD_NAME_MICROSOFTLINKER:                       sResult=QString("Microsoft linker");                            break;
        case RECORD_NAME_MICROSOFTLINKERDATABASE:               sResult=QString("Microsoft Linker Database");                   break;
        case RECORD_NAME_MICROSOFTOFFICE:                       sResult=QString("Microsoft Office");                            break;
        case RECORD_NAME_MICROSOFTOFFICEWORD:                   sResult=QString("Microsoft Office Word");                       break;
        case RECORD_NAME_MICROSOFTPHOENIX:                      sResult=QString("Microsoft Phoenix");                           break;
        case RECORD_NAME_MICROSOFTVISIO:                        sResult=QString("Microsoft Visio");                             break;
        case RECORD_NAME_MICROSOFTVISUALSTUDIO:                 sResult=QString("Microsoft Visual Studio");                     break;
        case RECORD_NAME_MICROSOFTWINHELP:                      sResult=QString("Microsoft WinHelp");                           break;
        case RECORD_NAME_MINGW:                                 sResult=QString("MinGW");                                       break;
        case RECORD_NAME_MINKE:                                 sResult=QString("Minke");                                       break;
        case RECORD_NAME_MKFPACK:                               sResult=QString("MKFPack");                                     break;
        case RECORD_NAME_MOBILETENCENTPROTECT:                  sResult=QString("Mobile Tencent Protect");                      break;
        case RECORD_NAME_MODESTO:                               sResult=QString("Novell Modesto");                              break;
        case RECORD_NAME_MODGUARD:                              sResult=QString("ModGuard");                                    break;
        case RECORD_NAME_MOLEBOX:                               sResult=QString("MoleBox");                                     break;
        case RECORD_NAME_MOLEBOXULTRA:                          sResult=QString("MoleBox Ultra");                               break;
        case RECORD_NAME_MONEYCRYPTER:                          sResult=QString("Money Crypter");                               break;
        case RECORD_NAME_MORPHNAH:                              sResult=QString("Morphnah");                                    break;
        case RECORD_NAME_MORTALTEAMCRYPTER2:                    sResult=QString("Mortal Team Crypter 2");                       break;
        case RECORD_NAME_MORTALTEAMCRYPTER:                     sResult=QString("Mortal Team Crypter");                         break;
        case RECORD_NAME_MORUKCREWCRYPTERPRIVATE:               sResult=QString("MoruK creW Crypter Private");                  break;
        case RECORD_NAME_MOTODEVSTUDIOFORANDROID:               sResult=QString("MOTODEV Studio for Android");                  break;
        case RECORD_NAME_MP3:                                   sResult=QString("MP3");                                         break;
        case RECORD_NAME_MP4:                                   sResult=QString("MP4");                                         break;
        case RECORD_NAME_MPACK:                                 sResult=QString("mPack");                                       break;
        case RECORD_NAME_MPRESS:                                sResult=QString("MPRESS");                                      break;
        case RECORD_NAME_MRUNDECTETABLE:                        sResult=QString("Mr Undectetable");                             break;
        case RECORD_NAME_MSDOS:                                 sResult=QString("MS-DOS");                                      break;
        case RECORD_NAME_MSLRH:                                 sResult=QString("MSLRH");                                       break;
        case RECORD_NAME_MSYS2:                                 sResult=QString("MSYS2");                                       break;
        case RECORD_NAME_MSYS:                                  sResult=QString("Msys");                                        break;
        case RECORD_NAME_MZ0OPE:                                sResult=QString("MZ0oPE");                                      break;
        case RECORD_NAME_NAGAINLLVM:                            sResult=QString("Nagain LLVM");                                 break;
        case RECORD_NAME_NAGAPTPROTECTION:                      sResult=QString("Nagapt Protection");                           break;
        case RECORD_NAME_NAKEDPACKER:                           sResult=QString("NakedPacker");                                 break;
        case RECORD_NAME_NASM:                                  sResult=QString("NASM");                                        break;
        case RECORD_NAME_NCODE:                                 sResult=QString("N-Code");                                      break;
        case RECORD_NAME_NEOLITE:                               sResult=QString("NeoLite");                                     break;
        case RECORD_NAME_NETBSD:                                sResult=QString("NetBSD");                                      break;
        case RECORD_NAME_NETEASEAPKSIGNER:                      sResult=QString("NetEase ApkSigner");                           break;
        case RECORD_NAME_NIDHOGG:                               sResult=QString("Nidhogg");                                     break;
        case RECORD_NAME_NIM:                                   sResult=QString("Nim");                                         break;
        case RECORD_NAME_NJOINER:                               sResult=QString("N-Joiner");                                    break;
        case RECORD_NAME_NJOY:                                  sResult=QString("N-Joy");                                       break;
        case RECORD_NAME_NME:                                   sResult=QString("NME");                                         break;
        case RECORD_NAME_NOOBYPROTECT:                          sResult=QString("NoobyProtect");                                break;
        case RECORD_NAME_NOODLECRYPT:                           sResult=QString("NoodleCrypt");                                 break;
        case RECORD_NAME_NORTHSTARPESHRINKER:                   sResult=QString("North Star PE Shrinker");                      break;
        case RECORD_NAME_NOSINSTALLER:                          sResult=QString("NOS Installer");                               break;
        case RECORD_NAME_NOSTUBLINKER:                          sResult=QString("NOSTUBLINKER");                                break;
        case RECORD_NAME_NOXCRYPT:                              sResult=QString("noX Crypt");                                   break;
        case RECORD_NAME_NPACK:                                 sResult=QString("nPack");                                       break;
        case RECORD_NAME_NQSHIELD:                              sResult=QString("NQ Shield");                                   break;
        case RECORD_NAME_NSIS:                                  sResult=QString("Nullsoft Scriptable Install System");          break;
        case RECORD_NAME_NSK:                                   sResult=QString("Hewlett-Packard Non-Stop Kernel");             break;
        case RECORD_NAME_NSPACK:                                sResult=QString("NsPack");                                      break;
        case RECORD_NAME_OBFUSCAR:                              sResult=QString("Obfuscar");                                    break;
        case RECORD_NAME_OBFUSCATORLLVM:                        sResult=QString("Obfuscator-LLVM");                             break;
        case RECORD_NAME_OBFUSCATORNET2009:                     sResult=QString("Obfuscator.NET 2009");                         break;
        case RECORD_NAME_OBJECTIVEC:                            sResult=QString("Objective-C");                                 break;
        case RECORD_NAME_OBJECTPASCAL:                          sResult=QString("Object Pascal");                               break;
        case RECORD_NAME_OBJECTPASCALDELPHI:                    sResult=QString("Object Pascal(Delphi)");                       break;
        case RECORD_NAME_OBSIDIUM:                              sResult=QString("Obsidium");                                    break;
        case RECORD_NAME_OLLVMTLL:                              sResult=QString("ollvm-tll(LLVM 6.0+Ollvm+Armariris)");         break;
        case RECORD_NAME_ONESPANPROTECTION:                     sResult=QString("OneSpan Protection");                          break;
        case RECORD_NAME_OPENBSD:                               sResult=QString("OpenBSD");                                     break;
        case RECORD_NAME_OPENDOCUMENT:                          sResult=QString("Open Document");                               break;
        case RECORD_NAME_OPENJDK:                               sResult=QString("OpenJDK");                                     break;
        case RECORD_NAME_OPENSOURCECODECRYPTER:                 sResult=QString("Open Source Code Crypter");                    break;
        case RECORD_NAME_OPENVMS:                               sResult=QString("Open VMS");                                    break;
        case RECORD_NAME_OPERA:                                 sResult=QString("Opera");                                       break;
        case RECORD_NAME_ORACLESOLARISLINKEDITORS:              sResult=QString("Oracle Solaris Link Editors");                 break;
        case RECORD_NAME_ORIEN:                                 sResult=QString("ORiEN");                                       break;
        case RECORD_NAME_OS2:                                   sResult=QString("OS2");                                         break;
        case RECORD_NAME_OSCCRYPTER:                            sResult=QString("OSC-Crypter");                                 break;
        case RECORD_NAME_OS_X:                                  sResult=QString("OS X");                                        break;
        case RECORD_NAME_P0KESCRAMBLER:                         sResult=QString("p0ke Scrambler");                              break;
        case RECORD_NAME_PACKMAN:                               sResult=QString("Packman");                                     break;
        case RECORD_NAME_PACKWIN:                               sResult=QString("PACKWIN");                                     break;
        case RECORD_NAME_PANDORA:                               sResult=QString("Pandora");                                     break;
        case RECORD_NAME_PANGXIE:                               sResult=QString("PangXie");                                     break;
        case RECORD_NAME_PCGUARD:                               sResult=QString("PC Guard");                                    break;
        case RECORD_NAME_PCOM:                                  sResult=QString("PCOM");                                        break;
        case RECORD_NAME_PCSHRINK:                              sResult=QString("PCShrink");                                    break;
        case RECORD_NAME_PDB:                                   sResult=QString("PDB");                                         break;
        case RECORD_NAME_PDBFILELINK:                           sResult=QString("PDB file link");                               break;
        case RECORD_NAME_PDF:                                   sResult=QString("PDF");                                         break;
        case RECORD_NAME_PEARMOR:                               sResult=QString("PE-Armor");                                    break;
        case RECORD_NAME_PEBUNDLE:                              sResult=QString("PEBundle");                                    break;
        case RECORD_NAME_PECOMPACT:                             sResult=QString("PECompact");                                   break;
        case RECORD_NAME_PECRYPT32:                             sResult=QString("PECRYPT32");                                   break;
        case RECORD_NAME_PEDIMINISHER:                          sResult=QString("PE Diminisher");                               break;
        case RECORD_NAME_PEENCRYPT:                             sResult=QString("PE Encrypt");                                  break;
        case RECORD_NAME_PELOCK:                                sResult=QString("PELock");                                      break;
        case RECORD_NAME_PELOCKNT:                              sResult=QString("PELOCKnt");                                    break;
        case RECORD_NAME_PENGUINCRYPT:                          sResult=QString("PEnguinCrypt");                                break; // TODO Check name
        case RECORD_NAME_PEPACK:                                sResult=QString("PE-PACK");                                     break;
        case RECORD_NAME_PEPACKSPROTECT:                        sResult=QString("pepack's Protect");                            break;
        case RECORD_NAME_PEQUAKE:                               sResult=QString("PE Quake");                                    break;
        case RECORD_NAME_PERL:                                  sResult=QString("Perl");                                        break;
        case RECORD_NAME_PESHIELD:                              sResult=QString("PE-SHiELD");                                   break; // TODO Check name
        case RECORD_NAME_PESPIN:                                sResult=QString("PESpin");                                      break;
        case RECORD_NAME_PETITE:                                sResult=QString("Petite");                                      break;
        case RECORD_NAME_PETITE_KERNEL32:                       sResult=QString("Petite.kernel32");                             break;
        case RECORD_NAME_PETITE_USER32:                         sResult=QString("Petite.user32");                               break;
        case RECORD_NAME_PEX:                                   sResult=QString("PeX");                                         break;
        case RECORD_NAME_PFECX:                                 sResult=QString("PFE CX");                                      break;
        case RECORD_NAME_PGMPAK:                                sResult=QString("PGMPAK");                                      break;
        case RECORD_NAME_PHOENIXPROTECTOR:                      sResult=QString("Phoenix Protector");                           break;
        case RECORD_NAME_PHP:                                   sResult=QString("PHP");                                         break;
        case RECORD_NAME_PICRYPTOR:                             sResult=QString("PI Cryptor");                                  break;
        case RECORD_NAME_PKLITE32:                              sResult=QString("PKLITE32");                                    break;
        case RECORD_NAME_PKLITE:                                sResult=QString("PKLITE");                                      break;
        case RECORD_NAME_PKZIPMINISFX:                          sResult=QString("PKZIP mini-sfx");                              break;
        case RECORD_NAME_PLAIN:                                 sResult=QString("Plain");                                       break;
        case RECORD_NAME_PLEXCLANG:                             sResult=QString("Plex clang");                                  break;
        case RECORD_NAME_PMODEW:                                sResult=QString("PMODE/W");                                     break;
        case RECORD_NAME_PNG:                                   sResult=QString("PNG");                                         break;
        case RECORD_NAME_POKECRYPTER:                           sResult=QString("Poke Crypter");                                break;
        case RECORD_NAME_POLYCRYPTPE:                           sResult=QString("PolyCrypt PE");                                break;
        case RECORD_NAME_POSIX:                                 sResult=QString("Posix");                                       break;
        case RECORD_NAME_POWERBASIC:                            sResult=QString("PowerBASIC");                                  break;
        case RECORD_NAME_PRIVATEEXEPROTECTOR:                   sResult=QString("Private EXE Protector");                       break;
        case RECORD_NAME_PROGUARD:                              sResult=QString("Proguard");                                    break;
        case RECORD_NAME_PROPACK:                               sResult=QString("PRO-PACK");                                    break;
        case RECORD_NAME_PROTECTEXE:                            sResult=QString("PROTECT! EXE");                                break;
        case RECORD_NAME_PSEUDOAPKSIGNER:                       sResult=QString("PseudoApkSigner");                             break;
        case RECORD_NAME_PUBCRYPTER:                            sResult=QString("Pub Crypter");                                 break;
        case RECORD_NAME_PUNISHER:                              sResult=QString("PUNiSHER");                                    break;
        case RECORD_NAME_PUREBASIC:                             sResult=QString("PureBasic");                                   break;
        case RECORD_NAME_PUSSYCRYPTER:                          sResult=QString("PussyCrypter");                                break;
        case RECORD_NAME_PYINSTALLER:                           sResult=QString("PyInstaller");                                 break;
        case RECORD_NAME_PYTHON:                                sResult=QString("Python");                                      break;
        case RECORD_NAME_QDBH:                                  sResult=QString("qdbh");                                        break;
        case RECORD_NAME_QIHOO360PROTECTION:                    sResult=QString("Qihoo 360 Protection");                        break;
        case RECORD_NAME_QRYPT0R:                               sResult=QString("QrYPt0r");                                     break;
        case RECORD_NAME_QT:                                    sResult=QString("Qt");                                          break;
        case RECORD_NAME_QTINSTALLER:                           sResult=QString("Qt Installer");                                break;
        case RECORD_NAME_QUICKPACKNT:                           sResult=QString("QuickPack NT");                                break;
        case RECORD_NAME_R8:                                    sResult=QString("R8");                                          break;
        case RECORD_NAME_RADIALIX:                              sResult=QString("Radialix");                                    break;
        case RECORD_NAME_RAR:                                   sResult=QString("RAR");                                         break;
        case RECORD_NAME_RCRYPTOR:                              sResult=QString("RCryptor(Russian Cryptor)");                   break;
        case RECORD_NAME_RDGTEJONCRYPTER:                       sResult=QString("RDG Tejon Crypter");                           break;
        case RECORD_NAME_REDHATLINUX:                           sResult=QString("Red Hat Linux");                               break;
        case RECORD_NAME_RELPACK:                               sResult=QString("Relpack");                                     break;
        case RECORD_NAME_RENETPACK:                             sResult=QString("ReNET-pack");                                  break;
        case RECORD_NAME_RESOURCE:                              sResult=QString("Resource");                                    break;
        case RECORD_NAME_REVPROT:                               sResult=QString("REVProt");                                     break;
        case RECORD_NAME_RJCRUSH:                               sResult=QString("RJcrush");                                     break;
        case RECORD_NAME_RLP:                                   sResult=QString("RLP");                                         break;
        case RECORD_NAME_RLPACK:                                sResult=QString("RLPack");                                      break;
        case RECORD_NAME_ROGUEPACK:                             sResult=QString("RoguePack");                                   break;
        case RECORD_NAME_ROSASM:                                sResult=QString("RosAsm");                                      break;
        case RECORD_NAME_RTF:                                   sResult=QString("Rich Text Format");                            break;
        case RECORD_NAME_RUBY:                                  sResult=QString("Ruby");                                        break;
        case RECORD_NAME_RUST:                                  sResult=QString("Rust");                                        break;
        case RECORD_NAME_SAFEENGINELLVM:                        sResult=QString("Safengine LLVM");                              break;
        case RECORD_NAME_SAFEENGINESHIELDEN:                    sResult=QString("Safengine Shielden");                          break;
        case RECORD_NAME_SANDHOOK:                              sResult=QString("SandHook");                                    break;
        case RECORD_NAME_SCOBFUSCATOR:                          sResult=QString("SC Obfuscator");                               break;
        case RECORD_NAME_SCPACK:                                sResult=QString("SC Pack");                                     break;
        case RECORD_NAME_SCRNCH:                                sResult=QString("SCRNCH");                                      break;
        case RECORD_NAME_SDPROTECTORPRO:                        sResult=QString("SDProtector Pro");                             break;
        case RECORD_NAME_SECNEO:                                sResult=QString("SecNeo");                                      break;
        case RECORD_NAME_SECSHELL:                              sResult=QString("SecShell");                                    break;
        case RECORD_NAME_SECURESHADE:                           sResult=QString("Secure Shade");                                break;
        case RECORD_NAME_SECUROM:                               sResult=QString("SecuROM");                                     break;
        case RECORD_NAME_SERGREENAPPACKER:                      sResult=QString("SerGreen Appacker");                           break;
        case RECORD_NAME_SETUPFACTORY:                          sResult=QString("Setup Factory");                               break;
        case RECORD_NAME_SEXECRYPTER:                           sResult=QString("Sexe Crypter");                                break;
        case RECORD_NAME_SHELL:                                 sResult=QString("Shell");                                       break;
        case RECORD_NAME_SHRINKER:                              sResult=QString("Shrinker");                                    break;
        case RECORD_NAME_SIGNATORY:                             sResult=QString("signatory");                                   break;
        case RECORD_NAME_SIGNUPDATE:                            sResult=QString("signupdate");                                  break;
        case RECORD_NAME_SIMBIOZ:                               sResult=QString("SimbiOZ");                                     break;
        case RECORD_NAME_SIMCRYPTER:                            sResult=QString("Sim Crypter");                                 break;
        case RECORD_NAME_SIMPLECRYPTER:                         sResult=QString("Simple Crypter");                              break;
        case RECORD_NAME_SIMPLEPACK:                            sResult=QString("Simple Pack");                                 break;
        case RECORD_NAME_SINGLEJAR:                             sResult=QString("SingleJar");                                   break;
        case RECORD_NAME_SIXXPACK:                              sResult=QString("Sixxpack");                                    break;
        case RECORD_NAME_SKATER:                                sResult=QString("Skater");                                      break;
        case RECORD_NAME_SMARTASSEMBLY:                         sResult=QString("Smart Assembly");                              break;
        case RECORD_NAME_SMARTINSTALLMAKER:                     sResult=QString("Smart Install Maker");                         break;
        case RECORD_NAME_SMOKESCREENCRYPTER:                    sResult=QString("SmokeScreen Crypter");                         break;
        case RECORD_NAME_SNAPDRAGONLLVMARM:                     sResult=QString("Snapdragon LLVM ARM");                         break;
        case RECORD_NAME_SNAPPROTECT:                           sResult=QString("SnapProtect");                                 break;
        case RECORD_NAME_SNOOPCRYPT:                            sResult=QString("Snoop Crypt");                                 break;
        case RECORD_NAME_SOFTDEFENDER:                          sResult=QString("Soft Defender");                               break;
        case RECORD_NAME_SOFTSENTRY:                            sResult=QString("SoftSentry");                                  break;
        case RECORD_NAME_SOFTWARECOMPRESS:                      sResult=QString("Software Compress");                           break;
        case RECORD_NAME_SOFTWAREZATOR:                         sResult=QString("SoftwareZator");                               break;
        case RECORD_NAME_SOLARIS:                               sResult=QString("Sun Solaris");                                 break;
        case RECORD_NAME_SOURCERYCODEBENCH:                     sResult=QString("Sourcery CodeBench");                          break;
        case RECORD_NAME_SOURCERYCODEBENCHLITE:                 sResult=QString("Sourcery CodeBench Lite");                     break;
        case RECORD_NAME_SPICESNET:                             sResult=QString("Spices.Net");                                  break;
        case RECORD_NAME_SPIRIT:                                sResult=QString("$pirit");                                      break;
        case RECORD_NAME_SPOONINSTALLER:                        sResult=QString("Spoon Installer");                             break;
        case RECORD_NAME_SPOONSTUDIO2011:                       sResult=QString("Spoon Studio 2011");                           break;
        case RECORD_NAME_SPOONSTUDIO:                           sResult=QString("Spoon Studio");                                break;
        case RECORD_NAME_SQUEEZSFX:                             sResult=QString("Squeez Self Extractor");                       break;
        case RECORD_NAME_STARFORCE:                             sResult=QString("StarForce");                                   break;
        case RECORD_NAME_STARTOSLINUX:                          sResult=QString("StartOS Linux");                               break;
        case RECORD_NAME_STASFODIDOCRYPTOR:                     sResult=QString("StasFodidoCryptor");                           break;
        case RECORD_NAME_STONESPEENCRYPTOR:                     sResult=QString("Stone's PE Encryptor");                        break;
        case RECORD_NAME_SUNOS:                                 sResult=QString("SunOS");                                       break;
        case RECORD_NAME_SUNWORKSHOP:                           sResult=QString("Sun WorkShop");                                break;
        case RECORD_NAME_SUSELINUX:                             sResult=QString("SUSE Linux");                                  break;
        case RECORD_NAME_SVKPROTECTOR:                          sResult=QString("SVK Protector");                               break;
        case RECORD_NAME_SWF:                                   sResult=QString("SWF");                                         break;
        case RECORD_NAME_SWIFT:                                 sResult=QString("Swift");                                       break;
        case RECORD_NAME_TARMAINSTALLER:                        sResult=QString("Tarma Installer");                             break;
        case RECORD_NAME_TELOCK:                                sResult=QString("tElock");                                      break;
        case RECORD_NAME_TENCENTLEGU:                           sResult=QString("Tencent Legu");                                break;
        case RECORD_NAME_TENCENTPROTECTION:                     sResult=QString("Tencent Protection");                          break;
        case RECORD_NAME_TGRCRYPTER:                            sResult=QString("TGR Crypter");                                 break;
        case RECORD_NAME_THEBESTCRYPTORBYFSK:                   sResult=QString("The Best Cryptor [by FsK]");                   break;
        case RECORD_NAME_THEMIDAWINLICENSE:                     sResult=QString("Themida/Winlicense");                          break;
        case RECORD_NAME_THEZONECRYPTER:                        sResult=QString("The Zone Crypter");                            break;
        case RECORD_NAME_THINSTALL:                             sResult=QString("Thinstall(VMware ThinApp)");                   break;
        case RECORD_NAME_THUMBC:                                sResult=QString("Thumb C");                                     break;
        case RECORD_NAME_TIFF:                                  sResult=QString("TIFF");                                        break;
        case RECORD_NAME_TINYC:                                 sResult=QString("Tiny C");                                      break;
        case RECORD_NAME_TINYPROG:                              sResult=QString("TinyProg");                                    break;
        case RECORD_NAME_TINYSIGN:                              sResult=QString("tiny-sign");                                   break;
        case RECORD_NAME_TOTALCOMMANDERINSTALLER:               sResult=QString("Total Commander Installer");                   break;
        case RECORD_NAME_TPPPACK:                               sResult=QString("TTP Pack");                                    break;
        case RECORD_NAME_TRU64:                                 sResult=QString("Compaq TRU64 UNIX");                           break;
        case RECORD_NAME_TSTCRYPTER:                            sResult=QString("TsT Crypter");                                 break;
        case RECORD_NAME_TTF:                                   sResult=QString("True Type Font");                              break;
        case RECORD_NAME_TTPROTECT:                             sResult=QString("TTprotect");                                   break;
        case RECORD_NAME_TURBOBASIC:                            sResult=QString("Turbo Basic");                                 break;
        case RECORD_NAME_TURBOC:                                sResult=QString("Turbo C");                                     break;
        case RECORD_NAME_TURBOCPP:                              sResult=QString("Turbo C++");                                   break;
        case RECORD_NAME_TURBOLINKER:                           sResult=QString("Turbo linker");                                break;
        case RECORD_NAME_TURBOLINUX:                            sResult=QString("Turbolinux");                                  break;
        case RECORD_NAME_TURBOSTUDIO:                           sResult=QString("Turbo Studio");                                break;
        case RECORD_NAME_TURKISHCYBERSIGNATURE:                 sResult=QString("Turkish Cyber Signature");                     break;
        case RECORD_NAME_TURKOJANCRYPTER:                       sResult=QString("Turkojan Crypter");                            break;
        case RECORD_NAME_TVOS:                                  sResult=QString("tvOS");                                        break;
        case RECORD_NAME_TVOSSDK:                               sResult=QString("tvOS SDK");                                    break;
        case RECORD_NAME_UBUNTUCLANG:                           sResult=QString("Ubuntu clang");                                break;
        case RECORD_NAME_UBUNTULINUX:                           sResult=QString("Ubuntu Linux");                                break;
        case RECORD_NAME_UCEXE:                                 sResult=QString("UCEXE");                                       break;
        case RECORD_NAME_UNDERGROUNDCRYPTER:                    sResult=QString("UnderGround Crypter");                         break;
        case RECORD_NAME_UNDOCRYPTER:                           sResult=QString("UnDo Crypter");                                break;
        case RECORD_NAME_UNICODE:                               sResult=QString("Unicode");                                     break;
        case RECORD_NAME_UNICOMSDK:                             sResult=QString("Unicom SDK");                                  break;
        case RECORD_NAME_UNILINK:                               sResult=QString("UniLink");                                     break;
        case RECORD_NAME_UNITY:                                 sResult=QString("Unity");                                       break;
        case RECORD_NAME_UNIVERSALTUPLECOMPILER:                sResult=QString("Universal Tuple Compiler");                    break;
        case RECORD_NAME_UNIX:                                  sResult=QString("Unix");                                        break;
        case RECORD_NAME_UNKOWNCRYPTER:                         sResult=QString("unkOwn Crypter");                              break;
        case RECORD_NAME_UNK_UPXLIKE:                           sResult=QString("(Unknown)UPX-like");                           break;
        case RECORD_NAME_UNOPIX:                                sResult=QString("Unopix");                                      break;
        case RECORD_NAME_UPX:                                   sResult=QString("UPX");                                         break;
        case RECORD_NAME_UTF8:                                  sResult=QString("UTF-8");                                       break;
        case RECORD_NAME_VALVE:                                 sResult=QString("Valve");                                       break;
        case RECORD_NAME_VBNET:                                 sResult=QString("VB .NET");                                     break;
        case RECORD_NAME_VBSTOEXE:                              sResult=QString("Vbs To Exe");                                  break;
        case RECORD_NAME_VCASMPROTECTOR:                        sResult=QString("VCasm-Protector");                             break;
        case RECORD_NAME_VCL:                                   sResult=QString("Visual Component Library");                    break;
        case RECORD_NAME_VCLPACKAGEINFO:                        sResult=QString("VCL PackageInfo");                             break;
        case RECORD_NAME_VDOG:                                  sResult=QString("VDog");                                        break;
        case RECORD_NAME_VERACRYPT:                             sResult=QString("VeraCrypt");                                   break;
        case RECORD_NAME_VINELINUX:                             sResult=QString("Vine Linux");                                  break;
        case RECORD_NAME_VIRTUALIZEPROTECT:                     sResult=QString("VirtualizeProtect");                           break;
        case RECORD_NAME_VIRTUALPASCAL:                         sResult=QString("Virtual Pascal");                              break;
        case RECORD_NAME_VISE:                                  sResult=QString("Vise");                                        break;
        case RECORD_NAME_VISUALBASIC:                           sResult=QString("Visual Basic");                                break;
        case RECORD_NAME_VISUALCCPP:                            sResult=QString("Visual C/C++");                                break;
        case RECORD_NAME_VISUALCSHARP:                          sResult=QString("Visual C#");                                   break;
        case RECORD_NAME_VISUALOBJECTS:                         sResult=QString("Visual Objects");                              break;
        case RECORD_NAME_VMPROTECT:                             sResult=QString("VMProtect");                                   break;
        case RECORD_NAME_VMUNPACKER:                            sResult=QString("VMUnpacker");                                  break;
        case RECORD_NAME_VMWARE:                                sResult=QString("VMware");                                      break;
        case RECORD_NAME_VPACKER:                               sResult=QString("VPacker");                                     break;
        case RECORD_NAME_WALLE:                                 sResult=QString("Walle");                                       break;
        case RECORD_NAME_WANGZEHUALLVM:                         sResult=QString("wangzehua LLVM");                              break;
        case RECORD_NAME_WATCHOS:                               sResult=QString("watchOS");                                     break;
        case RECORD_NAME_WATCHOSSDK:                            sResult=QString("watchOS SDK");                                 break;
        case RECORD_NAME_WATCOMC:                               sResult=QString("Watcom C");                                    break;
        case RECORD_NAME_WATCOMCCPP:                            sResult=QString("Watcom C/C++");                                break;
        case RECORD_NAME_WATCOMLINKER:                          sResult=QString("Watcom linker");                               break;
        case RECORD_NAME_WAV:                                   sResult=QString("WAV");                                         break;
        case RECORD_NAME_WDOSX:                                 sResult=QString("WDOSX");                                       break;
        case RECORD_NAME_WHITELLCRYPT:                          sResult=QString("Whitell Crypt");                               break;
        case RECORD_NAME_WINACE:                                sResult=QString("WinACE");                                      break;
        case RECORD_NAME_WINAUTH:                               sResult=QString("Windows Authenticode");                        break;
        case RECORD_NAME_WINDOFCRYPT:                           sResult=QString("WindOfCrypt");                                 break;
        case RECORD_NAME_WINDOWS:                               sResult=QString("Windows");                                     break;
        case RECORD_NAME_WINDOWSBITMAP:                         sResult=QString("Windows Bitmap");                              break;
        case RECORD_NAME_WINDOWSCE:                             sResult=QString("Windows CE");                                  break;
        case RECORD_NAME_WINDOWSICON:                           sResult=QString("Windows Icon");                                break;
        case RECORD_NAME_WINDOWSINSTALLER:                      sResult=QString("Windows Installer");                           break;
        case RECORD_NAME_WINDOWSMEDIA:                          sResult=QString("Windows Media");                               break;
        case RECORD_NAME_WINDRIVERLINUX:                        sResult=QString("Wind River Linux");                            break;
        case RECORD_NAME_WINGSCRYPT:                            sResult=QString("WingsCrypt");                                  break;
        case RECORD_NAME_WINKRIPT:                              sResult=QString("WinKript");                                    break;
        case RECORD_NAME_WINRAR:                                sResult=QString("WinRAR");                                      break;
        case RECORD_NAME_WINUPACK:                              sResult=QString("(Win)Upack");                                  break;
        case RECORD_NAME_WINZIP:                                sResult=QString("WinZip");                                      break;
        case RECORD_NAME_WISE:                                  sResult=QString("Wise");                                        break;
        case RECORD_NAME_WIXTOOLSET:                            sResult=QString("WiX Toolset");                                 break;
        case RECORD_NAME_WLCRYPT:                               sResult=QString("WL-Crypt");                                    break;
        case RECORD_NAME_WLGROUPCRYPTER:                        sResult=QString("WL-Group Crypter");                            break;
        case RECORD_NAME_WOUTHRSEXECRYPTER:                     sResult=QString("WouThrs EXE Crypter");                         break;
        case RECORD_NAME_WWPACK32:                              sResult=QString("WWPack32");                                    break;
        case RECORD_NAME_WWPACK:                                sResult=QString("WWPack");                                      break;
        case RECORD_NAME_WXWIDGETS:                             sResult=QString("wxWidgets");                                   break;
        case RECORD_NAME_XAR:                                   sResult=QString("xar");                                         break;
        case RECORD_NAME_XBOX:                                  sResult=QString("XBOX");                                        break;
        case RECORD_NAME_XCODE:                                 sResult=QString("Xcode");                                       break;
        case RECORD_NAME_XCOMP:                                 sResult=QString("XComp");                                       break;
        case RECORD_NAME_XENOCODE:                              sResult=QString("Xenocode");                                    break;
        case RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET:        sResult=QString("Xenocode Postbuild 2009 for .NET");            break;
        case RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET:        sResult=QString("Xenocode Postbuild 2010 for .NET");            break;
        case RECORD_NAME_XENOCODEPOSTBUILD:                     sResult=QString("Xenocode Postbuild");                          break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009:  sResult=QString("Xenocode Virtual Application Studio 2009");    break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010:  sResult=QString("Xenocode Virtual Application Studio 2010");    break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION: sResult=QString("Xenocode Virtual Application Studio 2010 ISV Edition"); break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION: sResult=QString("Xenocode Virtual Application Studio 2012 ISV Edition"); break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION: sResult=QString("Xenocode Virtual Application Studio 2013 ISV Edition"); break;
        case RECORD_NAME_XML:                                   sResult=QString("XML");                                         break;
        case RECORD_NAME_XPACK:                                 sResult=QString("XPack");                                       break;
        case RECORD_NAME_XTREAMLOK:                             sResult=QString("Xtreamlok");                                   break;
        case RECORD_NAME_XTREMEPROTECTOR:                       sResult=QString("Xtreme-Protector");                            break;
        case RECORD_NAME_XVOLKOLAK:                             sResult=QString("XVolkolak");                                   break;
        case RECORD_NAME_XZ:                                    sResult=QString("XZ");                                          break;
        case RECORD_NAME_YANDEX:                                sResult=QString("Yandex");                                      break;
        case RECORD_NAME_YANO:                                  sResult=QString("Yano");                                        break;
        case RECORD_NAME_YIDUN:                                 sResult=QString("yidun");                                       break;
        case RECORD_NAME_YODASCRYPTER:                          sResult=QString("Yoda's Crypter");                              break;
        case RECORD_NAME_YODASPROTECTOR:                        sResult=QString("Yoda's Protector");                            break;
        case RECORD_NAME_YZPACK:                                sResult=QString("YZPack");                                      break;
        case RECORD_NAME_ZELDACRYPT:                            sResult=QString("ZeldaCrypt");                                  break;
        case RECORD_NAME_ZIG:                                   sResult=QString("Zig");                                         break;
        case RECORD_NAME_ZIP:                                   sResult=QString("ZIP");                                         break;
        case RECORD_NAME_ZLIB:                                  sResult=QString("zlib");                                        break;
        case RECORD_NAME_ZPROTECT:                              sResult=QString("ZProtect");                                    break;
        case RECORD_NAME_UNKNOWN0:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN1:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN2:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN3:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN4:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN5:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN6:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN7:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN8:                              sResult=QString("_Unknown");                                    break;
        case RECORD_NAME_UNKNOWN9:                              sResult=QString("_Unknown");                                    break;
    }
    return sResult;
}

QString SpecAbstract::heurTypeIdToString(SpecAbstract::DETECTTYPE id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case DETECTTYPE_UNKNOWN:                          sResult=tr("Unknown");                                        break;
        case DETECTTYPE_HEADER:                           sResult=tr("Header");                                         break;
        case DETECTTYPE_OVERLAY:                          sResult=tr("Overlay");                                        break;
        case DETECTTYPE_ENTRYPOINT:                       sResult=tr("Entry point");                                    break;
        case DETECTTYPE_SECTIONNAME:                      sResult=tr("Section name");                                   break;
        case DETECTTYPE_IMPORTHASH:                       sResult=tr("Import hash");                                    break;
        case DETECTTYPE_CODESECTION:                      sResult=tr("Code section");                                   break;
        case DETECTTYPE_ENTRYPOINTSECTION:                sResult=tr("Entry point section");                            break;
        case DETECTTYPE_NETANSISTRING:                    sResult=QString(".NET ANSI %1").arg(tr("String"));            break;
        case DETECTTYPE_NETUNICODESTRING:                 sResult=QString(".NET Unicode %1").arg(tr("String"));         break;
        case DETECTTYPE_RICH:                             sResult=QString("RICH");                                      break;
        case DETECTTYPE_ARCHIVE:                          sResult=tr("Archive");                                        break;
        case DETECTTYPE_RESOURCES:                        sResult=tr("Resources");                                      break;
        case DETECTTYPE_DEXSTRING:                        sResult=QString("DEX %1").arg(tr("String"));                  break;
        case DETECTTYPE_DEXTYPE:                          sResult=QString("DEX %1").arg(tr("Type"));                    break;
    }

    return sResult;
}

SpecAbstract::UNPACK_OPTIONS SpecAbstract::getPossibleUnpackOptions(QIODevice *pDevice,bool bIsImage)
{
    // TODO
    UNPACK_OPTIONS result={};

    QSet<XBinary::FT> stFileTypes=XBinary::getFileTypes(pDevice);

    if(stFileTypes.contains(XBinary::FT_PE32)||stFileTypes.contains(XBinary::FT_PE64))
    {
        XPE pe(pDevice,bIsImage);

        if(pe.isValid())
        {
            if(pe.isValid())
            {
                result.bCopyOverlay=pe.isOverlayPresent();
            }
        }
    }

    return result;
}

QString SpecAbstract::_SCANS_STRUCT_toString(const _SCANS_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type),SpecAbstract::recordNameIdToString(pScanStruct->name),pScanStruct->sVersion,pScanStruct->sInfo);

    return sResult;
}

QString SpecAbstract::createResultString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type),SpecAbstract::recordNameIdToString(pScanStruct->name),pScanStruct->sVersion,pScanStruct->sInfo);

    return sResult;
}

QString SpecAbstract::createResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type),SpecAbstract::recordNameIdToString(pScanStruct->name));

    if(pScanStruct->sVersion!="")
    {
        sResult+=QString("(%1)").arg(pScanStruct->sVersion);
    }

    if(pScanStruct->sInfo!="")
    {
        sResult+=QString("[%1]").arg(pScanStruct->sInfo);
    }

    return sResult;
}

QString SpecAbstract::createFullResultString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2").arg(createTypeString(pScanStruct),createResultString(pScanStruct));

    return sResult;
}

QString SpecAbstract::createFullResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2").arg(createTypeString(pScanStruct),createResultString2(pScanStruct));

    return sResult;
}

QString SpecAbstract::createTypeString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->parentId.filePart!=RECORD_FILEPART_HEADER)
    {
        sResult+=SpecAbstract::recordFilePartIdToString(pScanStruct->parentId.filePart);

        if(pScanStruct->parentId.sVersion!="")
        {
            sResult+=QString("(%1)").arg(pScanStruct->parentId.sVersion);
        }

        if(pScanStruct->parentId.sInfo!="")
        {
            sResult+=QString("[%1]").arg(pScanStruct->parentId.sInfo);
        }

        sResult+=": ";
    }

    sResult+=XBinary::fileTypeIdToString(pScanStruct->id.fileType);

    return sResult;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::createHeaderScanStruct(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    SCAN_STRUCT result=*pScanStruct;

    result.id.sUuid=XBinary::generateUUID();
    result.type=RECORD_TYPE_GENERIC;
    result.name=RECORD_NAME_GENERIC;
    result.sVersion="";
    result.sInfo="";

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Enigma_vi(QIODevice *pDevice,bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    if(!result.bIsValid)
    {
        qint64 _nOffset=binary.find_array(nOffset,nSize,"\x00\x00\x00\x45\x4e\x49\x47\x4d\x41",9); // \x00\x00\x00ENIGMA

        if(_nOffset!=-1)
        {
            quint8 nMajor=binary.read_uint8(_nOffset+9);
            quint8 nMinor=binary.read_uint8(_nOffset+10);
            quint16 nYear=binary.read_uint16(_nOffset+11);
            quint16 nMonth=binary.read_uint16(_nOffset+13);
            quint16 nDay=binary.read_uint16(_nOffset+15);
            quint16 nHour=binary.read_uint16(_nOffset+17);
            quint16 nMin=binary.read_uint16(_nOffset+19);
            quint16 nSec=binary.read_uint16(_nOffset+21);

            result.sVersion=QString("%1.%2 build %3.%4.%5 %6:%7:%8").arg(nMajor).arg(nMinor,2,10,QChar('0')).arg(nYear,4,10,QChar('0')).arg(nMonth,2,10,QChar('0')).arg(nDay,2,10,QChar('0')).arg(nHour,2,10,QChar('0')).arg(nMin,2,10,QChar('0')).arg(nSec,2,10,QChar('0'));

            result.bIsValid=true;
        }
    }

    // 0 variant
    if(!result.bIsValid)
    {
        qint64 _nOffset=binary.find_ansiString(nOffset,nSize," *** Enigma protector v");

        if(_nOffset!=-1)
        {
            result.sVersion=binary.read_ansiString(_nOffset+23).section(" ",0,0);
            result.bIsValid=true;
        }
    }

    if(!result.bIsValid)
    {
        qint64 _nOffset=binary.find_ansiString(nOffset,nSize,"The Enigma Protector version");

        if(_nOffset!=-1)
        {
            result.sVersion=binary.read_ansiString(_nOffset+23).section(" ",0,0);
            result.bIsValid=true;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_DeepSea_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 _nOffset=binary.find_ansiString(nOffset,nSize,"DeepSeaObfuscator");

    if(_nOffset!=-1)
    {
        // TODO Check
        result.bIsValid=true;
        result.sVersion="4.X";

        QString sFullString=binary.read_ansiString(_nOffset+18);

        if(sFullString.contains("Evaluation"))
        {
            result.sInfo="Evaluation";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_SmartAssembly_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 _nOffset=binary.find_ansiString(nOffset,nSize,"Powered by SmartAssembly ");

    if(_nOffset!=-1)
    {
        result.bIsValid=true;
        result.sVersion=binary.read_ansiString(_nOffset+25);
        // TODO more checks!
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_R8_marker_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java
    // X~~D8{"compilation-mode":"release","has-checksums":false,"min-api":14,"version":"2.0.88"}
    qint64 _nOffset=binary.find_ansiString(nOffset,nSize,"\"compilation-mode\":\"");

    if(_nOffset>20) // TODO rewrite
    {
        _nOffset=binary.find_ansiString(_nOffset-5,20,"~~");

        if(_nOffset!=-1)
        {
            result.bIsValid=true;
            QString sString=binary.read_ansiString(_nOffset);

            result.sVersion=XBinary::regExp("\"version\":\"(.*?)\"",sString,1);

            if(sString.contains("~~D8")||sString.contains("~~R8"))
            {
                result.sInfo=XBinary::regExp("\"compilation-mode\":\"(.*?)\"",sString,1);
            }
            else
            {
                result.sInfo="CHECK D8: "+sString;
            }
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Go_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 _nOffset=nOffset;
    qint64 _nSize=nSize;

    QString sVersion;

    qint64 nMaxVersion=0;

    while(_nSize>0)
    {
        _nOffset=binary.find_ansiString(_nOffset,_nSize,"go1.");

        if(_nOffset==-1)
        {
            break;
        }

        QString _sVersion=XBinary::getVersionString(binary.read_ansiString(_nOffset+2,10));

        qint64 nVersionValue=XBinary::getVersionIntValue(_sVersion);

        if(nVersionValue>nMaxVersion)
        {
            nMaxVersion=nVersionValue;

            sVersion=_sVersion;
        }

        _nOffset++;

        _nSize=nSize-(_nOffset-nOffset)-1;
    }

    if(sVersion!="")
    {
        result.bIsValid=true;
        result.sVersion=sVersion;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Rust_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO version
    qint64 nOffset_Version=-1;

    if(nOffset_Version==-1)
    {
        nOffset_Version=binary.find_ansiString(nOffset,nSize,"Local\\RustBacktraceMutex");

        if(nOffset_Version!=-1)
        {
            result.bIsValid=true;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_ObfuscatorLLVM_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO get max version
    qint64 nOffset_Version=-1;

    if(nOffset_Version==-1)
    {
        nOffset_Version=binary.find_ansiString(nOffset,nSize,"Obfuscator-"); // 3.4 - 6.0.0

        if(nOffset_Version!=-1)
        {
            QString sVersionString=binary.read_ansiString(nOffset_Version);

            result=_get_ObfuscatorLLVM_string(sVersionString);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ObfuscatorLLVM_string(QString sString)
{
    VI_STRUCT result={};

    if( sString.contains("Obfuscator-clang version")||      // 3.4
        sString.contains("Obfuscator- clang version")||     // 3.51
        sString.contains("Obfuscator-LLVM clang version"))  // 3.6.1 - 6.0.0
    {
        result.bIsValid=true;

        result.sVersion=sString.section("version ",1,1).section("(",0,0).section(" ",0,0);
//        result.sVersion=sString.section("version ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_AndroidClang_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"Android clang");

    if(nOffset_Version!=-1)
    {
        QString sVersionString=binary.read_ansiString(nOffset_Version);

        result=_get_AndroidClang_string(sVersionString);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AndroidClang_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Android clang"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }
    else if(sString.contains("Android (")&&sString.contains(" clang version "))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" clang version ",1,1).section(" ",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_PlexClang_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Plex clang"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_UbuntuClang_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Ubuntu clang"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AlipayObfuscator_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Alipay"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);

        if(sString.contains("Trial"))
        {
            result.sInfo="Trial";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_wangzehuaLLVM_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("wangzehua  clang version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("wangzehua  clang version",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ByteGuard_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ByteGuard"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("ByteGuard ",1,1).section("-",0,0).section(")",0,0);
    }
    else if(sString.contains("Byteguard"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Byteguard ",1,1).section("-",0,0).section(")",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_TencentObfuscation_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Tencent-Obfuscation Compiler"))
    {
        // TODO Version
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AppImage_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("AppImage by Simon Peter, http://appimage.org/"))
    {
        // TODO Version
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_HikariObfuscator_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("HikariObfuscator")||sString.contains("_Hikari")||sString.contains("Hikari.git"))
    {
        // TODO Version
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SnapProtect_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("snap.protect version "))
    {
        result.sVersion=sString.section("snap.protect version ",1,1).section(" ",0,0);
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ByteDanceSecCompiler_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ByteDance-SecCompiler"))
    {
        // TODO Version
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DingbaozengNativeObfuscator_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("dingbaozeng/native_obfuscator.git"))
    {
        // TODO Version
        result.bIsValid=true;
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SafeengineLLVM_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Safengine clang version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_NagainLLVM_string(QString sString)
{
    VI_STRUCT result={};
    // http://www.nagain.com/
    if(sString.contains("Nagain-LLVM clang version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_iJiami_string(QString sString)
{
    VI_STRUCT result={};
    // https://www.ijiami.cn/
    if(sString.contains("ijiami LLVM Compiler- clang version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",5,5);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_AppleLLVM_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Apple LLVM version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Apple LLVM version ",1,1).section(" ",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ApportableClang_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Apportable clang version"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",3,3);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMAssembler_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM Assembler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMLinker_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM Linker,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1).section("]",0,0)+"]";
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMC_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM C Compiler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMCCPP_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM C/C++ Compiler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMNEONCCPP_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM NEON C/C++ Compiler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMThumbCCPP_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM/Thumb C/C++ Compiler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ARMThumbMacroAssembler_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ARM/Thumb Macro Assembler"))
    {
        result.bIsValid=true;

        if(sString.contains("vsn "))
        {
            result.sVersion=sString.section("vsn ",1,-1);
        }
        else
        {
            result.sVersion=sString.section(", ",1,-1);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_ThumbC_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("Thumb C Compiler,"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(", ",1,-1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_clang_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^clang version",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",2,2);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DynASM_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("DynASM"))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_Delphi_string(QString sString)
{
    VI_STRUCT result={};

    // Embarcadero Delphi for Android compiler version
    if(XBinary::isRegExpPresent("^Embarcadero Delphi for",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("version ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_LLD_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^Linker: LLD",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Linker: LLD ",1,1).section("(",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_OracleSolarisLinkEditors_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^ld: Software Generation Utilities - Solaris Link Editors:",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Solaris Link Editors: ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SunWorkShop_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("Sun WorkShop",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Sun WorkShop ",1,1).section(" ",0,1).section("\r",0,0).section("\n",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SnapdragonLLVMARM_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^Snapdragon LLVM ARM Compiler",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section(" ",4,4);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_NASM_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^The Netwide Assembler",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("The Netwide Assembler ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_TencentLegu_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("^legu",sString))
    {
        result.bIsValid=true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_OllvmTll_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("ollvm-tll.git"))
    {
        result.bIsValid=true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_DelphiVersionFromCompiler(QString sString)
{
    VI_STRUCT result={};

    sString=sString.section(" ",0,0);

    if(sString!="")
    {
        result.bIsValid=true;

        result.sVersion="XE7+";

        if(sString=="28.0")
        {
            result.sVersion="XE7";
        }
        else if(sString=="29.0")
        {
            result.sVersion="XE8";
        }
        else if(sString=="30.0")
        {
            result.sVersion="10 Seattle";
        }
        else if(sString=="31.0")
        {
            result.sVersion="10.1 Berlin";
        }
        else if(sString=="32.0")
        {
            result.sVersion="10.2 Tokyo";
        }
        else if(sString=="33.0")
        {
            result.sVersion="10.3 Rio";
        }
        else if(sString=="34.0")
        {
            result.sVersion="10.4 Sydney";
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_SourceryCodeBench_string(QString sString)
{
    VI_STRUCT result={};

    if(XBinary::isRegExpPresent("Sourcery CodeBench Lite ",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Sourcery CodeBench Lite ",1,1).section(")",0,0);
        result.sInfo="lite";
    }
    else if(XBinary::isRegExpPresent("Sourcery CodeBench ",sString))
    {
        result.bIsValid=true;

        result.sVersion=sString.section("Sourcery CodeBench ",1,1).section(")",0,0);
    }

    return result;
}

SpecAbstract::BINARYINFO_STRUCT SpecAbstract::getBinaryInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    BINARYINFO_STRUCT result={};

    XBinary binary(pDevice,pOptions->bIsImage);

    if(binary.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_BINARY;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=binary.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=binary.getMemoryMap();

        // Scan Header
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_binary_records,sizeof(_binary_records),result.basic_info.id.fileType,XBinary::FT_BINARY,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_archive_records,sizeof(_archive_records),result.basic_info.id.fileType,XBinary::FT_ARCHIVE,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_COM_records,sizeof(_COM_records),result.basic_info.id.fileType,XBinary::FT_COM,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureExpScan(&binary,&(result.basic_info.memoryMap),&result.basic_info.mapHeaderDetects,0,_COM_Exp_records,sizeof(_COM_Exp_records),result.basic_info.id.fileType,XBinary::FT_COM,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);

        if(result.basic_info.parentId.fileType!=XBinary::FT_UNKNOWN)
        {
            signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_PE_overlay_records,sizeof(_PE_overlay_records),result.basic_info.id.fileType,XBinary::FT_BINARY,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        }

        // TODO header data!
        result.bIsPlainText=binary.isPlainTextType();
        result.bIsUTF8=binary.isUTF8TextType();
        result.unicodeType=binary.getUnicodeType();

        // TODO Try QTextStream functions! Check
        if(result.unicodeType!=XBinary::UNICODE_TYPE_NONE)
        {
            result.sHeaderText=binary.read_unicodeString(2,qMin(result.basic_info.nSize,(qint64)0x1000),(result.unicodeType==XBinary::UNICODE_TYPE_BE));
            result.basic_info.id.fileType=XBinary::FT_UNICODE;
        }
        else if(result.bIsUTF8)
        {
            result.sHeaderText=binary.read_utf8String(3,qMin(result.basic_info.nSize,(qint64)0x1000));
            result.basic_info.id.fileType=XBinary::FT_UTF8;
        }
        else if(result.bIsPlainText)
        {
            result.sHeaderText=binary.read_ansiString(0,qMin(result.basic_info.nSize,(qint64)0x1000));
            result.basic_info.id.fileType=XBinary::FT_PLAINTEXT;
        }

        Binary_handle_Texts(pDevice,pOptions->bIsImage,&result);
        Binary_handle_COM(pDevice,pOptions->bIsImage,&result);
        Binary_handle_Formats(pDevice,pOptions->bIsImage,&result);
        Binary_handle_Databases(pDevice,pOptions->bIsImage,&result);
        Binary_handle_Images(pDevice,pOptions->bIsImage,&result);
        Binary_handle_Archives(pDevice,pOptions->bIsImage,&result);
        Binary_handle_Certificates(pDevice,pOptions->bIsImage,&result);
        Binary_handle_DebugData(pDevice,pOptions->bIsImage,&result);
        Binary_handle_InstallerData(pDevice,pOptions->bIsImage,&result);
        Binary_handle_SFXData(pDevice,pOptions->bIsImage,&result);
        Binary_handle_ProtectorData(pDevice,pOptions->bIsImage,&result);
        Binary_handle_LibraryData(pDevice,pOptions->bIsImage,&result);

        Binary_handleLanguages(pDevice,pOptions->bIsImage,&result);

        Binary_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultTexts.values());
        result.basic_info.listDetects.append(result.mapResultArchives.values());
        result.basic_info.listDetects.append(result.mapResultCertificates.values());
        result.basic_info.listDetects.append(result.mapResultDebugData.values());
        result.basic_info.listDetects.append(result.mapResultFormats.values());
        result.basic_info.listDetects.append(result.mapResultInstallerData.values());
        result.basic_info.listDetects.append(result.mapResultSFXData.values());
        result.basic_info.listDetects.append(result.mapResultProtectorData.values());
        result.basic_info.listDetects.append(result.mapResultLibraryData.values());
        result.basic_info.listDetects.append(result.mapResultDatabases.values());
        result.basic_info.listDetects.append(result.mapResultImages.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultCOMPackers.values());
        result.basic_info.listDetects.append(result.mapResultCOMProtectors.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }

        result.basic_info.listDetects.append(result.listRecursiveDetects);
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::MSDOSINFO_STRUCT SpecAbstract::getMSDOSInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    MSDOSINFO_STRUCT result={};

    XMSDOS msdos(pDevice,pOptions->bIsImage);

    if(msdos.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_MSDOS;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=msdos.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=msdos.getMemoryMap();

        result.nOverlayOffset=msdos.getOverlayOffset(&(result.basic_info.memoryMap));
        result.nOverlaySize=msdos.getOverlaySize(&(result.basic_info.memoryMap));

        if(result.nOverlaySize)
        {
            result.sOverlaySignature=msdos.getSignature(result.nOverlayOffset,150);
        }

        result.nEntryPointOffset=msdos.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature=msdos.getSignature(msdos.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_header_records,sizeof(_MSDOS_header_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_MSDOS_entrypoint_records,sizeof(_MSDOS_entrypoint_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);

        signatureExpScan(&msdos,&(result.basic_info.memoryMap),&result.mapEntryPointDetects,result.nEntryPointOffset,_MSDOS_entrypointExp_records,sizeof(_MSDOS_entrypointExp_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);

        MSDOS_handle_OperationSystems(pDevice,pOptions->bIsImage,&result);
        MSDOS_handle_Borland(pDevice,pOptions->bIsImage,&result);
        MSDOS_handle_Tools(pDevice,pOptions->bIsImage,&result);
        MSDOS_handle_Protection(pDevice,pOptions->bIsImage,&result);
        MSDOS_handle_SFX(pDevice,pOptions->bIsImage,&result);
        MSDOS_handle_DosExtenders(pDevice,pOptions->bIsImage,&result);

        MSDOS_handleLanguages(pDevice,pOptions->bIsImage,&result);

        MSDOS_handle_Recursive(pDevice,pOptions->bIsImage,&result,pOptions,pbIsStop);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultDosExtenders.values());
        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultPackers.values());
        result.basic_info.listDetects.append(result.mapResultSFX.values());
        result.basic_info.listDetects.append(result.mapResultProtectors.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }

        result.basic_info.listDetects.append(result.listRecursiveDetects);
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::ELFINFO_STRUCT SpecAbstract::getELFInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    ELFINFO_STRUCT result={};

    XELF elf(pDevice,pOptions->bIsImage);

    if(elf.isValid()&&(!(*pbIsStop)))
    {
        result.bIs64=elf.is64();
        result.bIsBigEndian=elf.isBigEndian();

        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=result.bIs64?XBinary::FT_ELF64:XBinary::FT_ELF32;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=elf.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=elf.getMemoryMap();

        result.sEntryPointSignature=elf.getSignature(elf.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.nStringTableSection=elf.getSectionStringTable(result.bIs64);
        result.baStringTable=elf.getSection(result.nStringTableSection);

        result.listTags=elf.getTagStructs();
        result.listLibraries=elf.getLibraries(&(result.basic_info.memoryMap),&result.listTags);

        result.listSectionHeaders=elf.getElf_ShdrList();
        result.listProgramHeaders=elf.getElf_PhdrList();

        result.listSectionRecords=XELF::getSectionRecords(&result.listSectionHeaders,pOptions->bIsImage,&result.baStringTable);
        result.listNotes=elf.getNotes(&result.listProgramHeaders);

        result.nCommentSection=XELF::getSectionNumber(".comment",&result.listSectionRecords);

        if(result.nCommentSection!=-1)
        {
            result.osCommentSection.nOffset=result.listSectionRecords.at(result.nCommentSection).nOffset;
            result.osCommentSection.nSize=result.listSectionRecords.at(result.nCommentSection).nSize;

            result.listComments=elf.getStringsFromSection(result.nCommentSection).values();
        }

        ELF_handle_CommentSection(pDevice,pOptions->bIsImage,&result);

        ELF_handle_OperationSystems(pDevice,pOptions->bIsImage,&result);
        ELF_handle_GCC(pDevice,pOptions->bIsImage,&result);
        ELF_handle_Tools(pDevice,pOptions->bIsImage,&result);
        ELF_handle_Protection(pDevice,pOptions->bIsImage,&result);

        ELF_handle_UnknownProtection(pDevice,pOptions->bIsImage,&result);

        ELF_handleLanguages(pDevice,pOptions->bIsImage,&result);

        ELF_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultPackers.values());
        result.basic_info.listDetects.append(result.mapResultProtectors.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::MACHOINFO_STRUCT SpecAbstract::getMACHOInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    MACHOINFO_STRUCT result={};

    XMACH mach(pDevice,pOptions->bIsImage);

    if(mach.isValid()&&(!(*pbIsStop)))
    {
        result.bIs64=mach.is64();
        result.bIsBigEndian=mach.isBigEndian();

        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=result.bIs64?XBinary::FT_MACHO64:XBinary::FT_MACHO32;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=mach.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=mach.getMemoryMap();

        result.sEntryPointSignature=mach.getSignature(mach.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.listCommandRecords=mach.getCommandRecords();

        result.listLibraryRecords=mach.getLibraryRecords(&result.listCommandRecords);
        result.listSegmentRecords=mach.getSegmentRecords(&result.listCommandRecords);
        result.listSectionRecords=mach.getSectionRecords(&result.listCommandRecords);

        // TODO Segments
        // TODO Sections

        MACHO_handle_Tools(pDevice,pOptions->bIsImage,&result);
        MACHO_handle_Protection(pDevice,pOptions->bIsImage,&result);

        MACHO_handleLanguages(pDevice,pOptions->bIsImage,&result);

        MACHO_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultProtectors.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::LEINFO_STRUCT SpecAbstract::getLEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    LEINFO_STRUCT result={};

    XLE le(pDevice,pOptions->bIsImage);

    if(le.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;

        if(le.isLX()) // TODO bLX
        {
            result.basic_info.id.fileType=XBinary::FT_LX;
        }
        else
        {
            result.basic_info.id.fileType=XBinary::FT_LE;
        }

        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=le.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=le.getMemoryMap();

        result.sEntryPointSignature=le.getSignature(le.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.listRichSignatures=le.getRichSignatureRecords();

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);

        LE_handle_Microsoft(pDevice,pOptions->bIsImage,&result,pbIsStop);
        LE_handle_Borland(pDevice,pOptions->bIsImage,&result);

        LE_handleLanguages(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::NEINFO_STRUCT SpecAbstract::getNEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    NEINFO_STRUCT result={};

    XNE ne(pDevice,pOptions->bIsImage);

    if(ne.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_NE;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=ne.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=ne.getMemoryMap();

        result.sEntryPointSignature=ne.getSignature(ne.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);

        NE_handle_Borland(pDevice,pOptions->bIsImage,&result);

        NE_handleLanguages(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::PEINFO_STRUCT SpecAbstract::getPEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    PEINFO_STRUCT result={};

    XPE pe(pDevice,pOptions->bIsImage);

    if(pe.isValid()&&(!(*pbIsStop)))
    {
        result.bIs64=pe.is64();

        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=result.bIs64?XBinary::FT_PE64:XBinary::FT_PE32;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=pe.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=pe.getMemoryMap();

        result.nEntryPointOffset=pe.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature=pe.getSignature(result.nEntryPointOffset,150);

        result.dosHeader=pe.getDosHeaderEx();
        result.fileHeader=pe.getFileHeader();
        result.nOverlayOffset=pe.getOverlayOffset();
        result.nOverlaySize=pe.getOverlaySize();

        if(result.nOverlaySize)
        {
            result.sOverlaySignature=pe.getSignature(result.nOverlayOffset,150);
        }

        if(result.bIs64)
        {
            result.optional_header.optionalHeader64=pe.getOptionalHeader64();
        }
        else
        {
            result.optional_header.optionalHeader32=pe.getOptionalHeader32();
        }

        result.listSectionHeaders=pe.getSectionHeaders();
        result.listSectionRecords=XPE::getSectionRecords(&result.listSectionHeaders,pe.isImage());
        result.listSectionNames=XPE::getSectionNames(&(result.listSectionRecords));

        result.listImports=pe.getImports(&(result.basic_info.memoryMap));
        //        for(qint32 i=0;i<result.listImports.count();i++)
        //        {
        //            qDebug(result.listImports.at(i).sName.toLatin1().data());
        //            for(int j=0;j<result.listImports.at(i).listPositions.count();j++)
        //            {
        //                qDebug("%d %s",j,result.listImports.at(i).listPositions.at(j).sFunction.toLatin1().data());
        //            }
        //        }
        result.nImportHash64=pe.getImportHash64(&(result.basic_info.memoryMap));
        result.nImportHash32=pe.getImportHash32(&(result.basic_info.memoryMap));
        result.listImportPositionHashes=pe.getImportPositionHashes(&(result.listImports));

#ifdef QT_DEBUG
        QString sDebugString=QString::number(result.nImportHash64,16)+" "+QString::number(result.nImportHash32,16);
        qDebug("Import hash: %s",sDebugString.toLatin1().data());

        QList<XPE::IMPORT_RECORD> listImports=pe.getImportRecords(&(result.basic_info.memoryMap));

        qint32 _nNumberOfImports=listImports.count();

        for(qint32 i=0;i<_nNumberOfImports;i++)
        {
            QString sRecord=listImports.at(i).sLibrary+" "+listImports.at(i).sFunction;

            qDebug("%s",sRecord.toLatin1().data());
        }

        qDebug("=====================================================================");

        QList<XPE::IMPORT_HEADER> listImportHeaders=pe.getImports(&(result.basic_info.memoryMap));

        for(qint32 i=0;i<listImportHeaders.count();i++)
        {
            qDebug("Import hash: %x",result.listImportPositionHashes.at(i));
            for(int j=0;j<listImportHeaders.at(i).listPositions.count();j++)
            {
                qDebug("%s %s",listImportHeaders.at(i).sName.toLatin1().data(),
                       listImportHeaders.at(i).listPositions.at(j).sFunction.toLatin1().data());
            }
        }
#endif
        result.exportHeader=pe.getExport(&(result.basic_info.memoryMap));
        result.listExportFunctionNames=pe.getExportFunctionsList(&(result.exportHeader));
        result.listResources=pe.getResources(&(result.basic_info.memoryMap));
        result.listRichSignatures=pe.getRichSignatureRecords();
        result.cliInfo=pe.getCliInfo(true,&(result.basic_info.memoryMap));
        result.sResourceManifest=pe.getResourceManifest(&result.listResources);
        result.resVersion=pe.getResourcesVersion(&result.listResources);

        result.nEntryPointAddress=result.bIs64?result.optional_header.optionalHeader64.AddressOfEntryPoint:result.optional_header.optionalHeader32.AddressOfEntryPoint;
        result.nImageBaseAddress=result.bIs64?result.optional_header.optionalHeader64.ImageBase:result.optional_header.optionalHeader32.ImageBase;
        result.nMinorLinkerVersion=result.bIs64?result.optional_header.optionalHeader64.MinorLinkerVersion:result.optional_header.optionalHeader32.MinorLinkerVersion;
        result.nMajorLinkerVersion=result.bIs64?result.optional_header.optionalHeader64.MajorLinkerVersion:result.optional_header.optionalHeader32.MajorLinkerVersion;
        result.nMinorImageVersion=result.bIs64?result.optional_header.optionalHeader64.MinorImageVersion:result.optional_header.optionalHeader32.MinorImageVersion;
        result.nMajorImageVersion=result.bIs64?result.optional_header.optionalHeader64.MajorImageVersion:result.optional_header.optionalHeader32.MajorImageVersion;

        result.nEntryPointSection=pe.getEntryPointSection(&(result.basic_info.memoryMap));
        result.nResourcesSection=pe.getResourcesSection(&(result.basic_info.memoryMap));
        result.nImportSection=pe.getImportSection(&(result.basic_info.memoryMap));
        result.nCodeSection=pe.getNormalCodeSection(&(result.basic_info.memoryMap));
        result.nDataSection=pe.getNormalDataSection(&(result.basic_info.memoryMap));
        result.nConstDataSection=pe.getConstDataSection(&(result.basic_info.memoryMap));
        result.nRelocsSection=pe.getRelocsSection(&(result.basic_info.memoryMap));
        result.nTLSSection=pe.getTLSSection(&(result.basic_info.memoryMap));

        result.bIsNetPresent=((result.cliInfo.bValid)||(pe.isNETPresent()&&(result.basic_info.bIsDeepScan)));
        result.bIsTLSPresent=(result.nTLSSection!=-1);

        if(result.nEntryPointSection!=-1)
        {
            result.sEntryPointSectionName=result.listSectionRecords.at(result.nEntryPointSection).sName;
        }

        //        result.mmCodeSectionSignatures=memoryScan(pDevice,nFirstSectionOffset,qMin((qint64)0x10000,nFirstSectionSize),_memory_records,sizeof(_memory_records),_filetype,SpecAbstract::XBinary::FT_PE);
        //        if(result.nCodeSection!=-1)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.listSections.at(result.nCodeSection).PointerToRawData,result.listSections.at(result.nCodeSection).SizeOfRawData,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        result.osHeader.nOffset=0;
        result.osHeader.nSize=qMin(result.basic_info.nSize,(qint64)2048);

        if(result.nCodeSection!=-1)
        {
            result.osCodeSection.nOffset=result.listSectionRecords.at(result.nCodeSection).nOffset;
            result.osCodeSection.nSize=result.listSectionRecords.at(result.nCodeSection).nSize; // TODO limit?
        }

        if(result.nDataSection!=-1)
        {
            result.osDataSection.nOffset=result.listSectionRecords.at(result.nDataSection).nOffset;
            result.osDataSection.nSize=result.listSectionRecords.at(result.nDataSection).nSize;
        }

        if(result.nConstDataSection!=-1)
        {
            result.osConstDataSection.nOffset=result.listSectionRecords.at(result.nConstDataSection).nOffset;
            result.osConstDataSection.nSize=result.listSectionRecords.at(result.nConstDataSection).nSize;
        }

        if(result.nEntryPointSection!=-1)
        {
            result.osEntryPointSection.nOffset=result.listSectionRecords.at(result.nEntryPointSection).nOffset;
            result.osEntryPointSection.nSize=result.listSectionRecords.at(result.nEntryPointSection).nSize;
        }

        if(result.nImportSection!=-1)
        {
            result.osImportSection.nOffset=result.listSectionRecords.at(result.nImportSection).nOffset;
            result.osImportSection.nSize=result.listSectionRecords.at(result.nImportSection).nSize;
        }

        if(result.nResourcesSection!=-1)
        {
            result.osResourcesSection.nOffset=result.listSectionRecords.at(result.nResourcesSection).nOffset;
            result.osResourcesSection.nSize=result.listSectionRecords.at(result.nResourcesSection).nSize;
        }

        //        if(result.nCodeSectionSize)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.nCodeSectionOffset,result.nCodeSectionSize,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        if(result.nDataSectionSize)
        //        {
        //            memoryScan(&result.mapDataSectionScanDetects,pDevice,result.nDataSectionOffset,result.nDataSectionSize,_datasectionscan_records,sizeof(_datasectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        // TODO Check if resources exists

        //        memoryScan(&result.mapHeaderScanDetects,pDevice,0,qMin(result.basic_info.nSize,(qint64)1024),_headerscan_records,sizeof(_headerscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.fileType,XBinary::FT_MSDOS,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_PE_header_records,sizeof(_PE_header_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_HEADER,pbIsStop);
        signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_PE_entrypoint_records,sizeof(_PE_entrypoint_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);
        signatureExpScan(&pe,&(result.basic_info.memoryMap),&result.mapEntryPointDetects,result.nEntryPointOffset,_PE_entrypointExp_records,sizeof(_PE_entrypointExp_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_binary_records,sizeof(_binary_records),result.basic_info.id.fileType,XBinary::FT_BINARY,&(result.basic_info),DETECTTYPE_OVERLAY,pbIsStop);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_archive_records,sizeof(_archive_records),result.basic_info.id.fileType,XBinary::FT_ARCHIVE,&(result.basic_info),DETECTTYPE_OVERLAY,pbIsStop);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_PE_overlay_records,sizeof(_PE_overlay_records),result.basic_info.id.fileType,XBinary::FT_BINARY,&(result.basic_info),DETECTTYPE_OVERLAY,pbIsStop);

        stringScan(&result.mapSectionNamesDetects,&result.listSectionNames,_PE_sectionNames_records,sizeof(_PE_sectionNames_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_SECTIONNAME,pbIsStop);

        // Import
        constScan(&(result.mapImportDetects),result.nImportHash64,result.nImportHash32,_PE_importhash_records,sizeof(_PE_importhash_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_IMPORTHASH,pbIsStop);

        // Export
        qint32 nNumberOfImports=result.listImportPositionHashes.count();

        for(qint32 i=0;i<nNumberOfImports;i++)
        {
            constScan(&(result.mapImportDetects),i,result.listImportPositionHashes.at(i),_PE_importpositionhash_records,sizeof(_PE_importpositionhash_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_IMPORTHASH,pbIsStop);
        }

        // TODO Resources scan
        PE_resourcesScan(&(result.mapResourcesDetects),&(result.listResources),_PE_resources_records,sizeof(_PE_resources_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_RESOURCES,pbIsStop);

        PE_x86Emul(pDevice,pOptions->bIsImage,&result);

        // Rich
//        int nNumberOfRichSignatures=result.listRichSignatures.count();

//        for(qint32 i=0;i<nNumberOfRichSignatures;i++)
//        {
//            PE_richScan(&(result.mapRichDetects),result.listRichSignatures.at(i).nId,result.listRichSignatures.at(i).nVersion,_PE_rich_records,sizeof(_PE_rich_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
//        }


        //        for(qint32 i=0;i<result.listImports.count();i++)
        //        {
        //            signatureScan(&result._mapImportDetects,QBinary::stringToHex(result.listImports.at(i).sName.toUpper()),_import_records,sizeof(_import_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        for(qint32 i=0;i<result.export_header.listPositions.count();i++)
        //        {
        //            signatureScan(&result.mapExportDetects,QBinary::stringToHex(result.export_header.listPositions.at(i).sFunctionName),_export_records,sizeof(_export_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        //        resourcesScan(&result.mapResourcesDetects,&result.listResources,_resources_records,sizeof(_resources_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);


        if(result.bIsNetPresent)
        {
            stringScan(&result.mapDotAnsiStringsDetects,&result.cliInfo.metaData.listAnsiStrings,_PE_dot_ansistrings_records,sizeof(_PE_dot_ansistrings_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_NETANSISTRING,pbIsStop);
            stringScan(&result.mapDotUnicodeStringsDetects,&result.cliInfo.metaData.listUnicodeStrings,_PE_dot_unicodestrings_records,sizeof(_PE_dot_unicodestrings_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_NETUNICODESTRING,pbIsStop);

            //            for(qint32 i=0;i<result.cliInfo.listUnicodeStrings.count();i++)
            //            {
            //                signatureScan(&result.mapDotUnicodestringsDetects,QBinary::stringToHex(result.cliInfo.listUnicodeStrings.at(i)),_dot_unicodestrings_records,sizeof(_dot_unicodestrings_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
            //            }

            if(result.basic_info.bIsDeepScan)
            {
                if(pe.checkOffsetSize(result.osCodeSection))
                {
                    qint64 nSectionOffset=result.osCodeSection.nOffset;
                    qint64 nSectionSize=result.osCodeSection.nSize;

                    memoryScan(&result.mapCodeSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_dot_codesection_records,sizeof(_PE_dot_codesection_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_CODESECTION,pbIsStop);
                }
            }
        }

        if(result.basic_info.bIsDeepScan)
        {
            if(pe.checkOffsetSize(result.osCodeSection))
            {
                qint64 nSectionOffset=result.osCodeSection.nOffset;
                qint64 nSectionSize=result.osCodeSection.nSize;

                memoryScan(&result.mapCodeSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_codesection_records,sizeof(_PE_codesection_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_CODESECTION,pbIsStop);
            }

            if(pe.checkOffsetSize(result.osEntryPointSection))
            {
                qint64 nSectionOffset=result.osEntryPointSection.nOffset;
                qint64 nSectionSize=result.osEntryPointSection.nSize;

                memoryScan(&result.mapEntryPointSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_entrypointsection_records,sizeof(_PE_entrypointsection_records),result.basic_info.id.fileType,XBinary::FT_PE,&(result.basic_info),DETECTTYPE_ENTRYPOINTSECTION,pbIsStop);
            }
        }

        PE_handle_import(pDevice,pOptions->bIsImage,&result);

        PE_handle_OperationSystems(pDevice,pOptions->bIsImage,&result);
        PE_handle_Protection(pDevice,pOptions->bIsImage,&result,pbIsStop);
        PE_handle_SafeengineShielden(pDevice,pOptions->bIsImage,&result);
        PE_handle_VProtect(pDevice,pOptions->bIsImage,&result);
        PE_handle_TTProtect(pDevice,pOptions->bIsImage,&result); // TODO remove
        PE_handle_VMProtect(pDevice,pOptions->bIsImage,&result);
        PE_handle_tElock(pDevice,pOptions->bIsImage,&result);
        PE_handle_Armadillo(pDevice,pOptions->bIsImage,&result);
        PE_handle_Obsidium(pDevice,pOptions->bIsImage,&result);
        PE_handle_Themida(pDevice,pOptions->bIsImage,&result);
        PE_handle_StarForce(pDevice,pOptions->bIsImage,&result);
        PE_handle_Petite(pDevice,pOptions->bIsImage,&result);
        PE_handle_NETProtection(pDevice,pOptions->bIsImage,&result);
        PE_handle_PolyMorph(pDevice,pOptions->bIsImage,&result);
        PE_handle_Microsoft(pDevice,pOptions->bIsImage,&result,pbIsStop);
        PE_handle_Borland(pDevice,pOptions->bIsImage,&result);
        PE_handle_Watcom(pDevice,pOptions->bIsImage,&result);
        PE_handle_Tools(pDevice,pOptions->bIsImage,&result);
        PE_handle_wxWidgets(pDevice,pOptions->bIsImage,&result);
        PE_handle_GCC(pDevice,pOptions->bIsImage,&result);
        PE_handle_Signtools(pDevice,pOptions->bIsImage,&result);
        PE_handle_SFX(pDevice,pOptions->bIsImage,&result);
        PE_handle_Installers(pDevice,pOptions->bIsImage,&result);
        PE_handle_DongleProtection(pDevice,pOptions->bIsImage,&result);
//        PE_handle_AnslymPacker(pDevice,pOptions->bIsImage,&result);
        PE_handle_NeoLite(pDevice,pOptions->bIsImage,&result);
        PE_handle_PrivateEXEProtector(pDevice,pOptions->bIsImage,&result);

        PE_handle_VisualBasicCryptors(pDevice,pOptions->bIsImage,&result);
        PE_handle_DelphiCryptors(pDevice,pOptions->bIsImage,&result);

        PE_handle_Joiners(pDevice,pOptions->bIsImage,&result);
        PE_handle_PETools(pDevice,pOptions->bIsImage,&result);

        if(pOptions->bHeuristicScan)
        {
            PE_handle_UnknownProtection(pDevice,pOptions->bIsImage,&result);
        }

        PE_handleLanguages(pDevice,pOptions->bIsImage,&result);

        PE_handle_FixDetects(pDevice,pOptions->bIsImage,&result); 

        PE_handle_Recursive(pDevice,pOptions->bIsImage,&result,pOptions,pbIsStop);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultPETools.values());
        result.basic_info.listDetects.append(result.mapResultSigntools.values());
        result.basic_info.listDetects.append(result.mapResultProtectors.values());
        result.basic_info.listDetects.append(result.mapResultNETObfuscators.values());
        result.basic_info.listDetects.append(result.mapResultDongleProtection.values());
        result.basic_info.listDetects.append(result.mapResultPackers.values());
        result.basic_info.listDetects.append(result.mapResultNETCompressors.values());
        result.basic_info.listDetects.append(result.mapResultJoiners.values());
        result.basic_info.listDetects.append(result.mapResultSFX.values());
        result.basic_info.listDetects.append(result.mapResultInstallers.values());

        // TODO unknown cryptors
        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }

        result.basic_info.listDetects.append(result.listRecursiveDetects);
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::getDEXInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    DEXINFO_STRUCT result={};

    XDEX dex(pDevice);

    if(dex.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_DEX;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=dex.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=dex.getMemoryMap();

        result.header=dex.getHeader();
        result.mapItems=dex.getMapItems();

        result.bIsStringPoolSorted=dex.isStringPoolSorted();
        result.bIsOverlayPresent=dex.isOverlayPresent(&(result.basic_info.memoryMap));

        result.listStrings=dex.getStrings(&(result.mapItems),pbIsStop);
        result.listTypeItemStrings=dex.getTypeItemStrings(&(result.mapItems),&result.listStrings,pbIsStop);

        stringScan(&result.mapStringDetects,&result.listStrings,_DEX_string_records,sizeof(_DEX_string_records),result.basic_info.id.fileType,XBinary::FT_DEX,&(result.basic_info),DETECTTYPE_DEXSTRING,pbIsStop);
        stringScan(&result.mapTypeDetects,&result.listTypeItemStrings,_DEX_type_records,sizeof(_DEX_type_records),result.basic_info.id.fileType,XBinary::FT_DEX,&(result.basic_info),DETECTTYPE_DEXTYPE,pbIsStop);

        if(pOptions->bDeepScan)
        {
//            QList<XDEX_DEF::STRING_ITEM_ID> getList_STRING_ITEM_ID(&mapItems);
//            QList<XDEX_DEF::TYPE_ITEM_ID> getList_TYPE_ITEM_ID(&mapItems);
//            QList<XDEX_DEF::PROTO_ITEM_ID> getList_PROTO_ITEM_ID(&mapItems);
            result.listFieldIDs=dex.getList_FIELD_ITEM_ID(&(result.mapItems),pbIsStop);
            result.listMethodIDs=dex.getList_METHOD_ITEM_ID(&(result.mapItems),pbIsStop);
//            QList<XDEX_DEF::CLASS_ITEM_DEF> getList_CLASS_ITEM_DEF(&mapItems);

#ifdef QT_DEBUG
//            {
//                QList<XDEX_DEF::CLASS_ITEM_DEF> listClasses=dex.getList_CLASS_ITEM_DEF(&mapItems);

//                int nNumberOfItems=listClasses.count();

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

//                int nNumberOfItems=listMethods.count();

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

        DEX_handle_Tools(pDevice,&result,pbIsStop);
        DEX_handle_Protection(pDevice,&result,pbIsStop);
        DEX_handle_Dexguard(pDevice,&result,pbIsStop);

        DEX_handleLanguages(pDevice,&result);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultProtectors.values());
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::ZIPINFO_STRUCT SpecAbstract::getZIPInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    ZIPINFO_STRUCT result={};

    XZip xzip(pDevice);

    if(xzip.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_ZIP;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=xzip.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=xzip.getMemoryMap();

        result.listArchiveRecords=xzip.getRecords();

        result.bIsJAR=XArchive::isArchiveRecordPresent("META-INF/MANIFEST.MF",&(result.listArchiveRecords));
        result.bIsAPK=XArchive::isArchiveRecordPresent("classes.dex",&(result.listArchiveRecords));
        result.bIsIPA=XArchive::isArchiveRecordPresent("Payload/",&(result.listArchiveRecords));
        result.bIsKotlin=   XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version",&(result.listArchiveRecords))||
                            XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins",&(result.listArchiveRecords));

        if(result.bIsIPA)
        {
            result.basic_info.id.fileType=XBinary::FT_IPA;
        }
        else if((result.bIsJAR)&&(!(result.bIsAPK)))
        {
            result.basic_info.id.fileType=XBinary::FT_JAR;
        }
        else if(result.bIsAPK)
        {
            result.basic_info.id.fileType=XBinary::FT_APK;
        }

        if(result.bIsAPK)
        {
            archiveScan(&(result.mapArchiveDetects),&(result.listArchiveRecords),_APK_file_records,sizeof(_APK_file_records),result.basic_info.id.fileType,XBinary::FT_APK,&(result.basic_info),DETECTTYPE_ARCHIVE,pbIsStop);
            archiveExpScan(&(result.mapArchiveDetects),&(result.listArchiveRecords),_APK_fileExp_records,sizeof(_APK_fileExp_records),result.basic_info.id.fileType,XBinary::FT_APK,&(result.basic_info),DETECTTYPE_ARCHIVE,pbIsStop);
            result.dexInfoClasses=Zip_scan_DEX(pDevice,pOptions->bIsImage,&result,pOptions,pbIsStop,"classes.dex");
        }

        Zip_handle_Metainfos(pDevice,pOptions->bIsImage,&result);
        Zip_handle_Microsoftoffice(pDevice,pOptions->bIsImage,&result);
        Zip_handle_OpenOffice(pDevice,pOptions->bIsImage,&result);

        Zip_handle_JAR(pDevice,pOptions->bIsImage,&result,pOptions,pbIsStop);
        Zip_handle_APK(pDevice,pOptions->bIsImage,&result);
        Zip_handle_IPA(pDevice,pOptions->bIsImage,&result);

        Zip_handle_Recursive(pDevice,pOptions->bIsImage,&result,pOptions,pbIsStop);

        Zip_handleLanguages(pDevice,pOptions->bIsImage,&result);

        Zip_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultOperationSystems.values());
        result.basic_info.listDetects.append(result.mapResultArchives.values());
        result.basic_info.listDetects.append(result.mapResultFormats.values());
        result.basic_info.listDetects.append(result.mapResultTools.values());
        result.basic_info.listDetects.append(result.mapResultSigntools.values());
        result.basic_info.listDetects.append(result.mapResultLanguages.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultAPKProtectors.values());

        if(!result.basic_info.listDetects.count())
        {
            _SCANS_STRUCT ssUnknown={};

            ssUnknown.type=SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name=SpecAbstract::RECORD_NAME_UNKNOWN;

            result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssUnknown));

            result.basic_info.bIsUnknown=true;
        }

        result.basic_info.listDetects.append(result.listRecursiveDetects);
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::MACHOFATINFO_STRUCT SpecAbstract::getMACHOFATInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset, bool *pbIsStop)
{
    QElapsedTimer timer;
    timer.start();

    MACHOFATINFO_STRUCT result={};

    XMACHOFat xmachofat(pDevice);

    if(xmachofat.isValid()&&(!(*pbIsStop)))
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.fileType=XBinary::FT_ARCHIVE;
        result.basic_info.id.filePart=RECORD_FILEPART_HEADER;
        result.basic_info.id.sUuid=XBinary::generateUUID();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=xmachofat.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowDetects=pOptions->bShowDetects;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=xmachofat.getMemoryMap();

        result.listArchiveRecords=xmachofat.getRecords();

        qint32 nNumberOfRecords=result.listArchiveRecords.count();

        for(qint32 i=0;(i<nNumberOfRecords)&&(!(*pbIsStop));i++)
        {
            SpecAbstract::SCAN_RESULT scanResult={0};

            SpecAbstract::ID _parentId=result.basic_info.id;
            _parentId.filePart=SpecAbstract::RECORD_FILEPART_ARCHIVERECORD;
            _parentId.sInfo=result.listArchiveRecords.at(i).sFileName;
            _parentId.bVirtual=true; // TODO Check

            QTemporaryFile fileTemp;

            if(fileTemp.open())
            {
                QString sTempFileName=fileTemp.fileName();

                if(xmachofat.decompressToFile(&(result.listArchiveRecords.at(i)),sTempFileName))
                {
                    QFile file;

                    file.setFileName(sTempFileName);

                    if(file.open(QIODevice::ReadOnly))
                    {
                        scan(&file,&scanResult,0,file.size(),_parentId,pOptions,false,pbIsStop);

                        file.close();
                    }
                }
            }

            result.listRecursiveDetects.append(scanResult.listRecords);
        }


        _SCANS_STRUCT ssFormat=getScansStruct(0,XBinary::FT_ARCHIVE,RECORD_TYPE_FORMAT,RECORD_NAME_MACHOFAT,"","",0);

        ssFormat.sVersion=xmachofat.getVersion();
        ssFormat.sInfo=QString("%1 records").arg(xmachofat.getNumberOfRecords());

        result.basic_info.listDetects.append(scansToScan(&(result.basic_info),&ssFormat));

        result.basic_info.listDetects.append(result.listRecursiveDetects);
    }

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::getScansStruct(quint32 nVariant, XBinary::FT fileType, SpecAbstract::RECORD_TYPE type, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo, qint64 nOffset)
{
    // TODO bIsHeuristic;
    _SCANS_STRUCT result={};

    result.nVariant=nVariant;
    result.fileType=fileType;
    result.type=type;
    result.name=name;
    result.sVersion=sVersion;
    result.sInfo=sInfo;
    result.nOffset=nOffset;

    return result;
}

void SpecAbstract::PE_handle_import(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)
    // Import Check

//#ifdef QT_DEBUG
//    for(qint32 j=0;j<pPEInfo->listImports.count();j++)
//    {
//        for(qint32 i=0;i<pPEInfo->listImports.at(j).listPositions.count();i++)
//        {
//            qDebug("(pPEInfo->listImports.at(%d).listPositions.at(%d).sName==\"%s\")&&",j,i,pPEInfo->listImports.at(j).listPositions.at(i).sName.toLatin1().data());
//        }
//    }
//#endif

    QSet<QString> stDetects;

    if(pPEInfo->listImports.count()>=1)
    {
        if(pPEInfo->listImports.at(0).sName.toUpper()=="KERNEL32.DLL")
        {
            if(pPEInfo->listImports.at(0).listPositions.count()==2)
            {
                if( (pPEInfo->listImports.at(0).listPositions.at(0).sName=="GetProcAddress")&&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName=="LoadLibraryA"))
                {
                    stDetects.insert("kernel32_zprotect");
                }
            }
            else if(pPEInfo->listImports.at(0).listPositions.count()==13)
            {
                if( (pPEInfo->listImports.at(0).listPositions.at(0).sName=="LoadLibraryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName=="GetProcAddress")&&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName=="VirtualAlloc")&&
                    (pPEInfo->listImports.at(0).listPositions.at(3).sName=="VirtualFree")&&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName=="ExitProcess")&&
                    (pPEInfo->listImports.at(0).listPositions.at(5).sName=="CreateFileA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName=="CloseHandle")&&
                    (pPEInfo->listImports.at(0).listPositions.at(7).sName=="WriteFile")&&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName=="GetSystemDirectoryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName=="GetFileTime")&&
                    (pPEInfo->listImports.at(0).listPositions.at(10).sName=="SetFileTime")&&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName=="GetWindowsDirectoryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(12).sName=="lstrcatA"))
                {
                    if(pPEInfo->listImports.count()==1)
                    {
                        stDetects.insert("kernel32_alloy0");
                    }
                }
            }
            else if(pPEInfo->listImports.at(0).listPositions.count()==15)
            {
                if( (pPEInfo->listImports.at(0).listPositions.at(0).sName=="LoadLibraryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName=="GetProcAddress")&&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName=="VirtualAlloc")&&
                    (pPEInfo->listImports.at(0).listPositions.at(3).sName=="VirtualFree")&&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName=="ExitProcess")&&
                    (pPEInfo->listImports.at(0).listPositions.at(5).sName=="CreateFileA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName=="CloseHandle")&&
                    (pPEInfo->listImports.at(0).listPositions.at(7).sName=="WriteFile")&&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName=="GetSystemDirectoryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName=="GetFileTime")&&
                    (pPEInfo->listImports.at(0).listPositions.at(10).sName=="SetFileTime")&&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName=="GetWindowsDirectoryA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(12).sName=="lstrcatA")&&
                    (pPEInfo->listImports.at(0).listPositions.at(13).sName=="FreeLibrary")&&
                    (pPEInfo->listImports.at(0).listPositions.at(14).sName=="GetTempPathA"))
                {
                    if(pPEInfo->listImports.count()==1)
                    {
                        stDetects.insert("kernel32_alloy2");
                    }
                }
            }
        }
        else if(pPEInfo->listImports.at(0).sName.toUpper()=="USER32.DLL")
        {
            if(pPEInfo->listImports.at(0).listPositions.count()==1)
            {
                if((pPEInfo->listImports.at(0).listPositions.at(0).sName=="MessageBoxA"))
                {
                    if(pPEInfo->listImports.count()==2)
                    {
                        stDetects.insert("user32_pespina");
                    }

                    if(pPEInfo->listImports.count()==3)
                    {
                        stDetects.insert("user32_pespin");
                    }
                }
            }
        }
        else if(pPEInfo->listImports.at(0).sName.toUpper()=="KERNEL32")
        {
            if(pPEInfo->listImports.at(0).listPositions.count()==1)
            {
                if((pPEInfo->listImports.at(0).listPositions.at(0).nOrdinal==1))
                {
                    if(pPEInfo->listImports.count()==1)
                    {
                        stDetects.insert("kernel32_yzpack_b");
                    }
                }
            }
        }
    }

    if(pPEInfo->listImports.count()>=2)
    {
        if(pPEInfo->listImports.at(1).sName.toUpper()=="COMCTL32.DLL")
        {
            if(pPEInfo->listImports.at(1).listPositions.count()==1)
            {
                if((pPEInfo->listImports.at(1).listPositions.at(0).sName=="InitCommonControls"))
                {
                    if(pPEInfo->listImports.count()==2)
                    {
                        stDetects.insert("comctl32_pespina");
                    }

                    if(pPEInfo->listImports.count()==3)
                    {
                        stDetects.insert("comctl32_pespin");
                    }
                }
            }
        }
    }

    if(pPEInfo->listImports.count()>=3)
    {
        if(pPEInfo->listImports.at(2).sName.toUpper()=="KERNEL32.DLL")
        {
            if(pPEInfo->listImports.at(2).listPositions.count()==2)
            {
                if( (pPEInfo->listImports.at(2).listPositions.at(0).sName=="LoadLibraryA")&&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName=="GetProcAddress"))
                {
                    if(pPEInfo->listImports.count()==3)
                    {
                        stDetects.insert("kernel32_pespinx");
                    }
                }
            }
            else if(pPEInfo->listImports.at(2).listPositions.count()==4)
            {
                if( (pPEInfo->listImports.at(2).listPositions.at(0).sName=="LoadLibraryA")&&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName=="GetProcAddress")&&
                    (pPEInfo->listImports.at(2).listPositions.at(2).sName=="VirtualAlloc")&&
                    (pPEInfo->listImports.at(2).listPositions.at(3).sName=="VirtualFree"))
                {
                    if(pPEInfo->listImports.count()==3)
                    {
                        stDetects.insert("kernel32_pespin");
                    }
                }
            }
        }
    }

#ifdef QT_DEBUG
    qDebug()<<stDetects;
#endif

    // TODO 32/64
    if(stDetects.contains("kernel32_zprotect"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ZPROTECT,getScansStruct(0,XBinary::FT_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ZPROTECT,"","",0));
    }

    if(stDetects.contains("user32_pespina")&&stDetects.contains("comctl32_pespina"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"1.0-1.2","",0));
    }

    if(stDetects.contains("user32_pespin")&&stDetects.contains("comctl32_pespin")&&stDetects.contains("kernel32_pespin"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"","",0));
    }

    if(stDetects.contains("user32_pespin")&&stDetects.contains("comctl32_pespin")&&stDetects.contains("kernel32_pespinx"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"1.3X","",0));
    }

    if(stDetects.contains("kernel32_alloy0"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ALLOY,getScansStruct(0,XBinary::FT_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ALLOY,"4.X","",0));
    }

    if(stDetects.contains("kernel32_alloy2"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ALLOY,getScansStruct(2,XBinary::FT_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ALLOY,"4.X","",0));
    }

    //    if(stDetects.contains("kernel32_pecompact2"))
    //    {
    //        pPEInfo->mapImportDetects.insert(RECORD_NAME_PECOMPACT,getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_PECOMPACT,"2.X","",0));
    //    }

    // TODO
    // Import
}

void SpecAbstract::PE_handle_OperationSystems(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        _SCANS_STRUCT ssOperationSystem=getScansStructFromOsInfo(pe.getOsInfo());

        pPEInfo->mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pPEInfo->basic_info),&ssOperationSystem));
    }
}

void SpecAbstract::PE_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo, bool *pbIsStop)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // MPRESS
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MPRESS))
        {
            _SCANS_STRUCT recordMPRESS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MPRESS);

            qint64 nOffsetMPRESS=pe.find_ansiString(0x1f0,16,"v");

            if(nOffsetMPRESS!=-1)
            {
                // TODO Check!
                recordMPRESS.sVersion=pe.read_ansiString(nOffsetMPRESS+1,0x1ff-nOffsetMPRESS);
            }

            pPEInfo->mapResultPackers.insert(recordMPRESS.name,scansToScan(&(pPEInfo->basic_info),&recordMPRESS));
        }


        // Spoon Studio
        if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Spoon Studio 2011"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SPOONSTUDIO2011,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ",".");
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Spoon Studio"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SPOONSTUDIO,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ",".");
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2009"))
        {
            // Xenocode Virtual Application Studio 2009
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010 ISV Edition"))
        {
            // Xenocode Virtual Application Studio 2010 (ISV Edition)
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2012 ISV Edition"))
        {
            // Xenocode Virtual Application Studio 2012 (ISV Edition)
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2013 ISV Edition"))
        {
            // Xenocode Virtual Application Studio 2013 (ISV Edition)
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Turbo Studio"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_TURBOSTUDIO,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SPOONSTUDIO))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SPOONSTUDIO,"","",0);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        else if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_XENOCODE))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODE,"","",0);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(XPE::getResourcesVersionValue("CompanyName",&(pPEInfo->resVersion)).contains("SerGreen"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_SERGREENAPPACKER,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // MoleBox Ultra
        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MOLEBOXULTRA))
        {
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_MOLEBOXULTRA))
            {
                _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MOLEBOXULTRA);
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ACTIVEMARK))
        {
            _SCANS_STRUCT ssOverlay=pPEInfo->mapOverlayDetects.value(RECORD_NAME_ACTIVEMARK);
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ACTIVEMARK,ssOverlay.sVersion,ssOverlay.sInfo,0);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SECUROM))
        {
            // TODO Version
            _SCANS_STRUCT ssOverlay=pPEInfo->mapOverlayDetects.value(RECORD_NAME_SECUROM);
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SECUROM,ssOverlay.sVersion,ssOverlay.sInfo,0);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_ENIGMAVIRTUALBOX))
        {
            _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_ENIGMAVIRTUALBOX);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ZLIB))
        {
            if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                VI_STRUCT viStruct=get_PyInstaller_vi(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

                if(viStruct.bIsValid)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_PYINSTALLER,"","",0);

                    ss.sVersion=viStruct.sVersion;
                    ss.sInfo=viStruct.sInfo;

                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }

        if(!pPEInfo->cliInfo.bValid)
        {
            // TODO MPRESS import

            // UPX
            // TODO 32-64
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX))
            {
                VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,pPEInfo->osHeader.nOffset,pPEInfo->osHeader.nSize,XBinary::FT_PE);

                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_UPX))
                {
                    if((viUPX.bIsValid))
                    {
                        _SCANS_STRUCT recordUPX={};

                        recordUPX.type=RECORD_TYPE_PACKER;
                        recordUPX.name=RECORD_NAME_UPX;
                        recordUPX.sVersion=viUPX.sVersion;
                        recordUPX.sInfo=viUPX.sInfo;

                        pPEInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pPEInfo->basic_info),&recordUPX));
                    }
                    else
                    {
                        _SCANS_STRUCT recordUPX=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_UPX);

                        recordUPX.sInfo=append(recordUPX.sInfo,"modified");

                        pPEInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pPEInfo->basic_info),&recordUPX));
                    }
                }
            }

            // EXPRESSOR
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXPRESSOR)||(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXPRESSOR_KERNEL32)&&pPEInfo->mapImportDetects.contains(RECORD_NAME_EXPRESSOR_USER32)))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXPRESSOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXPRESSOR);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // ASProtect
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASPROTECT))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ASPROTECT))
                {
                    _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ASPROTECT);

                    pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                }
            }

            // PE-Quake
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEQUAKE))
            {
                _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEQUAKE);

                pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }

            // MORPHNAH
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MORPHNAH))
            {
                _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MORPHNAH);

                pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }

            // PECompact
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PECOMPACT))
            {
                _SCANS_STRUCT recordPC=pPEInfo->mapImportDetects.value(RECORD_NAME_PECOMPACT);

                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PECOMPACT))
                {
                    if(recordPC.nVariant==1)
                    {
                        recordPC.sVersion="1.10b4-1.10b5";
                    }

                    pPEInfo->mapResultPackers.insert(recordPC.name,scansToScan(&(pPEInfo->basic_info),&recordPC));
                }
                else
                {
                    VI_STRUCT viPECompact=PE_get_PECompact_vi(pDevice,bIsImage,pPEInfo);

                    if(viPECompact.bIsValid)
                    {
                        recordPC.sVersion=viPECompact.sVersion;
                        recordPC.sInfo=viPECompact.sInfo;

                        pPEInfo->mapResultPackers.insert(recordPC.name,scansToScan(&(pPEInfo->basic_info),&recordPC));
                    }
                }
            }

            // NSPack
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NSPACK))
            {
                if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSPACK))
                {
                    _SCANS_STRUCT recordNSPack=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSPACK);
                    pPEInfo->mapResultPackers.insert(recordNSPack.name,scansToScan(&(pPEInfo->basic_info),&recordNSPack));
                }
                else if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NSPACK))
                {
                    _SCANS_STRUCT recordNSPack=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NSPACK);
                    pPEInfo->mapResultPackers.insert(recordNSPack.name,scansToScan(&(pPEInfo->basic_info),&recordNSPack));
                }
            }

            // ENIGMA
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ENIGMA))
            {
                if(pe.checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 nSectionOffset=pPEInfo->osImportSection.nOffset;
                    qint64 nSectionSize=pPEInfo->osImportSection.nSize;

                    bool bDetect=false;

                    _SCANS_STRUCT recordEnigma={};

                    recordEnigma.type=SpecAbstract::RECORD_TYPE_PROTECTOR;
                    recordEnigma.name=SpecAbstract::RECORD_NAME_ENIGMA;

                    if(!bDetect)
                    {
                        VI_STRUCT viEngima=get_Enigma_vi(pDevice,bIsImage,nSectionOffset,nSectionSize);

                        if(viEngima.bIsValid)
                        {
                            recordEnigma.sVersion=viEngima.sVersion;
                            bDetect=true;
                        }
                    }

                    if(!bDetect)
                    {
                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ENIGMA))
                        {
                            recordEnigma.sVersion=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ENIGMA).sVersion;
                            bDetect=true;
                        }
                    }

                    if(bDetect)
                    {
                        pPEInfo->mapResultProtectors.insert(recordEnigma.name,scansToScan(&(pPEInfo->basic_info),&recordEnigma));
                    }
                }
            }

            // PESpin
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PESPIN))
            {
                _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PESPIN);

                // Get version
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PESPIN))
                {
                    quint8 nByte=pPEInfo->sEntryPointSignature.mid(54,2).toUInt(nullptr,16);

                    switch(nByte)
                    {
                        case 0x5C: ss.sVersion="0.1";     break;
                        case 0xB7: ss.sVersion="0.3";     break;
                        case 0x73: ss.sVersion="0.4";     break;
                        case 0x83: ss.sVersion="0.7";     break;
                        case 0xC8: ss.sVersion="1.0";     break;
                        case 0x7D: ss.sVersion="1.1";     break;
                        case 0x71: ss.sVersion="1.3beta"; break;
                        case 0xAC: ss.sVersion="1.3";     break;
                        case 0x88: ss.sVersion="1.3x";    break;
                        case 0x17: ss.sVersion="1.32";    break;
                        case 0x77: ss.sVersion="1.33";    break;
                    }
                }

                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // nPack
            // TODO Timestamp 'nPck'
            // TODO Check 64
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NPACK))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NPACK))
                {
                    _SCANS_STRUCT recordNPACK=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NPACK);

                    if(pe.checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        qint64 _nOffset=pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize=pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"nPack v");

                        if(nOffset_Version!=-1)
                        {
                            recordNPACK.sVersion=pe.read_ansiString(nOffset_Version+7).section(":",0,0);
                        }
                        else
                        {
                            recordNPACK.sVersion="1.1.200.2006";
                        }
                    }

                    pPEInfo->mapResultPackers.insert(recordNPACK.name,scansToScan(&(pPEInfo->basic_info),&recordNPACK));
                }
            }

            if(!pPEInfo->bIs64)
            {
                // MaskPE
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_MASKPE))
                {
                    if(pPEInfo->mapEntryPointSectionDetects.contains(RECORD_NAME_MASKPE))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointSectionDetects.value(RECORD_NAME_MASKPE);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PE-Armor
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEARMOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEARMOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEARMOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // DalCrypt
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_DALKRYPT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // N-Code
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NCODE))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NCODE);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // LameCrypt
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_LAMECRYPT))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_LAMECRYPT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // SC Obfuscator
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SCOBFUSCATOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SCOBFUSCATOR);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // PCShrink
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PCSHRINK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PCSHRINK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PCSHRINK);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // DragonArmor
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DRAGONARMOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_DRAGONARMOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_DRAGONARMOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // NoodleCrypt
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NOODLECRYPT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NOODLECRYPT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NOODLECRYPT);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PEnguinCrypt
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PENGUINCRYPT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PENGUINCRYPT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PENGUINCRYPT);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EXECrypt
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXECRYPT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXECRYPT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXECRYPT);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EXE Password Protector
                // TODO Manifest name: Microsoft.Windows.ExeProtector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXEPASSWORDPROTECTOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXEPASSWORDPROTECTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXEPASSWORDPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXESTEALTH))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXESTEALTH))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXESTEALTH);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PE Diminisher
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEDIMINISHER))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEDIMINISHER);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // G!X Protector
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_GIXPROTECTOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_GIXPROTECTOR);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // PC Guard
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PCGUARD))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PCGUARD))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PCGUARD);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Soft Defender
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SOFTDEFENDER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SOFTDEFENDER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SOFTDEFENDER);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PECRYPT32
                // TODO Check!!!
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PECRYPT32))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PECRYPT32))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PECRYPT32);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EXECryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXECRYPTOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXECRYPTOR);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // YZPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_YZPACK))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_YZPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_YZPACK);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // BCPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR)) // TODO !!!
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // CRYPToCRACks PE Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRYPTOCRACKPEPROTECTOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTOCRACKPEPROTECTOR);

                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRYPTOCRACKPEPROTECTOR))
                    {
                        ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRYPTOCRACKPEPROTECTOR);
                    }

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // ZProtect
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ZPROTECT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSTUBLINKER))
                    {
                        if(pPEInfo->listSectionRecords.count()>=2)
                        {
                            if(pe.compareSignature(&(pPEInfo->basic_info.memoryMap),"'kernel32.dll'00000000'VirtualAlloc'00000000",pPEInfo->listSectionRecords.at(1).nOffset))
                            {
                                _SCANS_STRUCT recordZProtect=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ZPROTECT,"1.3-1.4.4","",0);
                                pPEInfo->mapResultProtectors.insert(recordZProtect.name,scansToScan(&(pPEInfo->basic_info),&recordZProtect));
                            }
                        }
                    }
                }
                else if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ZPROTECT))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ZPROTECT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                if(!pPEInfo->mapResultProtectors.contains(RECORD_NAME_ZPROTECT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSTUBLINKER))
                    {
                        if(pPEInfo->listSectionRecords.count()>=2)
                        {
                            if( (pPEInfo->listSectionHeaders.at(0).PointerToRawData==0)&&
                                (pPEInfo->listSectionHeaders.at(0).SizeOfRawData==0)&&
                                (pPEInfo->listSectionHeaders.at(0).Characteristics==0xe00000a0))
                            {
                                bool bDetect1=(pPEInfo->nEntryPointSection==1);
                                bool bDetect2=(pe.getEntropy(pPEInfo->listSectionRecords.at(2).nOffset,pPEInfo->listSectionRecords.at(2).nSize)>7.6);

                                if(bDetect1||bDetect2)
                                {
                                    _SCANS_STRUCT recordZProtect=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ZPROTECT,"1.XX","",0);
                                    pPEInfo->mapResultProtectors.insert(recordZProtect.name,scansToScan(&(pPEInfo->basic_info),&recordZProtect));
                                }
                            }
                        }
                    }
                }

                // ExeFog
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXEFOG))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_EXEFOG);

                    if( (pPEInfo->fileHeader.TimeDateStamp==0)&&
                        (pPEInfo->optional_header.optionalHeader32.MajorLinkerVersion==0)&&
                        (pPEInfo->optional_header.optionalHeader32.MinorLinkerVersion==0)&&
                        (pPEInfo->optional_header.optionalHeader32.BaseOfData==0x1000))
                    {
                        if(pPEInfo->listSectionHeaders.count())
                        {
                            if(pPEInfo->listSectionHeaders.at(0).Characteristics==0xe0000020)
                            {
                                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                            }
                        }
                    }
                }

                // AHPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_AHPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AHPACKER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AHPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // 12311134
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_12311134)) // TODO Check!
                {
                    _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_12311134);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AZProtect
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AZPROTECT))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AZPROTECT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AverCryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AVERCRYPTOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_AVERCRYPTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AVERCRYPTOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // WinKript
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WINKRIPT))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_WINKRIPT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AffilliateEXE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_AFFILLIATEEXE))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AFFILLIATEEXE);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // Advanced UPX Scrammbler
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ADVANCEDUPXSCRAMMBLER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ADVANCEDUPXSCRAMMBLER);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // BeRoEXEPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BEROEXEPACKER))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BEROEXEPACKER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_BEROEXEPACKER);

                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BEROEXEPACKER))
                        {
                            ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BEROEXEPACKER);
                        }

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                    else if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC))
                    {
                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BEROEXEPACKER))
                        {
                            _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BEROEXEPACKER);
                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }

                // Winupack
                if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINUPACK))
                {
                    _SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINUPACK);

                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WINUPACK))
                    {
                        ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_WINUPACK);
                    }

                    //                    recordWinupack.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(((pPEInfo->nMinorLinkerVersion)/16)*10+(pPEInfo->nMinorLinkerVersion)%16);

                    int nBuildNumber=0;

                    if((ss.nVariant==1)||(ss.nVariant==2))
                    {
                        nBuildNumber=pPEInfo->nMinorLinkerVersion;
                    }
                    else if((ss.nVariant==3)||(ss.nVariant==4))
                    {
                        nBuildNumber=pPEInfo->nMinorImageVersion;
                    }
#ifdef QT_DEBUG
                    qDebug("nBuildNumber: %x",nBuildNumber);
#endif
                    switch(nBuildNumber)
                    {
                        case 0x21:  ss.sVersion="0.21";         break;
                        case 0x22:  ss.sVersion="0.22";         break;
                        case 0x23:  ss.sVersion="0.23";         break;
                        case 0x24:  ss.sVersion="0.24";         break;
                        case 0x25:  ss.sVersion="0.25";         break;
                        case 0x26:  ss.sVersion="0.26";         break;
                        case 0x27:  ss.sVersion="0.27";         break;
                        case 0x28:  ss.sVersion="0.28";         break;
                        case 0x29:  ss.sVersion="0.29";         break;
                        case 0x30:  ss.sVersion="0.30";         break;
                        case 0x31:  ss.sVersion="0.31";         break;
                        case 0x32:  ss.sVersion="0.32";         break;
                        case 0x33:  ss.sVersion="0.33";         break;
                        case 0x34:  ss.sVersion="0.34";         break;
                        case 0x35:  ss.sVersion="0.35";         break;
                        case 0x36:  ss.sVersion="0.36 beta";    break;
                        case 0x37:  ss.sVersion="0.37 beta";    break;
                        case 0x38:  ss.sVersion="0.38 beta";    break;
                        case 0x39:  ss.sVersion="0.39 final";   break;
                        case 0x3A:  ss.sVersion="0.399";        break;
                    }

                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // ANDpakk2
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ANDPAKK2)||
                        pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDPAKK2))
                {
                    // TODO compare entryPoint and import sections
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ANDPAKK2))
                    {
                        _SCANS_STRUCT recordANFpakk2=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ANDPAKK2);
                        pPEInfo->mapResultPackers.insert(recordANFpakk2.name,scansToScan(&(pPEInfo->basic_info),&recordANFpakk2));
                    }
                }

                // KByS
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KBYS))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KBYS))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KBYS);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Crunch
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRUNCH))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRUNCH))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRUNCH);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // ASDPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASDPACK))
                {
                    bool bDetected=false;
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ASDPACK);

                    if(pPEInfo->listSectionRecords.count()==2)
                    {
                        if(pPEInfo->bIsTLSPresent)
                        {
                            bDetected=true; // 1.00
                        }
                    }

                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ASDPACK))
                    {
                        ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ASDPACK);
                        bDetected=true;
                    }

                    if(bDetected)
                    {

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // VPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_VPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_VPACKER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_VPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // RLP
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RLP))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RLP))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RLP);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Crinkler
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRINKLER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRINKLER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRINKLER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EZIP
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EZIP))
                {
                    if(pPEInfo->nOverlaySize)
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EZIP);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // KKrunchy
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KKRUNCHY))
                {
                    if( pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_KKRUNCHY)||
                        pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC))
                    {
                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KKRUNCHY))
                        {
                            _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KKRUNCHY);

                            if(!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_KKRUNCHY))
                            {
                                ss.sInfo="Patched";
                            }

                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }

                // QuickPack NT
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_QUICKPACKNT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QUICKPACKNT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QUICKPACKNT);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // MKFPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MKFPACK))
                {
                    qint64 mLfanew=pPEInfo->dosHeader.e_lfanew-5;

                    if(mLfanew>0)
                    {
                        QString sSignature=pe.read_ansiString(mLfanew,5);

                        if(sSignature=="llydd")
                        {
                            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MKFPACK);
                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }

                // 32lite
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_32LITE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_32LITE))
                    {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_32LITE);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EProt
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EPROT))
                {
                    if(pPEInfo->nEntryPointSection>0)
                    {
                        if(pPEInfo->sEntryPointSectionName=="!eprot")
                        {
                            quint32 nValue=pe.read_uint32(pPEInfo->osEntryPointSection.nOffset+pPEInfo->osEntryPointSection.nSize-4);

                            if(nValue==0x78787878)
                            {
                                _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPROT);
                                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                            }
                        }
                    }
                }

                // RLPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RLPACK))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_RLPACK);

                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RLPACK))
                    {
                        ss.sInfo=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RLPACK).sInfo;
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                    else if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_FAKESIGNATURE))
                    {
                        if(pPEInfo->listSectionHeaders.count()>=2)
                        {
                            if(pPEInfo->listSectionHeaders.at(0).SizeOfRawData<=0x200)
                            {
                                ss.sInfo=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_FAKESIGNATURE).sInfo;
                                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                            }
                        }
                    }
                }

                // Packman
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PACKMAN))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PACKMAN))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PACKMAN);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Fish PE Packer
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FISHPEPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_FISHPEPACKER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_FISHPEPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Inquartos Obfuscator
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_INQUARTOSOBFUSCATOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Hide & Protect
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HIDEANDPROTECT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_HIDEANDPROTECT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_HIDEANDPROTECT);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // mPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MPACK);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EncryptPE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ENCRYPTPE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ENCRYPTPE))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ENCRYPTPE);

                        qint64 _nOffset=pPEInfo->osHeader.nOffset;
                        qint64 _nSize=pPEInfo->osHeader.nSize;

                        qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"EncryptPE V");

                        if(nOffset_Version!=-1)
                        {
                            ss.sVersion=pe.read_ansiString(nOffset_Version+11).section(",",0,0);
                        }

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Yoda's Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_YODASPROTECTOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_YODASPROTECTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_YODASPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Xtreme-Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_XTREMEPROTECTOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_XTREMEPROTECTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_XTREMEPROTECTOR);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // ACProtect
                // 1.X-2.X
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ACPROTECT))
                {
                    if(pe.checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        qint64 nSectionOffset=pPEInfo->osImportSection.nOffset;
                        qint64 nSectionSize=pPEInfo->osImportSection.nSize;

                        qint64 nOffset1=pe.find_array(nSectionOffset,nSectionSize,"MineImport_Endss",16);

                        if(nOffset1!=-1)
                        {
                            _SCANS_STRUCT recordACProtect={};
                            recordACProtect.type=RECORD_TYPE_PROTECTOR;
                            recordACProtect.name=RECORD_NAME_ACPROTECT;

                            recordACProtect.sVersion="1.XX-2.XX";

                            //                            qint64 nOffset2=pe.find_array(nSectionOffset,nSectionSize,"Randimize",9);

                            //                            if(nOffset2!=-1)
                            //                            {
                            //                                recordACProtect.sVersion="1.X";
                            //                            }


                            pPEInfo->mapResultProtectors.insert(recordACProtect.name,scansToScan(&(pPEInfo->basic_info),&recordACProtect));
                        }
                    }
                }

                // ACProtect
                // 2.0.X
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ACPROTECT)) // TODO CHECK
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ACPROTECT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // FSG
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FSG))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FSG))
                    {
                        _SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FSG);

                        if(ss.nVariant==0)
                        {
                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                        else if(ss.nVariant==1)
                        {
                            if(pe.read_ansiString(0x154)=="KERNEL32.dll")
                            {
                                ss.sVersion="1.33";
                            }
                            else
                            {
                                ss.sVersion="2.00";
                            }

                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }

                // MEW
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MEW10))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MEW10))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MEW10);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MEW11SE))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MEW11SE))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MEW11SE);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Alex Protector
                // 2.0.X
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ALEXPROTECTOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ALEXPROTECTOR))
                    {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ALEXPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PEBundle
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEBUNDLE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEBUNDLE))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEBUNDLE);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PE-SHiELD
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PESHIELD))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PESHIELD))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PESHIELD);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PUNiSHER
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PUNISHER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PUNISHER))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PUNISHER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Shrinker
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SHRINKER))
                {
                    if(pe.isImportFunctionPresentI("KERNEL32.DLL","8",&(pPEInfo->listImports)))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SHRINKER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Secure Shade
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SECURESHADE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SECURESHADE))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SECURESHADE);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PolyCrypt PE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_POLYCRYPTPE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_POLYCRYPTPE))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_POLYCRYPTPE);

                        if(pPEInfo->nImportSection==pPEInfo->nEntryPointSection)
                        {
                            if(pe.checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
                            {
                                qint64 _nOffset=pPEInfo->osEntryPointSection.nOffset;
                                qint64 _nSize=pPEInfo->osEntryPointSection.nSize;

                                qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"PolyCrypt PE (c) 2004-2005, JLabSoftware.");

                                if(nOffset_Version==-1)
                                {
                                    recordSS.sInfo="Modified";
                                }
                            }
                        }

                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HMIMYSPROTECTOR))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_HMIMYSPROTECTOR))
                    {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HMIMYSPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                    {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                    else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HMIMYSPACKER))
                {
                    if(XPE::isSectionNamePresent(".hmimys",&(pPEInfo->listSectionHeaders))) // TODO Check
                    {
                        _SCANS_STRUCT recordSS=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_HMIMYSPACKER,"","",0);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ORIEN))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ORIEN))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ORIEN);

                        QString sVersion=pPEInfo->sEntryPointSignature.mid(16,2);

                        if(sVersion=="CE")
                        {
                            recordSS.sVersion="2.11";
                        }
                        else if(sVersion=="CD")
                        {
                            recordSS.sVersion="2.12";
                        }

                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Alloy
                // 4.X
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ALLOY))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ALLOY))
                    {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ALLOY);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PeX
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEX))
                {
                    // TODO compare entryPoint and import sections
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEX))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEX);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PEVProt
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_REVPROT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_REVPROT))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_REVPROT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Software Compress
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SOFTWARECOMPRESS))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SOFTWARECOMPRESS))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SOFTWARECOMPRESS);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // SDProtector Pro
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SDPROTECTORPRO))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SDPROTECTORPRO))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SDPROTECTORPRO);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Simple Pack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SIMPLEPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SIMPLEPACK))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_SIMPLEPACK);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // NakedPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NAKEDPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NAKEDPACKER)&&(!pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NAKEDPACKER);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // KaOs PE-DLL eXecutable Undetecter
                // the same as NakedPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)&&pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // ASPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASPACK))
                {
                    // TODO compare entryPoint and import sections
                    QString _sSignature=pPEInfo->sEntryPointSignature;
                    qint64 _nOffset=0;
//                    QString _sVersion;

                    // TODO a function
                    while(true)
                    {
                        bool bContinue=false;

                        if(XBinary::compareSignatureStrings(_sSignature,"90"))
                        {
                            bContinue=true;
                            _nOffset++;
                            _sSignature.remove(0,2);
                        }

                        if(XBinary::compareSignatureStrings(_sSignature,"7500"))
                        {
                            bContinue=true;
                            _nOffset+=2;
                            _sSignature.remove(0,4);
                        }

                        if(XBinary::compareSignatureStrings(_sSignature,"7501"))
                        {
                            bContinue=true;
                            _nOffset+=3;
                            _sSignature.remove(0,6);
                        }

                        if(XBinary::compareSignatureStrings(_sSignature,"E9"))
                        {
                            bContinue=true;
                            _nOffset++;
                            _sSignature.remove(0,2);
                            qint32 nAddress=XBinary::hexToInt32(_sSignature);
                            _nOffset+=4;
                            // TODO image
                            qint64 nSignatureOffset=pe.addressToOffset(pPEInfo->nImageBaseAddress+pPEInfo->nEntryPointAddress+_nOffset+nAddress);

                            if(nSignatureOffset!=-1)
                            {
                                _sSignature=pe.getSignature(nSignatureOffset,150);
                            }
                            else
                            {
                                break;
                            }
                        }

                        if(_nOffset)
                        {
                            signatureScan(&(pPEInfo->mapEntryPointDetects),_sSignature,_PE_entrypoint_records,sizeof(_PE_entrypoint_records),pPEInfo->basic_info.id.fileType,XBinary::FT_PE,&(pPEInfo->basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);
                            signatureExpScan(&pe,&(pPEInfo->basic_info.memoryMap),&(pPEInfo->mapEntryPointDetects),pPEInfo->nEntryPointOffset+_nOffset,_PE_entrypointExp_records,sizeof(_PE_entrypointExp_records),pPEInfo->basic_info.id.fileType,XBinary::FT_PE,&(pPEInfo->basic_info),DETECTTYPE_ENTRYPOINT,pbIsStop);
                        }

                        if(_nOffset>20)
                        {
                            break;
                        }

                        if(!bContinue)
                        {
                            break;
                        }

                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ASPACK))
                        {
                            break;
                        }
                    }

                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ASPACK))
                    {
                        _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ASPACK);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // No Import
                // WWPACK32
                // TODO false
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WWPACK32))
                {
                    _SCANS_STRUCT ss={};

                    ss.type=RECORD_TYPE_PACKER;
                    ss.name=RECORD_NAME_WWPACK32;
                    ss.sVersion=XBinary::hexToString(pPEInfo->sEntryPointSignature.mid(102,8));
                    //recordAndpakk.sInfo;

                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // EXE Pack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EPEXEPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EPEXEPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                    else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EPEXEPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EPROT))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPROT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // RCryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RCRYPTOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RCRYPTOR);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // PE-PACK
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEPACK);

                        if(pe.checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
                        {
                            qint64 _nOffset=pPEInfo->osImportSection.nOffset;
                            qint64 _nSize=pPEInfo->osImportSection.nSize;

                            qint64 nOffset_PEPACK=pe.find_ansiString(_nOffset,_nSize,"PE-PACK v");

                            if(nOffset_PEPACK!=-1)
                            {
                                ss.sVersion=pe.read_ansiString(nOffset_PEPACK+9,50);
                                ss.sVersion=ss.sVersion.section(" ",0,0);
                            }
                        }

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PKLITE32
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PKLITE32))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PKLITE32);

                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // MoleBox
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MOLEBOX))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MOLEBOX);

                    QString sComment=XPE::getResourcesVersionValue("Comments",&(pPEInfo->resVersion));

                    if(sComment.contains("MoleBox "))
                    {
                        ss.sVersion=sComment.section("MoleBox ",1,-1);
                    }

                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // XComp
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_XCOMP))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_XCOMP))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_XCOMP);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // XPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_XPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_XPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_XPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Krypton
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KRYPTON))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KRYPTON))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KRYPTON);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // SVK Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SVKPROTECTOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SVKPROTECTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SVKPROTECTOR);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // TPP Pack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_TPPPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_TPPPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_TPPPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // VCasm-Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_VCASMPROTECTOR))
                {
                    _SCANS_STRUCT ss={};
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_VCASMPROTECTOR))
                    {
                        ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_VCASMPROTECTOR);
                    }

                    if(pe.checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        ss=pPEInfo->mapImportDetects.value(RECORD_NAME_VCASMPROTECTOR);

                        qint64 _nOffset=pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize=pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"vcasm_protect_");

                        QString sVersionString;

                        if(nOffset_Version!=-1)
                        {
                            sVersionString=pe.read_ansiString(nOffset_Version).section("_",2,-1);
                        }

                        if(sVersionString=="2004_11_30")
                        {
                            ss.sVersion="1.0";
                        }
                        if(sVersionString=="2005_3_18")
                        {
                            ss.sVersion="1.1-1.2";
                        }
                    }


                    if(ss.name!=RECORD_NAME_UNKNOWN)
                    {
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // JDPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_JDPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_JDPACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_JDPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Yoda's crypter
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_YODASCRYPTER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_YODASCRYPTER))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_YODASCRYPTER);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // QrYPt0r
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_QRYPT0R))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_QRYPT0R))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_QRYPT0R);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // DBPE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DBPE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_DBPE))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_DBPE);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // FISH PE Shield
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FISHPESHIELD))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_FISHPESHIELD))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_FISHPESHIELD);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // bambam
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BAMBAM))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BAMBAM))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BAMBAM);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // DotFix NeceProtect
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DOTFIXNICEPROTECT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_DOTFIXNICEPROTECT))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_DOTFIXNICEPROTECT);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // The Best Cryptor [by FsK]
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_THEBESTCRYPTORBYFSK))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_THEBESTCRYPTORBYFSK);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // DYAMAR
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DYAMAR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_DYAMAR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DYAMAR);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // CExe
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CEXE))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CEXE);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // K!Cryptor
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KCRYPTOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KCRYPTOR))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KCRYPTOR);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Crypter
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRYPTER))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRYPTER);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // Thinstall
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_THINSTALL)) // TODO Imports EP
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_THINSTALL);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
                else if(XPE::getResourcesVersionValue("ThinAppVersion",&(pPEInfo->resVersion))!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THINSTALL,"","",0);
                    ss.sVersion=XPE::getResourcesVersionValue("ThinAppVersion",&(pPEInfo->resVersion)).trimmed();

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
                else if(XPE::getResourcesVersionValue("ThinstallVersion",&(pPEInfo->resVersion))!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THINSTALL,"","",0);
                    ss.sVersion=XPE::getResourcesVersionValue("ThinstallVersion",&(pPEInfo->resVersion)).trimmed();

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // ABC Cryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ABCCRYPTOR))
                {
                    _SCANS_STRUCT recordEP=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ABCCRYPTOR);

                    if((pPEInfo->nEntryPointAddress-pPEInfo->listSectionHeaders.at(pPEInfo->nEntryPointSection).VirtualAddress)==1)
                    {
                        pPEInfo->mapResultPackers.insert(recordEP.name,scansToScan(&(pPEInfo->basic_info),&recordEP));
                    }
                }

                // exe 32 pack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXE32PACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXE32PACK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXE32PACK);

                        qint64 _nOffset=pPEInfo->osHeader.nOffset;
                        qint64 _nSize=qMin(pPEInfo->basic_info.nSize,(qint64)0x2000);

                        qint64 nOffset_version=pe.find_ansiString(_nOffset,_nSize,"Packed by exe32pack");

                        if(nOffset_version!=-1)
                        {
                            ss.sVersion=pe.read_ansiString(nOffset_version+20,50);
                            ss.sVersion=ss.sVersion.section(" ",0,0);
                        }

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // SC PACK
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SCPACK))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_SCPACK))
                    {
                        if(pPEInfo->listSectionRecords.count()>=3)
                        {
                            if(pPEInfo->nEntryPointSection==1)
                            {
                                if(pPEInfo->listSectionHeaders.at(1).VirtualAddress==pPEInfo->nEntryPointAddress)
                                {
                                    _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SCPACK);

                                    pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                                }
                            }
                        }
                    }
                }

                // dePack
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_DEPACK))
                {
                    if(pe.compareEntryPoint("EB$$60"))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_DEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
            else
            {
                // Only 64
                // lARP64
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_LARP64))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_LARP64))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_LARP64);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_VMProtect(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            bool bSuccess=false;

            QSet<QString> stDetects;

            qint32 nNumberOfImports=pPEInfo->listImports.count();

            // TODO Check!
            if(nNumberOfImports>=2)
            {
                if(pPEInfo->listImports.at(nNumberOfImports-2).sName.toUpper()=="KERNEL32.DLL")
                {
                    if(pPEInfo->listImports.at(nNumberOfImports-2).listPositions.count()==12)
                    {
                        if( (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(0).sName=="LocalAlloc")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(1).sName=="LocalFree")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(2).sName=="GetModuleFileNameW")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(3).sName=="GetProcessAffinityMask")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(4).sName=="SetProcessAffinityMask")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(5).sName=="SetThreadAffinityMask")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(6).sName=="Sleep")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(7).sName=="ExitProcess")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(8).sName=="FreeLibrary")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(9).sName=="LoadLibraryA")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(10).sName=="GetModuleHandleA")&&
                            (pPEInfo->listImports.at(nNumberOfImports-2).listPositions.at(11).sName=="GetProcAddress"))
                        {
                            stDetects.insert("kernel32_3");
                        }
                    }
                }

                if(pPEInfo->listImports.at(nNumberOfImports-1).sName.toUpper()=="USER32.DLL")
                {
                    if(pPEInfo->listImports.at(nNumberOfImports-1).listPositions.count()==2)
                    {
                        if( (pPEInfo->listImports.at(nNumberOfImports-1).listPositions.at(0).sName=="GetProcessWindowStation")&&
                            (pPEInfo->listImports.at(nNumberOfImports-1).listPositions.at(1).sName=="GetUserObjectInformationW"))
                        {
                            stDetects.insert("user32_3");
                        }
                    }
                }
            }

            if( stDetects.contains("kernel32_3")&&
                stDetects.contains("user32_3"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VMPROTECT,"","",0);
                ss.sVersion="3.X";
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));

                bSuccess=true;
            }

            // Import
            if(!bSuccess)
            {
                bSuccess=pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_VMPROTECT);
            }

            if(!bSuccess)
            {
                bSuccess=pPEInfo->mapImportDetects.contains(RECORD_NAME_VMPROTECT);
            }

            if(!bSuccess)
            {
                if(pPEInfo->nEntryPointSection>=3)
                {
                    bSuccess=true;

                    qint32 nNumberOfSections=pPEInfo->listSectionHeaders.count();

                    for(qint32 i=0;i<nNumberOfSections;i++)
                    {
                        if( (i==pPEInfo->nEntryPointSection)||
                            (i==pPEInfo->nResourcesSection)||
                            (i==pPEInfo->nTLSSection)||
                            (i==pPEInfo->nRelocsSection)||
                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name)==".INIT")||
                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name)==".tls")||
                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name).contains("0"))
                          )
                        {
                            continue;
                        }

                        if(pPEInfo->listSectionHeaders.at(i).SizeOfRawData)
                        {
                            bSuccess=false;
                            break;
                        }
                    }
                }
            }

            if(bSuccess)
            {
                if( pe.compareEntryPoint("68........E8")||
                    pe.compareEntryPoint("68........E9")||
                    pe.compareEntryPoint("9C60")||
                    pe.compareEntryPoint("EB$$E9$$$$$$$$68........E8")||
                    pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_VMPROTECT))
                {
                    // TODO more checks
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VMPROTECT,"","",0);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_VProtect(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->nEntryPointSection>0)
            {
                if(pPEInfo->sEntryPointSectionName=="VProtect") // TODO !!!
                {
                    if(pe.checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        qint64 nSectionOffset=pPEInfo->osEntryPointSection.nOffset;
                        qint64 nSectionSize=pPEInfo->osEntryPointSection.nSize;

                        qint64 nOffset_Version=pe.find_ansiString(nSectionOffset,nSectionSize,"VProtect");

                        if(nOffset_Version!=-1)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VIRTUALIZEPROTECT,"","",0);

                            nOffset_Version=pe.find_ansiString(nSectionOffset,nSectionSize,"VProtect Ultimate v");

                            if(nOffset_Version!=-1)
                            {
                                ss.sVersion=pe.read_ansiString(nOffset_Version).section(" v",1,1);
                            }

                            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_TTProtect(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->listImportPositionHashes.count()>=1)
            {
                if(pPEInfo->listImportPositionHashes.at(0)==0xf3f52749) // TODO !!!
                {
                    if(pPEInfo->nEntryPointSection>0)
                    {
                        if(pPEInfo->sEntryPointSectionName==".TTP") // TODO !!!
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_TTPROTECT,"","",0);

                            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_SafeengineShielden(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SAFEENGINESHIELDEN))
            {
                if(pPEInfo->nEntryPointSection>0)
                {
                    if(pPEInfo->sEntryPointSectionName==".sedata") // TODO !!!
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SAFEENGINESHIELDEN,"2.XX","",0);

                        qint64 nSectionOffset=pPEInfo->listSectionRecords.at(1).nOffset;
                        qint64 nSectionSize=pPEInfo->listSectionRecords.at(1).nSize;

                        qint64 nOffset_Version=pe.find_ansiString(nSectionOffset,nSectionSize,"Safengine Shielden v");

                        if(nOffset_Version!=-1)
                        {
                            ss.sVersion=pe.read_ansiString(nOffset_Version).section(" v",1,1);
                        }

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_tElock(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->listImports.count()==2)
            {
                bool bKernel32=false;
                bool bUser32=false;

                // TODO
                if(pPEInfo->listImports.at(0).sName=="kernel32.dll")
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==1)
                    {
                        if(pPEInfo->listImports.at(0).listPositions.at(0).sFunction=="GetModuleHandleA")
                        {
                            bKernel32=true;
                        }
                    }
                }
                if(pPEInfo->listImports.at(1).sName=="user32.dll")
                {
                    if(pPEInfo->listImports.at(1).listPositions.count()==1)
                    {
                        if((pPEInfo->listImports.at(1).listPositions.at(0).sFunction=="MessageBoxA"))
                        {
                            bUser32=true;
                        }
                    }
                }

                if(bKernel32&&bUser32)
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_TELOCK))
                    {
                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_TELOCK);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Armadillo(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            bool bHeaderDetect=false;
            bool bImportDetect=false;

            if((pPEInfo->nMajorLinkerVersion==0x53)&&(pPEInfo->nMinorLinkerVersion==0x52))
            {
                bHeaderDetect=true;
            }

            int nNumberOfImports=pPEInfo->listImports.count();

            if(nNumberOfImports>=3)
            {
                bImportDetect=  (   (pPEInfo->listImports.at(0).sName.toUpper()=="KERNEL32.DLL")&&
                                    (pPEInfo->listImports.at(1).sName.toUpper()=="USER32.DLL")&&
                                    (pPEInfo->listImports.at(2).sName.toUpper()=="GDI32.DLL")   )||
                                (   (pPEInfo->listImports.at(0).sName.toUpper()=="KERNEL32.DLL")&&
                                    (pPEInfo->listImports.at(1).sName.toUpper()=="GDI32.DLL")&&
                                    (pPEInfo->listImports.at(2).sName.toUpper()=="USER32.DLL")   );
            }

            if(bImportDetect||bHeaderDetect)
            {
                bool bDetect=false;

                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ARMADILLO,"","",0);

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ARMADILLO))
                {
                    ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ARMADILLO);

                    bDetect=true;
                }

                if(bHeaderDetect)
                {
                    bDetect=true;
                }

                if(bDetect)
                {
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Obsidium(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // TODO x64
        // KERNEL32.DLL
        // USER32.DLL
        // ADVAPI32.DLL
        // SHEL32.DLL
        if(!pPEInfo->cliInfo.bValid)
        {
            int nNumberOfImports=pPEInfo->listImports.count();

            if((nNumberOfImports==2)||(nNumberOfImports==3))
            {
                bool bKernel32=false;
                bool bUser32=false;
//                bool bAdvapi32=false;

                if(pPEInfo->listImports.at(0).sName=="KERNEL32.DLL")
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==1)
                    {
                        if((pPEInfo->listImports.at(0).listPositions.at(0).sFunction=="ExitProcess"))
                        {
                            bKernel32=true;
                        }
                    }
                }

                if(pPEInfo->listImports.at(1).sName=="USER32.DLL")
                {
                    if(pPEInfo->listImports.at(1).listPositions.count()==1)
                    {
                        if((pPEInfo->listImports.at(1).listPositions.at(0).sFunction=="MessageBoxA"))
                        {
                            bUser32=true;
                        }
                    }
                }

                if(nNumberOfImports==3)
                {
                    if(pPEInfo->listImports.at(2).sName=="ADVAPI32.DLL")
                    {
                        if(pPEInfo->listImports.at(2).listPositions.count()==1)
                        {
                            if((pPEInfo->listImports.at(2).listPositions.at(0).sFunction=="RegOpenKeyExA"))
                            {
//                                bAdvapi32=true;
                            }
                        }
                    }
                }

                if(bKernel32&&bUser32)
                {
                    if( pe.compareEntryPoint("EB$$50EB$$E8")||
                        pe.compareEntryPoint("EB$$E8........EB$$EB"))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_OBSIDIUM,"","",0);

                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Themida(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->listImports.count()==1)
            {
                if(pPEInfo->listImports.at(0).sName=="kernel32.dll")
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==1)
                    {
                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_THEMIDAWINLICENSE))
                        {
                            _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_THEMIDAWINLICENSE);

                            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }
            }
            else if(pPEInfo->listImports.count()==2)
            {
                bool bKernel32=false;
                bool bComctl32=false;

                // TODO
                if(pPEInfo->listImports.at(0).sName=="KERNEL32.dll")
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==2)
                    {
                        if( (pPEInfo->listImports.at(0).listPositions.at(0).sFunction=="CreateFileA")||
                            (pPEInfo->listImports.at(0).listPositions.at(1).sFunction=="lstrcpy"))
                        {
                            bKernel32=true;
                        }
                    }
                }
                else if(pPEInfo->listImports.at(0).sName=="kernel32.dll") // TODO Check
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==1)
                    {
                        if((pPEInfo->listImports.at(0).listPositions.at(0).sFunction=="lstrcpy"))
                        {
                            bKernel32=true;
                        }
                    }
                }

                if((pPEInfo->listImports.at(1).sName=="COMCTL32.dll")||(pPEInfo->listImports.at(1).sName=="comctl32.dll"))
                {
                    if(pPEInfo->listImports.at(1).listPositions.count()==1)
                    {
                        if((pPEInfo->listImports.at(1).listPositions.at(0).sFunction=="InitCommonControls"))
                        {
                            bComctl32=true;
                        }
                    }
                }

                if(bKernel32&&bComctl32)
                {
                    // TODO Version
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THEMIDAWINLICENSE,"1.XX-2.XX","",0);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(!pPEInfo->mapResultProtectors.contains(RECORD_NAME_THEMIDAWINLICENSE))
            {
                // New version
                qint32 nNumbersOfImport=pPEInfo->listImports.count();

                bool bSuccess=true;

                for(qint32 i=0;i<nNumbersOfImport;i++)
                {
                    if(pPEInfo->listImports.at(i).listPositions.count()!=1)
                    {
                        bSuccess=false;
                        break;
                    }
                }

                if(bSuccess)
                {
                    if(pPEInfo->listSectionNames.count()>1)
                    {
                        if(pPEInfo->listSectionNames.at(0)=="        ")
                        {
                            bSuccess=false;

                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THEMIDAWINLICENSE,"3.XX","",0);

                            if(XPE::isSectionNamePresent(".themida",&(pPEInfo->listSectionHeaders)))
                            {
                                ss.sInfo="Themida";
                                bSuccess=true;
                            }
                            else if(XPE::isSectionNamePresent(".winlice",&(pPEInfo->listSectionHeaders)))
                            {
                                ss.sInfo="Winlicense";
                                bSuccess=true;
                            }

                            if(bSuccess)
                            {
                                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                            }
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_StarForce(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        bool bSF3=XPE::isSectionNamePresent(".sforce3",&(pPEInfo->listSectionHeaders)); // TODO
        bool bSF4=XPE::isSectionNamePresent(".ps4",&(pPEInfo->listSectionHeaders)); // TODO

        if(bSF3||bSF4)
        {
            QString sVersion;
            QString sInfo;

            if(bSF3)
            {
                sVersion="3.X";
            }

            if(bSF4)
            {
                sVersion="4.X-5.X";
            }

            qint32 nNumberOfImports=pPEInfo->listImports.count();

            for(qint32 i=0;i<nNumberOfImports;i++)
            {
                if(pPEInfo->listImports.at(i).listPositions.count()==1)
                {
                    if(pPEInfo->listImports.at(i).listPositions.at(0).sName=="")
                    {
                        sInfo=pPEInfo->listImports.at(i).sName;
                    }
                }
            }

            _SCANS_STRUCT recordSS=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_STARFORCE,sVersion,sInfo,0);
            pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::PE_handle_Petite(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(!pPEInfo->bIs64)
            {
                bool bKernel32=false;
                bool bUser32=false;
                QString sVersion;

                // TODO !!!
                // TODO Petite 2.4 Check header

                qint32 nNumberOfImports=pPEInfo->listImports.count();

                for(qint32 i=0;i<nNumberOfImports;i++)
                {
                    if(pPEInfo->listImports.at(i).sName.toUpper()=="USER32.DLL")
                    {
                        if(pPEInfo->listImports.at(i).listPositions.count()==2)
                        {
                            if( (pPEInfo->listImports.at(i).listPositions.at(0).sName=="MessageBoxA")&&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName=="wsprintfA"))
                            {
                                bUser32=true;
                            }
                        }
                        else if(pPEInfo->listImports.at(i).listPositions.count()==1)
                        {
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="MessageBoxA"))
                            {
                                bUser32=true;
                            }
                        }
                    }
                    else if(pPEInfo->listImports.at(i).sName.toUpper()=="KERNEL32.DLL")
                    {
                        if(pPEInfo->listImports.at(i).listPositions.count()==7)
                        {
                            if( (pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName=="GetModuleHandleA")&&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName=="GetProcAddress")&&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName=="VirtualProtect")&&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName=="VirtualAlloc")&&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName=="VirtualFree")&&
                                (pPEInfo->listImports.at(i).listPositions.at(6).sName=="LoadLibraryA"))
                            {
                                sVersion="2.4";
                                bKernel32=true;
                            }
                            else if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(1).sName=="LoadLibraryA")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(2).sName=="GetProcAddress")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(3).sName=="VirtualProtect")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(4).sName=="GlobalAlloc")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(5).sName=="GlobalFree")&&
                                    (pPEInfo->listImports.at(i).listPositions.at(6).sName=="GetModuleHandleA"))
                            {
                                sVersion="2.3";
                                bKernel32=true;
                            }
                        }

                        if(pPEInfo->listImports.at(i).listPositions.count()==6)
                        {
                            if( (pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName=="GetModuleHandleA")&&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName=="GetProcAddress")&&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName=="VirtualProtect")&&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName=="GlobalAlloc")&&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName=="GlobalFree"))
                            {
                                sVersion="2.3";// DLL only?? // TODO Check
                                bKernel32=true;
                            }
                        }
                        else if(pPEInfo->listImports.at(i).listPositions.count()==5)
                        {
                            if( (pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName=="LoadLibraryA")&&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName=="GetProcAddress")&&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName=="VirtualProtect")&&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName=="GlobalAlloc"))
                            {
                                sVersion="2.2";
                                bKernel32=true;
                            }
                        }
                        else if(pPEInfo->listImports.at(i).listPositions.count()==4)
                        {
                            if( (pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName=="GetProcAddress")&&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName=="LoadLibraryA")&&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName=="GlobalAlloc"))
                            {
                                sVersion="1.4";
                                bKernel32=true;
                            }
                        }
                    }
                }

                // TODO Import hash
                if(bUser32&&bKernel32)
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PETITE))
                    {
                        _SCANS_STRUCT recordPETITE=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        recordPETITE.sVersion=sVersion;
                        pPEInfo->mapResultPackers.insert(recordPETITE.name,scansToScan(&(pPEInfo->basic_info),&recordPETITE));
                    }
                }
                else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_PETITE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PETITE))
                    {
                        _SCANS_STRUCT recordPETITE=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        pPEInfo->mapResultPackers.insert(recordPETITE.name,scansToScan(&(pPEInfo->basic_info),&recordPETITE));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_NETProtection(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(pPEInfo->bIsNetPresent)
        {
            // .NET
            // Enigma
            if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan)) // TODO
            {
                qint64 nSectionOffset=pPEInfo->osCodeSection.nOffset;
                qint64 nSectionSize=pPEInfo->osCodeSection.nSize;

                VI_STRUCT viEnigma=get_Enigma_vi(pDevice,bIsImage,nSectionOffset,nSectionSize);

                if(viEnigma.bIsValid)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ENIGMA,viEnigma.sVersion,".NET",0);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // .Net reactor
            if(pPEInfo->listSectionRecords.count()>=2)
            {
                if(pPEInfo->basic_info.bIsDeepScan)
                {
                    qint64 _nOffset=pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize=pPEInfo->listSectionRecords.at(1).nSize;

                    qint64 nOffset_NetReactor=pe.find_signature(&(pPEInfo->basic_info.memoryMap),_nOffset,_nSize,"5266686E204D182276B5331112330C6D0A204D18229EA129611C76B505190158");

                    if(nOffset_NetReactor!=-1)
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_DOTNETREACTOR,"4.8-4.9","",0);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // TODO
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_YANO))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_YANO);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTFUSCATOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DOTFUSCATOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_AGILENET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_AGILENET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_SKATER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_SKATER);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_BABELNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_BABELNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_GOLIATHNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_GOLIATHNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_SPICESNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_SPICESNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_OBFUSCATORNET2009))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_OBFUSCATORNET2009);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            {
                bool bDetect=false;
                _SCANS_STRUCT ss={};

                if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA))
                {
                    ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect=true;
                }
                else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_DEEPSEA))
                {
                    ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect=true;
                }

                if(bDetect)
                {
                    qint64 nSectionOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize=pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi=get_DeepSea_vi(pDevice,bIsImage,nSectionOffset,nSectionSize);

                    if(vi.bIsValid)
                    {
                        ss.sVersion=vi.sVersion;
                        ss.sInfo=vi.sInfo;
                    }

                    pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // cliSecure
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_CLISECURE))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_CLISECURE);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else
            {
                if(pPEInfo->listSectionHeaders.count()>=2)
                {
                    qint64 _nOffset=pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize=pPEInfo->listSectionRecords.at(1).nSize;
                    qint32 _nCharacteristics=pPEInfo->listSectionRecords.at(1).nCharacteristics;

                    if(_nCharacteristics&(XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE))
                    {
                        qint64 nOffset_CliSecure=pe.find_unicodeString(_nOffset,_nSize,"CliSecure");

                        if(nOffset_CliSecure!=-1)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_CLISECURE,"4.X","",0);
                            pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }
            }

            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_FISHNET))||(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_FISHNET)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_FISHNET,"1.X","",0); // TODO
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss)); // TODO obfuscator?
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_NSPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_NSPACK);
                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DNGUARD))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DNGUARD);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // .NETZ
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETZ))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_DOTNETZ))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_MAXTOCODE))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_MAXTOCODE);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_PHOENIXPROTECTOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            {
                bool bDetect=false;
                _SCANS_STRUCT ss={};

                if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_SMARTASSEMBLY))
                {
                    ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect=true;
                }
                else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_SMARTASSEMBLY))
                {
                    ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect=true;
                }

                if(bDetect)
                {
                    qint64 nSectionOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize=pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi=get_SmartAssembly_vi(pDevice,bIsImage,nSectionOffset,nSectionSize);

                    if(vi.bIsValid)
                    {
                        ss.sVersion=vi.sVersion;
                        ss.sInfo=vi.sInfo;
                    }

                    pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_CONFUSER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_CONFUSER);

                if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize=pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_detect=pe.find_ansiString(_nOffset,_nSize,"Confuser v");

                    if(nOffset_detect!=-1)
                    {
                        ss.sVersion=pe.read_ansiString(nOffset_detect+10);
                    }

                    if(nOffset_detect==-1)
                    {
                        qint64 nOffset_ConfuserEx=pe.find_ansiString(_nOffset,_nSize,"ConfuserEx v");

                        if(nOffset_ConfuserEx!=-1)
                        {
                            ss.name=RECORD_NAME_CONFUSEREX;
                            ss.sVersion=pe.read_ansiString(nOffset_ConfuserEx+12);
                        }
                    }
                }

                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Xenocode Postbuild
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_XENOCODEPOSTBUILD))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_XENOCODEPOSTBUILD);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // CodeVeil
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_CODEVEIL))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapDotUnicodeStringsDetects.contains(RECORD_NAME_CODEVEIL))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotUnicodeStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // CodeWall
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_CODEWALL))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_CODEWALL);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // Crypto Obfuscator for .NET
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_CRYPTOOBFUSCATORFORNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_CRYPTOOBFUSCATORFORNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // Eazfuscator
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_EAZFUSCATOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_EAZFUSCATOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // Obfuscar
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_OBFUSCAR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_OBFUSCAR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // .NET Spider
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETSPIDER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSPIDER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // Phoenix Protector
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_PHOENIXPROTECTOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // Sixxpack
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_SIXXPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_SIXXPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // ReNET-Pack
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_RENETPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_RENETPACK);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // .netshrink
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSHRINK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_DOTNETSHRINK);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // Xenocode Virtual Application Studio 2009
        if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Postbuild 2009 for .NET"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Xenocode Postbuild 2010 for .NET
        if(XPE::getResourcesVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Postbuild 2010 for .NET"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET,"","",0);
            ss.sVersion=XPE::getResourcesVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(!pPEInfo->mapResultProtectors.contains(RECORD_NAME_DOTNETREACTOR))
        {
            if( pPEInfo->mapImportDetects.contains(RECORD_NAME_DOTNETREACTOR)&&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"__",&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DOTNETREACTOR);
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }
        if(!pPEInfo->mapResultProtectors.contains(RECORD_NAME_CODEVEIL))
        {
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CODEVEIL))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CODEVEIL))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CODEVEIL);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Microsoft(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo, bool *pbIsStop)
{
    _SCANS_STRUCT ssLinker={};
    _SCANS_STRUCT ssCompiler={};
    _SCANS_STRUCT ssTool={};
    _SCANS_STRUCT ssMFC={};
    _SCANS_STRUCT ssNET={};

    QMap<QString,QString> mapVersions;

    mapVersions.insert("6.00","12.00");
    mapVersions.insert("7.00","13.00");
    mapVersions.insert("7.10","13.10");
    mapVersions.insert("8.00","14.00");
    mapVersions.insert("9.00","15.00");
    mapVersions.insert("10.00","16.00");
    mapVersions.insert("11.00","17.00");
    mapVersions.insert("12.00","18.00");
    mapVersions.insert("14.00","19.00");
    mapVersions.insert("14.10","19.10");
    mapVersions.insert("14.11","19.11");
    mapVersions.insert("14.12","19.12");
    mapVersions.insert("14.13","19.13");
    mapVersions.insert("14.14","19.14");
    mapVersions.insert("14.15","19.15");
    mapVersions.insert("14.16","19.16");
    mapVersions.insert("14.20","19.20");

    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // Linker
        if( (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))&&
            (!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)))
        {
            ssLinker.type=RECORD_TYPE_LINKER;
            ssLinker.name=RECORD_NAME_MICROSOFTLINKER;
        }
        else if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
        {
            bool bMicrosoftLinker=false;

            if((pPEInfo->nMajorLinkerVersion==8)&&(pPEInfo->nMinorImageVersion==0)) // 8.0
            {
                bMicrosoftLinker=true;
            }

            if(bMicrosoftLinker)
            {
                ssLinker.type=RECORD_TYPE_LINKER;
                ssLinker.name=RECORD_NAME_MICROSOFTLINKER;
            }
        }
        else if((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))&&(pPEInfo->cliInfo.bValid))
        {
            ssLinker.type=RECORD_TYPE_LINKER;
            ssLinker.name=RECORD_NAME_MICROSOFTLINKER;

            ssCompiler.type=RECORD_TYPE_COMPILER;
            ssCompiler.name=RECORD_NAME_VISUALCSHARP;
        }

        // MFC
        // Static
        if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
        {
            qint64 _nOffset=pPEInfo->osDataSection.nOffset;
            qint64 _nSize=pPEInfo->osDataSection.nSize;

            qint64 nOffset_MFC=pe.find_ansiString(_nOffset,_nSize,"CMFCComObject");

            if(nOffset_MFC!=-1)
            {
                ssMFC.type=RECORD_TYPE_LIBRARY;
                ssMFC.name=RECORD_NAME_MFC;
                ssMFC.sInfo="Static";
            }
        }

        qint32 nNumberOfImports=pPEInfo->listImports.count();

        for(qint32 i=0;i<nNumberOfImports;i++)
        {
            // https://en.wikipedia.org/wiki/Microsoft_Foundation_Class_Library
            // TODO eMbedded Visual C++ 4.0 		mfcce400.dll 	MFC 6.0
            if(XBinary::isRegExpPresent("^MFC",pPEInfo->listImports.at(i).sName.toUpper()))
            {
                //                    QRegularExpression rxVersion("(\\d+)");
                //                    QRegularExpressionMatch matchVersion=rxVersion.match(pPEInfo->listImports.at(i).sName.toUpper());
                //
                //                    if(matchVersion.hasMatch())
                //                    {
                //                        double dVersion=matchVersion.captured(0).toDouble()/10;
                //
                //                        if(dVersion)
                //                        {
                //                            recordMFC.type=RECORD_TYPE_LIBRARY;
                //                            recordMFC.name=RECORD_NAME_MFC;
                //                            recordMFC.sVersion=QString::number(dVersion,'f',2);
                //
                //                            if(pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL"))
                //                            {
                //                                recordMFC.sInfo="Unicode";
                //                            }
                //                        }
                //                    }

                QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                if(sVersion!="")
                {
                    double dVersion=sVersion.toDouble()/10;

                    if(dVersion)
                    {
                        ssMFC.type=RECORD_TYPE_LIBRARY;
                        ssMFC.name=RECORD_NAME_MFC;
                        ssMFC.sVersion=QString::number(dVersion,'f',2);

                        if(pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL"))
                        {
                            ssMFC.sInfo="Unicode";
                        }
                    }
                }

                break;
            }
        }

        // Rich
        int nRichSignaturesCount=pPEInfo->listRichSignatures.count();

        QList<_SCANS_STRUCT> listRichDescriptions;

        for(int i=0;i<nRichSignaturesCount;i++)
        {
            listRichDescriptions.append(MSDOS_richScan(pPEInfo->listRichSignatures.at(i).nId,pPEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pPEInfo->basic_info.id.fileType,XBinary::FT_MSDOS,&(pPEInfo->basic_info),DETECTTYPE_RICH,pbIsStop));
        }

        int nRichDescriptionsCount=listRichDescriptions.count();

        bool bVB=false;
        for(int i=nRichDescriptionsCount-1;i>=0;i--)
        {
            if(listRichDescriptions.at(i).type==SpecAbstract::RECORD_TYPE_LINKER)
            {
                ssLinker.name=listRichDescriptions.at(i).name;
                ssLinker.sVersion=listRichDescriptions.at(i).sVersion;
                ssLinker.sInfo=listRichDescriptions.at(i).sInfo;
                ssLinker.type=listRichDescriptions.at(i).type;
            }

            if(listRichDescriptions.at(i).type==SpecAbstract::RECORD_TYPE_COMPILER)
            {
                if(!bVB)
                {
                    if(listRichDescriptions.at(i).name==RECORD_NAME_UNIVERSALTUPLECOMPILER)
                    {
                        if(listRichDescriptions.at(i).sInfo!="Basic")
                        {
                            ssCompiler.name=RECORD_NAME_VISUALCCPP;
                            ssCompiler.sVersion=listRichDescriptions.at(i).sVersion;
                            ssCompiler.sInfo=listRichDescriptions.at(i).sInfo;
                            ssCompiler.type=listRichDescriptions.at(i).type;
                        }
                        else
                        {
                            ssCompiler.type=RECORD_TYPE_COMPILER;
                            ssCompiler.name=RECORD_NAME_VISUALBASIC;
                            ssCompiler.sVersion=listRichDescriptions.at(i).sVersion;

                            QString _sVersion=ssCompiler.sVersion.section(".",0,1);
                            QString _sVersionCompiler=mapVersions.key(_sVersion,"");

                            if(_sVersionCompiler!="")
                            {
                                ssCompiler.sVersion=ssCompiler.sVersion.replace(_sVersion,_sVersionCompiler);
                            }

                            ssCompiler.sInfo="Native";
                            bVB=true;
                        }
                    }
                    else
                    {
                        ssCompiler.name=listRichDescriptions.at(i).name;
                        ssCompiler.sVersion=listRichDescriptions.at(i).sVersion;
                        ssCompiler.sInfo=listRichDescriptions.at(i).sInfo;
                        ssCompiler.type=listRichDescriptions.at(i).type;
                    }
                }

            }

            if(listRichDescriptions.at(i).name==SpecAbstract::RECORD_NAME_IMPORT)
            {
                break;
            }
        }

        // TODO Check MASM for .NET

        if(!pPEInfo->cliInfo.bValid)
        {
            // VB
            bool bVBnew=false;

            _SCANS_STRUCT _recordCompiler={};

            if(XPE::isImportLibraryPresentI("VB40032.DLL",&(pPEInfo->listImports)))
            {
                _recordCompiler.type=RECORD_TYPE_COMPILER;
                _recordCompiler.name=RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion="4.0";
            }
            else if(XPE::isImportLibraryPresentI("MSVBVM50.DLL",&(pPEInfo->listImports)))
            {
                _recordCompiler.type=RECORD_TYPE_COMPILER;
                _recordCompiler.name=RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion="5.0";
                bVBnew=true;
            }

            if(XPE::isImportLibraryPresentI("MSVBVM60.DLL",&(pPEInfo->listImports)))
            {
                _recordCompiler.type=RECORD_TYPE_COMPILER;
                _recordCompiler.name=RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion="6.0";
                bVBnew=true;
            }

            if(bVBnew)
            {
                if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize=pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_Options=pe.find_uint32(_nOffset,_nSize,0x21354256);

                    if(nOffset_Options==-1)
                    {
                        nOffset_Options=pe.find_uint32(_nOffset,_nSize,0x21364256);
                    }

                    if(nOffset_Options!=-1)
                    {
                        quint32 nOffsetOptions2=pe.read_uint32(_nOffset+0x30);

                        quint32 nOffsetOptions3=pe.addressToOffset(pe.getBaseAddress()+nOffsetOptions2);
                        quint32 nValue=pe.read_uint32(nOffsetOptions3+0x20);
                        _recordCompiler.sInfo=nValue?"P-Code":"Native";
                    }
                }
            }

            if(ssCompiler.name!=RECORD_NAME_VISUALBASIC)
            {
                if(_recordCompiler.name==RECORD_NAME_VISUALBASIC)
                {
                    ssCompiler=_recordCompiler;
                }
            }
        }
        else
        {
            ssNET.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            ssNET.name=SpecAbstract::RECORD_NAME_DOTNET;
            ssNET.sVersion=pPEInfo->cliInfo.metaData.header.sVersion;

            if(pPEInfo->cliInfo.bHidden)
            {
                ssNET.sInfo="Hidden";
            }

            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_VBNET))
            {
                ssCompiler.type=RECORD_TYPE_COMPILER;
                ssCompiler.name=RECORD_NAME_VBNET;
            }
        }

        if((ssMFC.name==RECORD_NAME_MFC)&&(ssCompiler.type==RECORD_TYPE_UNKNOWN))
        {
            ssCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
            ssCompiler.name=SpecAbstract::RECORD_NAME_VISUALCCPP;

            QString _sVersion=mapVersions.value(ssMFC.sVersion);

            if(_sVersion!="")
            {
                ssCompiler.sVersion=_sVersion;
            }
        }

        if(ssCompiler.name!=RECORD_NAME_VISUALCCPP)
        {
            // TODO Check mb MS Linker only

            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_VISUALCCPP))
            {
                _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_VISUALCCPP);

                ssCompiler.type=ss.type;
                ssCompiler.name=ss.name;
                ssCompiler.sVersion=ss.sVersion;
            }
        }

        // TODO if Export ^? RECORD_NAME_VISUALCCPP/C++

        if((ssMFC.name==RECORD_NAME_MFC)&&(ssMFC.sVersion==""))
        {
            if((ssCompiler.name==RECORD_NAME_VISUALCCPP)&&(ssLinker.sVersion!=""))
            {
                ssMFC.sVersion=ssLinker.sVersion.section(".",0,1);
            }
        }

        if((ssMFC.name==RECORD_NAME_MFC)&&(ssLinker.name!=RECORD_NAME_MICROSOFTLINKER))
        {
            ssLinker.type=SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name=SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if((ssCompiler.name==RECORD_NAME_VISUALCCPP)&&(ssLinker.name!=RECORD_NAME_MICROSOFTLINKER))
        {
            ssLinker.type=SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name=SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if((ssLinker.name==RECORD_NAME_MICROSOFTLINKER)&&(ssLinker.sVersion==""))
        {
            ssLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
        }

        if((ssMFC.name==RECORD_NAME_MFC)&&(ssLinker.sVersion=="")&&(pPEInfo->nMinorLinkerVersion!=10))
        {
            ssLinker.sVersion=ssMFC.sVersion;
            //            recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
        }

        if(ssLinker.name==RECORD_NAME_MICROSOFTLINKER)
        {
            if( (ssCompiler.name==RECORD_NAME_VISUALCCPP)||
                (ssCompiler.name==RECORD_NAME_VISUALCSHARP))
            {
                if(ssCompiler.sVersion=="")
                {
                    QString sLinkerVersion=ssLinker.sVersion;
                    QString sLinkerMajorVersion=sLinkerVersion.section(".",0,1);

                    QString _sVersion=mapVersions.value(sLinkerMajorVersion);

                    if(_sVersion!="")
                    {
                        ssCompiler.sVersion=_sVersion;
                    }
                }
            }
        }

        if( (ssCompiler.name==RECORD_NAME_VISUALCCPP)||
            (ssCompiler.name==RECORD_NAME_VISUALCSHARP))
        {
            QString sLinkerVersion=ssLinker.sVersion;
            QString sCompilerVersion=ssCompiler.sVersion;
            QString sCompilerMajorVersion=sCompilerVersion.section(".",0,1);

            ssTool.type=SpecAbstract::RECORD_TYPE_TOOL;
            ssTool.name=SpecAbstract::RECORD_NAME_MICROSOFTVISUALSTUDIO;

            // https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warnings-by-compiler-version?view=vs-2019

            if(sCompilerVersion=="12.00.8168")
            {
                ssTool.sVersion="6.0";
            }
            else if(sCompilerVersion=="12.00.8804")
            {
                ssTool.sVersion="6.0 SP5-SP6";
            }
            else if(sCompilerVersion=="12.00.8447")
            {
                ssTool.sVersion="6.0 SP5";
            }
            else if((sLinkerVersion=="7.00.9466")&&(sCompilerVersion=="13.00.9466"))
            {
                ssTool.sVersion="2002";
            }
            else if((sLinkerVersion=="7.10.3052")&&(sCompilerVersion=="13.10.3052"))
            {
                ssTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.3077")&&(sCompilerVersion=="13.10.3077"))
            {
                ssTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.4035")&&(sCompilerVersion=="13.10.4035"))
            {
                ssTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.6030")&&(sCompilerVersion=="13.10.6030"))
            {
                ssTool.sVersion="2003 SP1";
            }
            else if((sLinkerVersion=="8.00.40310")&&(sCompilerVersion=="14.00.40310"))
            {
                ssTool.sVersion="2005";
            }
            else if((sLinkerVersion=="8.00.50727")&&(sCompilerVersion=="14.00.50727"))
            {
                ssTool.sVersion="2005";
            }
            else if((sLinkerVersion=="9.00.21022")&&(sCompilerVersion=="15.00.21022"))
            {
                ssTool.sVersion="2008 RTM";
            }
            else if((sLinkerVersion=="9.00.30411")&&(sCompilerVersion=="15.00.30411"))
            {
                ssTool.sVersion="2008 with Feature Pack";
            }
            else if((sLinkerVersion=="9.00.30729")&&(sCompilerVersion=="15.00.30729"))
            {
                ssTool.sVersion="2008 SP1";
            }
            else if((sLinkerVersion=="10.00.30319")&&(sCompilerVersion=="16.00.30319"))
            {
                ssTool.sVersion="2010 RTM";
            }
            else if((sLinkerVersion=="10.00.40219")&&(sCompilerVersion=="16.00.40219"))
            {
                ssTool.sVersion="2010 SP1";
            }
            else if((sLinkerVersion=="11.00.50727")&&(sCompilerVersion=="17.00.50727"))
            {
                ssTool.sVersion="2012";
            }
            else if((sLinkerVersion=="11.00.51025")&&(sCompilerVersion=="17.00.51025"))
            {
                ssTool.sVersion="2012";
            }
            else if((sLinkerVersion=="11.00.51106")&&(sCompilerVersion=="17.00.51106"))
            {
                ssTool.sVersion="2012 Update 1";
            }
            else if((sLinkerVersion=="11.00.60315")&&(sCompilerVersion=="17.00.60315"))
            {
                ssTool.sVersion="2012 Update 2";
            }
            else if((sLinkerVersion=="11.00.60610")&&(sCompilerVersion=="17.00.60610"))
            {
                ssTool.sVersion="2012 Update 3";
            }
            else if((sLinkerVersion=="11.00.61030")&&(sCompilerVersion=="17.00.61030"))
            {
                ssTool.sVersion="2012 Update 4";
            }
            else if((sLinkerVersion=="12.00.21005")&&(sCompilerVersion=="18.00.21005"))
            {
                ssTool.sVersion="2013 RTM";
            }
            else if((sLinkerVersion=="12.00.30501")&&(sCompilerVersion=="18.00.30501"))
            {
                ssTool.sVersion="2013 Update 2";
            }
            else if((sLinkerVersion=="12.00.30723")&&(sCompilerVersion=="18.00.30723"))
            {
                ssTool.sVersion="2013 Update 3";
            }
            else if((sLinkerVersion=="12.00.31101")&&(sCompilerVersion=="18.00.31101"))
            {
                ssTool.sVersion="2013 Update 4";
            }
            else if((sLinkerVersion=="12.00.40629")&&(sCompilerVersion=="18.00.40629"))
            {
                ssTool.sVersion="2013 SP5";
            }
            else if((sLinkerVersion=="14.00.22215")&&(sCompilerVersion=="19.00.22215"))
            {
                ssTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23007")&&(sCompilerVersion=="19.00.23007"))
            {
                ssTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23013")&&(sCompilerVersion=="19.00.23013"))
            {
                ssTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23026")&&(sCompilerVersion=="19.00.23026"))
            {
                ssTool.sVersion="2015 RTM";
            }
            else if((sLinkerVersion=="14.00.23506")&&(sCompilerVersion=="19.00.23506"))
            {
                ssTool.sVersion="2015 Update 1";
            }
            else if((sLinkerVersion=="14.00.23918")&&(sCompilerVersion=="19.00.23918"))
            {
                ssTool.sVersion="2015 Update 2";
            }
            else if((sLinkerVersion=="14.00.24103")&&(sCompilerVersion=="19.00.24103"))
            {
                ssTool.sVersion="2015 SP1"; // ???
            }
            else if((sLinkerVersion=="14.00.24118")&&(sCompilerVersion=="19.00.24118"))
            {
                ssTool.sVersion="2015 SP1"; // ???
            }
            else if((sLinkerVersion=="14.00.24123")&&(sCompilerVersion=="19.00.24123"))
            {
                ssTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24210")&&(sCompilerVersion=="19.00.24210"))
            {
                ssTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24212")&&(sCompilerVersion=="19.00.24212"))
            {
                ssTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24213")&&(sCompilerVersion=="19.00.24213"))
            {
                ssTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24215")&&(sCompilerVersion=="19.00.24215"))
            {
                ssTool.sVersion="2015 Update 3.1";
            }
            else if((sLinkerVersion=="14.00.24218")&&(sCompilerVersion=="19.00.24218"))
            {
                ssTool.sVersion="2015 Update 3.1";
            }
            else if((sLinkerVersion=="14.00.24723")&&(sCompilerVersion=="19.00.24723"))
            {
                ssTool.sVersion="2015"; // Update 4? 2017?
            }
            else if((sLinkerVersion=="14.10.25017")&&(sCompilerVersion=="19.10.25017"))
            {
                ssTool.sVersion="2017 RTM";
            }
            else if((sLinkerVersion=="14.10.25019")&&(sCompilerVersion=="19.10.25019"))
            {
                ssTool.sVersion="2017"; // 15.2?
            }
            else if((sLinkerVersion=="14.10.25506")&&(sCompilerVersion=="19.10.25506"))
            {
                ssTool.sVersion="2017 version 15.3";
            }
            else if((sLinkerVersion=="14.11.25547")&&(sCompilerVersion=="19.11.25547"))
            {
                ssTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.11.25830")&&(sCompilerVersion=="19.11.25830"))
            {
                ssTool.sVersion="2017 version 15.5";
            }
            else if((sLinkerVersion=="14.12.25834")&&(sCompilerVersion=="19.12.25834")) // TODO Check v15.5.4
            {
                ssTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.13.26128")&&(sCompilerVersion=="19.13.26128"))
            {
                ssTool.sVersion="2017 version 15.6";
            }
            else if((sLinkerVersion=="14.14.26428")&&(sCompilerVersion=="19.14.26428"))
            {
                ssTool.sVersion="2017 version 15.7";
            }
            else if((sLinkerVersion=="14.15.26726")&&(sCompilerVersion=="19.15.26726"))
            {
                ssTool.sVersion="2017 version 15.8";
            }
            else if((sLinkerVersion=="14.16.26926")&&(sCompilerVersion=="19.16.26926"))
            {
                ssTool.sVersion="2017 version 15.9";
            }
            else if((sLinkerVersion=="14.16.27027")&&(sCompilerVersion=="19.16.27027")) // TODO Check
            {
                ssTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.20.27004")&&(sCompilerVersion=="19.20.27004"))
            {
                ssTool.sVersion="2019 RTM";
            }
            else if((sLinkerVersion=="14.20.27508")&&(sCompilerVersion=="19.20.27508"))
            {
                ssTool.sVersion="2019";
            }
            else if(sCompilerMajorVersion=="12.00")
            {
                ssTool.sVersion="6.0";
            }
            else if(sCompilerMajorVersion=="13.00")
            {
                ssTool.sVersion="2002";
            }
            else if(sCompilerMajorVersion=="13.10")
            {
                ssTool.sVersion="2003";
            }
            else if(sCompilerMajorVersion=="14.00")
            {
                ssTool.sVersion="2005";
            }
            else if(sCompilerMajorVersion=="15.00")
            {
                ssTool.sVersion="2008";
            }
            else if(sCompilerMajorVersion=="16.00")
            {
                ssTool.sVersion="2010";
            }
            else if(sCompilerMajorVersion=="17.00")
            {
                ssTool.sVersion="2012";
            }
            else if(sCompilerMajorVersion=="18.00")
            {
                ssTool.sVersion="2013";
            }
            else if(sCompilerMajorVersion=="19.00")
            {
                ssTool.sVersion="2015";
            }
            else if(sCompilerMajorVersion=="19.10") // TODO ???
            {
                ssTool.sVersion="2017 RTM";
            }
            else if(sCompilerMajorVersion=="19.11")
            {
                ssTool.sVersion="2017 version 15.3";
            }
            else if(sCompilerMajorVersion=="19.12")
            {
                ssTool.sVersion="2017 version 15.5";
            }
            else if(sCompilerMajorVersion=="19.13")
            {
                ssTool.sVersion="2017 version 15.6";
            }
            else if(sCompilerMajorVersion=="19.14")
            {
                ssTool.sVersion="2017 version 15.7";
            }
            else if(sCompilerMajorVersion=="19.15")
            {
                ssTool.sVersion="2017 version 15.8";
            }
            else if(sCompilerMajorVersion=="19.16")
            {
                ssTool.sVersion="2017 version 15.9";
            }
            else if(sCompilerMajorVersion=="19.20")
            {
                ssTool.sVersion="2019";
            }

            if(ssTool.sVersion=="")
            {
                // TODO
            }
        }
        else if(ssCompiler.name==SpecAbstract::RECORD_NAME_MASM)
        {
            QString sCompilerVersion=ssCompiler.sVersion;
            QString sLinkerVersion=ssLinker.sVersion;

            if((sLinkerVersion=="5.12.8078")&&(sCompilerVersion=="6.14.8444"))
            {
                ssTool.type=SpecAbstract::RECORD_TYPE_TOOL;
                ssTool.name=SpecAbstract::RECORD_NAME_MASM32;
                ssTool.sVersion="8-11";
            }
        }

        if(pe.isImportLibraryPresentI("MSVCRT.dll",&(pPEInfo->listImports)))
        {
            // TODO
        }

        if(ssLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));
        }

        if(ssCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
        }

        if(ssTool.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultTools.insert(ssTool.name,scansToScan(&(pPEInfo->basic_info),&ssTool));
        }

        if(ssMFC.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLibraries.insert(ssMFC.name,scansToScan(&(pPEInfo->basic_info),&ssMFC));
        }

        if(ssNET.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLibraries.insert(ssNET.name,scansToScan(&(pPEInfo->basic_info),&ssNET));
        }
    }
}

void SpecAbstract::PE_handle_Borland(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    // TODO Turbo Linker
    // https://delphi.fandom.com/wiki/Determine_Delphi_Application
    // TODO if Delphi Linker -> 2.25
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        _SCANS_STRUCT recordLinker={};
        _SCANS_STRUCT recordCompiler={};
        _SCANS_STRUCT recordTool={};
        _SCANS_STRUCT recordVCL={};

        if(pPEInfo->basic_info.mapHeaderDetects.contains(SpecAbstract::RECORD_NAME_TURBOLINKER))
        {
            _SCANS_STRUCT recordTurboLinker=pPEInfo->basic_info.mapHeaderDetects.value(SpecAbstract::RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi=get_TurboLinker_vi(pDevice,bIsImage);

            if(vi.bIsValid)
            {
                recordTurboLinker.sVersion=vi.sVersion;
            }
            else
            {
                recordTurboLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
            }

            recordLinker=recordTurboLinker;
        }

        if(!pPEInfo->cliInfo.bValid)
        {
            qint64 nOffset_string=-1;
            qint64 nOffset_Boolean=-1;
            qint64 nOffset_String=-1;
            qint64 nOffset_TObject=-1;
            //        qint64 nOffset_AnsiString=-1;
            //        qint64 nOffset_WideString=-1;

            qint64 nOffset_BorlandCPP=-1;
            qint64 nOffset_CodegearCPP=-1;
            qint64 nOffset_EmbarcaderoCPP_old=-1;
            qint64 nOffset_EmbarcaderoCPP_new=-1;

            QList<VCL_STRUCT> listVCL;

            bool bCppExport=    (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames),"__CPPdebugHook"))||
                                (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames),"___CPPdebugHook"));

            if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                qint64 _nSize=pPEInfo->osCodeSection.nSize;

                nOffset_TObject=pe.find_array(_nOffset,_nSize,"\x07\x54\x4f\x62\x6a\x65\x63\x74",8); // TObject

                if(nOffset_TObject!=-1)
                {
                    nOffset_Boolean=pe.find_array(_nOffset,_nSize,"\x07\x42\x6f\x6f\x6c\x65\x61\x6e",8); // Boolean
                    nOffset_string=pe.find_array(_nOffset,_nSize,"\x06\x73\x74\x72\x69\x6e\x67",7); // string

                    if((nOffset_Boolean!=-1)||(nOffset_string!=-1))
                    {
                        if(nOffset_string==-1)
                        {
                            nOffset_String=pe.find_array(_nOffset,_nSize,"\x06\x53\x74\x72\x69\x6e\x67",7); // String
                        }

                        listVCL=PE_getVCLstruct(pDevice,bIsImage,_nOffset,_nSize,pPEInfo->bIs64);
                    }
                }
                //            nOffset_AnsiString=pe.find_array(_nOffset,_nSize,"\x0a\x41\x6e\x73\x69\x53\x74\x72\x69\x6e\x67",11); // AnsiString
                //            nOffset_WideString=pe.find_array(_nOffset,_nSize,"\x0a\x57\x69\x64\x65\x53\x74\x72\x69\x6e\x67",11); // WideString
            }

            if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osDataSection.nOffset;
                qint64 _nSize=pPEInfo->osDataSection.nSize;

                nOffset_BorlandCPP=pe.find_ansiString(_nOffset,_nSize,"Borland C++ - Copyright "); // Borland C++ - Copyright 1994 Borland Intl.

                if(nOffset_BorlandCPP==-1)
                {
                    nOffset_CodegearCPP=pe.find_ansiString(_nOffset,_nSize,"CodeGear C++ - Copyright "); // CodeGear C++ - Copyright 2008 Embarcadero Technologies

                    if(nOffset_CodegearCPP==-1)
                    {
                        nOffset_EmbarcaderoCPP_old=pe.find_ansiString(_nOffset,_nSize,"Embarcadero RAD Studio - Copyright "); // Embarcadero RAD Studio - Copyright 2009 Embarcadero Technologies, Inc.

                        if(nOffset_EmbarcaderoCPP_old==-1)
                        {
                            nOffset_EmbarcaderoCPP_new=pe.find_ansiString(_nOffset,_nSize,"Embarcadero RAD Studio 27.0 - Copyright 2020 Embarcadero Technologies, Inc.");
                        }
                    }
                }
            }

            bool bPackageinfo=XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"PACKAGEINFO",&(pPEInfo->listResources));
            bool bDvcal=XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"DVCLAL",&(pPEInfo->listResources));

            if(bPackageinfo||
                    bDvcal||
                    pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP)||
                    (nOffset_TObject!=-1)||
                    (nOffset_BorlandCPP!=-1)||
                    (nOffset_CodegearCPP!=-1)||
                    (nOffset_EmbarcaderoCPP_old!=-1)||
                    (nOffset_EmbarcaderoCPP_new!=-1)||
                    bCppExport)
            {
                bool bCpp=false;
                bool bVCL=bPackageinfo;
                QString sVCLVersion;
                QString sDelphiVersion;
                QString sBuilderVersion;
                QString sObjectPascalCompilerVersion;
                QString sCppCompilerVersion;
                bool bNewVersion=false;

                enum COMPANY
                {
                    COMPANY_BORLAND=0,
                    COMPANY_CODEGEAR,
                    COMPANY_EMBARCADERO
                };

                COMPANY company=COMPANY_BORLAND;

                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP)||
                        (nOffset_BorlandCPP!=-1)||
                        (nOffset_CodegearCPP!=-1)||
                        (nOffset_EmbarcaderoCPP_old!=-1)||
                        (nOffset_EmbarcaderoCPP_new!=-1)||
                        bCppExport)
                {
                    bCpp=true;

                    if(nOffset_BorlandCPP!=-1)
                    {
                        company=COMPANY_BORLAND;
                    }
                    else if(nOffset_CodegearCPP!=-1)
                    {
                        company=COMPANY_CODEGEAR;
                    }
                    else if(nOffset_EmbarcaderoCPP_old!=-1)
                    {
                        company=COMPANY_EMBARCADERO;
                    }
                    else if(nOffset_EmbarcaderoCPP_new!=-1)
                    {
                        company=COMPANY_EMBARCADERO;
                    }
                    else if(bCppExport)
                    {
                        company=COMPANY_EMBARCADERO;
                    }
                }

                if(nOffset_TObject!=-1)
                {
                    if(nOffset_string!=-1)
                    {
                        if(bDvcal||bPackageinfo)
                        {
                            // TODO Borland Version
                            sDelphiVersion="2005+";
                            bNewVersion=true;
                        }
                        else
                        {
                            sDelphiVersion="2";
                            sObjectPascalCompilerVersion="9.0";
                        }
                    }
                    else if(nOffset_String!=-1)
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="3-7";
                    }
                }

                if(bPackageinfo)
                {
                    VCL_PACKAGEINFO pi=PE_getVCLPackageInfo(pDevice,bIsImage,&pPEInfo->listResources);

                    if(pi.listModules.count())
                    {
                        quint32 nProducer=(pi.nFlags>>26)&0x3;

                        if(nProducer==2) // C++
                        {
                            bCpp=true;
                        }
                        else if(nProducer==3) // Pascal
                        {
                            bCpp=false;
                        }

                        //                    for(int i=0;i<pi.listModules.count();i++)
                        //                    {
                        //                        qDebug(pi.listModules.at(i).sName.toLatin1().data());
                        //                    }
                    }
                }

                if(nOffset_BorlandCPP!=-1)
                {
                    sCppCompilerVersion=pe.read_ansiString(nOffset_BorlandCPP+24,4);
                }

                if(nOffset_CodegearCPP!=-1)
                {
                    sCppCompilerVersion=pe.read_ansiString(nOffset_CodegearCPP+25,4);
                }

                if(nOffset_EmbarcaderoCPP_old!=-1)
                {
                    sCppCompilerVersion=pe.read_ansiString(nOffset_EmbarcaderoCPP_old+35,4);
                }

                if(nOffset_EmbarcaderoCPP_new!=-1)
                {
                    sCppCompilerVersion=pe.read_ansiString(nOffset_EmbarcaderoCPP_new+40,4);
                }

                if(sCppCompilerVersion=="2009")
                {
                    sBuilderVersion="2009";
                }
                else if(sCppCompilerVersion=="2015")
                {
                    sBuilderVersion="2015";
                }
                else if(sCppCompilerVersion=="2020")
                {
                    sBuilderVersion="10.4";
                }

                if(listVCL.count())
                {
                    bVCL=true;
                    int nVCLOffset=listVCL.at(0).nOffset;
                    int nVCLValue=listVCL.at(0).nValue;

                    //                    qDebug("nVCLOffset: %d",nVCLOffset);
                    //                    qDebug("nVCLValue: %d",nVCLValue);
                    //                bVCL=true;

                    if((nVCLOffset==24)&&(nVCLValue==168))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="2";
                        sObjectPascalCompilerVersion="9.0";
                        //                    sVCLVersion="20";
                    }
                    else if((nVCLOffset==28)&&(nVCLValue==180))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="3";
                        sObjectPascalCompilerVersion="10.0";
                        //                    sVCLVersion="30";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==276))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="4";
                        sObjectPascalCompilerVersion="12.0";
                        //                    sVCLVersion="40";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==288))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="5";
                        sObjectPascalCompilerVersion="13.0";
                        //                    sVCLVersion="50";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==296))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="6 CLX";
                        sObjectPascalCompilerVersion="14.0";
                        //                    sVCLVersion="60";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==300))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="7 CLX";
                        sObjectPascalCompilerVersion="15.0";
                        //                    sVCLVersion="70";
                    }
                    //                else if(nVCLOffset==40)
                    //                {
                    //                    if(nVCLValue==264)
                    //                    {
                    //                        recordTool.sVersion="???TODO";
                    //                        sVCLVersion="50";
                    //                    }
                    //                }
                    else if((nVCLOffset==40)&&(nVCLValue==348))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="6-7";
                        sObjectPascalCompilerVersion="14.0-15.0";
                        //                    sVCLVersion="140-150";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==356))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="2005";
                        sObjectPascalCompilerVersion="17.0";
                        //                    sVCLVersion="170";
                    }
                    else if((nVCLOffset==40)&&(nVCLValue==400))
                    {
                        company=COMPANY_BORLAND;
                        sDelphiVersion="2006";
                        sObjectPascalCompilerVersion="18.0";
                        //                    sVCLVersion="180";
                    }
                    else if((nVCLOffset==52)&&(nVCLValue==420))
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="2009";
                        sObjectPascalCompilerVersion="20.0";
                        //                    sVCLVersion="200";
                    }
                    else if((nVCLOffset==52)&&(nVCLValue==428))
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="2010-XE";
                        sObjectPascalCompilerVersion="21.0-22.0";
                        //                    sVCLVersion="210-220";
                    }
                    else if((nVCLOffset==52)&&(nVCLValue==436))
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="XE2-XE4";
                        sObjectPascalCompilerVersion="23.0-25.0";
                        //                    sVCLVersion="230-250";

                        bNewVersion=true;
                    }
                    else if((nVCLOffset==52)&&(nVCLValue==444))
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="XE2-XE8";
                        sObjectPascalCompilerVersion="23.0-29.0";
                        //                    sVCLVersion="230-290";

                        bNewVersion=true;
                    }
                    else if((nVCLOffset==104)&&(nVCLValue==760)) // 64
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="XE2";
                        sObjectPascalCompilerVersion="23.0";

                        bNewVersion=true;
                    }
                    else if((nVCLOffset==128)&&(nVCLValue==776)) // 64
                    {
                        company=COMPANY_EMBARCADERO;
                        sDelphiVersion="XE8-10 Seattle";
                        sObjectPascalCompilerVersion="30.0";

                        bNewVersion=true;
                    }
                    // TODO more x64
                }

                // TODO Console !!!

                if(bNewVersion)
                {
                    if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        qint64 _nOffset=pPEInfo->osConstDataSection.nOffset;
                        qint64 _nSize=pPEInfo->osConstDataSection.nSize;

                        qint64 nOffset_Version=0;

                        if(pPEInfo->bIs64)
                        {
                            nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"Embarcadero Delphi for Win64 compiler version ");
                        }
                        else
                        {
                            nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"Embarcadero Delphi for Win32 compiler version ");
                        }

                        if(nOffset_Version!=-1)
                        {
                            company=COMPANY_EMBARCADERO;

                            sObjectPascalCompilerVersion=pe.read_ansiString(nOffset_Version+46);

                            sDelphiVersion=_get_DelphiVersionFromCompiler(sObjectPascalCompilerVersion).sVersion;
                        }
                    }
                }

                recordCompiler.type=RECORD_TYPE_COMPILER;
                recordTool.type=RECORD_TYPE_TOOL;

                if(!bCpp)
                {
                    if(company==COMPANY_BORLAND)
                    {
                        recordCompiler.name=RECORD_NAME_BORLANDOBJECTPASCALDELPHI;
                        recordTool.name=RECORD_NAME_BORLANDDELPHI;
                    }
                    else if(company==COMPANY_CODEGEAR)
                    {
                        recordCompiler.name=RECORD_NAME_CODEGEAROBJECTPASCALDELPHI;
                        recordTool.name=RECORD_NAME_CODEGEARDELPHI;
                    }
                    else if(company==COMPANY_EMBARCADERO)
                    {
                        recordCompiler.name=RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI;
                        recordTool.name=RECORD_NAME_EMBARCADERODELPHI;
                    }

                    recordCompiler.sVersion=sObjectPascalCompilerVersion;
                    recordTool.sVersion=sDelphiVersion;
                }
                else
                {
                    if(company==COMPANY_BORLAND)
                    {
                        recordCompiler.name=RECORD_NAME_BORLANDCPP;
                        recordTool.name=RECORD_NAME_BORLANDCPPBUILDER;
                    }
                    else if(company==COMPANY_CODEGEAR)
                    {
                        recordCompiler.name=RECORD_NAME_CODEGEARCPP;
                        recordTool.name=RECORD_NAME_CODEGEARCPPBUILDER;
                    }
                    else if(company==COMPANY_EMBARCADERO)
                    {
                        recordCompiler.name=RECORD_NAME_EMBARCADEROCPP;
                        recordTool.name=RECORD_NAME_EMBARCADEROCPPBUILDER;
                    }

                    recordCompiler.sVersion=sCppCompilerVersion;
                    recordTool.sVersion=sBuilderVersion;
                }

                if(bVCL)
                {
                    recordVCL.type=RECORD_TYPE_LIBRARY;
                    recordVCL.name=RECORD_NAME_VCL;
                    recordVCL.sVersion=sVCLVersion;
                }

                if(recordLinker.type==RECORD_TYPE_UNKNOWN)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LINKER,RECORD_NAME_TURBOLINKER,"","",0);
                    recordLinker=ss;
                }
            }
        }
        else
        {
            // .NET TODO: Check!!!!
            if(pPEInfo->mapDotAnsiStringsDetects.contains(RECORD_NAME_EMBARCADERODELPHIDOTNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsiStringsDetects.value(RECORD_NAME_EMBARCADERODELPHIDOTNET);
                recordTool=ss;
            }
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pPEInfo->basic_info),&recordLinker));
        }

        if(recordCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pPEInfo->basic_info),&recordCompiler));
        }

        if(recordVCL.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLibraries.insert(recordVCL.name,scansToScan(&(pPEInfo->basic_info),&recordVCL));
        }

        if(recordTool.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultTools.insert(recordTool.name,scansToScan(&(pPEInfo->basic_info),&recordTool));
        }
    }
}

void SpecAbstract::PE_handle_Watcom(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    // TODO Turbo Linker
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        _SCANS_STRUCT ssLinker={};
        _SCANS_STRUCT ssCompiler={};

        // Watcom linker
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WATCOMLINKER))
        {
            ssLinker=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WATCOMLINKER);
            ssLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
        }

        // Watcom CPP
        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WATCOMCCPP))
        {
            // TODO Version???
            ssCompiler=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_WATCOMCCPP);
        }

        if((ssLinker.type!=RECORD_TYPE_UNKNOWN)&&(ssCompiler.type==RECORD_TYPE_UNKNOWN))
        {
            ssCompiler=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_WATCOMCCPP,"","",0);
        }

        if((ssLinker.type==RECORD_TYPE_UNKNOWN)&&(ssCompiler.type!=RECORD_TYPE_UNKNOWN))
        {
            ssLinker=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LINKER,RECORD_NAME_WATCOMLINKER,"","",0);
        }

        if(ssLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));
        }

        if(ssCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
        }
    }
}

void SpecAbstract::PE_handle_Tools(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if((pPEInfo->bIsTLSPresent)&&(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RUST)))
        {
            if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                VI_STRUCT viStruct=get_Rust_vi(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

                if(viStruct.bIsValid)
                {
                    _SCANS_STRUCT ssCompiler=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RUST);

                    ssCompiler.sVersion=viStruct.sVersion;
                    ssCompiler.sInfo=viStruct.sInfo;

                    pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
                }
            }
        }

        if(pe.isResourcePresent(XPE_DEF::S_RT_RCDATA,"SCRIPT",&(pPEInfo->listResources)))
        {
            _SCANS_STRUCT ssLibrary=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_AUTOIT,"3.XX","",0);
            // TODO Version
            pPEInfo->mapResultLibraries.insert(ssLibrary.name,scansToScan(&(pPEInfo->basic_info),&ssLibrary));
        }
        else if(pe.getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion))=="Compiled AutoIt Script")
        {
            _SCANS_STRUCT ssLibrary=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_AUTOIT,"2.XX","",0);

            ssLibrary.sVersion=pe.getFileVersionMS(&(pPEInfo->resVersion));
            pPEInfo->mapResultLibraries.insert(ssLibrary.name,scansToScan(&(pPEInfo->basic_info),&ssLibrary));
        }

        if(XPE::isImportLibraryPresentI("msvcrt.dll",&(pPEInfo->listImports))&&(pPEInfo->nMajorLinkerVersion==6)&&(pPEInfo->nMinorLinkerVersion==0))
        {
            bool bDetected=false;

            if(pPEInfo->bIs64)
            {
                if(pPEInfo->listSectionNames.count()==3)
                {
                    if((pPEInfo->listSectionNames.at(0)==".text")&&(pPEInfo->listSectionNames.at(1)==".data")&&(pPEInfo->listSectionNames.at(2)==".pdata"))
                    {
                        bDetected=true;
                    }
                }
            }
            else
            {
                if(pPEInfo->listSectionNames.count()==2)
                {
                    if((pPEInfo->listSectionNames.at(0)==".text")&&(pPEInfo->listSectionNames.at(1)==".data"))
                    {
                        bDetected=true;
                    }
                }
            }

            if(bDetected)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_TINYC,"","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_CHROMIUMCRASHPAD))
        {
            XPE::SECTION_RECORD sr=XPE::getSectionRecordByName("CPADinfo",&(pPEInfo->listSectionRecords));

            if(sr.nSize)
            {
                quint32 nSignature=pe.read_uint32(sr.nOffset);

                if(nSignature==0x43506164)
                {
                    quint32 nVersion=pe.read_uint32(sr.nOffset+8);

                    _SCANS_STRUCT ssLibrary=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_CHROMIUMCRASHPAD,"","",0);
                    ssLibrary.sVersion=QString("%1.0").arg(nVersion);
                    pPEInfo->mapResultLibraries.insert(ssLibrary.name,scansToScan(&(pPEInfo->basic_info),&ssLibrary));
                }
            }
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EXCELSIORJET))
        {
            // TODO Version
            _SCANS_STRUCT ssLibrary=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_JAVA,"","Native",0);
            pPEInfo->mapResultLibraries.insert(ssLibrary.name,scansToScan(&(pPEInfo->basic_info),&ssLibrary));

            // TODO Version
            _SCANS_STRUCT ssCompiler=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_EXCELSIORJET,"","",0); // mb Tool
            pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_GO)||pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_GO))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_GO,"1.X","",0);

            if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                VI_STRUCT viStruct=get_Go_vi(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

                if(viStruct.bIsValid)
                {
                    ss.sVersion=viStruct.sVersion;
                    ss.sInfo=viStruct.sInfo;
                }
            }

            pPEInfo->mapResultTools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Visual Objects
        if(pe.compareSignature(&(pPEInfo->basic_info.memoryMap),"'This Visual Objects application cannot be run in DOS mode'",0x312))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_VISUALOBJECTS,"2.XX","",0);
            ss.sVersion=QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion),QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // FASM
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASM))
        {
            // TODO correct Version
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FASM,"","",0);
            ss.sVersion=QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion),QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Zig
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)&&(pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GENERICLINKER).nVariant==1))
        { 
            if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                VI_STRUCT viStruct=get_Zig_vi(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

                if(viStruct.bIsValid)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_ZIG,"","",0);

                    ss.sVersion=viStruct.sVersion;
                    ss.sInfo=viStruct.sInfo;

                    pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }

        if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
        {
            VI_STRUCT viNim=get_Nim_vi(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

            if(viNim.bIsValid)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_NIM,"","",0);
                pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // Valve
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VALVE))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_STUB,RECORD_NAME_VALVE,"","",0);
            pPEInfo->mapResultTools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // UniLink
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UNILINK))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LINKER,RECORD_NAME_UNILINK,"","",0);
            pPEInfo->mapResultLinkers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // DMD32 D
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DMD32D))
        {
            // TODO correct Version
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_DMD32D,"","",0);
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // GoLink, GoAsm
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GOLINK))
        {
            _SCANS_STRUCT ssLinker=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LINKER,RECORD_NAME_GOLINK,"","",0);
            ssLinker.sVersion=QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion),QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));

            _SCANS_STRUCT ssCompiler=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_GOASM,"","",0);
            pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
        }

        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LAYHEYFORTRAN90))
        {
            QString sLFString=pe.read_ansiString(0x200);

            if(sLFString=="This program must be run under Windows 95, NT, or Win32s\r\nPress any key to exit.$")
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_LAYHEYFORTRAN90,"","",0);
                pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // Flex
        if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
        {
            qint64 _nOffset=pPEInfo->osDataSection.nOffset;
            qint64 _nSize=pPEInfo->osDataSection.nSize;
            // TODO FPC Version in Major and Minor linker

            qint64 nOffset_FlexLM=pe.find_ansiString(_nOffset,_nSize,"@(#) FLEXlm ");

            if(nOffset_FlexLM!=-1)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_FLEXLM,"","",0);

                ss.sVersion=pe.read_ansiString(nOffset_FlexLM+12,50);
                ss.sVersion=ss.sVersion.section(" ",0,0);

                if(ss.sVersion.left(1)=="v")
                {
                    ss.sVersion.remove(0,1);
                }

                // TODO Version
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            qint64 nOffset_FlexNet=-1;

            if(nOffset_FlexLM==-1)
            {
                nOffset_FlexNet=pe.find_ansiString(_nOffset,_nSize,"@(#) FLEXnet Licensing v");
            }

            if(nOffset_FlexNet==-1)
            {
                nOffset_FlexNet=pe.find_ansiString(_nOffset,_nSize,"@(#) FlexNet Licensing v");
            }

            if(nOffset_FlexNet!=-1)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_FLEXNET,"","",0);

                ss.sVersion=pe.read_ansiString(nOffset_FlexNet+24,50);

                if(ss.sVersion.contains("build"))
                {
                    ss.sVersion=ss.sVersion.section(" ",0,2);
                }
                else
                {
                    ss.sVersion=ss.sVersion.section(" ",0,0);
                }

                // TODO Version
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        if(!pPEInfo->cliInfo.bValid)
        {
            // Qt
            // TODO Find Strings QObject
            if(XPE::isImportLibraryPresentI("QtCore4.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"4.X","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("QtCored4.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"4.X","Debug",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt5Core.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"5.X","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt5Cored.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"5.X","Debug",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt6Core.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"6.X","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt6Cored.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"6.X","Debug",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_QT))
            {
                // TODO Version!
                _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_QT);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osDataSection.nOffset;
                qint64 _nSize=pPEInfo->osDataSection.nSize;
                // TODO FPC Version in Major and Minor linker

                qint64 nOffset_FPC=pe.find_ansiString(_nOffset,_nSize,"FPC ");

                if(nOffset_FPC!=-1)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);
                    QString sFPCVersion=pe.read_ansiString(nOffset_FPC);
                    ss.sVersion=sFPCVersion.section(" ",1,-1).section(" - ",0,0);

                    pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));

                    // Lazarus
                    qint64 nOffset_Lazarus=pe.find_ansiString(_nOffset,_nSize,"Lazarus LCL: ");

                    if(nOffset_Lazarus==-1)
                    {
                        if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                        {
                            _nOffset=pPEInfo->osConstDataSection.nOffset;
                            _nSize=pPEInfo->osConstDataSection.nSize;

                            nOffset_Lazarus=pe.find_ansiString(_nOffset,_nSize,"Lazarus LCL: ");
                        }
                    }

                    QString sLazarusVersion;

                    if(nOffset_Lazarus!=-1)
                    {
                        sLazarusVersion=pe.read_ansiString(nOffset_Lazarus+13);
                        sLazarusVersion=sLazarusVersion.section(" ",0,0);
                    }

                    if(nOffset_Lazarus!=-1)
                    {
                        _SCANS_STRUCT ssLazarus=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_TOOL,RECORD_NAME_LAZARUS,"","",0);

                        ssLazarus.sVersion=sLazarusVersion;

                        pPEInfo->mapResultTools.insert(ssLazarus.name,scansToScan(&(pPEInfo->basic_info),&ssLazarus));
                    }
                }
                else
                {
                    //                    qint64 nOffset_TObject=pe.find_array(_nOffset,_nSize,"\x07\x54\x4f\x62\x6a\x65\x63\x74",8); // TObject

                    //                    if(nOffset_TObject!=-1)
                    //                    {

                    //                        SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                    //                        // TODO Version
                    //                        pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    //                    }
                    qint64 nOffset_RunTimeError=pe.find_array(_nOffset,_nSize,"\x0e\x52\x75\x6e\x74\x69\x6d\x65\x20\x65\x72\x72\x6f\x72\x20",15); // Runtime Error TODO: use findAnsiString

                    if(nOffset_RunTimeError!=-1)
                    {

                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                        // TODO Version
                        pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // Python
            // TODO Create function
            int nNumberOfImports=pPEInfo->listImports.count();

            for(int i=0;i<nNumberOfImports;i++)
            {
                if(XBinary::isRegExpPresent("^PYTHON",pPEInfo->listImports.at(i).sName.toUpper()))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_PYTHON,"","",0);

                            ss.sVersion=QString::number(dVersion/10,'f',1);
                            pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }

                    break;
                }
                else if(XBinary::isRegExpPresent("^LIBPYTHON",pPEInfo->listImports.at(i).sName.toUpper()))
                {
                    QString sVersion=XBinary::regExp("(\\d.\\d)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_PYTHON,"","",0);

                            ss.sVersion=QString::number(dVersion);
                            pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }

                    break;
                }
            }

            // Perl
            // TODO Create function
            for(int i=0;i<nNumberOfImports;i++)
            {
                if(XBinary::isRegExpPresent("^PERL",pPEInfo->listImports.at(i).sName.toUpper()))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_PERL,"","",0);

                            ss.sVersion=QString::number(dVersion/100,'f',2);
                            pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }

                    break;
                }
            }

            // Virtual Pascal
            if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osDataSection.nOffset;
                qint64 _nSize=pPEInfo->osDataSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_VP=pe.find_ansiString(_nOffset,_nSize,"Virtual Pascal - Copyright (C) "); // "Virtual Pascal - Copyright (C) 1996-2000 vpascal.com"

                if(nOffset_VP!=-1)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_VIRTUALPASCAL,"","",0);

                    // TODO Version???
                    ss.sVersion=QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion),QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // PowerBASIC
            if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                qint64 _nSize=pPEInfo->osCodeSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_PB=pe.find_ansiString(_nOffset,_nSize,"PowerBASIC");

                if(nOffset_PB!=-1)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_POWERBASIC,"","",0);

                    // TODO Version???
                    pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // PureBasic
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PUREBASIC))
            {
                _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PUREBASIC);

                // TODO Version???
                pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // lcc-win
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_LCCWIN))
            {
                _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_LCCWIN);

                // TODO Version???
                pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));

                if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
                {
                    _SCANS_STRUCT ssLinker={};
                    ssLinker.name=RECORD_NAME_LCCLNK;
                    ssLinker.type=RECORD_TYPE_LINKER;
                    ssLinker.sVersion=QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion),QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PETools(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_VMUNPACKER))
        {
            _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_VMUNPACKER);

            pPEInfo->mapResultPETools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_XVOLKOLAK))
        {
            _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_XVOLKOLAK);

            pPEInfo->mapResultPETools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_HOODLUM))
        {
            _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_HOODLUM);

            pPEInfo->mapResultPETools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::PE_handle_wxWidgets(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            bool bDynamic=false;
            bool bStatic=false;
            QString sVersion;
            QString sInfo;

            int nNumberOfImports=pPEInfo->listImports.count();

            for(int i=0;i<nNumberOfImports;i++)
            {
                if(XBinary::isRegExpPresent("^WX",pPEInfo->listImports.at(i).sName.toUpper()))
                {
                    QString sDllVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sDllVersion!="")
                    {
                        double dVersion=sDllVersion.toDouble();

                        if(dVersion)
                        {
                            // TODO a function
                            if(dVersion<100)
                            {
                                sVersion=QString::number(dVersion/10,'f',1);
                            }
                            else if(dVersion<1000)
                            {
                                sVersion=QString::number(dVersion/100,'f',2);
                            }

                            bDynamic=true;
                        }
                    }

                    break;
                }
            }

            if(!bDynamic)
            {
                if(XPE::isResourcePresent(XPE_DEF::S_RT_MENU,"WXWINDOWMENU",&(pPEInfo->listResources)))
                {
                    bStatic=true;
                }
            }

            if(bDynamic||bStatic)
            {
                if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osConstDataSection.nOffset;
                    qint64 _nSize=pPEInfo->osConstDataSection.nSize;
                    // TODO VP Version in Major and Minor linker

                    qint64 nOffset_Version=-1;

                    if(nOffset_Version==-1)
                    {
                        nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"3.1.1 (wchar_t,Visual C++ 1900,wx containers)");

                        if(nOffset_Version!=-1)
                        {
                            sVersion="3.1.1";
                            sInfo="Visual C++ 1900";
                        }
                    }

                    if(nOffset_Version==-1)
                    {
                        nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"3.1.2 (wchar_t,Visual C++ 1900,wx containers,compatible with 3.0)");

                        if(nOffset_Version!=-1)
                        {
                            sVersion="3.1.2";
                            sInfo="Visual C++ 1900";
                        }
                    }
                }
            }

            if(bDynamic||bStatic)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_WXWIDGETS,"","",0);

                if(bDynamic)
                {
                    ss.sInfo="";
                }
                else if(bStatic)
                {
                    ss.sInfo="Static";
                }

                ss.sVersion=sVersion;
                ss.sInfo=append(ss.sInfo,sInfo);

                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_GCC(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    _SCANS_STRUCT ssLinker={};
    _SCANS_STRUCT ssCompiler={};
    _SCANS_STRUCT ssTool={};

    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            bool bDetectGCC=false;
            bool bHeurGCC=false;

            if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
            {
                switch(pPEInfo->nMajorLinkerVersion)
                {
                    case 2:
                        switch(pPEInfo->nMinorLinkerVersion) // TODO Check MinGW versions
                        {
                            case 22:
                            case 23:
                            case 24:
                            case 25:
                            case 26:
                            case 27:
                            case 28:
                            case 29:
                            case 30:
                            case 31:
                            case 32:
                            case 33:
                            case 34:
                            case 35:
                            case 36:
                            case 56:
                                bHeurGCC=true;
                                break;
                        }

                        break;
                }
            }

            QString sDllLib;

            if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                sDllLib=pe.read_ansiString(pPEInfo->osConstDataSection.nOffset);
            }

            if( XPE::isImportLibraryPresentI("msys-1.0.dll",&(pPEInfo->listImports))||
                sDllLib.contains("msys-"))
            {
                // Msys 1.0
                ssTool.type=RECORD_TYPE_TOOL;
                ssTool.name=RECORD_NAME_MSYS;
                ssTool.sVersion="1.0";
            }

            if( (sDllLib.contains("gcc"))||
                (sDllLib.contains("libgcj"))||
                (sDllLib.contains("cyggcj"))||
                (sDllLib=="_set_invalid_parameter_handler")||
                XPE::isImportLibraryPresentI("libgcc_s_dw2-1.dll",&(pPEInfo->listImports))||
                pPEInfo->mapOverlayDetects.contains(RECORD_NAME_MINGW)||
                pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_GCC))
            {
                bDetectGCC=true;
            }

            if(bDetectGCC||bHeurGCC)
            {
                // Mingw
                // Msys
                if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    VI_STRUCT viStruct=get_GCC_vi1(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize);

                    ssCompiler.sVersion=viStruct.sVersion;

                    // TODO MinGW-w64
                    if(viStruct.sInfo.contains("MinGW"))
                    {
                        ssTool.type=RECORD_TYPE_TOOL;
                        ssTool.name=RECORD_NAME_MINGW;
                    }
                    else if(viStruct.sInfo.contains("MSYS2"))
                    {
                        ssTool.type=RECORD_TYPE_TOOL;
                        ssTool.name=RECORD_NAME_MSYS2;
                    }
                    else if(viStruct.sInfo.contains("Cygwin"))
                    {
                        ssTool.type=RECORD_TYPE_TOOL;
                        ssTool.name=RECORD_NAME_CYGWIN;
                    }

                    if(ssCompiler.sVersion=="")
                    {
                        QString _sGCCVersion;

                        if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                        {
                            _sGCCVersion=get_GCC_vi2(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize).sVersion;

                            if(_sGCCVersion!="")
                            {
                                ssCompiler.sVersion=_sGCCVersion;
                            }
                        }

                        if(_sGCCVersion=="")
                        {
                            if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                            {
                                _sGCCVersion=get_GCC_vi2(pDevice,bIsImage,pPEInfo->osDataSection.nOffset,pPEInfo->osDataSection.nSize).sVersion;

                                if(_sGCCVersion!="")
                                {
                                    ssCompiler.sVersion=_sGCCVersion;
                                }
                            }
                        }
                    }

                    if((ssTool.type==RECORD_TYPE_UNKNOWN)&&(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_GCC)))
                    {
                        if(pPEInfo->mapEntryPointDetects.value(RECORD_NAME_GCC).sInfo.contains("MinGW"))
                        {
                            ssTool.type=RECORD_TYPE_TOOL;
                            ssTool.name=RECORD_NAME_MINGW;
                        }
                    }
                }

                if(ssCompiler.sVersion!="")
                {
                    bDetectGCC=true;
                }

                if(!bDetectGCC)
                {
                    if(pPEInfo->basic_info.bIsDeepScan)
                    {
                        qint64 nGCC_MinGW=pe.find_ansiString(pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize,"Mingw-w64 runtime failure:");

                        if(nGCC_MinGW!=-1)
                        {
                            ssTool.type=RECORD_TYPE_TOOL;
                            ssTool.name=RECORD_NAME_MINGW;

                            bDetectGCC=true;
                        }
                    }
                }

                if(bDetectGCC)
                {
                    ssCompiler.type=RECORD_TYPE_COMPILER;
                    ssCompiler.name=RECORD_NAME_GCC;
                }
            }

            int nNumberOfImports=pPEInfo->listImports.count();

            for(int i=0;i<nNumberOfImports;i++)
            {
                if(XBinary::isRegExpPresent("^CYGWIN",pPEInfo->listImports.at(i).sName.toUpper()))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            ssTool.sVersion=QString::number(dVersion,'f',2);
                        }
                    }

                    ssTool.type=RECORD_TYPE_TOOL;
                    ssTool.name=RECORD_NAME_CYGWIN;

                    break;
                }
            }

            if(ssCompiler.type==RECORD_TYPE_UNKNOWN)
            {
                if(XPE::isSectionNamePresent(".stabstr",&(pPEInfo->listSectionHeaders))) // TODO
                {
                    XPE::SECTION_RECORD sr=XPE::getSectionRecordByName(".stabstr",&(pPEInfo->listSectionRecords));

                    if(sr.nSize)
                    {
                        qint64 _nOffset=sr.nOffset;
                        qint64 _nSize=sr.nSize;

                        bool bSuccess=false;

                        if(!bSuccess)
                        {
                            qint64 nGCC_MinGW=pe.find_ansiString(_nOffset,_nSize,"/gcc/mingw32/");

                            if(nGCC_MinGW!=-1)
                            {
                                ssTool.type=RECORD_TYPE_TOOL;
                                ssTool.name=RECORD_NAME_MINGW;

                                bSuccess=true;
                            }
                        }

                        if(!bSuccess)
                        {
                            qint64 nCygwin=pe.find_ansiString(_nOffset,_nSize,"/gcc/i686-pc-cygwin/");

                            if(nCygwin!=-1)
                            {
                                ssTool.type=RECORD_TYPE_TOOL;
                                ssTool.name=RECORD_NAME_CYGWIN;

                                bSuccess=true;
                            }
                        }
                    }
                }
            }

            if(ssCompiler.type==RECORD_TYPE_UNKNOWN)
            {
                if( (ssTool.name==RECORD_NAME_MINGW)||
                    (ssTool.name==RECORD_NAME_MSYS)||
                    (ssTool.name==RECORD_NAME_MSYS2)||
                    (ssTool.name==RECORD_NAME_CYGWIN))
                {
                    ssCompiler.type=RECORD_TYPE_COMPILER;
                    ssCompiler.name=RECORD_NAME_GCC;
                }
            }

            if((ssCompiler.name==RECORD_NAME_GCC)&&(ssTool.type==RECORD_TYPE_UNKNOWN))
            {
                ssTool.type=RECORD_TYPE_TOOL;
                ssTool.name=RECORD_NAME_MINGW;
            }

            if((ssCompiler.name==RECORD_NAME_GCC)&&(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)))
            {
                ssLinker.type=RECORD_TYPE_LINKER;
                ssLinker.name=RECORD_NAME_GNULINKER;
                ssLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            }

            if(ssTool.name==RECORD_NAME_MINGW)
            {
                if(ssTool.sVersion=="")
                {
                    switch(pPEInfo->nMajorLinkerVersion)
                    {
                    case 2:
                        switch(pPEInfo->nMinorLinkerVersion)
                        {
                            case 23:    ssTool.sVersion="4.7.0-4.8.0";      break;
                            case 24:    ssTool.sVersion="4.8.2-4.9.2";      break;
                            case 25:    ssTool.sVersion="5.3.0";            break;
                            case 29:    ssTool.sVersion="7.3.0";            break;
                            case 30:    ssTool.sVersion="7.3.0";            break; // TODO Check
                        }
                        break;
                    }
                }
            }

            // TODO Check overlay debug

            if(ssLinker.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));
            }
            if(ssCompiler.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
            }
            if(ssTool.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultTools.insert(ssTool.name,scansToScan(&(pPEInfo->basic_info),&ssTool));
            }
        }
    }
}

void SpecAbstract::PE_handle_Signtools(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(pe.isSignPresent())
        {
            // TODO image
            XPE_DEF::IMAGE_DATA_DIRECTORY dd=pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY);

            QList<XPE::CERT> listCerts=pe.getCertList(dd.VirtualAddress,dd.Size);

            if(listCerts.count())
            {
                if((listCerts.at(0).record.wRevision==0x200)&&(listCerts.at(0).record.wCertificateType==2))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SIGNTOOL,RECORD_NAME_WINAUTH,"2.0","PKCS #7",0);
                    pPEInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Installers(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            // Inno Setup
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INNOSETUP)||pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INNOSETUP,"","",0);

                if((pe.read_uint32(0x30)==0x6E556E49)) // Uninstall
                {
                    ss.sInfo="Uninstall";

                    if(pe.checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
                    {
                        qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                        qint64 _nSize=pPEInfo->osCodeSection.nSize;

                        qint64 nOffsetVersion=pe.find_ansiString(_nOffset,_nSize,"Setup version: Inno Setup version ");

                        if(nOffsetVersion!=-1)
                        {
                            QString sVersionString=pe.read_ansiString(nOffsetVersion+34);
                            ss.sVersion=sVersionString.section(" ",0,0);
                            QString sEncodes=sVersionString.section(" ",1,1);

                            if(sEncodes=="(a)")
                            {
                                ss.sInfo=append(ss.sInfo,"ANSI");
                            }
                            else if(sEncodes=="(u)")
                            {
                                ss.sInfo=append(ss.sInfo,"Unicode");
                            }
                        }
                    }
                }
                else if(pPEInfo->mapOverlayDetects.value(RECORD_NAME_INNOSETUP).sInfo=="Uninstall")
                {
                    ss.sInfo="Uninstall";
                    qint64 _nOffset=pPEInfo->nOverlayOffset;
                    qint64 _nSize=pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion=pe.find_ansiString(_nOffset,_nSize,"Inno Setup Messages (");

                    if(nOffsetVersion!=-1)
                    {
                        QString sVersionString=pe.read_ansiString(nOffsetVersion+21);
                        ss.sVersion=sVersionString.section(" ",0,0);
                        ss.sVersion=ss.sVersion.remove(")");
                        QString sEncodes=sVersionString.section(" ",1,1);

                        // TODO Check
                        if(sEncodes=="(a))")
                        {
                            ss.sInfo=append(ss.sInfo,"ANSI");
                        }
                        else if(sEncodes=="(u))")
                        {
                            ss.sInfo=append(ss.sInfo,"Unicode");
                        }
                    }
                }
                else
                {
                    qint64 nLdrTableOffset=-1;

                    if(pe.read_uint32(0x30)==0x6F6E6E49)
                    {
                        ss.sVersion="1.XX-5.1.X";
                        ss.sInfo="Install";
                        nLdrTableOffset=pe.read_uint32(0x30+4);
                    }
                    else // New versions
                    {
                        XPE::RESOURCE_RECORD resHeader=XPE::getResourceRecord(XPE_DEF::S_RT_RCDATA,11111,&(pPEInfo->listResources));

                        nLdrTableOffset=resHeader.nOffset;

                        if(nLdrTableOffset!=-1)
                        {
                            ss.sVersion="5.1.X-X.X.X";
                            ss.sInfo="Install";
                        }
                    }

                    if(nLdrTableOffset!=-1)
                    {
                        // TODO 1 function
                        QString sSignature=pe.getSignature(nLdrTableOffset+0,12);

                        if(sSignature.left(12)=="72446C507453") // rDlPtS
                        {
                            //                    result.nLdrTableVersion=read_uint32(nLdrTableOffset+12+0);
                            //                    result.nTotalSize=read_uint32(nLdrTableOffset+12+4);
                            //                    result.nSetupE32Offset=read_uint32(nLdrTableOffset+12+8);
                            //                    result.nSetupE32UncompressedSize=read_uint32(nLdrTableOffset+12+12);
                            //                    result.nSetupE32CRC=read_uint32(nLdrTableOffset+12+16);
                            //                    result.nSetupBin0Offset=read_uint32(nLdrTableOffset+12+20);
                            //                    result.nSetupBin1Offset=read_uint32(nLdrTableOffset+12+24);
                            //                    result.nTableCRC=read_uint32(nLdrTableOffset+12+28);

                            QString sSetupDataString=pe.read_ansiString(pe.read_uint32(nLdrTableOffset+12+20));

                            if(!sSetupDataString.contains("("))
                            {
                                sSetupDataString=pe.read_ansiString(pe.read_uint32(nLdrTableOffset+12+24));
                                // TODO
//                                ss.sInfo=append(ss.sInfo,"OLD.TODO");
                            }

                            QString sVersion=XBinary::regExp("\\((.*?)\\)",sSetupDataString,1);
                            QString sOptions=XBinary::regExp("\\) \\((.*?)\\)",sSetupDataString,1);

                            if(sVersion!="")
                            {
                                ss.sVersion=sVersion;
                            }

                            if(sOptions!="")
                            {
                                QString sEncode=sOptions;

                                if(sEncode=="a")
                                {
                                    ss.sInfo=append(ss.sInfo,"ANSI");
                                }
                                else if(sEncode=="u")
                                {
                                    ss.sInfo=append(ss.sInfo,"Unicode");
                                }
                            }
                        }
                    }
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_CAB))
            {
                // Wix Tools
                if(XPE::isSectionNamePresent(".wixburn",&(pPEInfo->listSectionHeaders))) // TODO
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WIXTOOLSET,"","",0);
                    ss.sVersion="3.X"; // TODO check "E:\delivery\Dev\wix37\build\ship\x86\burn.pdb"
                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_NOSINSTALLER))
            {
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_NOSINSTALLER))
                {
                    // TODO Version from resources!
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_NOSINSTALLER,"","",0);
                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // CAB SFX
            if(pPEInfo->sResourceManifest.contains("sfxcab.exe"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_CAB,"","",0);

                if(pe.checkOffsetSize(pPEInfo->osResourcesSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 nSectionOffset=  pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).PointerToRawData+
                                            pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).Misc.VirtualSize;

                    qint64 nVersionOffset=pe.find_signature(&(pPEInfo->basic_info.memoryMap),nSectionOffset-0x600,0x600,"BD04EFFE00000100");
                    if(nVersionOffset!=-1)
                    {
                        ss.sVersion=QString("%1.%2.%3.%4")
                                .arg(pe.read_uint16(nVersionOffset+16+2))
                                .arg(pe.read_uint16(nVersionOffset+16+0))
                                .arg(pe.read_uint16(nVersionOffset+16+6))
                                .arg(pe.read_uint16(nVersionOffset+16+4));
                    }
                }

                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Install Anywhere
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INSTALLANYWHERE))
            {
                if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion))=="InstallAnywhere")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLANYWHERE,"","",0);
                    ss.sVersion=XPE::getResourcesVersionValue("ProductVersion",&(pPEInfo->resVersion));
                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_GHOSTINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GHOSTINSTALLER,"","",0);
                ss.sVersion="1.0";
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_QTINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_QTINSTALLER,"","",0);
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INSTALL4J))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALL4J,"","",0);
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SMARTINSTALLMAKER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SMARTINSTALLMAKER,"","",0);
                ss.sVersion=XBinary::hexToString(pPEInfo->sOverlaySignature.mid(46,14)); // TODO make 1 function
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_TARMAINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_TARMAINSTALLER,"","",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_CLICKTEAM))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_CLICKTEAM,"","",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // NSIS
            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_NSIS))||(pPEInfo->sResourceManifest.contains("Nullsoft.NSIS")))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_NSIS,"","",0);

                QString _sInfo=pPEInfo->mapOverlayDetects.value(RECORD_NAME_NSIS).sInfo;

                if(_sInfo!="")
                {
                    ss.sInfo=_sInfo;
                }

                //                QRegularExpression rxVersion("Null[sS]oft Install System v?(.*?)<");
                //                QRegularExpressionMatch matchVersion=rxVersion.match(pPEInfo->sResourceManifest);

                //                if(matchVersion.hasMatch())
                //                {
                //                    ss.sVersion=matchVersion.captured(1);
                //                }

                QString sVersion=XBinary::regExp("Null[sS]oft Install System v?(.*?)<",pPEInfo->sResourceManifest,1);

                if(sVersion!="")
                {
                    ss.sVersion=sVersion;
                }

                // TODO options

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // InstallShield
            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ",".");
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->sResourceManifest.contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);

                if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osDataSection.nOffset;
                    qint64 _nSize=pPEInfo->osDataSection.nSize;

                    qint64 nOffsetVersion=pe.find_ansiString(_nOffset,_nSize,"SOFTWARE\\InstallShield\\1");

                    if(nOffsetVersion!=-1)
                    {
                        QString sVersionString=pe.read_ansiString(nOffsetVersion);
                        ss.sVersion=sVersionString.section("\\",2,2);
                    }
                }

                if(ss.sVersion=="")
                {
                    // TODO unicode
                    ss.sVersion=XPE::getResourcesVersionValue("ISInternalVersion",&(pPEInfo->resVersion));
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INSTALLSHIELD))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","PackageForTheWeb",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::getResourcesVersionValue("CompanyName",&(pPEInfo->resVersion)).contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);

                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion));

                if(XPE::getResourcesVersionValue("CompanyName",&(pPEInfo->resVersion)).contains("PackageForTheWeb"))
                {
                    ss.sInfo="PackageForTheWeb";
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->sResourceManifest.contains("AdvancedInstallerSetup"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ADVANCEDINSTALLER,"","",0);

                if((pPEInfo->nOverlayOffset)&&(pPEInfo->nOverlaySize)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->nOverlayOffset;
                    qint64 _nSize=pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion=pe.find_ansiString(_nOffset,_nSize,"Advanced Installer ");

                    if(nOffsetVersion!=-1)
                    {
                        QString sVersionString=pe.read_ansiString(nOffsetVersion);
                        ss.sVersion=sVersionString.section(" ",2,2);
                    }
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->sResourceManifest.contains("Illustrate.Spoon.Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SPOONINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->sResourceManifest.contains("DeployMaster Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_DEPLOYMASTER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( (pPEInfo->sResourceManifest.contains("Gentee.Installer.Install"))||
                (pPEInfo->sResourceManifest.contains("name=\"gentee\"")))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GENTEEINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else
            {
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_GENTEEINSTALLER))
                {
                    if(XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"SETUP_TEMP",&(pPEInfo->listResources)))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GENTEEINSTALLER,"","",0);

                        pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            if(pPEInfo->sResourceManifest.contains("BitRock Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_BITROCKINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("GP-Install")&&
                XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("TASPro6-Install"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GPINSTALL,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ",".");
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Total Commander Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_TOTALCOMMANDERINSTALLER,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("Comments",&(pPEInfo->resVersion)).contains("Actual Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ACTUALINSTALLER,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("Comments",&(pPEInfo->resVersion)).contains("Avast Antivirus"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_AVASTANTIVIRUS,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Opera Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_OPERA,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Yandex Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_YANDEX,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Google Update"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GOOGLE,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Visual Studio Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_MICROSOFTVISUALSTUDIO,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("InternalName",&(pPEInfo->resVersion)).contains("Dropbox Update Setup"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_DROPBOX,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("VeraCrypt"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_VERACRYPT,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Microsoft .NET Framework"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_MICROSOFTDOTNETFRAMEWORK,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourcesVersionValue("LegalTrademarks",&(pPEInfo->resVersion)).contains("Setup Factory"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SETUPFACTORY,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("ProductVersion",&(pPEInfo->resVersion)).trimmed();

                if(ss.sVersion.contains(","))
                {
                    ss.sVersion=ss.sVersion.remove(" ");
                    ss.sVersion=ss.sVersion.replace(",",".");
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Java")&&
                XPE::getResourcesVersionValue("InternalName",&(pPEInfo->resVersion)).contains("Setup Launcher"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_JAVA,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_VMWARE)||XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("VMware installation"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_VMWARE,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Windows Installer
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND))
            {
                VI_STRUCT vi=get_WindowsInstaller_vi(pDevice,bIsImage,pPEInfo->nOverlayOffset,pPEInfo->nOverlaySize);

                if(vi.sVersion!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WINDOWSINSTALLER,"","",0);

                    ss.sVersion=vi.sVersion;
                    ss.sInfo=vi.sInfo;

                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
               }
            }

            // Alchemy Mindworks
            if( XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,4001,&(pPEInfo->listResources))&&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,5001,&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ALCHEMYMINDWORKS,"","",0);
                // TODO versions

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(!pPEInfo->mapResultInstallers.contains(RECORD_NAME_WINDOWSINSTALLER))
            {
                int nNumberOfResources=pPEInfo->listResources.count();

                for(int i=0;i<nNumberOfResources;i++)
                {
                    qint64 _nOffset=pPEInfo->listResources.at(i).nOffset;
                    qint64 _nSize=pPEInfo->listResources.at(i).nSize;
                    qint64 _nSignatureSize=qMin(_nSize,(qint64)8);

                    if(_nSignatureSize)
                    {
                        QString sSignature=pe.getSignature(_nOffset,_nSignatureSize);

                        if(sSignature=="D0CF11E0A1B11AE1") // DOC File TODO move to signatures
                        {
                            VI_STRUCT vi=get_WindowsInstaller_vi(pDevice,bIsImage,_nOffset,_nSize);

                            if(vi.sVersion!="")
                            {
                                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WINDOWSINSTALLER,"","",0);

                                ss.sVersion=vi.sVersion;
                                ss.sInfo=vi.sInfo;

                                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));

                                break;
                            }
                        }
                    }
                }
            }

            // WISE Installer
            if(pPEInfo->exportHeader.sName=="STUB32.EXE")
            {
                if(pPEInfo->exportHeader.listPositions.count()==2)
                {
                    if( (pPEInfo->exportHeader.listPositions.at(0).sFunctionName=="_MainWndProc@16")||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName=="_StubFileWrite@12"))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WISE,"","",0);

                        // Check version
                        pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
                else if(pPEInfo->exportHeader.listPositions.count()==6)
                {
                    if( (pPEInfo->exportHeader.listPositions.at(0).sFunctionName=="_LanguageDlg@16")||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName=="_PasswordDlg@16")||
                        (pPEInfo->exportHeader.listPositions.at(2).sFunctionName=="_ProgressDlg@16")||
                        (pPEInfo->exportHeader.listPositions.at(3).sFunctionName=="_UpdateCRC@8")||
                        (pPEInfo->exportHeader.listPositions.at(4).sFunctionName=="_t1@40")||
                        (pPEInfo->exportHeader.listPositions.at(5).sFunctionName=="_t2@12"))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WISE,"","",0);

                        // Check version
                        pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_SFX(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_RAR))
            {
                if( XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG,"STARTDLG",&(pPEInfo->listResources))&&
                    XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG,"LICENSEDLG",&(pPEInfo->listResources)))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_WINRAR,"","",0);
                    // TODO Version
                    pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_WINRAR))||(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ZIP)))
            {
                if(pPEInfo->sResourceManifest.contains("WinRAR"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_WINRAR,"","",0);
                    // TODO Version
                    pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ZIP))
            {
                if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osDataSection.nOffset;
                    qint64 _nSize=pPEInfo->osDataSection.nSize;

                    qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"ZIP self-extractor");
                    if(nOffset_Version!=-1)
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_ZIP,"","",0);
                        // TODO Version
                        pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // 7z SFX
            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("7-Zip"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_7Z,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("ProductVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if((!pPEInfo->mapResultSFX.contains(RECORD_NAME_7Z))&&(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_7Z)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_7Z,"","",0);
                ss.sInfo="modified";
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // SQUEEZ SFX
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SQUEEZSFX))
            {
                if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Squeez"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SQUEEZSFX,"","",0);
                    ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                    pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // WinACE
            if(     XPE::getResourcesVersionValue("InternalName",&(pPEInfo->resVersion)).contains("WinACE")||
                    XPE::getResourcesVersionValue("InternalName",&(pPEInfo->resVersion)).contains("WinAce")||
                    XPE::getResourcesVersionValue("InternalName",&(pPEInfo->resVersion)).contains("UNACE"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_WINACE,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("ProductVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // WinZip
            if( (pPEInfo->sResourceManifest.contains("WinZipComputing.WinZip"))||
                (XPE::isSectionNamePresent("_winzip_",&(pPEInfo->listSectionHeaders)))) // TODO
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_WINZIP,"","",0);

                QString _sManifest=pPEInfo->sResourceManifest.section("assemblyIdentity",1,1);
                ss.sVersion=XBinary::regExp("version=\"(.*?)\"",_sManifest,1);
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Cab
            if(XPE::getResourcesVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Self-Extracting Cabinet"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_CAB,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("FileVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // GkSetup SFX
            if(XPE::getResourcesVersionValue("ProductName",&(pPEInfo->resVersion)).contains("GkSetup Self extractor"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_SFX,RECORD_NAME_GKSETUPSFX,"","",0);
                ss.sVersion=XPE::getResourcesVersionValue("ProductVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_PolyMorph(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)
    Q_UNUSED(pPEInfo)
    // ExeSax

}

void SpecAbstract::PE_handle_DongleProtection(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    if(pPEInfo->listImports.count()==1)
    {
        if(XBinary::isRegExpPresent("^NOVEX",pPEInfo->listImports.at(0).sName.toUpper()))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_DONGLEPROTECTION,RECORD_NAME_GUARDIANSTEALTH,"","",0);
            pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
    }
}

//void SpecAbstract::PE_handle_AnslymPacker(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//    XPE pe(pDevice,bIsImage);

//    if(pe.isValid())
//    {
//        if(!pPEInfo->cliInfo.bInit)
//        {
//            if((pPEInfo->nImportHash64==0xaf2e74867b)&&(pPEInfo->nImportHash32==0x51a4c42b))
//            {
//                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_ANSLYMPACKER,"","",0);
//                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//            }
//        }
//    }
//}

void SpecAbstract::PE_handle_NeoLite(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            if(pPEInfo->nEntryPointSection!=0)
            {
                if(pe.checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osEntryPointSection.nOffset;
                    qint64 _nSize=pPEInfo->osEntryPointSection.nSize;

                    qint64 nOffset_Version=pe.find_ansiString(_nOffset,_nSize,"NeoLite Executable File Compressor");

                    if(nOffset_Version!=-1)
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_NEOLITE,"1.0","",0);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PrivateEXEProtector(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bValid)
        {
            bool bKernel32ExitProcess=false;
            bool bKernel32=false;
            bool bUser32=false;
            bool bCharacteristics=false;
            bool bPEPLinker=false;
            bool bTurboLinker=false;

            if(pPEInfo->listImports.count()>=1)
            {
                if(pPEInfo->listImports.at(0).sName=="KERNEL32.DLL")
                {
                    if(pPEInfo->listImports.at(0).listPositions.count()==1)
                    {
                        bKernel32=true;

                        if(pPEInfo->listImports.at(0).listPositions.at(0).sName=="ExitProcess")
                        {
                            bKernel32ExitProcess=true;
                        }
                    }
                }
            }

            if(pPEInfo->listImports.count()==2)
            {
                if(pPEInfo->listImports.at(1).sName=="USER32.DLL")
                {
                    if(pPEInfo->listImports.at(1).listPositions.count()==1)
                    {
                        bUser32=true;
                    }
                }
            }

            int nNumberOfSections=pPEInfo->listSectionHeaders.count();

            for(int i=0;i<nNumberOfSections;i++)
            {
                if((pPEInfo->listSectionHeaders.at(i).Characteristics&0xFFFF)==0)
                {
                    bCharacteristics=true;
                    break;
                }
            }

            bPEPLinker=pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PRIVATEEXEPROTECTOR);
            bTurboLinker=pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER);

            if(bKernel32ExitProcess&&bCharacteristics&&bPEPLinker)
            {
                _SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PRIVATEEXEPROTECTOR);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(bKernel32&&bCharacteristics&&bTurboLinker)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PRIVATEEXEPROTECTOR,"2.25","",0);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(bKernel32&&bUser32&&bCharacteristics&&bTurboLinker)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PRIVATEEXEPROTECTOR,"2.30-2.70","",0);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_VisualBasicCryptors(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // 1337 Exe Crypter
        if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_1337EXECRYPTER))
        {
            if(XPE::isImportLibraryPresentI("MSVBVM60.DLL",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ssOverlay=pPEInfo->mapOverlayDetects.value(RECORD_NAME_1337EXECRYPTER);
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_1337EXECRYPTER,ssOverlay.sVersion,ssOverlay.sInfo,0);
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // AGAINNATIVITYCRYPTER
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER))
        {
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // AR Crypt
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ARCRYPT))
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ARCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // WingsCrypt
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WINGSCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WINGSCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Crypt R.Roads
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRYPTRROADS)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTRROADS);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Whitell Crypt
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WHITELLCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WHITELLCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // ZeldaCrypt
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ZELDACRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ZELDACRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Biohazard Crypter
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BIOHAZARDCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_BIOHAZARDCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Cryptable seducation
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRYPTABLESEDUCATION)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTABLESEDUCATION);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Cryptic
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRYPTIC)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTIC);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // CRyptOZ
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRYPTOZ)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTOZ);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Dirty Cryptor
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DIRTYCRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DIRTYCRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Fakus Cryptor
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FAKUSCRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_FAKUSCRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Fast file Crypt
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FASTFILECRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_FASTFILECRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // FileShield
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FILESHIELD)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_FILESHIELD);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // GhaZza CryPter
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_GHAZZACRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_GHAZZACRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_H4CKY0UORGCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_H4CKY0UORGCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HACCREWCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_HACCREWCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HALVCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_HALVCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KGBCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_KGBCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KIAMSCRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_KIAMSCRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KRATOSCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_KRATOSCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KUR0KX2TO)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_KUR0KX2TO);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_LUCYPHER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_LUCYPHER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MONEYCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MONEYCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER2)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER2);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NOXCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_NOXCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PUSSYCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PUSSYCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SMOKESCREENCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SMOKESCREENCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SNOOPCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SNOOPCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_STASFODIDOCRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_STASFODIDOCRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_TSTCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_TSTCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_TURKISHCYBERSIGNATURE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_TURKISHCYBERSIGNATURE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_TURKOJANCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_TURKOJANCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UNDOCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_UNDOCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WLCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WLCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ROGUEPACK)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ROGUEPACK);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::PE_handle_DelphiCryptors(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // Ass Crypter
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASSCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ASSCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Aase
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_AASE)) // TODO more checks!
        {
//                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AASE))
//                    {
//                        _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AASE);
//                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//                    }

            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AASE);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Anskya Polymorphic Packer
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ANSKYAPOLYMORPHICPACKER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ANSKYAPOLYMORPHICPACKER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // AnslymPacker
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ANSLYMPACKER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ANSLYMPACKER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Cigicigi Crypter
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CIGICIGICRYPTER)) // TODO more checks!
        {
            if(XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"AYARLAR",&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CIGICIGICRYPTER);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        // fEaRz Crypter
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FEARZCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_FEARZCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // fEaRz Packer
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FEARZPACKER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_FEARZPACKER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // GKripto
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_GKRIPTO)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_GKRIPTO);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HOUNDHACKCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_HOUNDHACKCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ICRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ICRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_INFCRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_INFCRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MALPACKER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MALPACKER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MINKE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MINKE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MORUKCREWCRYPTERPRIVATE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MORUKCREWCRYPTERPRIVATE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MRUNDECTETABLE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MRUNDECTETABLE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NIDHOGG)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_NIDHOGG);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NME)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_NME);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_OPENSOURCECODECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_OPENSOURCECODECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_OSCCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_OSCCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_P0KESCRAMBLER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_P0KESCRAMBLER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PANDORA)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PANDORA);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PFECX)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PFECX);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PICRYPTOR)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PICRYPTOR);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_POKECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_POKECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PUBCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PUBCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SIMCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SIMCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SEXECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SEXECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SIMPLECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_SIMPLECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_TGRCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_TGRCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_THEZONECRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_THEZONECRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UNDERGROUNDCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_UNDERGROUNDCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UNKOWNCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_UNKOWNCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WINDOFCRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WINDOFCRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_WLGROUPCRYPTER)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_WLGROUPCRYPTER);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

//        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DCRYPTPRIVATE)) // TODO more checks!
//        {
//            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DCRYPTPRIVATE);

//            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//        }

//        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
//        {
//            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DALKRYPT);

//            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//        }
    }
}

void SpecAbstract::PE_handle_Joiners(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // Blade Joiner
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BLADEJOINER))
        {
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_BLADEJOINER))
            {
                if(pPEInfo->nOverlaySize)
                {
                    _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BLADEJOINER);
                    pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                }
            }
        }

        // ExeJoiner
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXEJOINER))
        {
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXEJOINER))
            {
                if(pPEInfo->nOverlaySize)
                {
                    _SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXEJOINER);
                    pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                }
            }
        }

        // Celesty File Binder
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CELESTYFILEBINDER))
        {
            if(pe.isResourcePresent("RBIND",-1,&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_CELESTYFILEBINDER);
                pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }

        // N-Joiner
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NJOINER))
        {
            if(pe.isResourcePresent("NJ",-1,&(pPEInfo->listResources))||pe.isResourcePresent("NJOY",-1,&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_NJOINER);
                pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }
    }
}

bool SpecAbstract::PE_isProtectionPresent(SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    return (pPEInfo->mapResultPackers.count()||
            pPEInfo->mapResultProtectors.count()||
            pPEInfo->mapResultSFX.count()||
            pPEInfo->mapResultInstallers.count()||
            pPEInfo->mapResultNETObfuscators.count()||
            pPEInfo->mapResultDongleProtection.count());
}

void SpecAbstract::PE_handle_UnknownProtection(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
#ifdef QT_DEBUG
//        int i=pPEInfo->listImportPositionHashes.count()-1;

//        if(i>0)
//        {
//            if(pPEInfo->listImports.at(i).listPositions.count()>1)
//            {
//                _SCANS_STRUCT ss={};

//                ss.type=RECORD_TYPE_PROTECTOR;
//                ss.name=(SpecAbstract::RECORD_NAME)(RECORD_NAME_UNKNOWN0+i);
//                ss.sVersion=QString("%1").arg(pPEInfo->listImportPositionHashes.at(i),0,16);
//                ss.bIsHeuristic=true;

//                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//            }
//        }

#endif

        if(!PE_isProtectionPresent(pPEInfo))
        {
            if(pPEInfo->listSectionRecords.count())
            {
                if(pPEInfo->listSectionRecords.at(0).nSize==0)
                {
                    if( pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX)&&
                        (pPEInfo->mapImportDetects.value(RECORD_NAME_UPX).nVariant==0))
                    {
                        _SCANS_STRUCT ss={};

                        ss.type=RECORD_TYPE_PACKER;
                        ss.name=RECORD_NAME_UNK_UPXLIKE;
                        ss.bIsHeuristic=true;

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }
        }

        if(!PE_isProtectionPresent(pPEInfo))
        {
            QMapIterator<RECORD_NAME,_SCANS_STRUCT> i(pPEInfo->mapEntryPointDetects);

            while(i.hasNext())
            {
                i.next();

                _SCANS_STRUCT recordSS=i.value();

                if(recordSS.name!=RECORD_NAME_GENERIC)
                {
                    recordSS.bIsHeuristic=true;

                    if(recordSS.type==RECORD_TYPE_PACKER)
                    {
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                    else if(recordSS.type==RECORD_TYPE_PROTECTOR)
                    {
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }
            }
        }

        if((!pPEInfo->mapResultPackers.contains(RECORD_NAME_UPX))&&(!pPEInfo->mapResultPackers.contains(RECORD_NAME_UNK_UPXLIKE)))
        {
            VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,pPEInfo->osHeader.nOffset,pPEInfo->osHeader.nSize,XBinary::FT_PE);

            if((viUPX.bIsValid))
            {
                _SCANS_STRUCT recordSS={};

                recordSS.type=RECORD_TYPE_PACKER;
                recordSS.name=RECORD_NAME_UPX;
                recordSS.sVersion=viUPX.sVersion;
                recordSS.sInfo=viUPX.sInfo;
                recordSS.bIsHeuristic=true;

                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }

        if(!pPEInfo->mapResultPackers.contains(RECORD_NAME_ASPACK))
        {
            if(XPE::isSectionNamePresent(".aspack",&(pPEInfo->listSectionHeaders))&&XPE::isSectionNamePresent(".adata",&(pPEInfo->listSectionHeaders)))
            {
                _SCANS_STRUCT recordSS={};

                recordSS.type=RECORD_TYPE_PACKER;
                recordSS.name=RECORD_NAME_ASPACK;
                recordSS.sVersion="2.12-2.XX";
                recordSS.bIsHeuristic=true;

                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }

        if(!pPEInfo->mapResultPackers.contains(RECORD_NAME_PECOMPACT))
        {
            VI_STRUCT viPECompact=PE_get_PECompact_vi(pDevice,bIsImage,pPEInfo);

            if(viPECompact.bIsValid)
            {
                _SCANS_STRUCT recordSS={};

                recordSS.type=RECORD_TYPE_PACKER;
                recordSS.name=RECORD_NAME_PECOMPACT;
                recordSS.sVersion=viPECompact.sVersion;
                recordSS.sInfo=viPECompact.sInfo;
                recordSS.bIsHeuristic=true;

                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }

        if(!pPEInfo->mapResultPackers.contains(RECORD_NAME_KKRUNCHY))
        {
            if( pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_KKRUNCHY)&&
                (pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_KKRUNCHY).nVariant==0))
            {
                _SCANS_STRUCT recordSS={};

                recordSS.type=RECORD_TYPE_PACKER;
                recordSS.name=RECORD_NAME_KKRUNCHY;
                recordSS.bIsHeuristic=true;

                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }
    }
}

void SpecAbstract::PE_handle_FixDetects(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    if( pPEInfo->mapResultPackers.contains(RECORD_NAME_RLPACK)||
        pPEInfo->mapResultPackers.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR))
    {
        pPEInfo->mapResultLinkers.remove(RECORD_NAME_MICROSOFTLINKER);
        pPEInfo->mapResultCompilers.remove(RECORD_NAME_MASM);
        pPEInfo->mapResultTools.remove(RECORD_NAME_MASM32);
    }

    if( pPEInfo->mapResultPackers.contains(RECORD_NAME_AHPACKER)||
        pPEInfo->mapResultPackers.contains(RECORD_NAME_EPEXEPACK))
    {
        pPEInfo->mapResultPackers.remove(RECORD_NAME_AHPACKER);
    }

    // Check SafeEngine
    if( pPEInfo->mapResultCompilers.contains(RECORD_NAME_VISUALCCPP)&&
        pPEInfo->mapResultCompilers.contains(RECORD_NAME_BORLANDOBJECTPASCALDELPHI))
    {
        pPEInfo->mapResultCompilers.remove(RECORD_NAME_BORLANDOBJECTPASCALDELPHI);
    }

    if( pPEInfo->mapResultLinkers.contains(RECORD_NAME_MICROSOFTLINKER)&&
        pPEInfo->mapResultLinkers.contains(RECORD_NAME_TURBOLINKER))
    {
        pPEInfo->mapResultLinkers.remove(RECORD_NAME_TURBOLINKER);
    }

    if( pPEInfo->mapResultTools.contains(RECORD_NAME_MICROSOFTVISUALSTUDIO)&&
        pPEInfo->mapResultTools.contains(RECORD_NAME_BORLANDDELPHI))
    {
        pPEInfo->mapResultTools.remove(RECORD_NAME_BORLANDDELPHI);
    }

    if( pPEInfo->mapResultPackers.contains(RECORD_NAME_SIMPLEPACK)&&
        pPEInfo->mapResultCompilers.contains(RECORD_NAME_FASM))
    {
        pPEInfo->mapResultCompilers.remove(RECORD_NAME_FASM);
    }
}

void SpecAbstract::PE_handleLanguages(QIODevice *pDevice, bool bIsImage, PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pPEInfo->mapResultLinkers),&(pPEInfo->mapResultLanguages));
    getLanguage(&(pPEInfo->mapResultCompilers),&(pPEInfo->mapResultLanguages));
    getLanguage(&(pPEInfo->mapResultLibraries),&(pPEInfo->mapResultLanguages));
    getLanguage(&(pPEInfo->mapResultTools),&(pPEInfo->mapResultLanguages));
    getLanguage(&(pPEInfo->mapResultPackers),&(pPEInfo->mapResultLanguages));

    fixLanguage(&(pPEInfo->mapResultLanguages));
}

void SpecAbstract::PE_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo, SpecAbstract::SCAN_OPTIONS *pOptions, bool *pbIsStop)
{
    if(pOptions->bRecursiveScan)
    {
        XPE pe(pDevice,bIsImage);

        if(pe.isValid())
        {
            if(pPEInfo->nOverlaySize)
            {
                SpecAbstract::SCAN_RESULT scanResult={0};

                SpecAbstract::ID _parentId=pPEInfo->basic_info.id;
                _parentId.filePart=SpecAbstract::RECORD_FILEPART_OVERLAY;
                scan(pDevice,&scanResult,pPEInfo->nOverlayOffset,pPEInfo->nOverlaySize,_parentId,pOptions,false,pbIsStop);

                pPEInfo->listRecursiveDetects.append(scanResult.listRecords);
            }
        }
    }
}

void SpecAbstract::Binary_handle_Texts(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->bIsPlainText)||(pBinaryInfo->unicodeType!=XBinary::UNICODE_TYPE_NONE)||(pBinaryInfo->bIsUTF8))
    {
        int nSignaturesCount=sizeof(_TEXT_Exp_records)/sizeof(STRING_RECORD);

        for(int i=0;i<nSignaturesCount;i++) // TODO move to an own function !!!
        {
            if(XBinary::isRegExpPresent(_TEXT_Exp_records[i].pszString,pBinaryInfo->sHeaderText))
            {
                _SCANS_STRUCT record={};
                record.nVariant=_TEXT_Exp_records[i].basicInfo.nVariant;
                record.fileType=_TEXT_Exp_records[i].basicInfo.fileType;
                record.type=_TEXT_Exp_records[i].basicInfo.type;
                record.name=_TEXT_Exp_records[i].basicInfo.name;
                record.sVersion=_TEXT_Exp_records[i].basicInfo.pszVersion;
                record.sInfo=_TEXT_Exp_records[i].basicInfo.pszInfo;
                record.nOffset=0;

                pBinaryInfo->mapTextHeaderDetects.insert(record.name,record);
            }
        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_CCPP))
        {
            _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_CCPP);
            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_PYTHON))
        {
            if((pBinaryInfo->sHeaderText.contains("class"))&&(pBinaryInfo->sHeaderText.contains("self")))
            {
                _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_PYTHON);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_HTML))
        {
            _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_HTML);
            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_XML))
        {
            _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_XML);
            ss.sVersion=XBinary::regExp("version=['\"](.*?)['\"]",pBinaryInfo->sHeaderText,1);

            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_PHP))
        {
            _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_PHP);
            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }

//        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_PERL))
//        {
//            _SCANS_STRUCT ss=pBinaryInfo->mapTextHeaderDetects.value(RECORD_NAME_PERL);
//            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
//        }

        if(pBinaryInfo->mapTextHeaderDetects.contains(RECORD_NAME_SHELL))
        {
            QString sInterpreter;

            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!\\/usr\\/local\\/bin\\/(\\w+)",        pBinaryInfo->sHeaderText,1); // #!/usr/local/bin/ruby
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!\\/usr\\/bin\\/env (\\w+)",            pBinaryInfo->sHeaderText,1); // #!/usr/bin/env perl
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!\\/usr\\/bin\\/(\\w+)",                pBinaryInfo->sHeaderText,1); // #!/usr/bin/perl
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!\\/bin\\/(\\w+)",                      pBinaryInfo->sHeaderText,1); // #!/bin/sh
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!(\\w+)",                               pBinaryInfo->sHeaderText,1); // #!perl

            if(sInterpreter=="perl")
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_PERL,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="sh")
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_SHELL,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="ruby")
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_RUBY,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="python")
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_PYTHON,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_SHELL,sInterpreter,"",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
        }

//        if(pBinaryInfo->mapResultTexts.count()==0)
//        {
//            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_FORMAT,RECORD_NAME_PLAIN,"","",0);

//            if(pBinaryInfo->unicodeType!=XBinary::UNICODE_TYPE_NONE)
//            {
//                ss.name=RECORD_NAME_UNICODE;

//                if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_BE)
//                {
//                    ss.sVersion="Big Endian";
//                }
//                else if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_LE)
//                {
//                    ss.sVersion="Little Endian";
//                }
//            }
//            else if(pBinaryInfo->bIsUTF8)
//            {
//                ss.name=RECORD_NAME_UTF8;
//            }
//            else if(pBinaryInfo->bIsPlainText)
//            {
//                ss.name=RECORD_NAME_PLAIN;
//            }

//            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
//        }
    }
}

void SpecAbstract::Binary_handle_COM(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PKLITE))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PKLITE);
        pBinaryInfo->mapResultCOMPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UPX))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_UPX);
        pBinaryInfo->mapResultCOMPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_HACKSTOP))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HACKSTOP);
        pBinaryInfo->mapResultCOMProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYPTDISMEMBER))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYPTDISMEMBER);
        pBinaryInfo->mapResultCOMProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPIRIT))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPIRIT);
        pBinaryInfo->mapResultCOMProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ICE))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ICE);
        pBinaryInfo->mapResultCOMPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DIET))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DIET);
        pBinaryInfo->mapResultCOMPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYPTCOM))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_COM;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYPTCOM);
        pBinaryInfo->mapResultCOMProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->mapResultCOMProtectors.size()||pBinaryInfo->mapResultCOMPackers.size())
    {
        _SCANS_STRUCT ssOperationSystem=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_OPERATIONSYSTEM,RECORD_NAME_MSDOS,"","",0);

        pBinaryInfo->mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pBinaryInfo->basic_info),&ssOperationSystem));
    }
}

void SpecAbstract::Binary_handle_Archives(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    // 7-Zip
    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z))&&(pBinaryInfo->basic_info.nSize>=64))
    {
//        // TODO more options
//        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

//        if(ss.type==RECORD_TYPE_ARCHIVE)
//        {
//            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
//            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
//        }

        XSevenZip xsevenzip(pDevice);

        if(xsevenzip.isValid())
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;

            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

            ss.sVersion=xsevenzip.getVersion();
//            ss.sInfo=QString("%1 records").arg(xsevenzip.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // ZIP
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZIP))&&(pBinaryInfo->basic_info.nSize>=64)) // TODO min size
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZIP);

            ss.sVersion=xzip.getVersion();
            ss.sInfo=QString("%1 records").arg(xzip.getNumberOfRecords());

            if(xzip.isEncrypted())
            {
                ss.sInfo=append(ss.sInfo,"Encrypted");
            }

            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // GZIP
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GZIP))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // xar
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XAR))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XAR);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // LZFSE
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZFSE))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZFSE);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // CAB
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CAB))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        XCab xcab(pDevice);

        if(xcab.isValid())
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

            ss.sVersion=xcab.getVersion();
            ss.sInfo=QString("%1 records").arg(xcab.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // MAch-O FAT
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MACHOFAT))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        XMACHOFat xmachofat(pDevice);

        if(xmachofat.isValid())
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MACHOFAT);

            ss.sVersion=xmachofat.getVersion();
            ss.sInfo=QString("%1 records").arg(xmachofat.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // RAR
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RAR))&&(pBinaryInfo->basic_info.nSize>=64))
    {
        XRar xrar(pDevice);

        if(xrar.isValid())
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RAR);

            ss.sVersion=xrar.getVersion();

            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // zlib
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZLIB))&&(pBinaryInfo->basic_info.nSize>=32))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // XZ
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XZ))&&(pBinaryInfo->basic_info.nSize>=32))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XZ);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // ARJ
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARJ))&&(pBinaryInfo->basic_info.nSize>=4))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARJ);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // LHA
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHA))&&(pBinaryInfo->basic_info.nSize>=4))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHA);

        bool bDetected=false;

        switch(binary.read_uint8(0x5))
        {
            case 0x30: bDetected=1; break;
            case 0x31: bDetected=1; break;
            case 0x32: bDetected=1; break;
            case 0x33: bDetected=1; break;
            case 0x34: bDetected=1; break;
            case 0x35: bDetected=1; break;
            case 0x36: bDetected=1; break;
            case 0x64: bDetected=1; break;
            case 0x73: bDetected=1; break;
        }

        if(bDetected)
        {
            pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // BZIP2
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BZIP2))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BZIP2);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_Certificates(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    // Windows Authenticode Portable Executable Signature Format
    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINAUTH))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        quint32 nLength=XBinary::hexToUint32(pBinaryInfo->basic_info.sHeaderSignature.mid(0,8));

        if(nLength>=pBinaryInfo->basic_info.nSize)
        {
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINAUTH);
            pBinaryInfo->mapResultCertificates.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Binary_handle_DebugData(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MINGW))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // MinGW debug data
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MINGW);
        pBinaryInfo->mapResultDebugData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDBFILELINK))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // PDB File Link
        // TODO more infos
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDBFILELINK);
        pBinaryInfo->mapResultDebugData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_Formats(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->basic_info.nSize==0)
    {
        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_EMPTYFILE,"","",0);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // PDF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDF);
        ss.sVersion=XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5*2,6));
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Microsoft Compound
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPOUND);

        quint16 nSub1=binary.read_uint16(0x200);
        quint16 nSub2=binary.read_uint16(0x1000);

        // TODO More
        if((nSub1==0)&&(nSub2==0xFFFD))
        {
            ss.type=RECORD_TYPE_INSTALLER; // TODO mapResultInstallers
            ss.name=RECORD_NAME_MICROSOFTINSTALLER;
            ss.sVersion="";
            ss.sInfo="";
        }
        else if(nSub1==0xA5EC)
        {
            ss.type=RECORD_TYPE_FORMAT;
            ss.name=RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.sVersion="97-2003";
            ss.sInfo="";
        }

        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Microsoft Compiled HTML Help
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AUTOIT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // AutoIt Compiled Script
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AUTOIT);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RTF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // RTF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RTF);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LUACOMPILED))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Lua
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LUACOMPILED);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JAVACOMPILEDCLASS))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // java
        quint16 nMinor=binary.read_uint16(4,true);
        quint16 nMajor=binary.read_uint16(6,true);

        QString sVersion;

        if(nMajor)
        {
            switch(nMajor)
            {
                case 0x2D: sVersion="JDK 1.1"; break;
                case 0x2E: sVersion="JDK 1.2"; break;
                case 0x2F: sVersion="JDK 1.3"; break;
                case 0x30: sVersion="JDK 1.4"; break;
                case 0x31: sVersion="Java SE 5.0"; break;
                case 0x32: sVersion="Java SE 6.0"; break;
                case 0x33: sVersion="Java SE 7"; break;
                case 0x34: sVersion="Java SE 8"; break;
                case 0x35: sVersion="Java SE 9"; break;
                case 0x36: sVersion="Java SE 10"; break;
                case 0x37: sVersion="Java SE 11"; break;
                case 0x38: sVersion="Java SE 12"; break;
            }

            if((sVersion!="")&&(nMinor))
            {
                sVersion+=QString(".%1").arg(nMinor);
            }

            if(sVersion!="")
            {
                _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JAVACOMPILEDCLASS);
                ss.sVersion=sVersion;
                pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
        }
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_COFF))&&(pBinaryInfo->basic_info.nSize>=76))
    {
        // COFF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_COFF);

        bool bDetected=false;

        qint64 nOffset=binary.read_uint32(72,true)+58;

        if(binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap),"600A4C01",nOffset))
        {
            ss.sInfo="I386";
            bDetected=true;
        }
        if(binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap),"600A6486",nOffset))
        {
            ss.sInfo="AMD64";
            bDetected=true;
        }
        if(binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap),"600A0000FFFF....4C01",nOffset))
        {
            ss.sInfo="I386";
            bDetected=true;
        }
        if(binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap),"600A0000FFFF....6486",nOffset))
        {
            ss.sInfo="AMD64";
            bDetected=true;
        }

        if(bDetected)
        {
            pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEX))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // dex
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEX);
        ss.sVersion=XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(8,6));
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SWF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // SWF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SWF);
        ss.sVersion=QString("%1").arg(binary.read_uint8(3));
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTWINHELP))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Microsoft WinHelp
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTWINHELP);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP3))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // MP3
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP3);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP4))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // MP4
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP4);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSMEDIA))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Windows Media
        // TODO WMV/WMA
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSMEDIA);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FLASHVIDEO))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Flash Video
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FLASHVIDEO);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WAV))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // VAW
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WAV);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AU))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // AU
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AU);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEB))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // DEB
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEB);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVI))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // DEB
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVI);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TTF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // TTF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TTF);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDARSC))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDARSC);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDXML))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDXML);
        // TODO Version
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.nSize>=0x8010)
    {
        if(binary.compareSignature("01'CD001'01",0x8000))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_ISO9660,"","",0);
            // TODO Version
            pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Binary_handle_Databases(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDB))&&(pBinaryInfo->basic_info.nSize>=32))
    {
        // PDB
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDB);
        pBinaryInfo->mapResultDatabases.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKERDATABASE))&&(pBinaryInfo->basic_info.nSize>=32))
    {
        // Microsoft Linker Database
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTLINKERDATABASE);
        //        ss.sVersion=QString("%1.%2").arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(32*2,4))).arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(34*2,4)));
        pBinaryInfo->mapResultDatabases.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTACCESS))&&(pBinaryInfo->basic_info.nSize>=128))
    {
        // Microsoft Access Database
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTACCESS);

        quint32 nVersion=binary.read_int32(0x14);

        switch(nVersion)
        {
            case 0x0000: ss.sVersion="JET3"; break;// TODO
            case 0x0001: ss.sVersion="JET4"; break;// TODO
            case 0x0002: ss.sVersion="2007"; break;
            case 0x0103: ss.sVersion="2010"; break;
        }

        pBinaryInfo->mapResultDatabases.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_Images(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JPEG))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // JPEG
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JPEG);
        quint32 nMajor=pBinaryInfo->basic_info.sHeaderSignature.mid(11*2,2).toUInt(nullptr,16);
        quint32 nMinor=pBinaryInfo->basic_info.sHeaderSignature.mid(12*2,2).toUInt(nullptr,16);
        ss.sVersion=QString("%1.%2").arg(nMajor).arg(nMinor,2,10,QChar('0'));
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GIF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // GIF
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GIF);
        // TODO Version
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TIFF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // TIFF
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TIFF);
        // More information
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSICON))&&(pBinaryInfo->basic_info.nSize>=40))
    {
        // Windows Icon
        // TODO more information
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSICON);
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSBITMAP))&&(pBinaryInfo->basic_info.nSize>=40))
    {
        // Windows Bitmap
        // TODO more information
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        quint32 _nSize=qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(2*2,8).toUInt(nullptr,16));
        if(pBinaryInfo->basic_info.nSize>=_nSize)
        {
            QString sVersion;

            switch(qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(14*2,8).toUInt(nullptr,16)))
            {
            case  40: sVersion="3"; break;
            case 108: sVersion="4"; break;
            case 124: sVersion="5"; break;
            }

            if(sVersion!="")
            {
                _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSBITMAP);
                ss.sVersion=sVersion;
                pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
        }
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PNG))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // PNG
        // TODO options
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PNG);

        ss.sInfo=QString("%1x%2").arg(binary.read_uint32(16,true)).arg(binary.read_uint32(20,true));

        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DJVU))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // DJVU
        // TODO options
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_IMAGE;
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DJVU);
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_InstallerData(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    // Inno Setup
    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INNOSETUP);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLANYWHERE))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLANYWHERE);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GHOSTINSTALLER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GHOSTINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSIS))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSIS);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SIXXPACK))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SIXXPACK);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_THINSTALL))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_THINSTALL);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SMARTINSTALLMAKER))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SMARTINSTALLMAKER);
        ss.sVersion=XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(46,14));
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TARMAINSTALLER))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TARMAINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CLICKTEAM))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CLICKTEAM);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QTINSTALLER))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QTINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ADVANCEDINSTALLER))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ADVANCEDINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_OPERA))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_OPERA);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GPINSTALL))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GPINSTALL);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVASTANTIVIRUS))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVASTANTIVIRUS);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLSHIELD))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLSHIELD);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SETUPFACTORY))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SETUPFACTORY);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTUALINSTALLER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTUALINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALL4J))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALL4J);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VMWARE))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_VMWARE);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSINSTALLER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOSINSTALLER);
        pBinaryInfo->mapResultInstallerData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_SFXData(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINRAR))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINRAR);
        pBinaryInfo->mapResultSFXData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SQUEEZSFX))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SQUEEZSFX);
        pBinaryInfo->mapResultSFXData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z))&&(pBinaryInfo->basic_info.nSize>=20))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        if(ss.type==RECORD_TYPE_SFXDATA)
        {
            pBinaryInfo->mapResultSFXData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Binary_handle_ProtectorData(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FISHNET))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Inno Setup
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FISHNET);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XENOCODE))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Xenocode
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XENOCODE);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MOLEBOXULTRA))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MOLEBOXULTRA);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_1337EXECRYPTER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_1337EXECRYPTER);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTIVEMARK))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTIVEMARK);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARCRYPT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARCRYPT);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOXCRYPT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOXCRYPT);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASTFILECRYPT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FASTFILECRYPT);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZELDACRYPT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZELDACRYPT);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WLCRYPT))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WLCRYPT);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DOTNETSHRINK))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DOTNETSHRINK);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPOONSTUDIO))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPOONSTUDIO);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SECUROM))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SECUROM);
        ss.sVersion=binary.read_ansiString(8);
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SERGREENAPPACKER))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SERGREENAPPACKER);
        // TODO Version
        pBinaryInfo->mapResultProtectorData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
}

void SpecAbstract::Binary_handle_LibraryData(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SHELL))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        QString sString=binary.read_ansiString(0);

        if(sString.contains("python"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_BINARY,RECORD_TYPE_LIBRARY,RECORD_NAME_PYTHON,"","",0);
            pBinaryInfo->mapResultLibraryData.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Zip_handle_Microsoftoffice(QIODevice *pDevice, bool bIsImage, ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        XArchive::RECORD record=XArchive::getArchiveRecord("docProps/app.xml",&(pZipInfo->listArchiveRecords));

        if(!record.sFileName.isEmpty())
        {
            if((record.nUncompressedSize)&&(record.nUncompressedSize<=0x4000))
            {
                pZipInfo->basic_info.id.fileType=XBinary::FT_DOCUMENT;

                QString sData=xzip.decompress(&record).data();
                QString sApplication=XBinary::regExp("<Application>(.*?)</Application>",sData,1);

                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_MICROSOFTOFFICE,"","",0);

                if(sApplication=="Microsoft Office Word")
                {
                    ss.name=RECORD_NAME_MICROSOFTOFFICEWORD;
                }
                else if(sApplication=="Microsoft Excel")
                {
                    ss.name=RECORD_NAME_MICROSOFTEXCEL;
                }
                else if(sApplication=="Microsoft Visio")
                {
                    ss.name=RECORD_NAME_MICROSOFTVISIO;
                }
                else if(sApplication=="SheetJS")
                {
                    ss.name=RECORD_NAME_MICROSOFTEXCEL;
                    ss.sInfo="SheetJS";
                }

                ss.sVersion=XBinary::regExp("<AppVersion>(.*?)</AppVersion>",sData,1);
                pZipInfo->mapResultFormats.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_OpenOffice(QIODevice *pDevice, bool bIsImage, ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        XArchive::RECORD record=XArchive::getArchiveRecord("meta.xml",&(pZipInfo->listArchiveRecords));

        if(!record.sFileName.isEmpty())
        {
            if((record.nUncompressedSize)&&(record.nUncompressedSize<=0x4000))
            {
                QString sData=xzip.decompress(&record).data();

                // TODO
                if(sData.contains(":opendocument:"))
                {
                    pZipInfo->basic_info.id.fileType=XBinary::FT_DOCUMENT;

                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_OPENDOCUMENT,"","",0);

                    pZipInfo->mapResultFormats.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::Zip_handle_Metainfos(QIODevice *pDevice, bool bIsImage, SpecAbstract::ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    if((pZipInfo->bIsJAR)||(pZipInfo->bIsAPK))
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            QString sDataManifest=xzip.decompress(&(pZipInfo->listArchiveRecords),"META-INF/MANIFEST.MF").data();

            if(sDataManifest!="")
            {
                QString sCreatedBy=XBinary::regExp("Created-By: (.*?)\n",sDataManifest,1).remove("\r");
                QString sProtectedBy=XBinary::regExp("Protected-By: (.*?)\n",sDataManifest,1).remove("\r");
                QString sAntVersion=XBinary::regExp("Ant-Version: (.*?)\n",sDataManifest,1).remove("\r");
                QString sBuiltBy=XBinary::regExp("Built-By: (.*?)\n",sDataManifest,1).remove("\r");
                QString sBuiltJdk=XBinary::regExp("Build-Jdk: (.*?)\n",sDataManifest,1).remove("\r");

                if(sCreatedBy.contains("Android Gradle"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDGRADLE,"","",0);
                    ss.sVersion=XBinary::regExp("Android Gradle (.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("MOTODEV Studio for Android")||sCreatedBy.contains("MOTODEV Studio for ANDROID"))
                {
                    // TODO Check "MOTODEV Studio for ANDROID" version
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_MOTODEVSTUDIOFORANDROID,"","",0);
                    ss.sVersion=XBinary::regExp("MOTODEV Studio for Android v(.*?).release",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("Android Maven")||sCreatedBy.contains("Apache Maven Bundle Plugin"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDMAVENPLUGIN,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Radialix"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_RADIALIX,"","",0);
                    ss.sVersion=sCreatedBy.section(" (Radialix",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("AntiLVL"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_APKTOOL,RECORD_NAME_ANTILVL,"","",0);
                    ss.sVersion=sCreatedBy.section(" ",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("ApkEditor"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_APKTOOL,RECORD_NAME_APKEDITOR,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("d2j-apk-sign"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_D2JAPKSIGN,"","",0);
                    ss.sVersion=XBinary::regExp("d2j-apk-sign (.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("singlejar"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_SINGLEJAR,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("PseudoApkSigner"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_PSEUDOAPKSIGNER,"","",0);
                    ss.sVersion=XBinary::regExp("PseudoApkSigner (.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("ApkSigner"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_APKSIGNER,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("www.HiAPK.com"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_HIAPKCOM,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sBuiltBy.contains("com.haibison.apksigner")||sCreatedBy.contains("com.haibison.apksigner"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_APK_SIGNER,"","",0);

                    if(sBuiltBy.contains("com.haibison.apksigner"))
                    {
                        ss.sVersion=XBinary::regExp("com.haibison.apksigner (.*?)$",sBuiltBy,1);
                    }
                    else if(sCreatedBy.contains("com.haibison.apksigner"))
                    {
                        ss.sVersion=XBinary::regExp("com.haibison.apksigner (.*?)$",sCreatedBy,1);
                    }

                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sBuiltBy.contains("BundleTool")||sCreatedBy.contains("BundleTool"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_BUNDLETOOL,"","",0);

                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(COMEX SignApk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_COMEXSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (COMEX SignApk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(NetEase ApkSigner)")) // TODO Check " " !!!
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_NETEASEAPKSIGNER,"","",0);
                    ss.sVersion=sCreatedBy.section(" (NetEase ApkSigner)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(signatory)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_SIGNATORY,"","",0);
                    ss.sVersion=sCreatedBy.section(" (signatory)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(signupdate)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_SIGNUPDATE,"","",0);
                    ss.sVersion=sCreatedBy.section(" (signupdate)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Android SignApk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_ANDROIDSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (Android SignApk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(KT Android SignApk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_ANDROIDSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (KT Android SignApk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(abc SignApk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_ANDROIDSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (abc SignApk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(dotools sign apk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_DOTOOLSSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (dotools sign apk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Android apksigner)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_ANDROIDAPKSIGNER,"","",0);
                    ss.sVersion=sCreatedBy.section(" (Android apksigner)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(ApkModifier SignApk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_APKMODIFIERSIGNAPK,"","",0);
                    ss.sVersion=sCreatedBy.section(" (ApkModifier SignApk)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Baidu Signature platform)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_BAIDUSIGNATUREPLATFORM,"","",0);
                    ss.sVersion=sCreatedBy.section(" (Baidu Signature platform)",0,0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("tiny-sign"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_TINYSIGN,"","",0);
                    ss.sVersion=sCreatedBy.section("tiny-sign-",1,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("DexGuard, version"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXGUARD,"","",0);
                    ss.sVersion=XBinary::regExp("DexGuard, version (.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("ApkProtector"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_APKPROTECTOR,"","",0);

                    if(sCreatedBy.section(" ",0,0)=="ApkProtector")
                    {
                        ss.sVersion=sCreatedBy.section(" ",1,1).remove(")").remove("(");
                    }

                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Sun Microsystems Inc.)")||
                        sCreatedBy.contains("(BEA Systems, Inc.)")||
                        sCreatedBy.contains("(The FreeBSD Foundation)")||
                        sCreatedBy.contains("(d2j-null)")||
                        sCreatedBy.contains("(d2j-2.1-SNAPSHOT)")||
                        sCreatedBy.contains("(Oracle Corporation)")||
                        sCreatedBy.contains("(Apple Inc.)")||
                        sCreatedBy.contains("(Google Inc.)")||
                        sCreatedBy.contains("(Jeroen Frijters)")||
                        sCreatedBy.contains("(IBM Corporation)")||
                        sCreatedBy.contains("(JetBrains s.r.o)")||
                        sCreatedBy.contains("(Alibaba)")||
                        sCreatedBy.contains("(AdoptOpenJdk)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_JDK,"","",0);
                    ss.sVersion=sCreatedBy.section(" ",0,0);

                    if(sCreatedBy.contains("(Apple Inc.)"))
                    {
                        ss.name=RECORD_NAME_APPLEJDK;
                    }
                    else if(sCreatedBy.contains("(IBM Corporation)"))
                    {
                        ss.name=RECORD_NAME_IBMJDK;
                    }
                    else if(sCreatedBy.contains("(AdoptOpenJdk)"))
                    {
                        ss.name=RECORD_NAME_OPENJDK;
                    }

                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy=="1.6.0_21")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_JDK,"","",0);
                    ss.sVersion=sCreatedBy;
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(sCreatedBy.contains("(JetBrains s.r.o)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_JETBRAINS,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(d2j-null)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_APKTOOL,RECORD_NAME_DEX2JAR,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(d2j-2.1-SNAPSHOT)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_APKTOOL,RECORD_NAME_DEX2JAR,"2.1","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(Jeroen Frijters)"))
                {
                    // Check OpenJDK
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_IKVMDOTNET,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }
                else if(sCreatedBy.contains("(BEA Systems, Inc.)"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_BEAWEBLOGIC,"","",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                } 

                if(sAntVersion.contains("Apache Ant"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_APACHEANT,"","",0);
                    ss.sVersion=XBinary::regExp("Apache Ant (.*?)$",sAntVersion,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(sBuiltBy.contains("Generated-by-ADT"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_ECLIPSE,"","ADT",0);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(sBuiltJdk!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_TOOL,RECORD_NAME_JDK,"","",0);
                    ss.sVersion=sBuiltJdk;
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(sProtectedBy.contains("DexProtector"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXPROTECTOR,"","",0);

                    if(sProtectedBy.section(" ",0,0)=="DexProtector")
                    {
                        ss.sVersion=sProtectedBy.section(" ",1,1).remove(")").remove("(");
                    }
                    else if(sProtectedBy.section(" ",1,1)=="DexProtector")
                    {
                        ss.sVersion=sProtectedBy.section(" ",0,0);
                    }

                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(XBinary::regExp("^\\d+(\\.\\d+)*$",sCreatedBy,0)!="") // 0.0.0
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_GENERIC,RECORD_NAME_GENERIC,"","",0);

                    ss.sVersion=XBinary::regExp("(.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                if(sCreatedBy.contains("(d8)")||sCreatedBy.contains("(dx)")) // Dexguard
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_GENERIC,RECORD_NAME_GENERIC,"","",0);

                    ss.sVersion=XBinary::regExp("(.*?)$",sCreatedBy,1);
                    pZipInfo->mapMetainfosDetects.insert(ss.name,ss);
                }

                // TODO heur if String contains add to heur
            }
        }
    }
}

void SpecAbstract::Zip_handle_JAR(QIODevice *pDevice, bool bIsImage, ZIPINFO_STRUCT *pZipInfo, SpecAbstract::SCAN_OPTIONS *pOptions, bool *pbIsStop)
{
    Q_UNUSED(bIsImage)
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if(xzip.isValid()&&(!(*pbIsStop)))
    {
        _SCANS_STRUCT ssVM=getScansStruct(0,XBinary::FT_JAR,RECORD_TYPE_VIRTUALMACHINE,RECORD_NAME_JVM,"","",0);
        pZipInfo->mapResultOperationSystems.insert(ssVM.name,scansToScan(&(pZipInfo->basic_info),&ssVM));

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_JDK))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_JDK);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APPLEJDK))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APPLEJDK);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_IBMJDK))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_IBMJDK);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_OPENJDK))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_OPENJDK);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_JETBRAINS))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_JETBRAINS);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_IKVMDOTNET))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_IKVMDOTNET);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_BEAWEBLOGIC))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_BEAWEBLOGIC);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APACHEANT))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APACHEANT);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_SINGLEJAR))
        {
            _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_SINGLEJAR);
            pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Zip_handle_APK(QIODevice *pDevice, bool bIsImage, ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    if(pZipInfo->bIsAPK)
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            // 0x7109871a APK_SIGNATURE_SCHEME_V2_BLOCK_ID
            // TODO Check 0x7109871f https://github.com/18598925736/ApkChannelPackageJavaCore/blob/9342d57a1fc5f9271d569612df6028758f6ee42d/src/channel/data/Constants.java#L38
            // 0xf05368c0 APK_SIGNATURE_SCHEME_V3_BLOCK_ID
            // 0x42726577 padding
            // 0x504b4453 DEPENDENCY_INFO_BLOCK_ID; https://github.com/jomof/CppBuildCacheWorkInProgress/blob/148b94d712d14b6f2a13ab37a526c7795e2215b3/agp-7.1.0-alpha01/tools/base/signflinger/src/com/android/signflinger/SignedApk.java#L56
            // 0x71777777 Walle  https://github.com/Meituan-Dianping/walle/blob/f78edcf1117a0aa858a3d04bb24d86bf9ad51bb2/payload_reader/src/main/java/com/meituan/android/walle/ApkUtil.java#L40
            // 0x6dff800d SOURCE_STAMP_BLOCK_ID
            // 0x2146444e Google Play

            QList<XZip::APK_SIG_BLOCK_RECORD> listApkSignaturesBlockRecords=xzip.getAPKSignaturesBlockRecordsList();

            _SCANS_STRUCT ssSignTool=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_APKSIGNATURESCHEME,"","",0);

            if(XZip::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords,0x7109871a))
            {
                ssSignTool.sVersion="v2";
            }
            else if(XZip::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords,0xf05368c0))
            {
                ssSignTool.sVersion="v3";
            }

            // TODO V4

            if(ssSignTool.sVersion!="")
            {
                pZipInfo->mapResultSigntools.insert(ssSignTool.name,scansToScan(&(pZipInfo->basic_info),&ssSignTool));
            }

            if(XZip::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords,0x71777777))
            {
                _SCANS_STRUCT ssWalle=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_WALLE,"","",0);
                pZipInfo->mapResultTools.insert(ssWalle.name,scansToScan(&(pZipInfo->basic_info),&ssWalle));
            }

            if(XZip::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords,0x2146444e))
            {
                _SCANS_STRUCT ssGooglePlay=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_GOOGLEPLAY,"","",0);
                pZipInfo->mapResultTools.insert(ssGooglePlay.name,scansToScan(&(pZipInfo->basic_info),&ssGooglePlay));
            }

            if(pZipInfo->bIsKotlin)
            {
                _SCANS_STRUCT ssKotlin=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_LANGUAGE,RECORD_NAME_KOTLIN,"","",0);
                pZipInfo->mapResultLanguages.insert(ssKotlin.name,scansToScan(&(pZipInfo->basic_info),&ssKotlin));
            }
            else
            {
                _SCANS_STRUCT ssJava=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_LANGUAGE,RECORD_NAME_JAVA,"","",0);
                pZipInfo->mapResultLanguages.insert(ssJava.name,scansToScan(&(pZipInfo->basic_info),&ssJava));
            }

            if(pZipInfo->basic_info.bIsTest)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_SIGNTOOL,RECORD_NAME_UNKNOWN,"","",0);

                int nNumberOfRecords=listApkSignaturesBlockRecords.count();

                for(int i=0;i<nNumberOfRecords;i++)
                {
                    if(listApkSignaturesBlockRecords.at(i).nID>0xFFFF)
                    {
                        if( (listApkSignaturesBlockRecords.at(i).nID!=0x7109871a)&&
                            (listApkSignaturesBlockRecords.at(i).nID!=0xf05368c0)&&
                            (listApkSignaturesBlockRecords.at(i).nID!=0x42726577))
                        {
                            ss.name=(RECORD_NAME)((int)RECORD_NAME_UNKNOWN0+i);
                            ss.sVersion=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nID);
                            //ss.sInfo=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nDataSize);
                            pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
                        }
                    }
                }
            }

            QByteArray baAndroidManifest=xzip.decompress(&(pZipInfo->listArchiveRecords),"AndroidManifest.xml");

            QString sAndroidManifest=XAndroidBinary::getDecoded(&baAndroidManifest);

            QString sCompileSdkVersion=XBinary::regExp("android:compileSdkVersion=\"(.*?)\"",sAndroidManifest,1);
            QString sCompileSdkVersionCodename=XBinary::regExp("android:compileSdkVersionCodename=\"(.*?)\"",sAndroidManifest,1);
            QString sPlatformBuildVersionCode=XBinary::regExp("platformBuildVersionCode=\"(.*?)\"",sAndroidManifest,1);
            QString sPlatformBuildVersionName=XBinary::regExp("platformBuildVersionName=\"(.*?)\"",sAndroidManifest,1);
            QString sTargetSdkVersion=XBinary::regExp("android:targetSdkVersion=\"(.*?)\"",sAndroidManifest,1);
            QString sMinSdkVersion=XBinary::regExp("android:minSdkVersion=\"(.*?)\"",sAndroidManifest,1);
            QString sAndroid=XBinary::regExp("android:=\"(.*?)\"",sAndroidManifest,1);
            QString sAndroidVersionName=XBinary::regExp("android:versionName=\"(.*?)\"",sAndroidManifest,1);

            // Check
            if(!XBinary::checkStringNumber(sCompileSdkVersion,1,40))        sCompileSdkVersion="";
            if(!XBinary::checkStringNumber(sPlatformBuildVersionCode,1,40)) sPlatformBuildVersionCode="";
            if(!XBinary::checkStringNumber(sTargetSdkVersion,1,40))         sTargetSdkVersion="";
            if(!XBinary::checkStringNumber(sMinSdkVersion,1,40))            sMinSdkVersion="";
            if(!XBinary::checkStringNumber(sAndroid,1,40))                  sAndroid="";

            if(!XBinary::checkStringNumber(sCompileSdkVersionCodename.section(".",0,0),1,15))   sCompileSdkVersionCodename="";
            if(!XBinary::checkStringNumber(sPlatformBuildVersionName.section(".",0,0),1,15))    sPlatformBuildVersionName="";

            if( (sCompileSdkVersion!="")||
                (sCompileSdkVersionCodename!="")||
                (sPlatformBuildVersionCode!="")||
                (sPlatformBuildVersionName!="")||
                (sTargetSdkVersion!="")||
                (sMinSdkVersion!="")||
                (sAndroid!=""))
            {
                _SCANS_STRUCT ssAndroidSDK=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDSDK,"","",0);
                _SCANS_STRUCT ssAndroid=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_OPERATIONSYSTEM,RECORD_NAME_ANDROID,"","",0);

                QString _sVersion;
                QString _sAndroidVersion;

                _sVersion=sCompileSdkVersion;
                _sAndroidVersion=sCompileSdkVersionCodename;

                if(_sVersion=="")       _sVersion=sCompileSdkVersion;
                if(_sVersion=="")       _sVersion=sPlatformBuildVersionCode;
                if(_sVersion=="")       _sVersion=sTargetSdkVersion;
                if(_sVersion=="")       _sVersion=sMinSdkVersion;
                if(_sVersion=="")       _sVersion=sAndroid;

                if(_sAndroidVersion=="") _sAndroidVersion=sCompileSdkVersionCodename;
                if(_sAndroidVersion=="") _sAndroidVersion=sPlatformBuildVersionName;
                if(_sAndroidVersion=="") _sAndroidVersion=sAndroidVersionName;

                if(_sAndroidVersion=="")
                {
                    _sAndroidVersion=getAndroidVersionFromApi(_sVersion.toUInt());
                }

                if(_sVersion!="")
                {
                    ssAndroidSDK.sVersion=QString("API %1").arg(_sVersion);

                    pZipInfo->mapResultTools.insert(ssAndroidSDK.name,scansToScan(&(pZipInfo->basic_info),&ssAndroidSDK));
                }

                ssAndroid.sVersion=QString("%1").arg(_sAndroidVersion);

                pZipInfo->mapResultOperationSystems.insert(ssAndroid.name,scansToScan(&(pZipInfo->basic_info),&ssAndroid));
            }

            QString sJetpack=xzip.decompress(&(pZipInfo->listArchiveRecords),"META-INF/androidx.core_core.version").data();
            if(sJetpack!="")
            {
                QString sJetpackVersion=XBinary::regExp("(.*?)\n",sJetpack,1).remove("\r");

                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_LIBRARY,RECORD_NAME_ANDROIDJETPACK,"","",0);
                ss.sVersion=sJetpackVersion;
                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ANDROIDGRADLE))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ANDROIDGRADLE);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ANDROIDMAVENPLUGIN))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ANDROIDMAVENPLUGIN);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_RADIALIX))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_RADIALIX);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_MOTODEVSTUDIOFORANDROID))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ANTILVL))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ANTILVL);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APKEDITOR))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APKEDITOR);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_BUNDLETOOL))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_BUNDLETOOL);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DEX2JAR))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_DEX2JAR);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_D2JAPKSIGN))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_D2JAPKSIGN);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_PSEUDOAPKSIGNER))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_PSEUDOAPKSIGNER);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APKSIGNER))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APKSIGNER);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APK_SIGNER))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APK_SIGNER);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_NETEASEAPKSIGNER))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_NETEASEAPKSIGNER);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ANDROIDSIGNAPK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ANDROIDSIGNAPK);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DOTOOLSSIGNAPK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_DOTOOLSSIGNAPK);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_SIGNATORY))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_SIGNATORY);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_SIGNUPDATE))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_SIGNUPDATE);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ANDROIDAPKSIGNER))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ANDROIDAPKSIGNER);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APKMODIFIERSIGNAPK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APKMODIFIERSIGNAPK);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_BAIDUSIGNATUREPLATFORM))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_TINYSIGN))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_TINYSIGN);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_COMEXSIGNAPK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_COMEXSIGNAPK);
                pZipInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_ECLIPSE))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_ECLIPSE);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_HIAPKCOM))
            {
                _SCANS_STRUCT ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_HIAPKCOM);
                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_SECSHELL))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_SECSHELL);
                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_JIAGU))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_JIAGU);
                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_IJIAMI))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_IJIAMI);
                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_TENCENTPROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_TENCENTPROTECTION);
                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU)||pZipInfo->mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT))
            {
                _SCANS_STRUCT ss={};

                if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU))
                {
                    ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_TENCENTLEGU);
                }
                else if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT))
                {
                    ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_MOBILETENCENTPROTECT);
                }

                int nNumberOfRecords=pZipInfo->listArchiveRecords.count();

                for(int i=0;i<nNumberOfRecords;i++)
                {
                    if(pZipInfo->listArchiveRecords.at(i).sFileName.contains("lib/arm64-v8a/libshella-"))
                    {
                        ss.sVersion=XBinary::regExp("lib/arm64-v8a/libshella-(.*?).so",pZipInfo->listArchiveRecords.at(i).sFileName,1);

                        break;
                    }
                    else if(pZipInfo->listArchiveRecords.at(i).sFileName.contains("lib/armeabi-v7a/libshella-"))
                    {
                        ss.sVersion=XBinary::regExp("lib/armeabi-v7a/libshella-(.*?).so",pZipInfo->listArchiveRecords.at(i).sFileName,1);

                        break;
                    }
                    else if(pZipInfo->listArchiveRecords.at(i).sFileName.contains("lib/armeabi/libshella-"))
                    {
                        ss.sVersion=XBinary::regExp("lib/armeabi/libshella-(.*?).so",pZipInfo->listArchiveRecords.at(i).sFileName,1);

                        break;
                    }
                    else if(pZipInfo->listArchiveRecords.at(i).sFileName.contains("lib/x86/libshella-"))
                    {
                        ss.sVersion=XBinary::regExp("lib/x86/libshella-(.*?).so",pZipInfo->listArchiveRecords.at(i).sFileName,1);

                        break;
                    }
                }

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // AppGuard
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_APPGUARD))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_APPGUARD);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Kiro
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_KIRO))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_KIRO);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // DxShield
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_DXSHIELD))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_DXSHIELD);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // qdbh
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_QDBH))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_QDBH);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Bangcle Protection
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_BANGCLEPROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_BANGCLEPROTECTION);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Qihoo 360 Protection
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_QIHOO360PROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_QIHOO360PROTECTION);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Alibaba Protection
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_ALIBABAPROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_ALIBABAPROTECTION);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Baidu Protection
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_BAIDUPROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_BAIDUPROTECTION);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // NQ Shield
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_NQSHIELD))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_NQSHIELD);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Nagapt Protection
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_NAGAPTPROTECTION))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_NAGAPTPROTECTION);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // SecNeo
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_SECNEO))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_SECNEO);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // LIAPP
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_LIAPP))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_LIAPP);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // yidun
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_YIDUN))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_YIDUN);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // PangXie
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_PANGXIE))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_PANGXIE);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Hdus-Wjus
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_HDUS_WJUS))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_HDUS_WJUS);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Medusah
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_MEDUSAH))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_MEDUSAH);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // AppSolid
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_APPSOLID))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_APPSOLID);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Proguard
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_PROGUARD))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_PROGUARD);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // VDog
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_VDOG))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_VDOG);

                QString sVersion=xzip.decompress(&(pZipInfo->listArchiveRecords),"assets/version").data();

                if(sVersion!="")
                {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion=sVersion.section("VDOG-",1,1).section("_",0,0);
                }

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // APKProtect
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_APKPROTECT))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_APKPROTECT);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // ollvm-tll
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_OLLVMTLL))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_OLLVMTLL);

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // DexGuard
            if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD)||pZipInfo->dexInfoClasses.mapResultProtectors.contains(RECORD_NAME_DEXGUARD))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXGUARD,"","",0);

                if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD))
                {
                    ss.sVersion=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_DEXGUARD).sVersion;
                }
                else if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_GENERIC))
                {
                    ss.sVersion=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_GENERIC).sVersion;
                }

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_DEXPROTECTOR)||pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR))
            {
                _SCANS_STRUCT ss={};

                if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR))
                {
                    ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_DEXPROTECTOR);
                }
                else
                {
                    ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_DEXPROTECTOR);
                }

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_APKPROTECTOR)||pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR))
            {
                _SCANS_STRUCT ss={};

                if(pZipInfo->mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR))
                {
                    ss=pZipInfo->mapMetainfosDetects.value(RECORD_NAME_APKPROTECTOR);
                }
                else
                {
                    ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_APKPROTECTOR);
                }

                pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // SandHook
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_SANDHOOK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_SANDHOOK);

                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Unicom SDK
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_UNICOMSDK))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_UNICOMSDK);

                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Unity
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_UNITY))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_UNITY);

                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // IL2CPP
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_IL2CPP))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_IL2CPP);

                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // Basic4Android
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_BASIC4ANDROID))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_BASIC4ANDROID);

                pZipInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }

            // ApkToolPlus
            if(pZipInfo->mapArchiveDetects.contains(RECORD_NAME_APKTOOLPLUS))
            {
                _SCANS_STRUCT ss=pZipInfo->mapArchiveDetects.value(RECORD_NAME_APKTOOLPLUS);

                pZipInfo->mapResultTools.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_IPA(QIODevice *pDevice, bool bIsImage, SpecAbstract::ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        if(pZipInfo->bIsIPA)
        {
            _SCANS_STRUCT ssFormat=getScansStruct(0,XBinary::FT_ARCHIVE,RECORD_TYPE_FORMAT,RECORD_NAME_IPA,"","",0);

            ssFormat.sVersion=xzip.getVersion();
            ssFormat.sInfo=QString("%1 records").arg(xzip.getNumberOfRecords());

            pZipInfo->basic_info.listDetects.append(scansToScan(&(pZipInfo->basic_info),&ssFormat));
        }
    }
}

void SpecAbstract::Zip_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, SpecAbstract::SCAN_OPTIONS *pOptions, bool *pbIsStop)
{
    Q_UNUSED(bIsImage)

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        if(((pZipInfo->bIsAPK)||(pZipInfo->bIsIPA))&&(pOptions->bRecursiveScan))
        {
            if(pOptions->bDeepScan)
            {
                int nNumberOfRecords=pZipInfo->listArchiveRecords.count();

                for(int i=0;(i<nNumberOfRecords)&&(!(*pbIsStop));i++)
                {
                    if(pZipInfo->basic_info.bIsTest)
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_UNKNOWN,"","",0);

                        if(     pZipInfo->listArchiveRecords.at(i).sFileName.contains("libdiresu.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("assets/agconfig")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libkonyjsvm.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libapproov.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("apkPackerConfiguration")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libAppSuit.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libUnpacker.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libcovault.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libcovault-appsec.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libsecenh.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("guardit4j.fin")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libmedl.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libCodeGuard.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libshield.so")||
                                pZipInfo->listArchiveRecords.at(i).sFileName.contains("libvosWrapperEx.so"))
                        {
                            ss.sVersion=pZipInfo->listArchiveRecords.at(i).sFileName;
                            pZipInfo->mapResultAPKProtectors.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
                        }
                    }

                    QByteArray baRecordData=xzip.decompress(&(pZipInfo->listArchiveRecords.at(i)),true);

                    QSet<XBinary::FT> stFileTypes=XBinary::getFileTypes(&baRecordData,true);

                    if( stFileTypes.contains(XBinary::FT_DEX)||
                        stFileTypes.contains(XBinary::FT_ELF32)||
                        stFileTypes.contains(XBinary::FT_ELF64)||
                        stFileTypes.contains(XBinary::FT_MACHOFAT)||
                        stFileTypes.contains(XBinary::FT_MACHO32)||
                        stFileTypes.contains(XBinary::FT_MACHO64))
                    {
                        SpecAbstract::SCAN_RESULT scanResult={0};

                        SpecAbstract::ID _parentId=pZipInfo->basic_info.id;
                        _parentId.filePart=SpecAbstract::RECORD_FILEPART_ARCHIVERECORD;
                        _parentId.sInfo=pZipInfo->listArchiveRecords.at(i).sFileName;
                        _parentId.bVirtual=true; // TODO Check

                        if(pZipInfo->listArchiveRecords.at(i).nUncompressedSize>baRecordData.size())
                        {
                            QTemporaryFile fileTemp;

                            if(fileTemp.open())
                            {
                                QString sTempFileName=fileTemp.fileName();

                                if(xzip.decompressToFile(&(pZipInfo->listArchiveRecords.at(i)),sTempFileName))
                                {
                                    QFile file;

                                    file.setFileName(sTempFileName);

                                    if(file.open(QIODevice::ReadOnly))
                                    {
                                        scan(&file,&scanResult,0,file.size(),_parentId,pOptions,false,pbIsStop);

                                        file.close();
                                    }
                                }
                            }
                        }
                        else
                        {
                            QBuffer buffer(&baRecordData);

                            if(buffer.open(QIODevice::ReadOnly))
                            {
                                scan(&buffer,&scanResult,0,buffer.size(),_parentId,pOptions,false,pbIsStop);

                                buffer.close();
                            }
                        }

                        if(stFileTypes.contains(XBinary::FT_DEX))
                        {
                            // TODO get language(Java/Kotlin) from DEX
                            // bIsKotlin
                            // bIsJava
                        }

//                        if( stFileTypes.contains(XBinary::FT_ELF32)||
//                            stFileTypes.contains(XBinary::FT_ELF64))
//                        {
//                            filterResult(&scanResult.listRecords,QSet<RECORD_TYPE>()<<RECORD_TYPE_PACKER<<RECORD_TYPE_PROTECTOR);
//                        }

                        pZipInfo->listRecursiveDetects.append(scanResult.listRecords);
                    }
                }
            }
        }
    }
}

void SpecAbstract::Zip_handle_FixDetects(QIODevice *pDevice, bool bIsImage, SpecAbstract::ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(bIsImage)

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        if( pZipInfo->basic_info.id.fileType==XBinary::FT_ZIP)
        {
            pZipInfo->basic_info.id.fileType=XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_ARCHIVE,RECORD_TYPE_FORMAT,RECORD_NAME_ZIP,"","",0);

            ss.sVersion=xzip.getVersion();
            ss.sInfo=QString("%1 records").arg(xzip.getNumberOfRecords());

            if(xzip.isEncrypted())
            {
                ss.sInfo=append(ss.sInfo,"Encrypted");
            }

            // TODO files
            pZipInfo->mapResultArchives.insert(ss.name,scansToScan(&(pZipInfo->basic_info),&ss));
        }

        if(pZipInfo->basic_info.bIsTest)
        {
            if(pZipInfo->mapMetainfosDetects.count()==0)
            {
                QString sDataManifest=xzip.decompress("META-INF/MANIFEST.MF").data();

                QString sProtectedBy=XBinary::regExp("Protected-By: (.*?)\n",sDataManifest,1).remove("\r");
                QString sCreatedBy=XBinary::regExp("Created-By: (.*?)\n",sDataManifest,1).remove("\r");
                QString sBuiltBy=XBinary::regExp("Built-By: (.*?)\n",sDataManifest,1).remove("\r");

                if(sProtectedBy!="")
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_PROTECTOR;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                    recordSS.sVersion="Protected: "+sProtectedBy;

                    pZipInfo->mapResultAPKProtectors.insert(recordSS.name,scansToScan(&(pZipInfo->basic_info),&recordSS));
                }

                if((sCreatedBy!="")&&(sCreatedBy!="1.0 (Android)"))
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_PROTECTOR;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion="Created: "+sCreatedBy;

                    pZipInfo->mapResultAPKProtectors.insert(recordSS.name,scansToScan(&(pZipInfo->basic_info),&recordSS));
                }

                if(sBuiltBy!="")
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_PROTECTOR;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion="Built: "+sBuiltBy;

                    pZipInfo->mapResultAPKProtectors.insert(recordSS.name,scansToScan(&(pZipInfo->basic_info),&recordSS));
                }
            }
        }
    }
}

void SpecAbstract::Zip_handleLanguages(QIODevice *pDevice, bool bIsImage, ZIPINFO_STRUCT *pZipInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pZipInfo->mapResultLibraries),&(pZipInfo->mapResultLanguages));
    getLanguage(&(pZipInfo->mapResultTools),&(pZipInfo->mapResultLanguages));

    fixLanguage(&(pZipInfo->mapResultLanguages));
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::Zip_scan_DEX(QIODevice *pDevice, bool bIsImage, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, SCAN_OPTIONS *pOptions, bool *pbIsStop, QString sFileName)
{
    Q_UNUSED(bIsImage)

    DEXINFO_STRUCT result={};

    XZip xzip(pDevice);

    if(xzip.isValid())
    {
        QByteArray baRecordData=xzip.decompress(&(pZipInfo->listArchiveRecords),sFileName);

        QBuffer buffer(&baRecordData);

        if(buffer.open(QIODevice::ReadOnly))
        {
            result=getDEXInfo(&buffer,pZipInfo->basic_info.id,pOptions,0,pbIsStop);

            buffer.close();
        }
    }

    return result;
}

void SpecAbstract::Binary_handle_FixDetects(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    if(pBinaryInfo->mapResultFormats.contains(RECORD_NAME_PDF))
    {
        pBinaryInfo->mapResultTexts.clear();

        pBinaryInfo->mapResultFormats[RECORD_NAME_PDF].id.fileType=XBinary::FT_BINARY;
        pBinaryInfo->basic_info.id.fileType=XBinary::FT_BINARY;
    }
}

void SpecAbstract::Binary_handleLanguages(QIODevice *pDevice, bool bIsImage, BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)
    Q_UNUSED(pBinaryInfo)

    // TODO

//    getLanguage(&(pBinaryInfo->mapResultCOMPackers),&(pBinaryInfo->mapResultLanguages));
//    getLanguage(&(pBinaryInfo->mapResultCOMProtectors),&(pBinaryInfo->mapResultLanguages));
    // TODO fixes
}

void SpecAbstract::MSDOS_handle_OperationSystems(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        _SCANS_STRUCT ssOperationSystem=getScansStructFromOsInfo(msdos.getOsInfo());

        pMSDOSInfo->mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pMSDOSInfo->basic_info),&ssOperationSystem));
    }
}

void SpecAbstract::MSDOS_handle_Tools(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        // IBM PC Pascal
        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_IBMPCPASCAL))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_IBMPCPASCAL);
            pMSDOSInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        // WATCOM C
        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_WATCOMCCPP))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_WATCOMCCPP);
            pMSDOSInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        // BAT2EXEC
        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_BAT2EXEC))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_BAT2EXEC);
            pMSDOSInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

    }
}

void SpecAbstract::MSDOS_handle_Borland(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        _SCANS_STRUCT ssLinker={};
        _SCANS_STRUCT ssCompiler={};

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi=get_TurboLinker_vi(pDevice,bIsImage);

            if(vi.bIsValid)
            {
                ss.sVersion=vi.sVersion;
            }

            ssLinker=ss;
        }

        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            qint64 _nOffset=0;
            qint64 _nSize=pMSDOSInfo->basic_info.nSize;

            if(pMSDOSInfo->nOverlayOffset!=-1)
            {
                _nSize=pMSDOSInfo->nOverlayOffset;
            }

            qint64 nOffsetTurboC=-1;
            qint64 nOffsetTurboCPP=-1;
            qint64 nOffsetBorlandCPP=-1;

            nOffsetTurboC=msdos.find_ansiString(_nOffset,_nSize,"Turbo-C - ");

            if(nOffsetTurboC!=-1)
            {
                QString sBorlandString=msdos.read_ansiString(nOffsetTurboC);
                // TODO version
                _SCANS_STRUCT ssCompiler=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_TURBOC,"","",0);

                if(sBorlandString=="Turbo-C - Copyright (c) 1987 Borland Intl.")
                {
                    ssCompiler.sVersion="1987";
                }
                else if(sBorlandString=="Turbo-C - Copyright (c) 1988 Borland Intl.")
                {
                    ssCompiler.sVersion="1988";
                }

                pMSDOSInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pMSDOSInfo->basic_info),&ssCompiler));
            }

            if(nOffsetTurboC==-1)
            {
                nOffsetTurboCPP=msdos.find_ansiString(_nOffset,_nSize,"Turbo C++ - ");
            }

            if(nOffsetTurboCPP!=-1)
            {
                QString sBorlandString=msdos.read_ansiString(nOffsetTurboCPP);
                // TODO version
                _SCANS_STRUCT ssCompiler=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_TURBOCPP,"","",0);

                if(sBorlandString=="Turbo C++ - Copyright 1990 Borland Intl.")
                {
                    ssCompiler.sVersion="1990";
                }

                pMSDOSInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pMSDOSInfo->basic_info),&ssCompiler));
            }

            if((nOffsetTurboC==-1)&&(nOffsetTurboCPP==-1))
            {
                nOffsetBorlandCPP=msdos.find_ansiString(_nOffset,_nSize,"Borland C++");
            }

            if(nOffsetBorlandCPP!=-1)
            {
                QString sBorlandString=msdos.read_ansiString(nOffsetBorlandCPP);
                // TODO version
                _SCANS_STRUCT ssCompiler=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_BORLANDCPP,"","",0);

                if(sBorlandString=="Borland C++ - Copyright 1991 Borland Intl.")
                {
                    ssCompiler.sVersion="1991";
                }
                else if(sBorlandString=="Borland C++ - Copyright 1993 Borland Intl.")
                {
                    ssCompiler.sVersion="1993";
                }
                else if(sBorlandString=="Borland C++ - Copyright 1994 Borland Intl.")
                {
                    ssCompiler.sVersion="1994";
                }
                else if(sBorlandString=="Borland C++ - Copyright 1995 Borland Intl.")
                {
                    ssCompiler.sVersion="1995";
                }

                pMSDOSInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pMSDOSInfo->basic_info),&ssCompiler));
            }
        }

        if(ssCompiler.type==RECORD_TYPE_UNKNOWN)
        {
            if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_TURBOCPP))
            {
                ssCompiler=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_TURBOCPP);
            }
        }

        if(ssLinker.type==RECORD_TYPE_UNKNOWN)
        {
            if( (ssCompiler.name==RECORD_NAME_TURBOC)||
                (ssCompiler.name==RECORD_NAME_TURBOCPP)||
                (ssCompiler.name==RECORD_NAME_BORLANDCPP))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_LINKER,RECORD_NAME_TURBOLINKER,"","",0);

                // TODO Version
                // Turbo-C 1987 1.0
                // Turbo-C 1988 2.0
                // Borland C++ 1991 3.0-7.00?

                ssLinker=ss;
            }
        }

        if(ssLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pMSDOSInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pMSDOSInfo->basic_info),&ssLinker));
        }

        if(ssCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pMSDOSInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pMSDOSInfo->basic_info),&ssCompiler));
        }
    }
}

void SpecAbstract::MSDOS_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CRYEXE))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CRYEXE);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LSCRYPRT))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LSCRYPRT);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PACKWIN)||pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_PACKWIN))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_PACKWIN);

            if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PACKWIN))
            {
                pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PACKWIN);
            }

            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PKLITE))
        {
            // TODO more options
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PKLITE);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WWPACK))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WWPACK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if( pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZEXE)||
            pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_LZEXE))
        {
            bool bHeader=pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZEXE);
            bool bEP=pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_LZEXE);

            _SCANS_STRUCT ss={};

            if(bHeader&&bEP)
            {
                ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZEXE);
            }
            else if(bEP)
            {
                ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_LZEXE);
                ss.sInfo=append(ss.sInfo,"modified header");
            }
            else if(bHeader)
            {
                ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZEXE);
                ss.sInfo=append(ss.sInfo,"modified entrypoint");
            }

            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if( pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RJCRUSH)||
            pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_RJCRUSH))
        {
            bool bHeader=pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RJCRUSH);
            bool bEP=pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_RJCRUSH);

            _SCANS_STRUCT ss={};

            if(bHeader&&bEP)
            {
                ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RJCRUSH);
            }
            else if(bEP)
            {
                ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_RJCRUSH);
                ss.sInfo=append(ss.sInfo,"modified header");
            }
            else if(bHeader)
            {
                ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RJCRUSH);
                ss.sInfo=append(ss.sInfo,"modified entrypoint");
            }

            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_AINEXE))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_AINEXE);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_PGMPAK))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_PGMPAK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_JAM))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_JAM);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_LOCKTITE))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_LOCKTITE);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_PCOM))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_PCOM);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_AVPACK))
        {
            // TODO Check
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_AVPACK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_LGLZ))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_LGLZ);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_PROPACK))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_PROPACK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_RELPACK))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_RELPACK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_SCRNCH))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_SCRNCH);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_TINYPROG))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_TINYPROG);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_UCEXE))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_UCEXE);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_APACK))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_APACK);
            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_CCBYVORONTSOV))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_CCBYVORONTSOV);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_CRYPTCOM))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_CRYPTCOM);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_CRYPTORBYDISMEMBER))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_CRYPTORBYDISMEMBER);
            pMSDOSInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_UPX))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_UPX);

            VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,0,pMSDOSInfo->basic_info.nSize,XBinary::FT_MSDOS);

            if(viUPX.bIsValid)
            {
                if(viUPX.sVersion!="")
                {
                    ss.sVersion=viUPX.sVersion;
                }

                ss.sInfo=viUPX.sInfo;
            }

            pMSDOSInfo->mapResultPackers.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::MSDOS_handle_SFX(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHASSFX))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHASSFX);
            pMSDOSInfo->mapResultSFX.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }
        else if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_ICE))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_ICE);
            pMSDOSInfo->mapResultSFX.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }
        else if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_PKZIPMINISFX))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_PKZIPMINISFX);
            pMSDOSInfo->mapResultSFX.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::MSDOS_handle_DosExtenders(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo)
{
    XMSDOS msdos(pDevice,bIsImage);

    if(msdos.isValid())
    {
        if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_CAUSEWAY))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_CAUSEWAY);

            if(pMSDOSInfo->basic_info.bIsDeepScan)
            {
                qint64 nVersionOffset=msdos.find_ansiString(0,pMSDOSInfo->basic_info.nSize,"CauseWay DOS Extender v");

                if(nVersionOffset!=-1)
                {
                    QString sVersion=msdos.read_ansiString(nVersionOffset+23);
                    sVersion=sVersion.section(" ",0,0);

                    if(sVersion!="")
                    {
                        ss.sVersion=sVersion;
                    }
                }
            }

            pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        // CWSDPMI
        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            qint64 nVersionOffset=msdos.find_ansiString(0,0x100,"CWSDPMI");

            if(nVersionOffset!=-1)
            {
                QString sCWSDPMI=msdos.read_ansiString(nVersionOffset);

                if(sCWSDPMI.section(" ",0,0)=="CWSDPMI")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_CWSDPMI,"","",0);

                    ss.sVersion=sCWSDPMI.section(" ",1,1);

                    pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
                }
            }
        }
        // PMODE/W
        QString sPMODEW=msdos.read_ansiString(0x55);
        QString sPMODE_W=sPMODEW.section(" ",0,0);
        if((sPMODE_W=="PMODE/W")||(sPMODE_W=="PMODE\\W"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_PMODEW,"","",0);

            ss.sVersion=sPMODEW.section(" ",1,1).remove("v");

            pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        QString sWDOSX=msdos.read_ansiString(0x34);

        if(sWDOSX.section(" ",0,0)=="WDOSX")
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_WDOSX,"","",0);

            ss.sVersion=sWDOSX.section(" ",1,1);

            pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        // DOS/16M
        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            qint64 nVersionOffset=msdos.find_ansiString(0,qMin(pMSDOSInfo->basic_info.nSize,(qint64)0x1000),"DOS/16M Copyright (C) Tenberry Software Inc");

            if(nVersionOffset!=-1)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_DOS16M,"","",0);
                // TODO Version
                pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
            }
        }

        // DOS/4G
        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            // TODO vi
            qint64 nVersionOffset=msdos.find_ansiString(0,qMin(pMSDOSInfo->basic_info.nSize,(qint64)0x1000),"DOS/4G");

            if(nVersionOffset!=-1)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_DOS4G,"","",0);
                // TODO Version
                pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::MSDOS_handleLanguages(QIODevice *pDevice, bool bIsImage, MSDOSINFO_STRUCT *pMSDOSInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pMSDOSInfo->mapResultLinkers),&(pMSDOSInfo->mapResultLanguages));
    getLanguage(&(pMSDOSInfo->mapResultCompilers),&(pMSDOSInfo->mapResultLanguages));
    getLanguage(&(pMSDOSInfo->mapResultLibraries),&(pMSDOSInfo->mapResultLanguages));
    getLanguage(&(pMSDOSInfo->mapResultTools),&(pMSDOSInfo->mapResultLanguages));

    fixLanguage(&(pMSDOSInfo->mapResultLanguages));
}

void SpecAbstract::MSDOS_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop)
{
    if(pOptions->bRecursiveScan)
    {
        XMSDOS msdos(pDevice,bIsImage);

        if(msdos.isValid())
        {
            if(pMSDOSInfo->nOverlaySize)
            {
                SpecAbstract::SCAN_RESULT scanResult={0};

                SpecAbstract::ID _parentId=pMSDOSInfo->basic_info.id;
                _parentId.filePart=SpecAbstract::RECORD_FILEPART_OVERLAY;
                scan(pDevice,&scanResult,pMSDOSInfo->nOverlayOffset,pMSDOSInfo->nOverlaySize,_parentId,pOptions,false,pbIsStop);

                pMSDOSInfo->listRecursiveDetects.append(scanResult.listRecords);
            }
        }
    }
}

void SpecAbstract::ELF_handle_OperationSystems(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        _SCANS_STRUCT ssOperationSystem=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_OPERATIONSYSTEM,RECORD_NAME_UNIX,"","",0);

        quint8 osabi=elf.getIdent_osabi();

        if      (osabi==XELF_DEF::ELFOSABI_HPUX)        ssOperationSystem.name=RECORD_NAME_HPUX;
        else if (osabi==XELF_DEF::ELFOSABI_NETBSD)      ssOperationSystem.name=RECORD_NAME_NETBSD;
        else if (osabi==XELF_DEF::ELFOSABI_LINUX)       ssOperationSystem.name=RECORD_NAME_LINUX;
        else if (osabi==XELF_DEF::ELFOSABI_SOLARIS)     ssOperationSystem.name=RECORD_NAME_SOLARIS;
        else if (osabi==XELF_DEF::ELFOSABI_AIX)         ssOperationSystem.name=RECORD_NAME_AIX;
        else if (osabi==XELF_DEF::ELFOSABI_IRIX)        ssOperationSystem.name=RECORD_NAME_IRIX;
        else if (osabi==XELF_DEF::ELFOSABI_FREEBSD)     ssOperationSystem.name=RECORD_NAME_FREEBSD;
        else if (osabi==XELF_DEF::ELFOSABI_TRU64)       ssOperationSystem.name=RECORD_NAME_TRU64;
        else if (osabi==XELF_DEF::ELFOSABI_MODESTO)     ssOperationSystem.name=RECORD_NAME_MODESTO;
        else if (osabi==XELF_DEF::ELFOSABI_OPENBSD)     ssOperationSystem.name=RECORD_NAME_OPENBSD;
        else if (osabi==XELF_DEF::ELFOSABI_OPENVMS)     ssOperationSystem.name=RECORD_NAME_OPENVMS;
        else if (osabi==XELF_DEF::ELFOSABI_NSK)         ssOperationSystem.name=RECORD_NAME_NSK;
        else if (osabi==XELF_DEF::ELFOSABI_AROS)        ssOperationSystem.name=RECORD_NAME_AROS;
        else if (osabi==XELF_DEF::ELFOSABI_FENIXOS)     ssOperationSystem.name=RECORD_NAME_FENIXOS;

        if(ssOperationSystem.name==RECORD_NAME_UNIX)
        {
            if(XELF::isNotePresent(&(pELFInfo->listNotes),"Android"))
            {
                ssOperationSystem.name=RECORD_NAME_ANDROID;

                XELF::NOTE note=XELF::getNote(&(pELFInfo->listNotes),"Android");

                _SCANS_STRUCT ssAndroidSDK=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDSDK,"","",0);
                _SCANS_STRUCT ssAndroidNDK=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDNDK,"","",0);

                if(note.nSize>=4)
                {
                    quint32 nSDKVersion=elf.read_uint32(note.nDataOffset);
                    ssAndroidSDK.sVersion=QString("API %1").arg(nSDKVersion);

                    ssOperationSystem.sVersion=getAndroidVersionFromApi(nSDKVersion);
                }

                if(note.nSize>=4+64*2)
                {
                    QString sNdkVersion=elf.read_ansiString(note.nDataOffset+4);
                    QString sNdkBuild=elf.read_ansiString(note.nDataOffset+4+64);

                    ssAndroidNDK.sVersion=QString("%1(%2)").arg(sNdkVersion).arg(sNdkBuild);
                }

                pELFInfo->mapResultTools.insert(ssAndroidSDK.name,scansToScan(&(pELFInfo->basic_info),&ssAndroidSDK));
                pELFInfo->mapResultTools.insert(ssAndroidNDK.name,scansToScan(&(pELFInfo->basic_info),&ssAndroidNDK));
            }
        }

        if(ssOperationSystem.name==RECORD_NAME_UNIX)
        {
            if(XELF::isSectionNamePresent(".note.android.ident",&(pELFInfo->listSectionRecords)))
            {
                ssOperationSystem.name=RECORD_NAME_ANDROID;
            }
        }

        if((ssOperationSystem.name==RECORD_NAME_UNIX)||(ssOperationSystem.name==RECORD_NAME_LINUX))
        {
            qint32 nNumberOfComments=pELFInfo->listComments.count();

            for(int i=0;i<nNumberOfComments;i++)
            {
                bool bFound=false;

                QString sComment=pELFInfo->listComments.at(i);

                if(sComment.contains("Ubuntu")||sComment.contains("ubuntu"))
                {
                    ssOperationSystem.name=RECORD_NAME_UBUNTULINUX;

                    if(sComment.contains("ubuntu1~"))
                    {
                        ssOperationSystem.sVersion=sComment.section("ubuntu1~",1,-1).section(")",0,0);
                    }

                    bFound=true;
                }
                else if(sComment.contains("Debian")||sComment.contains("debian"))
                {
                    ssOperationSystem.name=RECORD_NAME_DEBIANLINUX;

                    bFound=true;
                }
                else if(sComment.contains("StartOS"))
                {
                    ssOperationSystem.name=RECORD_NAME_STARTOSLINUX;

                    bFound=true;
                }
                else if(sComment.contains("Gentoo"))
                {
                    ssOperationSystem.name=RECORD_NAME_GENTOOLINUX;

                    bFound=true;
                }
                else if(sComment.contains("Alpine"))
                {
                    ssOperationSystem.name=RECORD_NAME_ALPINELINUX;

                    bFound=true;
                }
                else if(sComment.contains("Wind River Linux"))
                {
                    ssOperationSystem.name=RECORD_NAME_WINDRIVERLINUX;

                    bFound=true;
                }
                else if(sComment.contains("SuSE")||sComment.contains("SUSE Linux"))
                {
                    ssOperationSystem.name=RECORD_NAME_SUSELINUX;

                    bFound=true;
                }
                else if(sComment.contains("Mandrakelinux")||sComment.contains("Linux-Mandrake")||sComment.contains("Mandrake Linux"))
                {
                    ssOperationSystem.name=RECORD_NAME_MANDRAKELINUX;

                    bFound=true;
                }
                else if(sComment.contains("ASPLinux"))
                {
                    ssOperationSystem.name=RECORD_NAME_ASPLINUX;

                    bFound=true;
                }
                else if(sComment.contains("Red Hat"))
                {
                    ssOperationSystem.name=RECORD_NAME_REDHATLINUX;

                    bFound=true;
                }
                else if(sComment.contains("Hancom Linux"))
                {
                    ssOperationSystem.name=RECORD_NAME_HANCOMLINUX;

                    bFound=true;
                }
                else if(sComment.contains("TurboLinux"))
                {
                    ssOperationSystem.name=RECORD_NAME_TURBOLINUX;

                    bFound=true;
                }
                else if(sComment.contains("Vine Linux"))
                {
                    ssOperationSystem.name=RECORD_NAME_VINELINUX;

                    bFound=true;
                }

                if(ssOperationSystem.name!=RECORD_NAME_LINUX)
                {
                    if(sComment.contains("SunOS"))
                    {
                        ssOperationSystem.name=RECORD_NAME_SUNOS;

                        if(sComment.contains("@(#)SunOS "))
                        {
                            ssOperationSystem.sVersion=sComment.section("@(#)SunOS ",1,-1);
                        }

                        bFound=true;
                    }
                }

                if(bFound)
                {
                    break;
                }
            }
        }

        if(ssOperationSystem.name==RECORD_NAME_UNIX)
        {
            ssOperationSystem.sVersion=QString("%1").arg(osabi);
        }

        ssOperationSystem.sInfo=QString("%1, %2, %3").arg(elf.getArch(),(pELFInfo->bIs64)?("64-bit"):("32-bit"),elf.getTypeAsString());

        pELFInfo->mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pELFInfo->basic_info),&ssOperationSystem));
    }
}

void SpecAbstract::ELF_handle_CommentSection(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    int nNumberOfComments=pELFInfo->listComments.count();

    for(int i=0;i<nNumberOfComments;i++)
    {
        QString sComment=pELFInfo->listComments.at(i);

        VI_STRUCT vi={};
        _SCANS_STRUCT ss={};

        // Apple LLVM / clang
        if(!vi.bIsValid)
        {
            vi=_get_ByteGuard_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_BYTEGUARD,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_GCC_string(sComment); // TODO Max version

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_GCC,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }        

        if(!vi.bIsValid)
        {
            vi=_get_AppleLLVM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_APPLELLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_AndroidClang_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ANDROIDCLANG,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_PlexClang_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_PLEXCLANG,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_UbuntuClang_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_UBUNTUCLANG,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ApportableClang_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_APPORTABLECLANG,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMAssembler_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMASSEMBLER,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMLinker_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_LINKER,RECORD_NAME_ARMLINKER,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMC_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMC,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMCCPP_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMCCPP,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMNEONCCPP_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMNEONCCPP,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMThumbCCPP_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMTHUMBCCPP,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ARMThumbMacroAssembler_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_ARMTHUMBMACROASSEMBLER,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ThumbC_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_THUMBC,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_clang_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_CLANG,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_DynASM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_DYNASM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_Delphi_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_LLD_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_LINKER,RECORD_NAME_LLD,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_OracleSolarisLinkEditors_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_LINKER,RECORD_NAME_ORACLESOLARISLINKEDITORS,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_SunWorkShop_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_LINKER,RECORD_NAME_SUNWORKSHOP,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_SnapdragonLLVMARM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_SNAPDRAGONLLVMARM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_NASM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_COMPILER,RECORD_NAME_NASM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_TencentLegu_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_TENCENTLEGU,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_AlipayObfuscator_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_ALIPAYOBFUSCATOR,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_wangzehuaLLVM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_WANGZEHUALLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_ObfuscatorLLVM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_OBFUSCATORLLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_NagainLLVM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_NAGAINLLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_iJiami_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_IJIAMILLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_SafeengineLLVM_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_SAFEENGINELLVM,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_TencentObfuscation_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_TENCENTPROTECTION,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(!vi.bIsValid)
        {
            vi=_get_AppImage_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_APPIMAGE,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_HikariObfuscator_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_HIKARIOBFUSCATOR,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_SnapProtect_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_SNAPPROTECT,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_ByteDanceSecCompiler_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_BYTEDANCESECCOMPILER,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_DingbaozengNativeObfuscator_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_OllvmTll_string(sComment);

            if(vi.bIsValid)
            {
                ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_OLLVMTLL,vi.sVersion,vi.sInfo,0);

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        {
            vi=_get_SourceryCodeBench_string(sComment);

            if(vi.bIsValid)
            {
                if(vi.sInfo=="lite")
                {
                    ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_SOURCERYCODEBENCHLITE,vi.sVersion,"",0);
                }
                else
                {
                    ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_SOURCERYCODEBENCH,vi.sVersion,"",0);
                }

                pELFInfo->mapCommentSectionDetects.insert(ss.name,ss);
            }
        }

        if(pELFInfo->basic_info.bIsTest)
        {
            if(ss.name==RECORD_NAME_UNKNOWN)
            {
                if( (!vi.bIsValid)&&
                    (!XBinary::isRegExpPresent(".o$",sComment))&&
                    (!XBinary::isRegExpPresent(".c$",sComment))&&
                    (!XBinary::isRegExpPresent(".S22$",sComment))&&
                    (!XBinary::isRegExpPresent(".s$",sComment))&&
                    (!XBinary::isRegExpPresent(".S$",sComment)))
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_PROTECTOR;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN9+(RECORD_NAME)(i+1));
                    recordSS.sVersion="COMMENT:"+sComment;

                    pELFInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
                }
            }
        }
    }
}

void SpecAbstract::ELF_handle_Tools(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        // Qt
        if(XELF::isSectionNamePresent(".qtversion",&(pELFInfo->listSectionRecords)))
        {
            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_QT;

            XELF::SECTION_RECORD record=XELF::getSectionRecord(".qtversion",&(pELFInfo->listSectionRecords));

            quint64 nVersion=0;

            if(pELFInfo->bIs64)
            {
                if(record.nSize==16)
                {
                    nVersion=elf.read_uint64(record.nOffset+8,pELFInfo->bIsBigEndian);
                }
            }
            else
            {
                if(record.nSize==8)
                {
                    nVersion=elf.read_uint32(record.nOffset+4,pELFInfo->bIsBigEndian);
                }
            }

            if(nVersion)
            {
                recordSS.sVersion=XBinary::get_uint32_full_version(nVersion);
            }

            pELFInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }
        else if(XELF::isSectionNamePresent(".qtplugin",&(pELFInfo->listSectionRecords)))
        {
            XELF::SECTION_RECORD record=XELF::getSectionRecord(".qtplugin",&(pELFInfo->listSectionRecords));

            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_QT;

            QString sVersionString=elf.read_ansiString(record.nOffset);
            recordSS.sVersion=XBinary::regExp("version=(.*?)\\\n",sVersionString,1);

            pELFInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }

        // gold
        if(XELF::isSectionNamePresent(".note.gnu.gold-version",&(pELFInfo->listSectionRecords)))
        {
            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LINKER;
            recordSS.name=SpecAbstract::RECORD_NAME_GOLD;

            XELF::SECTION_RECORD record=XELF::getSectionRecord(".note.gnu.gold-version",&(pELFInfo->listSectionRecords));

            SpecAbstract::VI_STRUCT vi=get_gold_vi(pDevice,bIsImage,record.nOffset,record.nSize);

            if(vi.bIsValid)
            {
                recordSS.sVersion=vi.sVersion;
            }

            pELFInfo->mapResultLinkers.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }

        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SOURCERYCODEBENCH))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SOURCERYCODEBENCH);

            pELFInfo->mapResultTools.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }
        else if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SOURCERYCODEBENCHLITE))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SOURCERYCODEBENCHLITE);

            pELFInfo->mapResultTools.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_APPLELLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_APPLELLVM);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Android clang
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ANDROIDCLANG))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ANDROIDCLANG);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Plex clang
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_PLEXCLANG))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_PLEXCLANG);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Ubuntu clang
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_UBUNTUCLANG))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_UBUNTUCLANG);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Apportable clang
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_APPORTABLECLANG))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_APPORTABLECLANG);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM Assembler
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMASSEMBLER))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMASSEMBLER);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM C
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMC))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMC);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM C/C++
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMCCPP))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMCCPP);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM NEON C/C++
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMNEONCCPP))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMNEONCCPP);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM/Thumb C/C++
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMTHUMBCCPP))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMTHUMBCCPP);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Thumb C
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_THUMBC))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_THUMBC);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM/Thumb Macro Assembler
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMTHUMBMACROASSEMBLER))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMTHUMBMACROASSEMBLER);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ARM Linker
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ARMLINKER))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ARMLINKER);

            pELFInfo->mapResultLinkers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // clang
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_CLANG))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_CLANG);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // DynASM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_DYNASM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_DYNASM);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Delphi
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI))
        {
            _SCANS_STRUCT ssCompiler=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI);

            pELFInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pELFInfo->basic_info),&ssCompiler));

            _SCANS_STRUCT ssTool=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_TOOL,RECORD_NAME_EMBARCADERODELPHI,_get_DelphiVersionFromCompiler(ssCompiler.sVersion).sVersion,"",0);

            pELFInfo->mapResultTools.insert(ssTool.name,scansToScan(&(pELFInfo->basic_info),&ssTool));
        }

        // LLD
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_LLD))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_LLD);

            pELFInfo->mapResultLinkers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Oracle Solaris Link Editors
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ORACLESOLARISLINKEDITORS))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ORACLESOLARISLINKEDITORS);

            pELFInfo->mapResultLinkers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Sun WorkShop
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SUNWORKSHOP))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SUNWORKSHOP);

            pELFInfo->mapResultTools.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Snapdragon LLVM ARM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SNAPDRAGONLLVMARM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SNAPDRAGONLLVMARM);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // NASM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_NASM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_NASM);

            pELFInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::ELF_handle_GCC(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        _SCANS_STRUCT recordCompiler={};
        // GCC
        if(XELF::isSectionNamePresent(".gcc_except_table",&(pELFInfo->listSectionRecords)))  // TODO
        {
            recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
            recordCompiler.name=SpecAbstract::RECORD_NAME_GCC;
        }

        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_GCC))
        {
            recordCompiler=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_GCC);
        }

        if(recordCompiler.type!=SpecAbstract::RECORD_TYPE_UNKNOWN)
        {
            pELFInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pELFInfo->basic_info),&recordCompiler));
        }
    }
}

void SpecAbstract::ELF_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    Q_UNUSED(pELFInfo)

    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        // UPX
        VI_STRUCT viUPXEnd=_get_UPX_vi(pDevice,bIsImage,pELFInfo->basic_info.nSize-0x24,0x24,XBinary::FT_ELF);
        VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,0,pELFInfo->basic_info.nSize,XBinary::FT_ELF);

        if((viUPXEnd.bIsValid)||(viUPX.bIsValid))
        {
            _SCANS_STRUCT recordSS={};

            recordSS.type=RECORD_TYPE_PACKER;
            recordSS.name=RECORD_NAME_UPX;

            if(viUPXEnd.sVersion!="") recordSS.sVersion=viUPXEnd.sVersion;
            if(viUPX.sVersion!="") recordSS.sVersion=viUPX.sVersion;

            if(viUPXEnd.sInfo!="") recordSS.sInfo=viUPXEnd.sInfo;
            if(viUPX.sInfo!="") recordSS.sInfo=viUPX.sInfo;

            pELFInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }

        if(viUPXEnd.nValue==0x21434553) // SEC!
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_SECNEO,"Old","UPX",0);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }
        else if(viUPXEnd.nValue==0x00010203)
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_SECNEO,"","UPX",0);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }
        else if(viUPXEnd.nValue==0x214d4a41) // "AJM!"
        {
            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_ELF,RECORD_TYPE_PROTECTOR,RECORD_NAME_IJIAMI,"","UPX",0);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Obfuscator-LLVM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_OBFUSCATORLLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_OBFUSCATORLLVM);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // wangzehua LLVM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_WANGZEHUALLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_WANGZEHUALLVM);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Byteguard
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_BYTEGUARD))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_BYTEGUARD);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Alipay Obfuscator
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_ALIPAYOBFUSCATOR))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_ALIPAYOBFUSCATOR);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Tencent Legu
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_TENCENTLEGU))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_TENCENTLEGU);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Safeengine LLVM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SAFEENGINELLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SAFEENGINELLVM);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Tencent-Obfuscation
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_TENCENTPROTECTION))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_TENCENTPROTECTION);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // AppImage
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_APPIMAGE)) // Check overlay
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_APPIMAGE);
            pELFInfo->mapResultTools.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // HikariObfuscator
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_HIKARIOBFUSCATOR))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_HIKARIOBFUSCATOR);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // SnapProtect
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_SNAPPROTECT))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_SNAPPROTECT);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // ByteDance-SecCompiler
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_BYTEDANCESECCOMPILER))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_BYTEDANCESECCOMPILER);
            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Dingbaozeng native obfuscator
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR);

            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // Nagain LLVM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_NAGAINLLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_NAGAINLLVM);

            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // iJiami LLVM
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_IJIAMILLVM))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_IJIAMILLVM);

            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }

        // LLVM 6.0 + Ollvm + Armariris
        if(pELFInfo->mapCommentSectionDetects.contains(RECORD_NAME_OLLVMTLL))
        {
            _SCANS_STRUCT ss=pELFInfo->mapCommentSectionDetects.value(RECORD_NAME_OLLVMTLL);

            pELFInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pELFInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::ELF_handle_UnknownProtection(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    Q_UNUSED(pELFInfo)

    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        if(pELFInfo->basic_info.bIsTest)
        {
            // TODO names of note sections

            QSet<QString> stRecords;

            int nNumberOfRecords=pELFInfo->listComments.count();

            for(int i=0;i<nNumberOfRecords;i++)
            {
                if(!stRecords.contains(pELFInfo->listComments.at(i)))
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_LIBRARY;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN9+i+1);
                    recordSS.sVersion=pELFInfo->listComments.at(i);

                    pELFInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));

                    stRecords.insert(pELFInfo->listComments.at(i));
                }
            }
        }
    }
}

void SpecAbstract::ELF_handle_FixDetects(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    if( pELFInfo->mapResultCompilers.contains(RECORD_NAME_GCC)||
        pELFInfo->mapResultCompilers.contains(RECORD_NAME_APPORTABLECLANG))
    {
        if(pELFInfo->mapResultCompilers.value(RECORD_NAME_GCC).sVersion=="")
        {
            pELFInfo->mapResultCompilers.remove(RECORD_NAME_GCC);
        }
    }
}

void SpecAbstract::ELF_handleLanguages(QIODevice *pDevice, bool bIsImage, ELFINFO_STRUCT *pELFInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pELFInfo->mapResultLinkers),&(pELFInfo->mapResultLanguages));
    getLanguage(&(pELFInfo->mapResultCompilers),&(pELFInfo->mapResultLanguages));
    getLanguage(&(pELFInfo->mapResultLibraries),&(pELFInfo->mapResultLanguages));
    getLanguage(&(pELFInfo->mapResultTools),&(pELFInfo->mapResultLanguages));

    fixLanguage(&(pELFInfo->mapResultLanguages));
}

void SpecAbstract::MACHO_handle_Tools(QIODevice *pDevice, bool bIsImage, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo)
{
    XMACH mach(pDevice,bIsImage);

    if(mach.isValid())
    {
        _SCANS_STRUCT recordSDK={};
        recordSDK.type=SpecAbstract::RECORD_TYPE_TOOL;
        recordSDK.name=SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordXcode={};

        recordXcode.type=SpecAbstract::RECORD_TYPE_TOOL;
        recordXcode.name=SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT recordGCC={};
        recordGCC.type=SpecAbstract::RECORD_TYPE_COMPILER;

        _SCANS_STRUCT recordCLANG={};
        recordCLANG.type=SpecAbstract::RECORD_TYPE_COMPILER;

        _SCANS_STRUCT recordSwift={};
        recordSwift.type=SpecAbstract::RECORD_TYPE_COMPILER;
        recordSwift.name=SpecAbstract::RECORD_NAME_UNKNOWN;

        _SCANS_STRUCT ssOperationSystem=getScansStructFromOsInfo(mach.getOsInfo());

        pMACHInfo->mapResultOperationSystems.insert(ssOperationSystem.name,scansToScan(&(pMACHInfo->basic_info),&ssOperationSystem));

        // GCC
        if(XMACH::isLibraryRecordNamePresent("libgcc_s.1.dylib",&(pMACHInfo->listLibraryRecords)))
        {
            recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
        }

        // Swift
        if( XMACH::isSectionNamePresent("__swift5_proto",&(pMACHInfo->listSectionRecords))||
            XMACH::isSectionNamePresent("__swift5_types",&(pMACHInfo->listSectionRecords)))
        {  // TODO Check
            recordSwift.name=SpecAbstract::RECORD_NAME_SWIFT;
            recordSwift.sVersion="5.XX";
        }
        else if( XMACH::isSectionNamePresent("__swift2_proto",&(pMACHInfo->listSectionRecords))||
            XMACH::isLibraryRecordNamePresent("libswiftCore.dylib",&(pMACHInfo->listLibraryRecords)))  // TODO
        {
            recordSwift.name=SpecAbstract::RECORD_NAME_SWIFT;
        }

        if( XMACH::isSectionNamePresent("__objc_selrefs",&(pMACHInfo->listSectionRecords))||
            XMACH::isSegmentNamePresent("__OBJC",&(pMACHInfo->listSegmentRecords))||
            XMACH::isLibraryRecordNamePresent("libobjc.A.dylib",&(pMACHInfo->listLibraryRecords)))
        {
            recordGCC.sInfo="Objective-C";
            recordCLANG.sInfo="Objective-C";
        }

        // XCODE
        qint64 nVersionMinOffset=-1;
        qint64 nBuildVersionOffset=-1;

        if(mach.isCommandPresent(XMACH_DEF::S_LC_BUILD_VERSION,&(pMACHInfo->listCommandRecords)))
        {
            nBuildVersionOffset=mach.getCommandRecordOffset(XMACH_DEF::S_LC_BUILD_VERSION,0,&(pMACHInfo->listCommandRecords));
        }
        else if(mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_IPHONEOS,&(pMACHInfo->listCommandRecords)))
        {
            nVersionMinOffset=mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_IPHONEOS,0,&(pMACHInfo->listCommandRecords));
            recordSDK.name=RECORD_NAME_IOSSDK;
        }
        else if(mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_MACOSX,&(pMACHInfo->listCommandRecords)))
        {
            nVersionMinOffset=mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_MACOSX,0,&(pMACHInfo->listCommandRecords));
            recordSDK.name=RECORD_NAME_MACOSSDK;
        }
        else if(mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_TVOS,&(pMACHInfo->listCommandRecords)))
        {
            nVersionMinOffset=mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_TVOS,0,&(pMACHInfo->listCommandRecords));
            recordSDK.name=RECORD_NAME_TVOSSDK;
        }
        else if(mach.isCommandPresent(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS,&(pMACHInfo->listCommandRecords)))
        {
            nVersionMinOffset=mach.getCommandRecordOffset(XMACH_DEF::S_LC_VERSION_MIN_WATCHOS,0,&(pMACHInfo->listCommandRecords));
            recordSDK.name=RECORD_NAME_WATCHOSSDK;
        }

        if(nBuildVersionOffset!=-1)
        {
            XMACH_DEF::build_version_command build_version=mach._read_build_version_command(nBuildVersionOffset);

            if      (build_version.platform==XMACH_DEF::S_PLATFORM_MACOS)       recordSDK.name=RECORD_NAME_MACOSSDK;
            else if (build_version.platform==XMACH_DEF::S_PLATFORM_BRIDGEOS)    recordSDK.name=RECORD_NAME_BRIDGEOS;
            else if (build_version.platform==XMACH_DEF::S_PLATFORM_IOS)         recordSDK.name=RECORD_NAME_IOSSDK;
            else if (build_version.platform==XMACH_DEF::S_PLATFORM_TVOS)        recordSDK.name=RECORD_NAME_TVOSSDK;
            else if (build_version.platform==XMACH_DEF::S_PLATFORM_WATCHOS)     recordSDK.name=RECORD_NAME_WATCHOSSDK;

            if(build_version.sdk)
            {
                recordSDK.sVersion=XBinary::get_uint32_full_version(build_version.sdk);
            }
        }
        else if(nVersionMinOffset!=-1)
        {
            XMACH_DEF::version_min_command version_min=mach._read_version_min_command(nVersionMinOffset);

            if(version_min.sdk)
            {
                recordSDK.sVersion=XBinary::get_uint32_full_version(version_min.sdk);
            }
        }

        if(recordSDK.name!=RECORD_NAME_UNKNOWN)
        {
            recordXcode.name=SpecAbstract::RECORD_NAME_XCODE;

            if(recordSDK.name==SpecAbstract::RECORD_NAME_MACOSSDK)
            {
                if(recordSDK.sVersion=="10.3.0")
                {
                    recordXcode.sVersion="1.0-3.1.4";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                }
                else if(recordSDK.sVersion=="10.4.0")
                {
                    recordXcode.sVersion="2.0-3.2.6";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.0.2-1.7";
                }
                else if(recordSDK.sVersion=="10.5.0")
                {
                    recordXcode.sVersion="2.5-3.2.6";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.0.2-1.7";
                }
                else if(recordSDK.sVersion=="10.6.0")
                {
                    recordXcode.sVersion="3.2-4.3.3";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.0.2-3.0";
                }
                else if(recordSDK.sVersion=="10.7.0")
                {
                    recordXcode.sVersion="4.1-4.6.3";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="2.1-4.2";
                }
                else if(recordSDK.sVersion=="10.8.0")
                {
                    recordXcode.sVersion="4.4-5.1.1";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="4.0-5.1";
                }
                else if(recordSDK.sVersion=="10.9.0")
                {
                    recordXcode.sVersion="5.0.1-6.4";
                    recordCLANG.sVersion="5.0-6.1.0";
                    recordSwift.sVersion="1.0-1.2";
                }
                else if(recordSDK.sVersion=="10.10.0")
                {
                    recordXcode.sVersion="6.1-6.4";
                    recordCLANG.sVersion="6.0-6.1.0";
                    recordSwift.sVersion="1.0-1.2";
                }
                else if(recordSDK.sVersion=="10.11.0")
                {
                    recordXcode.sVersion="7.0-7.1.1";
                    recordCLANG.sVersion="7.0.0";
                    recordSwift.sVersion="2.0-2.1";
                }
                else if(recordSDK.sVersion=="10.11.2")
                {
                    recordXcode.sVersion="7.2-7.2.1";
                    recordCLANG.sVersion="7.0.2";
                    recordSwift.sVersion="2.1.1";
                }
                else if(recordSDK.sVersion=="10.11.4")
                {
                    recordXcode.sVersion="7.3-7.3.1";
                    recordCLANG.sVersion="7.3.0";
                    recordSwift.sVersion="2.2";
                }
                else if(recordSDK.sVersion=="10.12.0")
                {
                    recordXcode.sVersion="8.0";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0";
                }
                else if(recordSDK.sVersion=="10.12.1")
                {
                    recordXcode.sVersion="8.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.1";
                }
                else if(recordSDK.sVersion=="10.12.2")
                {
                    recordXcode.sVersion="8.2-8.2.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.2";
                }
                else if(recordSDK.sVersion=="10.12.4")
                {
                    recordXcode.sVersion="8.3-8.3.3";
                    recordCLANG.sVersion="8.1.0";
                    recordSwift.sVersion="3.1";
                }
                else if(recordSDK.sVersion=="10.13.0")
                {
                    recordXcode.sVersion="9.0-9.0.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0";
                }
                else if(recordSDK.sVersion=="10.13.1")
                {
                    recordXcode.sVersion="9.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.2";
                }
                else if(recordSDK.sVersion=="10.13.2")
                {
                    recordXcode.sVersion="9.2";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.3";
                }
                else if(recordSDK.sVersion=="10.13.4")
                {
                    recordXcode.sVersion="9.3-9.4.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1-4.1.2";
                }
                else if(recordSDK.sVersion=="10.14.0")
                {
                    recordXcode.sVersion="10.0";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2";
                }
                else if(recordSDK.sVersion=="10.14.1")
                {
                    recordXcode.sVersion="10.1";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2.1";
                }
                else if(recordSDK.sVersion=="10.14.4")
                {
                    recordXcode.sVersion="10.2-10.2.1";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0-5.0.1";
                }
                else if(recordSDK.sVersion=="10.14.6")
                {
                    recordXcode.sVersion="10.3";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0.1";
                }
                else if(recordSDK.sVersion=="10.15.0")
                {
                    recordXcode.sVersion="11.0-11.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1";
                }
                else if (recordSDK.sVersion=="10.15.1")
                {
                    recordXcode.sVersion="11.2-11.2.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1.2";
                }
                else if (recordSDK.sVersion=="10.15.2")
                {
                    recordXcode.sVersion="11.3-11.3.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1.3";
                }
                else if (recordSDK.sVersion=="10.15.4")
                {
                    recordXcode.sVersion="11.4-11.5";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2-5.2.4";
                }
                else if (recordSDK.sVersion=="10.15.6")
                {
                    recordXcode.sVersion="11.6-12.1.1";
                    recordCLANG.sVersion="11.0.3-12.0.0";
                    recordSwift.sVersion="5.2.4-5.3";
                }
                else if (recordSDK.sVersion=="11.0.0")
                {
                    recordXcode.sVersion="12.2";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.1";
                }
                else if (recordSDK.sVersion=="11.1.0")
                {
                    recordXcode.sVersion="12.3-12.4";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.2";
                }
                else if (recordSDK.sVersion=="11.3.0")
                {
                    recordXcode.sVersion="12.5-13.0";
                    recordCLANG.sVersion="12.0.5-13.0.0";
                    recordSwift.sVersion="5.4-5.5";
                }
                else if (recordSDK.sVersion=="12.0.0")
                {
                    recordXcode.sVersion="13.1";
                    recordCLANG.sVersion="13.0.0";
                    recordSwift.sVersion="5.5.1";
                }
            }
            else if(recordSDK.name==SpecAbstract::RECORD_NAME_IOSSDK)
            {
                if(recordSDK.sVersion=="2.0.0")
                {
                    recordXcode.sVersion="3.0.0-3.2.1";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                }
                else if (recordSDK.sVersion=="3.1.3")
                {
                    recordXcode.sVersion="3.1.3-3.2.1";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                }
                else if (recordSDK.sVersion=="3.2.0")
                {
                    recordXcode.sVersion="3.2.2-3.2.4";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.0.2-1.5";
                }
                else if (recordSDK.sVersion=="4.0.0")
                {
                    recordXcode.sVersion="3.2.3";
                    recordGCC.name=SpecAbstract::RECORD_NAME_GCC;
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.5";
                }
                else if(recordSDK.sVersion=="4.1.0")
                {
                    recordXcode.sVersion="3.2.4";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.5";
                }
                else if (recordSDK.sVersion=="4.2.0")
                {
                    recordXcode.sVersion="3.2.5";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.6";
                }
                else if (recordSDK.sVersion=="4.3.0")
                {
                    recordXcode.sVersion="3.2.6-4.0.1";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="1.7-2.0";
                }
                else if(recordSDK.sVersion=="4.3.2")
                {
                    recordXcode.sVersion="4.0.2-4.1.1";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="2.0-2.1";
                }
                else if (recordSDK.sVersion=="4.5.0")
                {
                    recordXcode.sVersion="4.2-4.3";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="2.0-3.1";
                }
                else if (recordSDK.sVersion=="5.1.0")
                {
                    recordXcode.sVersion="4.3.1-4.4.1";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="3.1-4.0";
                }
                else if(recordSDK.sVersion=="6.0.0")
                {
                    recordXcode.sVersion="4.5-4.5.2";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="4.1";
                }
                else if (recordSDK.sVersion=="6.1.0")
                {
                    recordXcode.sVersion="4.6-4.6.3";
                    recordGCC.sVersion="4.0-4.2";
                    recordCLANG.sVersion="4.2";
                }
                else if (recordSDK.sVersion=="7.0.0")
                {
                    recordXcode.sVersion="5.0";
                    recordCLANG.sVersion="5.0";
                }
                else if (recordSDK.sVersion=="7.0.3")
                {
                    recordXcode.sVersion="5.0.1-5.0.2";
                    recordCLANG.sVersion="5.0";
                }
                else if (recordSDK.sVersion=="7.1.0")
                {
                    recordXcode.sVersion="5.1-5.1.1";
                    recordCLANG.sVersion="5.1";
                }
                else if (recordSDK.sVersion=="8.0.0")
                {
                    recordXcode.sVersion="6.0.1";
                    recordCLANG.sVersion="6.0";
                    recordSwift.sVersion="1.0";
                }
                else if (recordSDK.sVersion=="8.1.0")
                {
                    recordXcode.sVersion="6.1-6.1.1";
                    recordCLANG.sVersion="6.0";
                    recordSwift.sVersion="1.1";
                }
                else if (recordSDK.sVersion=="8.2.0")
                {
                    recordXcode.sVersion="6.2";
                    recordCLANG.sVersion="6.0";
                    recordSwift.sVersion="1.1";
                }
                else if (recordSDK.sVersion=="8.3.0")
                {
                    recordXcode.sVersion="6.3-6.3.2";
                    recordCLANG.sVersion="6.1.0";
                    recordSwift.sVersion="1.2";
                }
                else if (recordSDK.sVersion=="8.4.0")
                {
                    recordXcode.sVersion="6.4";
                    recordCLANG.sVersion="6.1.0";
                    recordSwift.sVersion="1.2";
                }
                else if (recordSDK.sVersion=="9.0.0")
                {
                    recordXcode.sVersion="7.0-7.0.1";
                    recordCLANG.sVersion="7.0.0";
                    recordSwift.sVersion="2.0";
                }
                else if (recordSDK.sVersion=="9.1.0")
                {
                    recordXcode.sVersion="7.1-7.1.1";
                    recordCLANG.sVersion="7.0.0";
                    recordSwift.sVersion="2.1";
                }
                else if (recordSDK.sVersion=="9.2.0")
                {
                    recordXcode.sVersion="7.2-7.2.1";
                    recordCLANG.sVersion="7.0.2";
                    recordSwift.sVersion="2.1.1";
                }
                else if (recordSDK.sVersion=="9.3.0")
                {
                    recordXcode.sVersion="7.3-7.3.1";
                    recordCLANG.sVersion="7.3.0";
                    recordSwift.sVersion="2.2";
                }
                else if(recordSDK.sVersion=="10.0.0")
                {
                    recordXcode.sVersion="8.0";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0";
                }
                else if(recordSDK.sVersion=="10.1.0")
                {
                    recordXcode.sVersion="8.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.1";
                }
                else if(recordSDK.sVersion=="10.2.0")
                {
                    recordXcode.sVersion="8.2-8.2.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.2";
                }
                else if(recordSDK.sVersion=="10.3.0")
                {
                    recordXcode.sVersion="8.3-8.3.2";
                    recordCLANG.sVersion="8.1.0";
                    recordSwift.sVersion="3.1";
                }
                else if(recordSDK.sVersion=="10.3.1")
                {
                    recordXcode.sVersion="8.3.3";
                    recordCLANG.sVersion="8.1.0";
                    recordSwift.sVersion="3.1";
                }
                else if(recordSDK.sVersion=="11.0.0")
                {
                    recordXcode.sVersion="9.0-9.0.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0";
                }
                else if(recordSDK.sVersion=="11.1.0")
                {
                    recordXcode.sVersion="9.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.2";
                }
                else if(recordSDK.sVersion=="11.2.0")
                {
                    recordXcode.sVersion="9.2";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.3";
                }
                else if(recordSDK.sVersion=="11.3.0")
                {
                    recordXcode.sVersion="9.3-9.3.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1";
                }
                else if(recordSDK.sVersion=="11.4.0")
                {
                    recordXcode.sVersion="9.4-9.4.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1.2";
                }
                else if(recordSDK.sVersion=="12.0.0")
                {
                    recordXcode.sVersion="10.0";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2";
                }
                else if(recordSDK.sVersion=="12.1.0")
                {
                    recordXcode.sVersion="10.1";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2.1";
                }
                else if(recordSDK.sVersion=="12.2.0")
                {
                    recordXcode.sVersion="10.2-10.2.1";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0-5.0.1";
                }
                else if(recordSDK.sVersion=="12.4.0")
                {
                    recordXcode.sVersion="10.3";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0.1";
                }
                else if(recordSDK.sVersion=="13.0.0")
                {
                    recordXcode.sVersion="11.0";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1";
                }
                else if (recordSDK.sVersion=="13.1.0")
                {
                    recordXcode.sVersion="11.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1";
                }
                else if (recordSDK.sVersion=="13.2.0")
                {
                    recordXcode.sVersion="11.2-11.3.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1.2-5.1.3";
                }
                else if (recordSDK.sVersion=="13.4.0")
                {
                    recordXcode.sVersion="11.4-11.4.1";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2-5.2.2";
                }
                else if (recordSDK.sVersion=="13.5.0")
                {
                    recordXcode.sVersion="11.5";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2.4";
                }
                else if (recordSDK.sVersion=="13.6.0")
                {
                    recordXcode.sVersion="11.6";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2.4";
                }
                else if (recordSDK.sVersion=="13.7.0")
                {
                    recordXcode.sVersion="11.7";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2.4";
                }
                else if (recordSDK.sVersion=="14.0.0")
                {
                    recordXcode.sVersion="12.0-12.0.1";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3";
                }
                else if (recordSDK.sVersion=="14.1.0")
                {
                    recordXcode.sVersion="12.1";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3";
                }
                else if (recordSDK.sVersion=="14.2.0")
                {
                    recordXcode.sVersion="12.1.1-12.2";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3-5.3.1";
                }
                else if (recordSDK.sVersion=="14.3.0")
                {
                    recordXcode.sVersion="12.3";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.2";
                }
                else if (recordSDK.sVersion=="14.4.0")
                {
                    recordXcode.sVersion="12.4";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.2";
                }
                else if (recordSDK.sVersion=="14.5.0")
                {
                    recordXcode.sVersion="12.5-12.5.1";
                    recordCLANG.sVersion="12.0.5";
                    recordSwift.sVersion="5.4-5.4.2";
                }
                else if (recordSDK.sVersion=="15.0.0")
                {
                    recordXcode.sVersion="13.0-13.1";
                    recordCLANG.sVersion="13.0.0";
                    recordSwift.sVersion="5.5-5.5.1";
                }
            }
            else if(recordSDK.name==SpecAbstract::RECORD_NAME_WATCHOSSDK)
            {
                if(recordSDK.sVersion=="2.0.0")
                {
                    recordXcode.sVersion="7.0-7.1.1";
                    recordCLANG.sVersion="7.0.0";
                    recordSwift.sVersion="2.0-2.1";
                }
                else if(recordSDK.sVersion=="2.1.0")
                {
                    recordXcode.sVersion="7.2-7.2.1";
                    recordCLANG.sVersion="7.0.2";
                    recordSwift.sVersion="2.1.1";
                }
                else if(recordSDK.sVersion=="2.2.0")
                {
                    recordXcode.sVersion="7.3-7.3.1";
                    recordCLANG.sVersion="7.3.0";
                    recordSwift.sVersion="2.2";
                }
                else if(recordSDK.sVersion=="3.0.0")
                {
                    recordXcode.sVersion="8.0";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0";
                }
                else if(recordSDK.sVersion=="3.1.0")
                {
                    recordXcode.sVersion="8.1-8.2.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.1-3.0.2";
                }
                else if(recordSDK.sVersion=="3.2.0")
                {
                    recordXcode.sVersion="8.3-8.3.3";
                    recordCLANG.sVersion="8.1.0";
                    recordSwift.sVersion="3.1";
                }
                else if(recordSDK.sVersion=="4.0.0")
                {
                    recordXcode.sVersion="9.0-9.0.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0";
                }
                else if(recordSDK.sVersion=="4.1.0")
                {
                    recordXcode.sVersion="9.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.2";
                }
                else if(recordSDK.sVersion=="4.2.0")
                {
                    recordXcode.sVersion="9.2";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.3";
                }
                else if(recordSDK.sVersion=="4.3.0")
                {
                    recordXcode.sVersion="9.3-9.4.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1-4.1.2";
                }
                else if(recordSDK.sVersion=="5.0.0")
                {
                    recordXcode.sVersion="10.0";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2";
                }
                else if(recordSDK.sVersion=="5.1.0")
                {
                    recordXcode.sVersion="10.1";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2.1";
                }
                else if(recordSDK.sVersion=="5.2.0")
                {
                    recordXcode.sVersion="10.2-10.2.1";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0-5.0.1";
                }
                else if(recordSDK.sVersion=="5.3.0")
                {
                    recordXcode.sVersion="10.3";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0.1";
                }
                else if(recordSDK.sVersion=="6.0.0")
                {
                    recordXcode.sVersion="11.0-11.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1";
                }
                else if (recordSDK.sVersion=="6.1.0")
                {
                    recordXcode.sVersion="11.2-11.3.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1.2-5.1.3";
                }
                else if (recordSDK.sVersion=="6.2.0")
                {
                    recordXcode.sVersion="11.4-11.7";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2-5.2.4";
                }
                else if (recordSDK.sVersion=="7.0.0")
                {
                    recordXcode.sVersion="12.0-12.1";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3";
                }
                else if (recordSDK.sVersion=="7.1.0")
                {
                    recordXcode.sVersion="12.1.1-12.2";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3-5.3.1";
                }
                else if (recordSDK.sVersion=="7.2.0")
                {
                    recordXcode.sVersion="12.3-12.4";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.2";
                }
                else if (recordSDK.sVersion=="7.4.0")
                {
                    recordXcode.sVersion="12.5-12.5.1";
                    recordCLANG.sVersion="12.0.5";
                    recordSwift.sVersion="5.4-5.4.2";
                }
                else if (recordSDK.sVersion=="8.0.0")
                {
                    recordXcode.sVersion="13.0";
                    recordCLANG.sVersion="13.0.0";
                    recordSwift.sVersion="5.5";
                }
                else if (recordSDK.sVersion=="8.0.1")
                {
                    recordXcode.sVersion="13.1";
                    recordCLANG.sVersion="13.0.0";
                    recordSwift.sVersion="5.5.1";
                }
            }
            else if(recordSDK.name==SpecAbstract::RECORD_NAME_TVOS)
            {
                if(recordSDK.sVersion=="9.0.0")
                {
                    recordXcode.sVersion="7.1-7.1.1";
                    recordCLANG.sVersion="7.0.0";
                    recordSwift.sVersion="2.1";
                }
                else if(recordSDK.sVersion=="9.1.0")
                {
                    recordXcode.sVersion="7.2-7.2.1";
                    recordCLANG.sVersion="7.0.2";
                    recordSwift.sVersion="2.1.1";
                }
                else if(recordSDK.sVersion=="9.2.0")
                {
                    recordXcode.sVersion="7.3-7.3.1";
                    recordCLANG.sVersion="7.3.0";
                    recordSwift.sVersion="2.2";
                }
                else if(recordSDK.sVersion=="10.0.0")
                {
                    recordXcode.sVersion="8.0-8.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0-3.0.1";
                }
                else if(recordSDK.sVersion=="10.1.0")
                {
                    recordXcode.sVersion="8.2-8.2.1";
                    recordCLANG.sVersion="8.0.0";
                    recordSwift.sVersion="3.0.2";
                }
                else if(recordSDK.sVersion=="10.2.0")
                {
                    recordXcode.sVersion="8.3-8.3.3";
                    recordCLANG.sVersion="8.1.0";
                    recordSwift.sVersion="3.1";
                }
                else if(recordSDK.sVersion=="11.0.0")
                {
                    recordXcode.sVersion="9.0-9.0.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0";
                }
                else if(recordSDK.sVersion=="11.1.0")
                {
                    recordXcode.sVersion="9.1";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.2";
                }
                else if(recordSDK.sVersion=="11.2.0")
                {
                    recordXcode.sVersion="9.2";
                    recordCLANG.sVersion="9.0.0";
                    recordSwift.sVersion="4.0.3";
                }
                else if(recordSDK.sVersion=="11.3.0")
                {
                    recordXcode.sVersion="9.3-9.3.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1";
                }
                else if(recordSDK.sVersion=="11.4.0")
                {
                    recordXcode.sVersion="9.4-9.4.1";
                    recordCLANG.sVersion="9.1.0";
                    recordSwift.sVersion="4.1.2";
                }
                else if(recordSDK.sVersion=="12.0.0")
                {
                    recordXcode.sVersion="10.0";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2";
                }
                else if(recordSDK.sVersion=="12.1.0")
                {
                    recordXcode.sVersion="10.1";
                    recordCLANG.sVersion="10.0.0";
                    recordSwift.sVersion="4.2.1";
                }
                else if(recordSDK.sVersion=="12.2.0")
                {
                    recordXcode.sVersion="10.2-10.2.1";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0-5.0.1";
                }
                else if(recordSDK.sVersion=="12.4.0")
                {
                    recordXcode.sVersion="10.3";
                    recordCLANG.sVersion="10.0.1";
                    recordSwift.sVersion="5.0.1";
                }
                else if(recordSDK.sVersion=="13.0.0")
                {
                    recordXcode.sVersion="11.0-11.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1";
                }
                else if(recordSDK.sVersion=="13.2.0")
                {
                    recordXcode.sVersion="11.2-11.3.1";
                    recordCLANG.sVersion="11.0.0";
                    recordSwift.sVersion="5.1.2-5.1.3";
                }
                else if (recordSDK.sVersion=="13.4.0")
                {
                    recordXcode.sVersion="11.4-11.7";
                    recordCLANG.sVersion="11.0.3";
                    recordSwift.sVersion="5.2-5.2.4";
                }
                else if (recordSDK.sVersion=="14.0.0")
                {
                    recordXcode.sVersion="12.0-12.1";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3";
                }
                else if (recordSDK.sVersion=="14.2.0")
                {
                    recordXcode.sVersion="12.1.1-12.2";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3-5.3.1";
                }
                else if (recordSDK.sVersion=="14.3.0")
                {
                    recordXcode.sVersion="12.3-12.4";
                    recordCLANG.sVersion="12.0.0";
                    recordSwift.sVersion="5.3.2";
                }
                else if (recordSDK.sVersion=="14.5.0")
                {
                    recordXcode.sVersion="12.5-12.5.1";
                    recordCLANG.sVersion="12.0.5";
                    recordSwift.sVersion="5.4-5.4.2";
                }
                else if (recordSDK.sVersion=="15.0.0")
                {
                    recordXcode.sVersion="13.0-13.1";
                    recordCLANG.sVersion="13.0.0";
                    recordSwift.sVersion="5.5-5.5.1";
                }
            }
        }

        // Qt
        if(XMACH::isLibraryRecordNamePresent("QtCore",&(pMACHInfo->listLibraryRecords)))
        {
            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName("QtCore",&(pMACHInfo->listLibraryRecords));

            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_QT;
            recordSS.sVersion=XBinary::get_uint32_full_version(lr.current_version);

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
        // Carbon
        if(XMACH::isLibraryRecordNamePresent("Carbon",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Carbon");

            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_CARBON;

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
        // Cocoa
        if(XMACH::isLibraryRecordNamePresent("Cocoa",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Cocoa");

            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_COCOA;

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }

        // Foundation
        if(XMACH::isLibraryRecordNamePresent("CoreFoundation",&(pMACHInfo->listLibraryRecords)))
        {
            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_FOUNDATION;
            recordSS.sVersion=XBinary::get_uint32_full_version(XMACH::getLibraryCurrentVersion("CoreFoundation",&(pMACHInfo->listLibraryRecords)));

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }

        if( (recordGCC.name==SpecAbstract::RECORD_NAME_UNKNOWN)&&
            (recordCLANG.name==SpecAbstract::RECORD_NAME_UNKNOWN))
        {
            recordCLANG.name=SpecAbstract::RECORD_NAME_CLANG; // Default
        }

        if(recordGCC.name!=SpecAbstract::RECORD_NAME_UNKNOWN)
        {
            pMACHInfo->mapResultCompilers.insert(recordGCC.name,scansToScan(&(pMACHInfo->basic_info),&recordGCC));
        }

        if(recordCLANG.name!=SpecAbstract::RECORD_NAME_UNKNOWN)
        {
            pMACHInfo->mapResultCompilers.insert(recordCLANG.name,scansToScan(&(pMACHInfo->basic_info),&recordCLANG));
        }

        if(recordSwift.name!=SpecAbstract::RECORD_NAME_UNKNOWN)
        {
            pMACHInfo->mapResultCompilers.insert(recordSwift.name,scansToScan(&(pMACHInfo->basic_info),&recordSwift));
        }

        if(recordSDK.name!=SpecAbstract::RECORD_NAME_UNKNOWN)
        {
            pMACHInfo->mapResultTools.insert(recordSDK.name,scansToScan(&(pMACHInfo->basic_info),&recordSDK));
        }

        if(recordXcode.name!=SpecAbstract::RECORD_NAME_UNKNOWN)
        {
            pMACHInfo->mapResultTools.insert(recordXcode.name,scansToScan(&(pMACHInfo->basic_info),&recordXcode));
        }
    }
}

void SpecAbstract::MACHO_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo)
{
    XMACH mach(pDevice,bIsImage);

    if(mach.isValid())
    {
        // VMProtect
        if(XMACH::isLibraryRecordNamePresent("libVMProtectSDK.dylib",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"libVMProtectSDK.dylib");

            _SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_PROTECTOR;
            recordSS.name=SpecAbstract::RECORD_NAME_VMPROTECT;

            pMACHInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::MACHO_handle_FixDetects(QIODevice *pDevice, bool bIsImage, SpecAbstract::MACHOINFO_STRUCT *pMACHInfo)
{
    XMACH mach(pDevice,bIsImage);

    if(mach.isValid())
    {
        if( pMACHInfo->mapResultLanguages.contains(RECORD_NAME_OBJECTIVEC)||
            pMACHInfo->mapResultLanguages.contains(RECORD_NAME_CCPP))
        {
            pMACHInfo->mapResultLanguages.remove(RECORD_NAME_CCPP);
        }

        if(pMACHInfo->basic_info.bIsTest)
        {
            QMap<quint64,QString> mapCommands=XMACH::getLoadCommandTypesS();

            QList<XMACH::COMMAND_RECORD> list=mach.getCommandRecords();

            QSet<quint32> stRecords;

            for(int i=0;i<list.count();i++)
            {
                if(!stRecords.contains(list.at(i).nType))
                {
                    _SCANS_STRUCT recordSS={};

                    recordSS.type=RECORD_TYPE_LIBRARY;
                    recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN9+i+1);
                    recordSS.sVersion=mapCommands.value(list.at(i).nType);

                    pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));

                    stRecords.insert(list.at(i).nType);
                }
            }
        }
    }
}

void SpecAbstract::MACHO_handleLanguages(QIODevice *pDevice, bool bIsImage, MACHOINFO_STRUCT *pMACHInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pMACHInfo->mapResultLinkers),&(pMACHInfo->mapResultLanguages));
    getLanguage(&(pMACHInfo->mapResultCompilers),&(pMACHInfo->mapResultLanguages));
    getLanguage(&(pMACHInfo->mapResultLibraries),&(pMACHInfo->mapResultLanguages));
    getLanguage(&(pMACHInfo->mapResultTools),&(pMACHInfo->mapResultLanguages));

    fixLanguage(&(pMACHInfo->mapResultLanguages));
}

void SpecAbstract::LE_handle_Microsoft(QIODevice *pDevice, bool bIsImage, LEINFO_STRUCT *pLEInfo, bool *pbIsStop)
{
    XLE le(pDevice,bIsImage);

    if(le.isValid())
    {
        _SCANS_STRUCT recordLinker={};
        _SCANS_STRUCT recordCompiler={};

        if((pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))&&(!pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)))
        {
            recordLinker.type=RECORD_TYPE_LINKER;
            recordLinker.name=RECORD_NAME_MICROSOFTLINKER;
        }

        // Rich
        int nRichSignaturesCount=pLEInfo->listRichSignatures.count();

        if(nRichSignaturesCount)
        {
            recordLinker.name=RECORD_NAME_MICROSOFTLINKER;
            recordLinker.type=SpecAbstract::RECORD_TYPE_LINKER;
        }

        QList<_SCANS_STRUCT> listRichDescriptions;

        for(int i=0;i<nRichSignaturesCount;i++)
        {
            listRichDescriptions.append(MSDOS_richScan(pLEInfo->listRichSignatures.at(i).nId,pLEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pLEInfo->basic_info.id.fileType,XBinary::FT_MSDOS,&(pLEInfo->basic_info),DETECTTYPE_RICH,pbIsStop));
        }

        int nRichDescriptionsCount=listRichDescriptions.count();

        for(int i=nRichDescriptionsCount-1;i>=0;i--)
        {
            if(listRichDescriptions.at(i).type==SpecAbstract::RECORD_TYPE_LINKER)
            {
                recordLinker.name=listRichDescriptions.at(i).name;
                recordLinker.sVersion=listRichDescriptions.at(i).sVersion;
                recordLinker.sInfo=listRichDescriptions.at(i).sInfo;
                recordLinker.type=listRichDescriptions.at(i).type;
            }

            if(listRichDescriptions.at(i).type==SpecAbstract::RECORD_TYPE_COMPILER)
            {
                if(listRichDescriptions.at(i).name==RECORD_NAME_UNIVERSALTUPLECOMPILER)
                {
                    recordCompiler.name=RECORD_NAME_VISUALCCPP;
                    recordCompiler.sVersion=listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo=listRichDescriptions.at(i).sInfo;
                    recordCompiler.type=listRichDescriptions.at(i).type;
                }
                else
                {
                    recordCompiler.name=listRichDescriptions.at(i).name;
                    recordCompiler.sVersion=listRichDescriptions.at(i).sVersion;
                    recordCompiler.sInfo=listRichDescriptions.at(i).sInfo;
                    recordCompiler.type=listRichDescriptions.at(i).type;
                }
            }
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pLEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pLEInfo->basic_info),&recordLinker));
        }

        if(recordCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pLEInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pLEInfo->basic_info),&recordCompiler));
        }
    }
}

void SpecAbstract::LE_handle_Borland(QIODevice *pDevice, bool bIsImage, SpecAbstract::LEINFO_STRUCT *pLEInfo)
{
    XLE le(pDevice,bIsImage);

    if(le.isValid())
    {
        _SCANS_STRUCT recordLinker={};

        if(pLEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER))
        {
            _SCANS_STRUCT ss=pLEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi=get_TurboLinker_vi(pDevice,bIsImage);

            if(vi.bIsValid)
            {
                ss.sVersion=vi.sVersion;
            }

            recordLinker=ss;
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pLEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pLEInfo->basic_info),&recordLinker));
        }
    }
}

void SpecAbstract::LE_handleLanguages(QIODevice *pDevice, bool bIsImage, LEINFO_STRUCT *pLEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pLEInfo->mapResultLinkers),&(pLEInfo->mapResultLanguages));
    getLanguage(&(pLEInfo->mapResultCompilers),&(pLEInfo->mapResultLanguages));
    getLanguage(&(pLEInfo->mapResultLibraries),&(pLEInfo->mapResultLanguages));
    getLanguage(&(pLEInfo->mapResultTools),&(pLEInfo->mapResultLanguages));

    fixLanguage(&(pLEInfo->mapResultLanguages));
}

void SpecAbstract::NE_handle_Borland(QIODevice *pDevice, bool bIsImage, SpecAbstract::NEINFO_STRUCT *pNEInfo)
{
    XNE ne(pDevice,bIsImage);

    if(ne.isValid())
    {
        _SCANS_STRUCT recordLinker={};

        if(pNEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER))
        {
            _SCANS_STRUCT ss=pNEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi=get_TurboLinker_vi(pDevice,bIsImage);

            if(vi.bIsValid)
            {
                ss.sVersion=vi.sVersion;
            }

            recordLinker=ss;
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pNEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pNEInfo->basic_info),&recordLinker));
        }
    }
}

void SpecAbstract::NE_handleLanguages(QIODevice *pDevice, bool bIsImage, NEINFO_STRUCT *pNEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    getLanguage(&(pNEInfo->mapResultLinkers),&(pNEInfo->mapResultLanguages));
    getLanguage(&(pNEInfo->mapResultCompilers),&(pNEInfo->mapResultLanguages));
    getLanguage(&(pNEInfo->mapResultLibraries),&(pNEInfo->mapResultLanguages));
    getLanguage(&(pNEInfo->mapResultTools),&(pNEInfo->mapResultLanguages));

    fixLanguage(&(pNEInfo->mapResultLanguages));
}

void SpecAbstract::DEX_handle_Tools(QIODevice *pDevice, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, bool *pbIsStop)
{
    Q_UNUSED(pbIsStop)

    XDEX dex(pDevice);

    if(dex.isValid())
    {
        _SCANS_STRUCT recordAndroidSDK=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDSDK,"","",0);
        _SCANS_STRUCT recordAndroid=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_OPERATIONSYSTEM,RECORD_NAME_ANDROID,"","",0);

        QString sDDEXVersion=dex.getVersion();

        // https://source.android.com/devices/tech/dalvik/dex-format
        if(sDDEXVersion=="035")
        {
            recordAndroidSDK.sVersion="API 14";
            recordAndroid.sVersion=getAndroidVersionFromApi(14);
        }
//        else if (sDDEXVersion=="036")
//        {
//            // Due to a Dalvik bug present in older versions of Android, Dex version 036 has been skipped.
//            // Dex version 036 is not valid for any version of Android and never will be.
//        }
        else if(sDDEXVersion=="037")
        {
            recordAndroidSDK.sVersion="API 24";
            recordAndroid.sVersion=getAndroidVersionFromApi(24);
        }
        else if(sDDEXVersion=="038")
        {
            recordAndroidSDK.sVersion="API 26";
            recordAndroid.sVersion=getAndroidVersionFromApi(26);
        }
        else if(sDDEXVersion=="039")
        {
            recordAndroidSDK.sVersion="API 28";
            recordAndroid.sVersion=getAndroidVersionFromApi(28);
        }
        else
        {
            recordAndroidSDK.sVersion=sDDEXVersion;
        }

        pDEXInfo->mapResultTools.insert(recordAndroidSDK.name,scansToScan(&(pDEXInfo->basic_info),&recordAndroidSDK));

        if(recordAndroid.sVersion!="")
        {
            pDEXInfo->mapResultOperationSystems.insert(recordAndroid.name,scansToScan(&(pDEXInfo->basic_info),&recordAndroid));
        }

        QList<XDEX_DEF::MAP_ITEM> listMaps=dex.getMapItems();

//        int nNumberOfMapItems=listMaps.count();

        // dx
        // https://github.com/aosp-mirror/platform_dalvik/blob/master/dx/src/com/android/dx/dex/file/DexFile.java#L122
//        QList<quint16> listDx;
//        listDx.append(XDEX_DEF::TYPE_HEADER_ITEM);
//        listDx.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
//        listDx.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
//        listDx.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
//        listDx.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
//        listDx.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
//        listDx.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
//        listDx.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);  // Optional API 26+
//        listDx.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM); // Optional API 26+
//        listDx.append(XDEX_DEF::TYPE_CODE_ITEM);
//        listDx.append(XDEX_DEF::TYPE_TYPE_LIST);
//        listDx.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
//        listDx.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
//        listDx.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
//        listDx.append(XDEX_DEF::TYPE_MAP_LIST);
        QList<quint16> listDx;
        listDx.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDx.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDx.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDx.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);  // Optional API 26+
        listDx.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM); // Optional API 26+
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDx.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDx.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDx.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDx.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDx.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDx.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDx.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDx.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDx.append(XDEX_DEF::TYPE_MAP_LIST);

        // DexLib
        // https://android.googlesource.com/platform/external/smali/+/9a12fbef9912a824a4824e392f0d2fdd5319f580/dexlib/src/main/java/org/jf/dexlib/DexFile.java?autodive=0%2F#210
        QList<quint16> listDexLib;
        listDexLib.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexLib.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexLib.append(XDEX_DEF::TYPE_MAP_LIST);

        // dexlib2
        // https://github.com/JesusFreke/smali/blob/master/dexlib2/src/main/java/org/jf/dexlib2/writer/DexWriter.java#L1465
        QList<quint16> listDexLib2;
        listDexLib2.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexLib2.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDexLib2.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexLib2.append(XDEX_DEF::TYPE_HIDDENAPI_CLASS_DATA_ITEM);   // Optional
        listDexLib2.append(XDEX_DEF::TYPE_MAP_LIST);

        QList<quint16> listDexLib2heur;
        listDexLib2heur.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexLib2heur.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);

        // r8
        // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/FileWriter.java#752
        QList<quint16> listR8;
        listR8.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listR8.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listR8.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listR8.append(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM);  // Optional
        listR8.append(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM);  // Optional
        listR8.append(XDEX_DEF::TYPE_CODE_ITEM);
        listR8.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listR8.append(XDEX_DEF::TYPE_TYPE_LIST);
        listR8.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listR8.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listR8.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listR8.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);  // Check
        listR8.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);
        listR8.append(XDEX_DEF::TYPE_MAP_LIST);

        // DexMerge
        // https://github.com/aosp-mirror/platform_dalvik/blob/master/dx/src/com/android/dx/merge/DexMerger.java#L95
        QList<quint16> listDexMerge;
        listDexMerge.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_MAP_LIST);
        listDexMerge.append(XDEX_DEF::TYPE_TYPE_LIST);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_SET_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_CODE_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_DEBUG_INFO_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATION_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM);
        listDexMerge.append(XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM);

        // fast-proxy
        // https://github.com/int02h/fast-proxy/blob/master/fastproxy/src/main/java/com/dpforge/fastproxy/dex/writer/DexWriter.java#L57
        // TODO more researches
        QList<quint16> listFastProxy;
        listFastProxy.append(XDEX_DEF::TYPE_HEADER_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_STRING_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_TYPE_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_PROTO_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_FIELD_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_METHOD_ID_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_CLASS_DEF_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_STRING_DATA_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_TYPE_LIST);
        listFastProxy.append(XDEX_DEF::TYPE_CODE_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_CLASS_DATA_ITEM);
        listFastProxy.append(XDEX_DEF::TYPE_MAP_LIST);

        // TODO Check https://github.com/facebookexperimental/r8
        // TODO https://github.com/davidbrazdil/dexter-backup/blob/e09c9397aa727f6180799254fb08e15955c1a89e/src/org/jf/dexlib/DexFromMemory.java
        // TODO https://github.com/rchiossi/dexterity/blob/ce66ca62a6df4c6d913bdde1d7d91f5fa90ff916/dx/dxlib.py#L505
        // TODO https://github.com/rchiossi/dexterity/blob/ce66ca62a6df4c6d913bdde1d7d91f5fa90ff916/lib/dex_builder.c#L404
        // TODO redex https://github.com/lzoghbi/thesis
        // TODO https://github.com/zyq8709/DexHunter/tree/master/dalvik/dx

        // https://r8.googlesource.com/r8/+/refs/heads/master/src/main/java/com/android/tools/r8/dex/Marker.java
        // Example: X~~D8{"compilation-mode":"release","has-checksums":false,"min-api":14,"version":"2.0.88"}

        VI_STRUCT viR8=get_R8_marker_vi(pDevice,false,0,pDEXInfo->basic_info.nSize);
        bool bR8_map=XDEX::compareMapItems(&listMaps,&listR8);
        bool bDX_map=XDEX::compareMapItems(&listMaps,&listDx);
//        bool bDexLib_map=XDEX::compareMapItems(&listMaps,&listDexLib);
        bool bDexLib2_map=XDEX::compareMapItems(&listMaps,&listDexLib2);
        bool bDexLib2heur_map=XDEX::compareMapItems(&listMaps,&listDexLib2heur);
        bool bDexMerge_map=XDEX::compareMapItems(&listMaps,&listDexMerge);
        bool bFastProxy_map=XDEX::compareMapItems(&listMaps,&listFastProxy);

        if(viR8.bIsValid)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_R8,"","",0);
            recordCompiler.sVersion=viR8.sVersion;
            recordCompiler.sInfo=viR8.sInfo;
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(!(pDEXInfo->bIsStringPoolSorted))
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_DEXLIB,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(bDX_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_DX,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(bDexLib2_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_DEXLIB2,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(bR8_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_R8,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(bDexLib2heur_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_DEXLIB2,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }
        else if(bFastProxy_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_FASTPROXY,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }

        if(bDexMerge_map)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_DEXMERGE,"","",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }

        if(viR8.bIsValid&&(!bR8_map))
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_R8,"","",0);
            recordCompiler.sVersion=viR8.sVersion;
            recordCompiler.sInfo=append(recordCompiler.sInfo,"CHECK !!!");
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }

        if(pDEXInfo->basic_info.bIsDeepScan)
        {
            qint32 nJackIndex=dex.getStringNumberFromListExp(&(pDEXInfo->listStrings),"^emitter: jack");

            if(nJackIndex!=-1)
            {
                _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_JACK,"","",0);
                recordCompiler.sVersion=pDEXInfo->listStrings.at(nJackIndex).section("-",1,-1);
                pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
            }
        }

        if(pDEXInfo->mapResultCompilers.size()==0)
        {
            _SCANS_STRUCT recordCompiler=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_COMPILER,RECORD_NAME_UNKNOWN,QString("%1").arg(dex.getMapItemsHash()),"",0);
            pDEXInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pDEXInfo->basic_info),&recordCompiler));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_APKTOOLPLUS))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_APKTOOLPLUS);
            pDEXInfo->mapResultTools.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_UNICOMSDK))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_UNICOMSDK);
            pDEXInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->basic_info.bIsDeepScan)
        {
            bool bIsFieldNamesUnicode=dex.isFieldNamesUnicode(&(pDEXInfo->listFieldIDs),&(pDEXInfo->listStrings));
            bool bIsMethodNamesUnicode=dex.isMethodNamesUnicode(&(pDEXInfo->listMethodIDs),&(pDEXInfo->listStrings));

            bool bInvalidHeaderSize=(pDEXInfo->header.header_size!=0x70);
            bool bLink=(pDEXInfo->header.link_off||pDEXInfo->header.link_size);

            QString sOverlay;

            if(pDEXInfo->basic_info.bIsTest)
            {
                sOverlay=QString("Maps %1").arg(dex.getMapItemsHash());

                if(pDEXInfo->bIsOverlayPresent)
                {
                    sOverlay=append(sOverlay,"Overlay");
                }

                if(bInvalidHeaderSize)
                {
                    sOverlay=append(sOverlay,"Invalid header size");
                }

                if(bLink)
                {
                    sOverlay=append(sOverlay,QString("Invalid Link(%1,%2)").arg(pDEXInfo->header.link_size).arg(pDEXInfo->header.link_off));
                }

                if(bIsFieldNamesUnicode)
                {
                    sOverlay=append(sOverlay,"bIsFieldNamesUnicode");
                }

                if(bIsMethodNamesUnicode)
                {
                    sOverlay=append(sOverlay,"bIsMethodNamesUnicode");
                }

                if(viR8.bIsValid)
                {
                    if(bDX_map)
                    {
                        sOverlay=append(sOverlay,"DX");
                    }

                    if(bDexLib2_map)
                    {
                        sOverlay=append(sOverlay,"DexLib2");
                    }

                    if(!(pDEXInfo->bIsStringPoolSorted))
                    {
                        sOverlay=append(sOverlay,"DexLib");
                    }

                    if(bDexMerge_map)
                    {
                        sOverlay=append(sOverlay,"DexMerge");
                    }
                }
            }

            int nNumberOfRecords=pDEXInfo->listStrings.count();

            for(int i=0;(i<nNumberOfRecords);i++)
            {
                if(pDEXInfo->basic_info.bIsTest)
                {
                    // TODO find!
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_APK,RECORD_TYPE_PROTECTOR,RECORD_NAME_UNKNOWN,"","",0);

                    if(     pDEXInfo->listStrings.at(i).contains("agconfig")||
                            pDEXInfo->listStrings.at(i).contains("AntiSkid")||
                            pDEXInfo->listStrings.at(i).contains("ALLATORI")||
                            pDEXInfo->listStrings.at(i).contains("AppSuit")||
                            pDEXInfo->listStrings.at(i).contains("appsuit")||
                            pDEXInfo->listStrings.at(i).contains("gemalto")||
                            pDEXInfo->listStrings.at(i).contains("WapperApplication")||
                            pDEXInfo->listStrings.at(i).contains("AppSealing")||
                            pDEXInfo->listStrings.at(i).contains("whitecryption")||
                            pDEXInfo->listStrings.at(i).contains("ModGuard")||
                            pDEXInfo->listStrings.at(i).contains("InjectedActivity"))
                    {
                        ss.sVersion=pDEXInfo->listStrings.at(i);
                        pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
                        ss.sInfo=append(ss.sInfo,sOverlay);

                        break;
                    }
                }
            }
        }
        // Check Ljava/lang/ClassLoader;
    }
}

void SpecAbstract::DEX_handle_Dexguard(QIODevice *pDevice, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, bool *pbIsStop)
{
    XDEX dex(pDevice);

    if(dex.isValid())
    {
        if(pDEXInfo->basic_info.bIsDeepScan)
        {
            if(XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings),"dexguard\\/",pbIsStop))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXGUARD,"","",0);
                pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
            }

            if(!pDEXInfo->mapTypeDetects.contains(RECORD_NAME_DEXGUARD))
            {
                int nNumberOfTypes=pDEXInfo->listTypeItemStrings.count();

                for(int i=0;(i<nNumberOfTypes)&&(!(*pbIsStop));i++)
                {
                    QString sType=pDEXInfo->listTypeItemStrings.at(i);

                    // TODO Check!
                    if(sType.size()<=7)
                    {
                        if(XBinary::isRegExpPresent("^Lo/",sType))
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXGUARD,"","",0);
                            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));

                            break;
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::DEX_handle_Protection(QIODevice *pDevice, SpecAbstract::DEXINFO_STRUCT *pDEXInfo, bool *pbIsStop)
{
    XDEX dex(pDevice);

    if(dex.isValid())
    {
        // DexProtect
        // 070002000000020083dc63003e000000120113000e0048000500e0000010011239022a001232d563ff0048030503d533ff00e1040608d544ff0048040504d544ff00e0040408b643e1040610d544ff0048040504d544ff00e0040410b643e1040618d544ff0048000504e0000018b6300f000d023901feff1221dd02067f48000502e100000828f50d0328cb0d000000
        if(pDEXInfo->bIsOverlayPresent)
        {
            if(dex.getOverlaySize()==0x60)
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXPROTECTOR,"","",0);
                pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
            }
        }
        else
        {
            if(pDEXInfo->basic_info.bIsDeepScan)
            {
                if(XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings),"\\/dexprotector\\/",pbIsStop))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_DEXPROTECTOR,"","",0);
                    pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
                }
            }
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_EASYPROTECTOR))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_EASYPROTECTOR);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_QDBH))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_QDBH);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_JIAGU))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_JIAGU);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_BANGCLEPROTECTION))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_BANGCLEPROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_ALLATORIOBFUSCATOR))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_ALLATORIOBFUSCATOR);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_PANGXIE))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_PANGXIE);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_NAGAPTPROTECTION))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_NAGAPTPROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_MODGUARD))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_MODGUARD);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_KIWIVERSIONOBFUSCATOR))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_KIWIVERSIONOBFUSCATOR);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_APKPROTECT))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_APKPROTECT);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }
        else
        {
            if(pDEXInfo->basic_info.bIsDeepScan)
            {
                if(XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings),"http://www.apkprotect.net/",pbIsStop))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_APKPROTECT,"","",0);
                    pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
                }
            }
        }

        if(pDEXInfo->basic_info.bIsHeuristicScan)
        {
            if(pDEXInfo->mapStringDetects.contains(RECORD_NAME_AESOBFUSCATOR))
            {
                _SCANS_STRUCT ss=pDEXInfo->mapStringDetects.value(RECORD_NAME_AESOBFUSCATOR);
                pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
            }
            else
            {
                if(pDEXInfo->basic_info.bIsDeepScan)
                {
                    if(XBinary::isStringInListPresentExp(&(pDEXInfo->listStrings),"licensing/AESObfuscator;",pbIsStop))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_AESOBFUSCATOR,"","",0);
                        pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
                    }
                }
            }
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_BTWORKSCODEGUARD))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_BTWORKSCODEGUARD);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_QIHOO360PROTECTION)) // Check overlay
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_QIHOO360PROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_ALIBABAPROTECTION)) // Check overlay
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_ALIBABAPROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_BAIDUPROTECTION)) // Check overlay
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_BAIDUPROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_TENCENTPROTECTION)) // Check overlay
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_TENCENTPROTECTION);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_SECNEO))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_SECNEO);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_LIAPP))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_LIAPP);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_VDOG))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_VDOG);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_APPSOLID))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_APPSOLID);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_MEDUSAH))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_MEDUSAH);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_NQSHIELD))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_NQSHIELD);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_YIDUN))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_YIDUN);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->mapTypeDetects.contains(RECORD_NAME_APKENCRYPTOR))
        {
            _SCANS_STRUCT ss=pDEXInfo->mapTypeDetects.value(RECORD_NAME_APKENCRYPTOR);
            pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
        }

        if(pDEXInfo->basic_info.bIsDeepScan)
        {
            if(XBinary::isStringInListPresentExp(&(pDEXInfo->listTypeItemStrings),"\\/proguard\\/",pbIsStop))
            {
                _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_PROTECTOR,RECORD_NAME_PROGUARD,"","",0);
                pDEXInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::DEX_handleLanguages(QIODevice *pDevice, DEXINFO_STRUCT *pDEXInfo)
{
    Q_UNUSED(pDevice)

    _SCANS_STRUCT ss=getScansStruct(0,XBinary::FT_DEX,RECORD_TYPE_LANGUAGE,RECORD_NAME_DALVIK,"","",0);
    pDEXInfo->mapResultLanguages.insert(ss.name,scansToScan(&(pDEXInfo->basic_info),&ss));

    getLanguage(&(pDEXInfo->mapResultLinkers),&(pDEXInfo->mapResultLanguages));
    getLanguage(&(pDEXInfo->mapResultCompilers),&(pDEXInfo->mapResultLanguages));
    getLanguage(&(pDEXInfo->mapResultLibraries),&(pDEXInfo->mapResultLanguages));
    getLanguage(&(pDEXInfo->mapResultTools),&(pDEXInfo->mapResultLanguages));

    fixLanguage(&(pDEXInfo->mapResultLanguages));
}

//void SpecAbstract::fixDetects(SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
//    {
//        pPEInfo->basic_info.mapHeaderDetects.remove(RECORD_NAME_MICROSOFTLINKER);
//    }

//    if(pPEInfo->_mapImportDetects.contains(RECORD_NAME_C)&&pPEInfo->_mapImportDetects.contains(RECORD_NAME_VISUALCPP))
//    {
//        pPEInfo->_mapImportDetects.remove(RECORD_NAME_VISUALCPP);
//    }

//    if(pPEInfo->mapSpecialDetects.contains(RECORD_NAME_ENIGMA))
//    {
//        pPEInfo->mapEntryPointDetects.remove(RECORD_NAME_BORLANDCPP);
//    }
//}

void SpecAbstract::updateVersion(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, QString sVersion)
{
    if(pMap->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=pMap->value(name);
        record.sVersion=sVersion;
        pMap->insert(name,record);
    }
}

void SpecAbstract::updateInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, QString sInfo)
{
    if(pMap->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=pMap->value(name);
        record.sInfo=sInfo;
        pMap->insert(name,record);
    }
}

void SpecAbstract::updateVersionAndInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *pMap, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo)
{
    if(pMap->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=pMap->value(name);
        record.sVersion=sVersion;
        record.sInfo=sInfo;
        pMap->insert(name,record);
    }
}

bool SpecAbstract::isScanStructPresent(QList<SpecAbstract::SCAN_STRUCT> *pListScanStructs, XBinary::FT fileType, SpecAbstract::RECORD_TYPE type, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo)
{
    bool bResult=false;

    int nNumberOfRecords=pListScanStructs->count();

    for(int i=0;i<nNumberOfRecords;i++)
    {
        if(     ((pListScanStructs->at(i).id.fileType==fileType)||(fileType==XBinary::FT_UNKNOWN))
            &&  ((pListScanStructs->at(i).type==type)||(type==SpecAbstract::RECORD_TYPE_UNKNOWN))
            &&  ((pListScanStructs->at(i).name==name)||(name==SpecAbstract::RECORD_NAME_UNKNOWN))
            &&  ((pListScanStructs->at(i).sVersion==sVersion)||(sVersion==""))
            &&  ((pListScanStructs->at(i).sInfo==sInfo)||(sInfo=="")))
        {
            bResult=true;
            break;
        }
    }

    return bResult;
}

bool SpecAbstract::checkVersionString(QString sVersion)
{
    bool bResult=false;

    if(sVersion.trimmed()!="")
    {
        bResult=true;

        int nStringSize=sVersion.size();

        // TODO
        for(int i=0;i<nStringSize;i++)
        {
            QChar _char=sVersion.at(i);

            if((_char>=QChar('0'))&&(_char<=QChar('9')))
            {

            }
            else if(_char==QChar('.'))
            {

            }
            else
            {
                bResult=false;
                break;
            }
        }
    }

    return bResult;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_UPX_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize,XBinary::FT fileType)
{
    // TODO unknown version
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO make both
    qint64 nStringOffset1=binary.find_ansiString(nOffset,nSize,"$Id: UPX");
    qint64 nStringOffset2=binary.find_ansiString(nOffset,nSize,"UPX!");

    if(nStringOffset1!=-1)
    {
        result.bIsValid=true;

        result.sVersion=binary.read_ansiString(nStringOffset1+9,10);
        result.sVersion=result.sVersion.section(" ",0,0);

        if(!checkVersionString(result.sVersion))
        {
            result.sVersion="";
        }

        // NRV
        qint64 nNRVStringOffset1=binary.find_array(nOffset,nSize,"\x24\x49\x64\x3a\x20\x4e\x52\x56\x20",9);

        if(nNRVStringOffset1!=-1)
        {
            QString sNRVVersion=binary.read_ansiString(nNRVStringOffset1+9,10);
            sNRVVersion=sNRVVersion.section(" ",0,0);

            if(checkVersionString(sNRVVersion))
            {
                result.sInfo=QString("NRV %1").arg(sNRVVersion);
            }
        }
    }

    if(nStringOffset2!=-1)
    {
        VI_STRUCT viUPX=_get_UPX_vi(pDevice,bIsImage,nStringOffset2,0x24,fileType);

        if(viUPX.bIsValid)
        {
            result.sInfo=append(result.sInfo,viUPX.sInfo);

            if(result.sVersion=="")
            {
                result.sVersion=viUPX.sVersion;
            }
        }

        result.bIsValid=true; // TODO Check
        // TODO 1 function

        if(result.sVersion=="")
        {
            result.sVersion=binary.read_ansiString(nStringOffset2-5,4);
        }
    }

    if(!checkVersionString(result.sVersion))
    {
        result.sVersion="";
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_UPX_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize, XBinary::FT fileType)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    if(binary.isOffsetAndSizeValid(nOffset,nSize))
    {
        if(nSize>=22)
        {
            result.bIsValid=true;

            quint8 nVersion=binary.read_uint8(nOffset+4);
            quint8 nFormat=binary.read_uint8(nOffset+5);
            quint8 nMethod=binary.read_uint8(nOffset+6);
            quint8 nLevel=binary.read_uint8(nOffset+7);

            quint32 nULen=0;
            quint32 nCLen=0;
            quint32 nUAdler=0;
            quint32 nCAdler=0;
            quint32 nFileSize=0;
            quint8 nFilter=0;
            quint8 nFilterCTO=0;
            quint8 nMRU=0;
            quint8 nHeaderChecksum=0;

            if(nFormat<128)
            {
                if((nFormat==1)||(nFormat==2)) // UPX_F_DOS_COM, UPX_F_DOS_SYS
                {
                    if(nSize>=22)
                    {
                        nULen=binary.read_uint16(nOffset+16);
                        nCLen=binary.read_uint16(nOffset+18);
                        nFilter=binary.read_uint8(nOffset+20);
                        nHeaderChecksum=binary.read_uint8(nOffset+21);
                    }
                    else
                    {
                        result.bIsValid=false;
                    }
                }
                else if(nFormat==3) // UPX_F_DOS_EXE
                {
                    if(nSize>=27)
                    {
                        nULen=binary.read_uint24(nOffset+16);
                        nCLen=binary.read_uint24(nOffset+19);
                        nFileSize=binary.read_uint24(nOffset+22);
                        nFilter=binary.read_uint8(nOffset+25);
                        nHeaderChecksum=binary.read_uint8(nOffset+26);
                    }
                    else
                    {
                        result.bIsValid=false;
                    }
                }
                else
                {
                    if(nSize>=32)
                    {
                        nULen=binary.read_uint32(nOffset+16);
                        nCLen=binary.read_uint32(nOffset+20);
                        nFileSize=binary.read_uint32(nOffset+24);
                        nFilter=binary.read_uint8(nOffset+28);
                        nFilterCTO=binary.read_uint8(nOffset+29);
                        nMRU=binary.read_uint8(nOffset+30);
                        nHeaderChecksum=binary.read_uint8(nOffset+31);
                    }
                    else
                    {
                        result.bIsValid=false;
                    }
                }

                if(result.bIsValid)
                {
                    nUAdler=binary.read_uint32(nOffset+8);
                    nCAdler=binary.read_uint32(nOffset+12);
                }
            }
            else
            {
                if(nSize>=32)
                {
                    nULen=binary.read_uint32(nOffset+8,true);
                    nCLen=binary.read_uint32(nOffset+12,true);
                    nUAdler=binary.read_uint32(nOffset+16,true);
                    nCAdler=binary.read_uint32(nOffset+20,true);
                    nFileSize=binary.read_uint32(nOffset+24,true);
                    nFilter=binary.read_uint8(nOffset+28);
                    nFilterCTO=binary.read_uint8(nOffset+29);
                    nMRU=binary.read_uint8(nOffset+30);
                    nHeaderChecksum=binary.read_uint8(nOffset+31);
                }
                else
                {
                    result.bIsValid=false;
                }
            }

            Q_UNUSED(nUAdler)
            Q_UNUSED(nCAdler)
            Q_UNUSED(nFileSize)
            Q_UNUSED(nFilter)
            Q_UNUSED(nFilterCTO)
            Q_UNUSED(nMRU)
            Q_UNUSED(nHeaderChecksum)

            if(result.bIsValid)
            {
                // Check Executable formats
                if(nFormat==0)                  result.bIsValid=false;
                if((nFormat>42)&&(nFormat<129)) result.bIsValid=false;
                if(nFormat>142)                 result.bIsValid=false;
                if(nFormat==7)                  result.bIsValid=false; // UPX_F_DOS_EXEH        OBSOLETE
                if(nFormat==6)                  result.bIsValid=false; // UPX_F_VXD_LE NOT      IMPLEMENTED
                if(nFormat==11)                 result.bIsValid=false; // UPX_F_WIN16_NE NOT    IMPLEMENTED
                if(nFormat==13)                 result.bIsValid=false; // UPX_F_LINUX_SEP_i386  NOT IMPLEMENTED
                if(nFormat==17)                 result.bIsValid=false; // UPX_F_ELKS_8086 NOT   IMPLEMENTED
                if(nFormat==130)                result.bIsValid=false; // UPX_F_SOLARIS_SPARC   NOT IMPLEMENTED

                if(fileType==XBinary::FT_COM)
                {
                    if( (nFormat!=1)&&          // UPX_F_DOS_COM
                        (nFormat!=2))           // UPX_F_DOS_SYS
                    {
                        result.bIsValid=false;
                    }
                }
                else if(fileType==XBinary::FT_MSDOS)
                {
                    if( (nFormat!=3))           // UPX_F_DOS_EXE
                    {
                        result.bIsValid=false;
                    }
                }
                else if((fileType==XBinary::FT_LE)||(fileType==XBinary::FT_LX))
                {
                    if( (nFormat!=5))           // UPX_F_WATCOM_LE
                    {
                        result.bIsValid=false;
                    }
                }
                else if(fileType==XBinary::FT_PE)
                {
                    if( (nFormat!=9)&&          // UPX_F_WIN32_PE
                        (nFormat!=21)&&         // UPX_F_WINCE_ARM_PE
                        (nFormat!=36))          // UPX_F_WIN64_PEP
                    {
                        result.bIsValid=false;
                    }
                }
                else if(fileType==XBinary::FT_MACHO)
                {
                    if( (nFormat!=29)&&         // UPX_F_MACH_i386
                        (nFormat!=32)&&         // UPX_F_MACH_ARMEL
                        (nFormat!=33)&&         // UPX_F_DYLIB_i386
                        (nFormat!=34)&&         // UPX_F_MACH_AMD64
                        (nFormat!=35)&&         // UPX_F_DYLIB_AMD64
                        (nFormat!=37)&&         // UPX_F_MACH_ARM64EL
                        (nFormat!=38)&&         // UPX_F_MACH_PPC64LE
                        (nFormat!=41)&&         // UPX_F_DYLIB_PPC64LE
                        (nFormat!=131)&&        // UPX_F_MACH_PPC32
                        (nFormat!=134)&&        // UPX_F_MACH_FAT
                        (nFormat!=138)&&        // UPX_F_DYLIB_PPC32
                        (nFormat!=139)&&        // UPX_F_MACH_PPC64
                        (nFormat!=142))         // UPX_F_DYLIB_PPC64
                    {
                        result.bIsValid=false;
                    }
                }
                else if(fileType==XBinary::FT_ELF)
                {
                    if( (nFormat!=10)&&         // UPX_F_LINUX_i386
                        (nFormat!=12)&&         // UPX_F_LINUX_ELF_i386
                        (nFormat!=14)&&         // UPX_F_LINUX_SH_i386
                        (nFormat!=15)&&         // UPX_F_VMLINUZ_i386
                        (nFormat!=16)&&         // UPX_F_BVMLINUZ_i386
                        (nFormat!=19)&&         // UPX_F_VMLINUX_i386
                        (nFormat!=20)&&         // UPX_F_LINUX_ELFI_i386
                        (nFormat!=22)&&         // UPX_F_LINUX_ELF64_AMD
                        (nFormat!=23)&&         // UPX_F_LINUX_ELF32_ARMEL
                        (nFormat!=24)&&         // UPX_F_BSD_i386
                        (nFormat!=25)&&         // UPX_F_BSD_ELF_i386
                        (nFormat!=26)&&         // UPX_F_BSD_SH_i386
                        (nFormat!=27)&&         // UPX_F_VMLINUX_AMD64
                        (nFormat!=28)&&         // UPX_F_VMLINUX_ARMEL
                        (nFormat!=30)&&         // UPX_F_LINUX_ELF32_MIPSEL
                        (nFormat!=31)&&         // UPX_F_VMLINUZ_ARMEL
                        (nFormat!=39)&&         // UPX_F_LINUX_ELFPPC64LE
                        (nFormat!=40)&&         // UPX_F_VMLINUX_PPC64LE
                        (nFormat!=42)&&         // UPX_F_LINUX_ELF64_ARM
                        (nFormat!=132)&&        // UPX_F_LINUX_ELFPPC32
                        (nFormat!=133)&&        // UPX_F_LINUX_ELF32_ARMEB
                        (nFormat!=135)&&        // UPX_F_VMLINUX_ARMEB
                        (nFormat!=136)&&        // UPX_F_VMLINUX_PPC32
                        (nFormat!=137)&&        // UPX_F_LINUX_ELF32_MIPSEB
                        (nFormat!=140)&&        // UPX_F_LINUX_ELFPPC64
                        (nFormat!=141))         // UPX_F_VMLINUX_PPC64
                    {
                        result.bIsValid=false;
                    }
                }

                // Check Version
                if(nVersion>14)
                {
                    result.bIsValid=false;
                }

                // Check Methods
                if((nMethod<2)||(nMethod>15))
                {
                    result.bIsValid=false;
                }

                // Check Level
                // https://github.com/upx/upx/blob/d7ba31cab8ce8d95d2c10e88d2ec787ac52005ef/src/compress_lzma.cpp#L137
                if(nLevel>10)
                {
                    result.bIsValid=false;
                }

                // Check size
                if(nCLen>nULen)
                {
                    result.bIsValid=false;
                }
            }

            if(result.bIsValid)
            {
                // TODO
//                switch(nVersion)
//                {
//                    case 11:    result.sVersion="1.10-";                break;
//                    case 12:    result.sVersion="1.10-";                break;
//                    case 13:    result.sVersion="1.90+";                break;
//                }

                switch(nMethod) // From https://github.com/upx/upx/blob/master/src/conf.h
                {

                    //#define M_CL1B_LE32     11
                    //#define M_CL1B_8        12
                    //#define M_CL1B_LE16     13
                    case 2:     result.sInfo=append(result.sInfo,"NRV2B_LE32");         break;
                    case 3:     result.sInfo=append(result.sInfo,"NRV2B_8");            break;
                    case 4:     result.sInfo=append(result.sInfo,"NRV2B_LE16");         break;
                    case 5:     result.sInfo=append(result.sInfo,"NRV2D_LE32");         break;
                    case 6:     result.sInfo=append(result.sInfo,"NRV2D_8");            break;
                    case 7:     result.sInfo=append(result.sInfo,"NRV2D_LE16");         break;
                    case 8:     result.sInfo=append(result.sInfo,"NRV2E_LE32");         break;
                    case 9:     result.sInfo=append(result.sInfo,"NRV2E_8");            break;
                    case 10:    result.sInfo=append(result.sInfo,"NRV2E_LE16");         break;
                    case 14:    result.sInfo=append(result.sInfo,"LZMA");               break;
                    case 15:    result.sInfo=append(result.sInfo,"zlib");               break;
                }

                if(result.sInfo!="")
                {
                    if(nLevel==8)
                    {
                        result.sInfo=append(result.sInfo,"best");
                    }
                    else
                    {
                        result.sInfo=append(result.sInfo,"brute");
                    }
                }

                result.nValue=binary.read_uint32(nOffset);

                if(result.nValue!=0x21585055) // UPX!
                {
                    result.sInfo=append(result.sInfo,QString("Modified(%1)").arg(XBinary::valueToHex((quint32)result.nValue)));
                }
            }
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_GCC_vi1(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO get max version
    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"GCC:");

    if(nOffset_Version!=-1)
    {
        QString sVersionString=binary.read_ansiString(nOffset_Version);

        result=_get_GCC_string(sVersionString);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_GCC_vi2(QIODevice *pDevice,bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO get max version
    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"gcc-");

    if(nOffset_Version!=-1)
    {
        result.bIsValid=true;
        QString sVersionString=binary.read_ansiString(nOffset_Version);
        result.sVersion=sVersionString.section("-",1,1).section("/",0,0);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Nim_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    if((binary.find_ansiString(nOffset,nSize,"io.nim")!=-1)||(binary.find_ansiString(nOffset,nSize,"fatal.nim")!=-1))
    {
        result.bIsValid=true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_Zig_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 nOffset_Version=binary.find_unicodeString(nOffset,nSize,"ZIG_DEBUG_COLOR");

    if(nOffset_Version!=-1)
    {
        result.bIsValid=true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_PyInstaller_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"PyInstaller: FormatMessageW failed.");

    if(nOffset_Version!=-1)
    {
        result.bIsValid=true;
        // TODO Version
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::_get_GCC_string(QString sString)
{
    VI_STRUCT result={};

    if(sString.contains("GCC:"))
    {
        result.bIsValid=true;

        // TODO MinGW-w64
        if(sString.contains("MinGW"))
        {
            result.sInfo="MinGW";
        }
        else if(sString.contains("MSYS2"))
        {
            result.sInfo="MSYS2";
        }
        else if(sString.contains("Cygwin"))
        {
            result.sInfo="Cygwin";
        }

        if( (sString.contains("(experimental)"))||
            (sString.contains("(prerelease)")))
        {
            result.sVersion=sString.section(" ",-3,-1); // TODO Check
        }
        else if(sString.contains("(GNU) c "))
        {
            result.sVersion=sString.section("(GNU) c ",1,-1);
        }
        else if(sString.contains("GNU"))
        {
            result.sVersion=sString.section(" ",2,-1);
        }
        else if(sString.contains("Rev1, Built by MSYS2 project"))
        {
            result.sVersion=sString.section(" ",-2,-1);
        }
        else if(sString.contains("(Ubuntu "))
        {
            result.sVersion=sString.section(") ",1,1).section(" ",0,0);
        }
        else if(sString.contains("StartOS)"))
        {
            result.sVersion=sString.section(")",1,1).section(" ",0,0);
        }
        else if(sString.contains("GCC: (c) "))
        {
            result.sVersion=sString.section("GCC: (c) ",1,1);
        }
        else
        {
            result.sVersion=sString.section(" ",-1,-1);
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_WindowsInstaller_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    qint64 nStringOffset=binary.find_ansiString(nOffset,nSize,"Windows Installer");

    if(nStringOffset!=-1)
    {
        result.bIsValid=true;

        QString _sString=binary.read_ansiString(nStringOffset);

        if(_sString.contains("xml",Qt::CaseInsensitive))
        {
            result.sInfo="XML";
        }

        QString sVersion=XBinary::regExp("\\((.*?)\\)",_sString,1);

        if(sVersion!="")
        {
            result.sVersion=sVersion;
        }
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_gold_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    // TODO get max version
    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"gold ");

    if(nOffset_Version!=-1)
    {
        result.bIsValid=true;
        QString sVersionString=binary.read_ansiString(nOffset_Version,nSize-(nOffset_Version-nOffset));
        result.sVersion=sVersionString.section(" ",1,1);
    }

    return result;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_TurboLinker_vi(QIODevice *pDevice, bool bIsImage)
{
    VI_STRUCT result={};

    XBinary binary(pDevice,bIsImage);

    if(binary.read_uint8(0x1E)==0xFB)
    {
        result.bIsValid=true;

        result.sVersion=QString::number((double)binary.read_uint8(0x1F)/16,'f',1);
    }

    return result;
}

bool SpecAbstract::PE_isValid_UPX(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    bool bResult=false;

    if(pPEInfo->listSectionHeaders.count()>=3)
    {
        // pPEInfo->listSections.at(0).SizeOfRawData!=0 dump file
        if((pPEInfo->listSectionHeaders.at(0).SizeOfRawData==0)&&((pPEInfo->nResourcesSection==-1)||(pPEInfo->nResourcesSection==2)))
        {
            bResult=true;
        }
    }

    return bResult;
}

void SpecAbstract::PE_x86Emul(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XBinary binary(pDevice,bIsImage);

    qint64 nAddress=pPEInfo->nImageBaseAddress+pPEInfo->nEntryPointAddress;

    QString sSignature;

    bool bSuccess=true;
    bool bVMProtect=true;

    int nCount=10;

    for(int i=0;i<nCount;i++)
    {
        qint64 nOffset=XBinary::addressToOffset(&(pPEInfo->basic_info.memoryMap),nAddress);

        if(nOffset==-1)
        {
            bSuccess=false;
            break;
        }

        quint8 nByte=binary.read_uint8(nOffset);
        nAddress++;
        nOffset++;

        if(nByte==0x9c) // pushf
        {
            sSignature+="9C";
        }
        else if(nByte==0x60) // pusha
        {
            sSignature+="60";
        }
        else if(nByte==0xe9) // jmp ..
        {
            sSignature+="E9$$$$$$$$";
            nAddress+=(4+binary.read_int32(nOffset));
        }
        else if(nByte==0xe8) // call ..
        {
            sSignature+="E8$$$$$$$$";
            nAddress+=(4+binary.read_int32(nOffset));
        }
        else if(nByte==0x68) // push ..
        {
            sSignature+="68........";
            nAddress+=4;
        }
        else if(nByte==0x53) // push ebx
        {
            sSignature+="53";
        }
        else if(nByte==0xC7) // mov DWORD PTR [reg+],imm
        {
            sSignature+="C7";
            quint8 nMODRM=binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if((nMODRM==0x04)||(nMODRM==0x44))
            {
                sSignature+=XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB=binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if(nSIB==0x24) // ESP+
                {
                    sSignature+="24";

                    if(nMODRM==0x44)
                    {
//                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature+="..";

                        nAddress++;
                        nOffset++;
                    }

                    sSignature+="........";

                    nAddress+=4;
                    nOffset+=4;
                }
                else
                {
                    bVMProtect=false;
                }
            }
            else
            {
                bVMProtect=false;
            }
        }
        else if(nByte==0x8D) // lea esp,dword ptr[esp+]
        {
            sSignature+="8D";
            quint8 nMODRM=binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if(nMODRM==0x64)
            {
                sSignature+=XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB=binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if(nSIB==0x24) // ESP+
                {
                    sSignature+="24";

                    if(nMODRM==0x64)
                    {
//                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature+="..";

                        nAddress++;
                        nOffset++;
                    }
                }
                else
                {
                    bVMProtect=false;
                }
            }
            else
            {
                bVMProtect=false;
            }
        }
        else
        {
            bVMProtect=false;
        }

        if(!bVMProtect)
        {
            break;
        }
    }

    if(!bSuccess)
    {
        bVMProtect=false;
    }
}

SpecAbstract::VI_STRUCT SpecAbstract::PE_get_PECompact_vi(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(bIsImage)

    VI_STRUCT result={};

    if(pPEInfo->listSectionHeaders.count()>=2)
    {
        if(pPEInfo->listSectionHeaders.at(0).PointerToRelocations==0x32434550)
        {
            result.bIsValid=true;

            quint32 nBuildNumber=pPEInfo->listSectionHeaders.at(0).PointerToLinenumbers;

            // TODO !!! more build versions
            switch(nBuildNumber)
            {
                case 20206:     result.sVersion="2.70";       break;
                case 20240:     result.sVersion="2.78a";      break;
                case 20243:     result.sVersion="2.79b1";     break;
                case 20245:     result.sVersion="2.79bB";     break;
                case 20247:     result.sVersion="2.79bD";     break;
                case 20252:     result.sVersion="2.80b1";     break;
                case 20256:     result.sVersion="2.80b5";     break;
                case 20261:     result.sVersion="2.82";       break;
                case 20285:     result.sVersion="2.92.0";     break;
                case 20288:     result.sVersion="2.93b3";     break;
                case 20294:     result.sVersion="2.96.2";     break;
                case 20295:     result.sVersion="2.97b1";     break;
                case 20296:     result.sVersion="2.98";       break;
                case 20300:     result.sVersion="2.98.04";    break;
                case 20301:     result.sVersion="2.98.05";    break;
                case 20302:     result.sVersion="2.98.06";    break;
                case 20303:     result.sVersion="2.99b";      break;
                case 20308:     result.sVersion="3.00.2";     break;
                case 20312:     result.sVersion="3.01.3";     break;
                case 20317:     result.sVersion="3.02.1";     break;
                case 20318:     result.sVersion="3.02.2";     break;
                case 20323:     result.sVersion="3.03.5b";    break;
                case 20327:     result.sVersion="3.03.9b";    break;
                case 20329:     result.sVersion="3.03.10b";   break;
                case 20334:     result.sVersion="3.03.12b";   break;
                case 20342:     result.sVersion="3.03.18b";   break;
                case 20343:     result.sVersion="3.03.19b";   break;
                case 20344:     result.sVersion="3.03.20b";   break;
                case 20345:     result.sVersion="3.03.21b";   break;
                case 20348:     result.sVersion="3.03.23b";   break;
                default:
                {
                    if(nBuildNumber>20308)
                    {
                        result.sVersion=QString("3.X(build %1)").arg(nBuildNumber);
                    }
                    else if(nBuildNumber==0)
                    {
                        result.sVersion="2.20-2.68";
                    }
                    else
                    {
                        result.sVersion=QString("2.X(build %1)").arg(nBuildNumber);
                    }
                }
            }

            //                            qDebug("nVersion: %d",nVersion);
        }
    }

    return result;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::scansToScan(SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::_SCANS_STRUCT *pScansStruct)
{
    SCAN_STRUCT result={};

    result.id=pBasicInfo->id;
    result.nSize=pBasicInfo->nSize;
    result.nOffset=pBasicInfo->nOffset;
    result.parentId=pBasicInfo->parentId;
    result.type=pScansStruct->type;
    result.name=pScansStruct->name;
    result.sVersion=pScansStruct->sVersion;
    result.sInfo=pScansStruct->sInfo;
    result.bIsHeuristic=pScansStruct->bIsHeuristic;
    result.sArch=pBasicInfo->memoryMap.sArch;

    return result;
}

QByteArray SpecAbstract::_BasicPEInfoToArray(SpecAbstract::BASIC_PE_INFO *pInfo)
{
    QByteArray baResult;
    QDataStream ds(&baResult,QIODevice::ReadWrite);

    ds<<pInfo->nEntryPoint;

    return baResult;
}

SpecAbstract::BASIC_PE_INFO SpecAbstract::_ArrayToBasicPEInfo(const QByteArray *pbaArray)
{
    BASIC_PE_INFO result={};

    QDataStream ds((QByteArray *)pbaArray,QIODevice::ReadOnly);

    ds>>result.nEntryPoint;

    return result;
}

void SpecAbstract::memoryScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMmREcords, QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize, SIGNATURE_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    if(nSize)
    {
        XBinary binary(pDevice,bIsImage);

        int nSignaturesCount=nRecordsSize/sizeof(SIGNATURE_RECORD);

        for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
        {
            if((pRecords[i].basicInfo.fileType==fileType1)||(pRecords[i].basicInfo.fileType==fileType2))
            {
                if((!pMmREcords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
                {
                    qint64 _nOffset=binary.find_signature(&(pBasicInfo->memoryMap),nOffset,nSize,(char *)pRecords[i].pszSignature);

                    if(_nOffset!=-1)
                    {
                        if(!pMmREcords->contains(pRecords[i].basicInfo.name))
                        {
                            _SCANS_STRUCT record={};
                            record.nVariant=pRecords[i].basicInfo.nVariant;
                            record.fileType=pRecords[i].basicInfo.fileType;
                            record.type=pRecords[i].basicInfo.type;
                            record.name=pRecords[i].basicInfo.name;
                            record.sVersion=pRecords[i].basicInfo.pszVersion;
                            record.sInfo=pRecords[i].basicInfo.pszInfo;
                            record.nOffset=_nOffset;

                            pMmREcords->insert(record.name,record);
                        }

                        if(pBasicInfo->bShowDetects)
                        {
                            DETECT_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                            heurRecord.fileType=pRecords[i].basicInfo.fileType;
                            heurRecord.type=pRecords[i].basicInfo.type;
                            heurRecord.name=pRecords[i].basicInfo.name;
                            heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                            heurRecord.nOffset=_nOffset;
                            heurRecord.filepart=pBasicInfo->id.filePart;
                            heurRecord.detectType=detectType;
                            heurRecord.sValue=pRecords[i].pszSignature;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::signatureScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QString sSignature, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        if((pRecords[i].basicInfo.fileType==fileType1)||(pRecords[i].basicInfo.fileType==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
            {
                if(XBinary::compareSignatureStrings(sSignature,pRecords[i].pszSignature))
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        _SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.fileType=pRecords[i].basicInfo.fileType;
                        record.type=pRecords[i].basicInfo.type;
                        record.name=pRecords[i].basicInfo.name;
                        record.sVersion=pRecords[i].basicInfo.pszVersion;
                        record.sInfo=pRecords[i].basicInfo.pszInfo;

                        record.nOffset=0;

                        pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                        qDebug("SIGNATURE SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if(pBasicInfo->bShowDetects)
                    {
                        DETECT_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType=pRecords[i].basicInfo.fileType;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filePart;
                        heurRecord.detectType=detectType;
                        heurRecord.sValue=pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_resourcesScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, PE_RESOURCES_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    int nSignaturesCount=nRecordsSize/sizeof(PE_RESOURCES_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        if((pRecords[i].basicInfo.fileType==fileType1)||(pRecords[i].basicInfo.fileType==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
            {
                bool bSuccess=false;

                QString sValue;

                if(pRecords[i].bIsString1)
                {
                    if(pRecords[i].bIsString2)
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].pszName1,pRecords[i].pszName2,pListResources);

                        sValue=QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].pszName2);
                    }
                    else
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].pszName1,pRecords[i].nID2,pListResources);

                        sValue=QString("%1 %2").arg(pRecords[i].pszName1).arg(pRecords[i].nID2);
                    }
                }
                else
                {
                    if(pRecords[i].bIsString2)
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].nID1,pRecords[i].pszName2,pListResources);

                        sValue=QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].pszName2);
                    }
                    else
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].nID1,pRecords[i].nID2,pListResources);

                        sValue=QString("%1 %2").arg(pRecords[i].nID1).arg(pRecords[i].nID2);
                    }
                }

                if(bSuccess)
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        _SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.fileType=pRecords[i].basicInfo.fileType;
                        record.type=pRecords[i].basicInfo.type;
                        record.name=pRecords[i].basicInfo.name;
                        record.sVersion=pRecords[i].basicInfo.pszVersion;
                        record.sInfo=pRecords[i].basicInfo.pszInfo;
                        record.nOffset=0;

                        pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                        qDebug("RESOURCES SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if(pBasicInfo->bShowDetects)
                    {
                        DETECT_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType=pRecords[i].basicInfo.fileType;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filePart;
                        heurRecord.detectType=detectType;
                        heurRecord.sValue=sValue;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::stringScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, SpecAbstract::STRING_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    int nNumberOfStrings=pListStrings->count();
    int nNumberOfSignatures=nRecordsSize/sizeof(STRING_RECORD);

    for(int i=0;i<nNumberOfStrings;i++)
    {
        quint32 nCRC=XBinary::getStringCustomCRC32(pListStrings->at(i));
        listStringCRC.append(nCRC);
    }

    for(int i=0;i<nNumberOfSignatures;i++)
    {
        quint32 nCRC=XBinary::getStringCustomCRC32(pRecords[i].pszString);
        listSignatureCRC.append(nCRC);
    }

    for(int i=0;(i<nNumberOfStrings)&&(!(*pbIsStop));i++)
    {
        for(int j=0; j<nNumberOfSignatures; j++)
        {
            if((pRecords[j].basicInfo.fileType==fileType1)||(pRecords[j].basicInfo.fileType==fileType2))
            {
                if((!pMapRecords->contains(pRecords[j].basicInfo.name))||(pBasicInfo->bShowDetects))
                {
                    quint32 nCRC1=listStringCRC[i];
                    quint32 nCRC2=listSignatureCRC[j];

                    if(nCRC1==nCRC2)
                    {
                        if(!pMapRecords->contains(pRecords[j].basicInfo.name))
                        {
                            _SCANS_STRUCT record={};
                            record.nVariant=pRecords[j].basicInfo.nVariant;
                            record.fileType=pRecords[j].basicInfo.fileType;
                            record.type=pRecords[j].basicInfo.type;
                            record.name=pRecords[j].basicInfo.name;
                            record.sVersion=pRecords[j].basicInfo.pszVersion;
                            record.sInfo=pRecords[j].basicInfo.pszInfo;

                            record.nOffset=0;

                            pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                            qDebug("STRING SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }

                        if(pBasicInfo->bShowDetects)
                        {
                            DETECT_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType=pRecords[j].basicInfo.fileType;
                            heurRecord.type=pRecords[j].basicInfo.type;
                            heurRecord.name=pRecords[j].basicInfo.name;
                            heurRecord.sVersion=pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset=0;
                            heurRecord.filepart=pBasicInfo->id.filePart;
                            heurRecord.detectType=detectType;
                            heurRecord.sValue=pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::constScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, SpecAbstract::CONST_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(CONST_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        if((pRecords[i].basicInfo.fileType==fileType1)||(pRecords[i].basicInfo.fileType==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
            {
                bool bSuccess=false;

                bSuccess=   ((pRecords[i].nConst1==nCost1)||(pRecords[i].nConst1==0xFFFFFFFF))&&
                            ((pRecords[i].nConst2==nCost2)||(pRecords[i].nConst2==0xFFFFFFFF));

                if(bSuccess)
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        _SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.fileType=pRecords[i].basicInfo.fileType;
                        record.type=pRecords[i].basicInfo.type;
                        record.name=pRecords[i].basicInfo.name;
                        record.sVersion=pRecords[i].basicInfo.pszVersion;
                        record.sInfo=pRecords[i].basicInfo.pszInfo;

                        record.nOffset=0;

                        pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                        qDebug("CONST SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if(pBasicInfo->bShowDetects)
                    {
                        DETECT_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType=pRecords[i].basicInfo.fileType;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filePart;
                        heurRecord.detectType=detectType;
                        heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nConst1)).arg(XBinary::valueToHex(pRecords[i].nConst2));

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::MSDOS_richScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
        {
            _SCANS_STRUCT record={};

            if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
            {
                if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                {
                    pMapRecords->insert(record.name,record);
                }

                if(pBasicInfo->bShowDetects)
                {
                    DETECT_RECORD heurRecord={};

                    heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                    heurRecord.fileType=pRecords[i].basicInfo.fileType;
                    heurRecord.type=pRecords[i].basicInfo.type;
                    heurRecord.name=pRecords[i].basicInfo.name;
                    heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                    heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                    heurRecord.nOffset=0;
                    heurRecord.filepart=pBasicInfo->id.filePart;
                    heurRecord.detectType=detectType;
                    heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID)).arg(XBinary::valueToHex(pRecords[i].nBuild));

                    pBasicInfo->listHeurs.append(heurRecord);
                }
            }
        }
    }
}

void SpecAbstract::archiveScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, SpecAbstract::STRING_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::DETECTTYPE detectType,bool *pbIsStop)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    int nNumberOfArchives=pListArchiveRecords->count();
    int nNumberOfSignatures=nRecordsSize/sizeof(STRING_RECORD);

    for(int i=0;i<nNumberOfArchives;i++)
    {
//        qDebug("%s", pListArchiveRecords->at(i).sFileName.toLatin1().data());
        quint32 nCRC=XBinary::getStringCustomCRC32(pListArchiveRecords->at(i).sFileName);
        listStringCRC.append(nCRC);
    }

    for(int i=0;i<nNumberOfSignatures;i++)
    {
//        qDebug("%s", pRecords[i].pszString);
        quint32 nCRC=XBinary::getStringCustomCRC32(pRecords[i].pszString);
        listSignatureCRC.append(nCRC);
    }

    for(int i=0;(i<nNumberOfArchives)&&(!(*pbIsStop));i++)
    {
        for(int j=0; (j<nNumberOfSignatures)&&(!(*pbIsStop)); j++)
        {
            if((pRecords[j].basicInfo.fileType==fileType1)||(pRecords[j].basicInfo.fileType==fileType2))
            {
                if((!pMapRecords->contains(pRecords[j].basicInfo.name))||(pBasicInfo->bShowDetects))
                {
                    quint32 nCRC1=listStringCRC[i];
                    quint32 nCRC2=listSignatureCRC[j];

                    if(nCRC1==nCRC2)
                    {
                        if(!pMapRecords->contains(pRecords[j].basicInfo.name))
                        {
                            _SCANS_STRUCT record={};
                            record.nVariant=pRecords[j].basicInfo.nVariant;
                            record.fileType=pRecords[j].basicInfo.fileType;
                            record.type=pRecords[j].basicInfo.type;
                            record.name=pRecords[j].basicInfo.name;
                            record.sVersion=pRecords[j].basicInfo.pszVersion;
                            record.sInfo=pRecords[j].basicInfo.pszInfo;

                            record.nOffset=0;

                            pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }

                        if(pBasicInfo->bShowDetects)
                        {
                            DETECT_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType=pRecords[j].basicInfo.fileType;
                            heurRecord.type=pRecords[j].basicInfo.type;
                            heurRecord.name=pRecords[j].basicInfo.name;
                            heurRecord.sVersion=pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset=0;
                            heurRecord.filepart=pBasicInfo->id.filePart;
                            heurRecord.detectType=detectType;
                            heurRecord.sValue=pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::archiveExpScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XArchive::RECORD> *pListArchiveRecords, SpecAbstract::STRING_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, SpecAbstract::BASIC_INFO *pBasicInfo, SpecAbstract::DETECTTYPE detectType, bool *pbIsStop)
{
    int nNumberOfArchives=pListArchiveRecords->count();
    int nNumberOfSignatures=nRecordsSize/sizeof(STRING_RECORD);

    for(int i=0;(i<nNumberOfArchives)&&(!(*pbIsStop));i++)
    {
        for(int j=0; (j<nNumberOfSignatures)&&(!(*pbIsStop)); j++)
        {
            if((pRecords[j].basicInfo.fileType==fileType1)||(pRecords[j].basicInfo.fileType==fileType2))
            {
                if((!pMapRecords->contains(pRecords[j].basicInfo.name))||(pBasicInfo->bShowDetects))
                {
                    if(XBinary::isRegExpPresent(pRecords[j].pszString,pListArchiveRecords->at(i).sFileName))
                    {
                        if(!pMapRecords->contains(pRecords[j].basicInfo.name))
                        {
                            _SCANS_STRUCT record={};
                            record.nVariant=pRecords[j].basicInfo.nVariant;
                            record.fileType=pRecords[j].basicInfo.fileType;
                            record.type=pRecords[j].basicInfo.type;
                            record.name=pRecords[j].basicInfo.name;
                            record.sVersion=pRecords[j].basicInfo.pszVersion;
                            record.sInfo=pRecords[j].basicInfo.pszInfo;

                            record.nOffset=0;

                            pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                            qDebug("ARCHIVE SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                        }

                        if(pBasicInfo->bShowDetects)
                        {
                            DETECT_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[j].basicInfo.nVariant;
                            heurRecord.fileType=pRecords[j].basicInfo.fileType;
                            heurRecord.type=pRecords[j].basicInfo.type;
                            heurRecord.name=pRecords[j].basicInfo.name;
                            heurRecord.sVersion=pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset=0;
                            heurRecord.filepart=pBasicInfo->id.filePart;
                            heurRecord.detectType=detectType;
                            heurRecord.sValue=pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, qint64 nOffset, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        if((pRecords[i].basicInfo.fileType==fileType1)||(pRecords[i].basicInfo.fileType==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowDetects))
            {
                if(pXBinary->compareSignature(pMemoryMap,pRecords[i].pszSignature,nOffset))
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        _SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.fileType=pRecords[i].basicInfo.fileType;
                        record.type=pRecords[i].basicInfo.type;
                        record.name=pRecords[i].basicInfo.name;
                        record.sVersion=pRecords[i].basicInfo.pszVersion;
                        record.sInfo=pRecords[i].basicInfo.pszInfo;

                        record.nOffset=0;

                        pMapRecords->insert(record.name,record);

#ifdef QT_DEBUG
                        qDebug("SIGNATURE EXP SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
                    }

                    if(pBasicInfo->bShowDetects)
                    {
                        DETECT_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.fileType=pRecords[i].basicInfo.fileType;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filePart;
                        heurRecord.detectType=detectType;
                        heurRecord.sValue=pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

QList<SpecAbstract::_SCANS_STRUCT> SpecAbstract::MSDOS_richScan(quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, XBinary::FT fileType1, XBinary::FT fileType2, BASIC_INFO *pBasicInfo, DETECTTYPE detectType, bool *pbIsStop)
{
    QList<_SCANS_STRUCT> listResult;

    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0;(i<nSignaturesCount)&&(!(*pbIsStop));i++)
    {
        _SCANS_STRUCT record={};

        if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
        {
            listResult.append(record);

            if(pBasicInfo->bShowDetects)
            {
                DETECT_RECORD heurRecord={};

                heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                heurRecord.fileType=pRecords[i].basicInfo.fileType;
                heurRecord.type=pRecords[i].basicInfo.type;
                heurRecord.name=pRecords[i].basicInfo.name;
                heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                heurRecord.nOffset=0;
                heurRecord.filepart=pBasicInfo->id.filePart;
                heurRecord.detectType=detectType;
                heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID),XBinary::valueToHex(pRecords[i].nBuild));

                pBasicInfo->listHeurs.append(heurRecord);
            }
        }
    }

    return listResult;
}

QByteArray SpecAbstract::serializeScanStruct(SCAN_STRUCT scanStruct, bool bIsHeader)
{
    QByteArray baResult;

    QDataStream ds(baResult);

    ds << scanStruct.nSize;
    ds << scanStruct.nOffset;
    ds << scanStruct.id.sUuid;
    ds << (quint32)scanStruct.id.fileType;
    ds << (quint32)scanStruct.id.filePart;
    ds << scanStruct.parentId.sUuid;
    ds << (quint32)scanStruct.parentId.fileType;
    ds << (quint32)scanStruct.parentId.filePart;
    ds << (quint32)scanStruct.type;
    ds << (quint32)scanStruct.name;
    ds << scanStruct.sVersion;
    ds << scanStruct.sInfo;
    ds << bIsHeader;

    return baResult;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::deserializeScanStruct(QByteArray baData, bool *pbIsHeader)
{
    SCAN_STRUCT ssResult={};

    QDataStream ds(baData);

    quint32 nTemp=0;

    ds >> ssResult.nSize;
    ds >> ssResult.nOffset;
    ds >> ssResult.id.sUuid;
    ds >> nTemp;
    ssResult.id.fileType=(XBinary::FT)nTemp;
    ds >> nTemp;
    ssResult.id.filePart=(RECORD_FILEPART)nTemp;
    ds >> ssResult.parentId.sUuid;
    ds >> nTemp;
    ssResult.parentId.fileType=(XBinary::FT)nTemp;
    ds >> nTemp;
    ssResult.parentId.filePart=(RECORD_FILEPART)nTemp;
    ds >> nTemp;
    ssResult.type=(RECORD_TYPE)nTemp;
    ds >> nTemp;
    ssResult.name=(RECORD_NAME)nTemp;
    ds >> ssResult.sVersion;
    ds >> ssResult.sInfo;
    ds >> *pbIsHeader;

    return ssResult;
}

QString SpecAbstract::getAndroidVersionFromApi(quint32 nAPI)
{
    QString sResult=tr("Unknown");

    if(nAPI==3)     sResult=QString("1.5");
    if(nAPI==4)     sResult=QString("1.6");
    if(nAPI==5)     sResult=QString("2.0");
    if(nAPI==6)     sResult=QString("2.0.1");
    if(nAPI==7)     sResult=QString("2.1");
    if(nAPI==8)     sResult=QString("2.2.X");
    if(nAPI==9)     sResult=QString("2.3-2.3.2");
    if(nAPI==10)    sResult=QString("2.3.3-2.3.7");
    if(nAPI==11)    sResult=QString("3.0");
    if(nAPI==12)    sResult=QString("3.1");
    if(nAPI==13)    sResult=QString("3.2.X");
    if(nAPI==14)    sResult=QString("4.0.1-4.0.2");
    if(nAPI==15)    sResult=QString("4.0.3-4.0.4");
    if(nAPI==16)    sResult=QString("4.1.X");
    if(nAPI==17)    sResult=QString("4.2.X");
    if(nAPI==18)    sResult=QString("4.3.X");
    if(nAPI==19)    sResult=QString("4.4-4.4.4");
    if(nAPI==20)    sResult=QString("4.4W");
    if(nAPI==21)    sResult=QString("5.0");
    if(nAPI==22)    sResult=QString("5.1");
    if(nAPI==23)    sResult=QString("6.0");
    if(nAPI==24)    sResult=QString("7.0");
    if(nAPI==25)    sResult=QString("7.1");
    if(nAPI==26)    sResult=QString("8.0");
    if(nAPI==27)    sResult=QString("8.1");
    if(nAPI==28)    sResult=QString("9.0");
    if(nAPI==29)    sResult=QString("10.0");
    if(nAPI==30)    sResult=QString("11.0");

    return sResult;
}

void SpecAbstract::getLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapDetects, QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages)
{
    QMapIterator<RECORD_NAME,SCAN_STRUCT> i(*pMapDetects);
    while (i.hasNext())
    {
        i.next();

        SCAN_STRUCT ssDetect=i.value();
        _SCANS_STRUCT ssLanguage=getScansStruct(0,ssDetect.id.fileType,RECORD_TYPE_LANGUAGE,RECORD_NAME_UNKNOWN,"","",0);

        // TODO Libraries like MFC
        switch(ssDetect.name)
        {
            case RECORD_NAME_C:
            case RECORD_NAME_ARMC:
            case RECORD_NAME_LCCLNK:
            case RECORD_NAME_LCCWIN:
            case RECORD_NAME_MICROSOFTC:
            case RECORD_NAME_THUMBC:
            case RECORD_NAME_TINYC:
            case RECORD_NAME_TURBOC:
            case RECORD_NAME_WATCOMC:
                ssLanguage.name=RECORD_NAME_C;
                break;
            case RECORD_NAME_CCPP:
            case RECORD_NAME_ARMCCPP:
            case RECORD_NAME_ARMNEONCCPP:
            case RECORD_NAME_ARMTHUMBCCPP:
            case RECORD_NAME_BORLANDCCPP:
            case RECORD_NAME_MINGW:
            case RECORD_NAME_MSYS:
            case RECORD_NAME_MSYS2:
            case RECORD_NAME_VISUALCCPP:
            case RECORD_NAME_WATCOMCCPP:
                ssLanguage.name=RECORD_NAME_CCPP;
                break;
            case RECORD_NAME_CLANG:
            case RECORD_NAME_GCC:
            case RECORD_NAME_ANDROIDCLANG:
            case RECORD_NAME_APPORTABLECLANG:
            case RECORD_NAME_PLEXCLANG:
            case RECORD_NAME_UBUNTUCLANG:
                if(ssDetect.sInfo.contains("Objective-C"))
                {
                    ssLanguage.name=RECORD_NAME_OBJECTIVEC;
                }
                else
                {
                    ssLanguage.name=RECORD_NAME_CCPP;
                }
                break;
            case RECORD_NAME_CPP:
            case RECORD_NAME_BORLANDCPP:
            case RECORD_NAME_BORLANDCPPBUILDER:
            case RECORD_NAME_CODEGEARCPP:
            case RECORD_NAME_CODEGEARCPPBUILDER:
            case RECORD_NAME_EMBARCADEROCPP:
            case RECORD_NAME_EMBARCADEROCPPBUILDER:
            case RECORD_NAME_MICROSOFTCPP:
            case RECORD_NAME_TURBOCPP:
                ssLanguage.name=RECORD_NAME_CPP;
                break;
            case RECORD_NAME_ASSEMBLER:
            case RECORD_NAME_ARMTHUMBMACROASSEMBLER:
            case RECORD_NAME_FASM:
            case RECORD_NAME_GNUASSEMBLER:
            case RECORD_NAME_GOASM:
            case RECORD_NAME_MASM:
            case RECORD_NAME_MASM32:
            case RECORD_NAME_NASM:
                ssLanguage.name=RECORD_NAME_ASSEMBLER;
                break;
            case RECORD_NAME_AUTOIT:
                ssLanguage.name=RECORD_NAME_AUTOIT;
                break;
            case RECORD_NAME_OBJECTPASCAL:
            case RECORD_NAME_LAZARUS:
            case RECORD_NAME_FPC:
            case RECORD_NAME_VIRTUALPASCAL:
            case RECORD_NAME_IBMPCPASCAL:
                ssLanguage.name=RECORD_NAME_OBJECTPASCAL;
                break;
            case RECORD_NAME_BORLANDDELPHI:
            case RECORD_NAME_BORLANDDELPHIDOTNET:
            case RECORD_NAME_BORLANDOBJECTPASCALDELPHI:
            case RECORD_NAME_CODEGEARDELPHI:
            case RECORD_NAME_CODEGEAROBJECTPASCALDELPHI:
            case RECORD_NAME_EMBARCADERODELPHI:
            case RECORD_NAME_EMBARCADERODELPHIDOTNET:
            case RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI:
                ssLanguage.name=RECORD_NAME_OBJECTPASCALDELPHI;
                break;
            case RECORD_NAME_D:
            case RECORD_NAME_DMD32D:
                ssLanguage.name=RECORD_NAME_D;
                break;
            case RECORD_NAME_CSHARP:
            case RECORD_NAME_DOTNET:
                ssLanguage.name=RECORD_NAME_CSHARP;
                break;
            case RECORD_NAME_GO:
                ssLanguage.name=RECORD_NAME_GO;
                break;
            case RECORD_NAME_JAVA:
            case RECORD_NAME_JVM:
            case RECORD_NAME_JDK:
            case RECORD_NAME_OPENJDK:
            case RECORD_NAME_IBMJDK:
            case RECORD_NAME_APPLEJDK:
                ssLanguage.name=RECORD_NAME_JAVA;
                break;
            case RECORD_NAME_KOTLIN:
                ssLanguage.name=RECORD_NAME_KOTLIN;
                break;
            case RECORD_NAME_FORTRAN:
            case RECORD_NAME_LAYHEYFORTRAN90:
                ssLanguage.name=RECORD_NAME_FORTRAN;
                break;
            case RECORD_NAME_NIM:
                ssLanguage.name=RECORD_NAME_NIM;
                break;
            case RECORD_NAME_OBJECTIVEC:
                ssLanguage.name=RECORD_NAME_OBJECTIVEC;
                break;
            case RECORD_NAME_BASIC:
            case RECORD_NAME_BASIC4ANDROID:
            case RECORD_NAME_POWERBASIC:
            case RECORD_NAME_PUREBASIC:
            case RECORD_NAME_TURBOBASIC:
            case RECORD_NAME_VBNET:
            case RECORD_NAME_VISUALBASIC:
                ssLanguage.name=RECORD_NAME_BASIC;
                break;
            case RECORD_NAME_RUST:
                ssLanguage.name=RECORD_NAME_RUST;
                break;
            case RECORD_NAME_RUBY:
                ssLanguage.name=RECORD_NAME_RUBY;
                break;
            case RECORD_NAME_PYTHON:
            case RECORD_NAME_PYINSTALLER:
                ssLanguage.name=RECORD_NAME_PYTHON;
                break;
            case RECORD_NAME_SWIFT:
                ssLanguage.name=RECORD_NAME_SWIFT;
                break;
        }

        if(ssLanguage.name!=RECORD_NAME_UNKNOWN)
        {
            SCAN_STRUCT ss=ssDetect;
            ss.type=ssLanguage.type;
            ss.name=ssLanguage.name;
            ss.sInfo="";
            ss.sVersion="";

            pMapLanguages->insert(ss.name,ss);
        }
    }
}

void SpecAbstract::fixLanguage(QMap<RECORD_NAME, SCAN_STRUCT> *pMapLanguages)
{
    if(pMapLanguages->contains(RECORD_NAME_C)&&pMapLanguages->contains(RECORD_NAME_CPP))
    {
        SCAN_STRUCT ss=pMapLanguages->value(RECORD_NAME_C);
        ss.name=RECORD_NAME_CCPP;
        pMapLanguages->insert(ss.name,ss);
    }

    if(pMapLanguages->contains(RECORD_NAME_C)&&pMapLanguages->contains(RECORD_NAME_CCPP))
    {
        pMapLanguages->remove(RECORD_NAME_C);
    }

    if(pMapLanguages->contains(RECORD_NAME_CPP)&&pMapLanguages->contains(RECORD_NAME_CCPP))
    {
        pMapLanguages->remove(RECORD_NAME_CPP);
    }

//    if(pMapLanguages->contains(RECORD_NAME_OBJECTIVEC)&&pMapLanguages->contains(RECORD_NAME_CCPP))
//    {
//        pMapLanguages->remove(RECORD_NAME_CCPP);
    //    }
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::getScansStructFromOsInfo(XBinary::OSINFO osinfo)
{
    _SCANS_STRUCT result={};

    result.type=RECORD_TYPE_OPERATIONSYSTEM;

    if      (osinfo.osName==XBinary::OSNAME_MSDOS)      result.name=RECORD_NAME_MSDOS;
    else if (osinfo.osName==XBinary::OSNAME_POSIX)      result.name=RECORD_NAME_POSIX;
    else if (osinfo.osName==XBinary::OSNAME_UNIX)       result.name=RECORD_NAME_UNIX;
    else if (osinfo.osName==XBinary::OSNAME_LINUX)      result.name=RECORD_NAME_LINUX;
    else if (osinfo.osName==XBinary::OSNAME_WINDOWS)    result.name=RECORD_NAME_WINDOWS;
    else if (osinfo.osName==XBinary::OSNAME_WINDOWSCE)  result.name=RECORD_NAME_WINDOWSCE;
    else if (osinfo.osName==XBinary::OSNAME_XBOX)       result.name=RECORD_NAME_XBOX;
    else if (osinfo.osName==XBinary::OSNAME_OS2)        result.name=RECORD_NAME_OS2;
    else if (osinfo.osName==XBinary::OSNAME_MAC_OS)     result.name=RECORD_NAME_MAC_OS;
    else if (osinfo.osName==XBinary::OSNAME_MAC_OS_X)   result.name=RECORD_NAME_MAC_OS_X;
    else if (osinfo.osName==XBinary::OSNAME_OS_X)       result.name=RECORD_NAME_OS_X;
    else if (osinfo.osName==XBinary::OSNAME_MACOS)      result.name=RECORD_NAME_MACOS;
    else if (osinfo.osName==XBinary::OSNAME_IPHONEOS)   result.name=RECORD_NAME_IPHONEOS;
    else if (osinfo.osName==XBinary::OSNAME_IPADOS)     result.name=RECORD_NAME_IPADOS;
    else if (osinfo.osName==XBinary::OSNAME_IOS)        result.name=RECORD_NAME_IOS;
    else if (osinfo.osName==XBinary::OSNAME_WATCHOS)    result.name=RECORD_NAME_WATCHOS;
    else if (osinfo.osName==XBinary::OSNAME_TVOS)       result.name=RECORD_NAME_TVOS;
    else if (osinfo.osName==XBinary::OSNAME_BRIDGEOS)   result.name=RECORD_NAME_BRIDGEOS;
    else if (osinfo.osName==XBinary::OSNAME_ANDROID)    result.name=RECORD_NAME_ANDROID;
    else if (osinfo.osName==XBinary::OSNAME_FREEBSD)    result.name=RECORD_NAME_FREEBSD;
    else if (osinfo.osName==XBinary::OSNAME_OPENBSD)    result.name=RECORD_NAME_OPENBSD;
    else if (osinfo.osName==XBinary::OSNAME_NETBSD)     result.name=RECORD_NAME_NETBSD;
    else if (osinfo.osName==XBinary::OSNAME_HPUX)       result.name=RECORD_NAME_HPUX;
    else if (osinfo.osName==XBinary::OSNAME_SOLARIS)    result.name=RECORD_NAME_SOLARIS;
    else if (osinfo.osName==XBinary::OSNAME_AIX)        result.name=RECORD_NAME_AIX;
    else if (osinfo.osName==XBinary::OSNAME_IRIX)       result.name=RECORD_NAME_IRIX;
    else if (osinfo.osName==XBinary::OSNAME_TRU64)      result.name=RECORD_NAME_TRU64;
    else if (osinfo.osName==XBinary::OSNAME_MODESTO)    result.name=RECORD_NAME_MODESTO;
    else if (osinfo.osName==XBinary::OSNAME_OPENVMS)    result.name=RECORD_NAME_OPENVMS;
    else if (osinfo.osName==XBinary::OSNAME_FENIXOS)    result.name=RECORD_NAME_FENIXOS;

    result.sVersion=osinfo.sOsVersion;
    result.sInfo=QString("%1, %2, %3").arg(osinfo.sArch,XBinary::modeIdToString(osinfo.mode),osinfo.sType);

    return result;
}

bool SpecAbstract::PE_compareRichRecord(_SCANS_STRUCT *pResult,SpecAbstract::MSRICH_RECORD *pRecord, quint16 nID, quint32 nBuild, XBinary::FT fileType1, XBinary::FT fileType2)
{
    bool bResult=false;

    if((pRecord->basicInfo.fileType==fileType1)||(pRecord->basicInfo.fileType==fileType2))
    {
        bool bCheck=false;

        bCheck= ((pRecord->nID==nID)||(pRecord->nID==(quint16)-1))&&
                ((pRecord->nBuild==nBuild)||(pRecord->nBuild==(quint32)-1));

        if(bCheck)
        {
            _SCANS_STRUCT record={};
            record.nVariant=pRecord->basicInfo.nVariant;
            record.fileType=pRecord->basicInfo.fileType;
            record.type=pRecord->basicInfo.type;
            record.name=pRecord->basicInfo.name;
            record.sVersion=pRecord->basicInfo.pszVersion;
            record.sInfo=pRecord->basicInfo.pszInfo;

            if(pRecord->nBuild==(quint32)-1)
            {
                record.sVersion+=QString(".%1").arg(nBuild);
            }

            record.nOffset=0;

#ifdef QT_DEBUG
            qDebug("RICH SCAN: %s",_SCANS_STRUCT_toString(&record).toLatin1().data());
#endif
            *pResult=record;

            bResult=true;
        }
    }

    return bResult;
}

void SpecAbstract::filterResult(QList<SpecAbstract::SCAN_STRUCT> *pListRecords, QSet<SpecAbstract::RECORD_TYPE> stRecordTypes)
{
    QList<SpecAbstract::SCAN_STRUCT> listRecords;
    int nNumberOfRecords=pListRecords->count();

    for(int i=0;i<nNumberOfRecords;i++)
    {
        if(stRecordTypes.contains(pListRecords->at(i).type))
        {
            listRecords.append(pListRecords->at(i));
        }
    }

    *pListRecords=listRecords;
}

QList<SpecAbstract::VCL_STRUCT> SpecAbstract::PE_getVCLstruct(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize,bool bIs64)
{
    QList<VCL_STRUCT> listResult;

    XPE pe(pDevice,bIsImage);

    qint64 _nOffset=nOffset;
    qint64 _nSize=nSize;

    int nAddressSize=bIs64?8:4;

    while(_nSize>0)
    {
        qint64 nClassOffset=pe.find_array(_nOffset,_nSize,"\x07\x08\x54\x43\x6f\x6e\x74\x72\x6f\x6c",10); // 0708'TControl'

        if(nClassOffset==-1)
        {
            break;
        }

        quint32 nDword=pe.read_uint32(nClassOffset+10);
        qint64 nClassOffset2=pe.addressToOffset(nDword);

        if(nClassOffset2!=-1)
        {
            for(int i=0;i<20;i++)
            {
                quint32 nValue=pe.read_uint32(nClassOffset2-nAddressSize*(i+1));

                if(nValue<=0xFFFF)
                {
                    VCL_STRUCT record={};

                    record.nValue=nValue;
                    record.nOffset=nAddressSize*(i+1);
                    record.bIs64=bIs64;

                    listResult.append(record);

                    break;
                }
            }
        }

        qint64 nDelta=(nClassOffset-_nOffset)+1;

        _nOffset+=nDelta;
        _nSize-=nDelta;
    }

    return listResult;
}

SpecAbstract::VCL_PACKAGEINFO SpecAbstract::PE_getVCLPackageInfo(QIODevice *pDevice,bool bIsImage, QList<XPE::RESOURCE_RECORD> *pListResources)
{
    VCL_PACKAGEINFO result={};

    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        XPE::RESOURCE_RECORD rh=pe.getResourceRecord(10,"PACKAGEINFO",pListResources);

        if((rh.nOffset!=-1)&&(rh.nSize))
        {
            qint64 nOffset=rh.nOffset;
            quint32 nFlags=pe.read_uint32(nOffset);

            quint32 _nFlags=nFlags&0xFF00;

            if(_nFlags==0)
            {
                result.nFlags=nFlags;
                nOffset+=4;
                result.nUnknown=pe.read_uint32(nOffset);

                if(result.nUnknown==0)
                {
                    nOffset+=4;
                    result.nRequiresCount=pe.read_uint32(nOffset);
                    nOffset+=4;
                }
                else
                {
                    nOffset+=3;
                }

                int nCount=result.nRequiresCount?result.nRequiresCount:1000;

                for(int i=0;i<nCount;i++)
                {
                    if(nOffset-rh.nOffset>rh.nSize)
                    {
                        break;
                    }

                    VCL_PACKAGEINFO_MODULE vpm=VCL_PACKAGEINFO_MODULE();
                    vpm.nFlags=pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.nHashCode=pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.sName=pe.read_ansiString(nOffset);
                    nOffset+=vpm.sName.length()+1;

                    result.listModules.append(vpm);
                }
            }
        }
    }

    return result;
}

SpecAbstract::_SCANS_STRUCT SpecAbstract::PE_getRichSignatureDescription(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo,quint32 nRichID)
{
    _SCANS_STRUCT result={};

    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(nRichID)
        {
            quint32 nMajor=nRichID>>16;
            quint32 nMinor=nRichID&0xFFFF;

            switch(nMajor)
            {
                case 0x00D:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_VISUALBASIC;
                    break;

                case 0x006:
                case 0x045:
                case 0x05e:
                case 0x07c:
                case 0x094:
                case 0x09a:
                case 0x0c9:
                case 0x0db:
                case 0x0ff:
                    result.type=SpecAbstract::RECORD_TYPE_CONVERTER;
                    result.name=SpecAbstract::RECORD_NAME_RESOURCE;
                    break;

                case 0x03f:
                case 0x05c:
                case 0x07a:
                case 0x092:
                case 0x09b:
                case 0x0ca:
                case 0x0dc:
                case 0x100:
                    result.type=SpecAbstract::RECORD_TYPE_LIBRARY;
                    result.name=SpecAbstract::RECORD_NAME_EXPORT;
                    break;

                //            case 0x001: Total Import
                case 0x002:
                case 0x019:
                case 0x09c:
                case 0x05d:
                case 0x07b:
                case 0x093:
                case 0x0cb:
                case 0x0dd:
                case 0x101:
                    result.type=SpecAbstract::RECORD_TYPE_LIBRARY;
                    result.name=SpecAbstract::RECORD_NAME_IMPORT;
                    break;

                case 0x004:
                case 0x013:
                case 0x03d:
                case 0x05a:
                case 0x078:
                case 0x091:
                case 0x09d:
                case 0x0cc:
                case 0x0de:
                case 0x102:
                    result.type=SpecAbstract::RECORD_TYPE_LINKER;
                    result.name=SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
                    break;

                case 0x00f:
                case 0x012:
                case 0x040:
                case 0x07d:
                case 0x095:
                case 0x09e:
                case 0x0cd:
                case 0x0df:
                case 0x103:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_MASM;
                    break;

                case 0x00a:
                case 0x015:
                case 0x01c:
                case 0x05f:
                case 0x06d:
                case 0x083:
                case 0x0aa:
                case 0x0ce:
                case 0x0e0:
                case 0x104:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    //            result.name=SpecAbstract::RECORD_NAME_MICROSOFTC;
                    result.name=SpecAbstract::RECORD_NAME_VISUALCCPP; // TODO Visual C++
                    result.sInfo="C";
                    break;

                case 0x00b:
                case 0x016:
                case 0x01d:
                case 0x060:
                case 0x06e:
                case 0x084:
                case 0x0ab:
                case 0x0cf:
                case 0x0e1:
                case 0x105:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                    result.sInfo="C++";
                    break;

                case 0x089:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                    result.sInfo="C/LTCG";
                    break;

                case 0x08a:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                    result.sInfo="C++/LTCG";
                    break;

                //
                case 0x085: // auto
                case 0x086: // auto
                case 0x087: // auto
                case 0x088: // auto

                //
                case 0x0d0: // auto
                case 0x0d1: // auto
                case 0x0d2: // auto
                case 0x0d3: // auto
                case 0x0d4: // auto
                case 0x0d5: // auto
                case 0x0d6: // auto

                //
                case 0x0e2: // auto
                case 0x0e3: // auto
                case 0x0e4: // auto
                case 0x0e5: // auto
                case 0x0e6: // auto
                case 0x0e7: // auto
                case 0x0e8: // auto

                //
                case 0x0ac:
                case 0x0ad:
                case 0x0ae:
                case 0x0af:
                case 0x0b0:
                case 0x0b1:
                case 0x0b2:

                //
                case 0x106:
                case 0x107:
                case 0x108:
                case 0x109:
                case 0x10a:
                case 0x10b:
                case 0x10c:
                    result.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    result.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                    break;
            }

            switch(nMajor)
            {
                case 0x006:
                    result.sVersion="5.00";
                    break;

                case 0x002:
                    result.sVersion="5.10";
                    break;

                case 0x013:
                    result.sVersion="5.12";
                    break;

                case 0x004:
                case 0x00d:
                    result.sVersion="6.00";
                    break;

                case 0x00a:
                case 0x00b:
                case 0x015:
                case 0x016:
                    result.sVersion="12.00";
                    break;

                case 0x012:
                    result.sVersion="6.14";
                    break;

                case 0x040:
                case 0x03d:
                case 0x045:
                case 0x03f:
                case 0x019:
                    result.sVersion="7.00";
                    break;

                case 0x01c:
                case 0x01d:
                    result.sVersion="13.00";
                    break;

                case 0x00f:
                case 0x05e:
                case 0x05c:
                case 0x05d:
                case 0x05a:
                    result.sVersion="7.10";
                    break;

                case 0x05f:
                case 0x060:
                    result.sVersion="13.10";
                    break;

                case 0x078:
                case 0x07a:
                case 0x07b:
                case 0x07c:
                case 0x07d:
                    result.sVersion="8.00";
                    break;

                case 0x06d:
                case 0x06e:
                    result.sVersion="14.00";
                    break;

                case 0x091:
                case 0x092:
                case 0x093:
                case 0x094:
                case 0x095:
                    result.sVersion="9.00";
                    break;

                case 0x083:
                case 0x084:
                case 0x085: // auto
                case 0x086: // auto
                case 0x087: // auto
                case 0x088: // auto
                case 0x089:
                case 0x08a:
                    result.sVersion="15.00";
                    break;

                case 0x09a:
                case 0x09b:
                case 0x09c:
                case 0x09d:
                case 0x09e:
                    result.sVersion="10.00";
                    break;

                case 0x0aa:
                case 0x0ab:
                case 0x0ac:
                case 0x0ad:
                case 0x0ae:
                case 0x0af:
                case 0x0b0:
                case 0x0b1:
                case 0x0b2:
                    result.sVersion="16.00";
                    break;

                case 0x0c9:
                case 0x0ca:
                case 0x0cb:
                case 0x0cc:
                case 0x0cd:
                    result.sVersion="11.00";
                    break;

                case 0x0ce:
                case 0x0cf:
                case 0x0d0: // auto
                case 0x0d1: // auto
                case 0x0d2: // auto
                case 0x0d3: // auto
                case 0x0d4: // auto
                case 0x0d5: // auto
                case 0x0d6: // auto
                    result.sVersion="17.00";
                    break;

                case 0x0db:
                case 0x0dc:
                case 0x0dd:
                case 0x0de:
                case 0x0df:
                    result.sVersion="12.00";
                    break;

                case 0x0e0:
                case 0x0e1:
                case 0x0e2: // auto
                case 0x0e3: // auto
                case 0x0e4: // auto
                case 0x0e5: // auto
                case 0x0e6: // auto
                case 0x0e7: // auto
                case 0x0e8: // auto
                    result.sVersion="18.00";
                    break;

                case 0x0ff:
                case 0x100:
                case 0x101:
                case 0x102:
                case 0x103:
                    result.sVersion="14.00";
                    break;

                case 0x104:
                case 0x105:
                case 0x106:
                case 0x107:
                case 0x108:
                case 0x109:
                case 0x10a:
                case 0x10b:
                case 0x10c:
                    result.sVersion="19.00";
                    break;
            }

            if(nMinor>=25008)
            {
                if(result.sVersion=="14.00")
                {
                    result.sVersion=QString("14.%1").arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
                }
                else if(result.sVersion=="19.00")
                {
                    result.sVersion=QString("19.%1").arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
                }
            }

            if(result.type!=SpecAbstract::RECORD_TYPE_UNKNOWN)
            {
                result.sVersion+=QString(".%1").arg(nMinor,2,10,QChar('0'));
            }
        }
    }

    return result;
}

void SpecAbstract::_errorMessage(QString sErrorMessage)
{
#ifdef QT_DEBUG
    qDebug("Error: %s",sErrorMessage.toLatin1().data());
#endif
    emit errorMessage(sErrorMessage);
}

void SpecAbstract::_infoMessage(QString sInfoMessage)
{
#ifdef QT_DEBUG
    qDebug("Info: %s",sInfoMessage.toLatin1().data());
#endif
    emit infoMessage(sInfoMessage);
}
