// copyright (c) 2017-2020 hors<horsicq@gmail.com>
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
#include "signatures.cpp"

SpecAbstract::SpecAbstract(QObject *parent)
{
    Q_UNUSED(parent)
}

void SpecAbstract::scan(QIODevice *pDevice, SpecAbstract::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, bool bInit)
{
    QElapsedTimer scanTimer;

    if(bInit)
    {
        scanTimer.start();
    }

    if(QString(pDevice->metaObject()->className())=="QFile")
    {
        pScanResult->sFileName=((QFile *)pDevice)->fileName(); // TODO
    }

    SubDevice sd(pDevice,nOffset,nSize);

    if(sd.open(QIODevice::ReadOnly))
    {
        QSet<XBinary::FT> stTypes=XBinary::getFileTypes(&sd);

        if(stTypes.contains(XBinary::FT_PE32)||stTypes.contains(XBinary::FT_PE64))
        {
            // TODO PE-MSDOS
            SpecAbstract::PEINFO_STRUCT pe_info=SpecAbstract::getPEInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(pe_info.basic_info.listDetects);
            pScanResult->listHeurs.append(pe_info.basic_info.listHeurs);
        }
        else if(stTypes.contains(XBinary::FT_ELF32)||stTypes.contains(XBinary::FT_ELF64))
        {
            SpecAbstract::ELFINFO_STRUCT elf_info=SpecAbstract::getELFInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(elf_info.basic_info.listDetects);
            pScanResult->listHeurs.append(elf_info.basic_info.listHeurs);
        }
        else if(stTypes.contains(XBinary::FT_MACH32)||stTypes.contains(XBinary::FT_MACH64))
        {
            SpecAbstract::MACHINFO_STRUCT mach_info=SpecAbstract::getMACHInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(mach_info.basic_info.listDetects);
            pScanResult->listHeurs.append(mach_info.basic_info.listHeurs);
        }
        else if(stTypes.contains(XBinary::FT_LE)||stTypes.contains(XBinary::FT_LX))
        {
            SpecAbstract::LEINFO_STRUCT le_info=SpecAbstract::getLEInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(le_info.basic_info.listDetects);
            pScanResult->listHeurs.append(le_info.basic_info.listHeurs);
        }
        else if(stTypes.contains(XBinary::FT_NE))
        {
            SpecAbstract::NEINFO_STRUCT ne_info=SpecAbstract::getNEInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(ne_info.basic_info.listDetects);
            pScanResult->listHeurs.append(ne_info.basic_info.listHeurs);
        }
        else if(stTypes.contains(XBinary::FT_MSDOS))
        {
            SpecAbstract::MSDOSINFO_STRUCT msdos_info=SpecAbstract::getMSDOSInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(msdos_info.basic_info.listDetects);
            pScanResult->listHeurs.append(msdos_info.basic_info.listHeurs);
        }
        else
        {
            SpecAbstract::BINARYINFO_STRUCT binary_info=SpecAbstract::getBinaryInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(binary_info.basic_info.listDetects);
            pScanResult->listHeurs.append(binary_info.basic_info.listHeurs);
        }

        sd.close();
    }

    if(pOptions->bIsTest)
    {
        QList<SpecAbstract::SCAN_STRUCT> _listDetects;

        int nCount=pScanResult->listRecords.count();

        for(int i=0;i<nCount;i++)
        {
            if(pScanResult->listRecords.at(i).sInfo=="TEST")
            {
                _listDetects.append(pScanResult->listRecords.at(i));
            }
        }

        pScanResult->listRecords=_listDetects;
    }

    if(bInit)
    {
        pScanResult->nScanTime=scanTimer.elapsed();
    }
}

QString SpecAbstract::append(QString sResult, QString sString)
{
    if(sString!="")
    {
        if(sResult!="")
        {
            sResult+=",";
        }

        sResult+=sString;
    }

    return sResult;
}

QString SpecAbstract::recordFiletypeIdToString(RECORD_FILETYPE id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case RECORD_FILETYPE_UNKNOWN:                           sResult=QString("Unknown");                                     break;
        case RECORD_FILETYPE_BINARY:                            sResult=QString("Binary");                                      break;
        case RECORD_FILETYPE_COM:                               sResult=QString("COM");                                         break;
        case RECORD_FILETYPE_MSDOS:                             sResult=QString("MSDOS");                                       break;
        case RECORD_FILETYPE_LE:                                sResult=QString("LE");                                          break;
        case RECORD_FILETYPE_LX:                                sResult=QString("LX");                                          break;
        case RECORD_FILETYPE_NE:                                sResult=QString("NE");                                          break;
        case RECORD_FILETYPE_PE:                                sResult=QString("PE");                                          break;
        case RECORD_FILETYPE_PE32:                              sResult=QString("PE 32");                                       break;
        case RECORD_FILETYPE_PE64:                              sResult=QString("PE 64");                                       break;
        case RECORD_FILETYPE_ELF:                               sResult=QString("ELF");                                         break;
        case RECORD_FILETYPE_ELF32:                             sResult=QString("ELF 32");                                      break;
        case RECORD_FILETYPE_ELF64:                             sResult=QString("ELF 64");                                      break;
        case RECORD_FILETYPE_MACH:                              sResult=QString("Mach-O");                                      break;
        case RECORD_FILETYPE_MACH32:                            sResult=QString("Mach-O 32");                                   break;
        case RECORD_FILETYPE_MACH64:                            sResult=QString("Mach-O 64");                                   break;
        case RECORD_FILETYPE_TEXT:                              sResult=QString("Text");                                        break;
//        case RECORD_FILETYPE_JAR:                               sResult=QString("JAR");                                         break;
        case RECORD_FILETYPE_APK:                               sResult=QString("APK");                                         break;
    }

    return sResult;
}

QString SpecAbstract::recordFilepartIdToString(SpecAbstract::RECORD_FILEPART id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
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
        case RECORD_TYPE_ARCHIVE:                               sResult=tr("Archive");                                          break;
        case RECORD_TYPE_CERTIFICATE:                           sResult=tr("Certificate");                                      break;
        case RECORD_TYPE_COMPILER:                              sResult=tr("Compiler");                                         break;
        case RECORD_TYPE_CONVERTER:                             sResult=tr("Converter");                                        break;
        case RECORD_TYPE_DATABASE:                              sResult=tr("Database");                                         break;
        case RECORD_TYPE_DEBUGDATA:                             sResult=tr("Debug data");                                       break;
        case RECORD_TYPE_DONGLEPROTECTION:                      sResult=QString("Dongle %1").arg(tr("protection"));             break;
        case RECORD_TYPE_DOSEXTENDER:                           sResult=QString("DOS %1").arg(tr("extender"));                  break;
        case RECORD_TYPE_FORMAT:                                sResult=tr("Format");                                           break;
        case RECORD_TYPE_GENERIC:                               sResult=tr("Generic");                                          break;
        case RECORD_TYPE_IMAGE:                                 sResult=tr("Image");                                            break;
        case RECORD_TYPE_INSTALLER:                             sResult=tr("Installer");                                        break;
        case RECORD_TYPE_INSTALLERDATA:                         sResult=tr("Installer data");                                   break;
        case RECORD_TYPE_JOINER:                                sResult=tr("Joiner");                                           break;
        case RECORD_TYPE_LIBRARY:                               sResult=tr("Library");                                          break;
        case RECORD_TYPE_LINKER:                                sResult=tr("Linker");                                           break;
        case RECORD_TYPE_NETCOMPRESSOR:                         sResult=QString(".NET %1").arg(tr("compressor"));               break;
        case RECORD_TYPE_NETOBFUSCATOR:                         sResult=QString(".NET %1").arg(tr("obfuscator"));               break;
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
    }

    return sResult;
}

QString SpecAbstract::recordNameIdToString(RECORD_NAME id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case RECORD_NAME_UNKNOWN:                               sResult=QString("Unknown");                                     break;
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
        case RECORD_NAME_AFFILLIATEEXE:                         sResult=QString("AffilliateEXE");                               break;
        case RECORD_NAME_AGAINNATIVITYCRYPTER:                  sResult=QString("Again Nativity Crypter");                      break;
        case RECORD_NAME_AGILENET:                              sResult=QString("Agile .NET");                                  break;
        case RECORD_NAME_AHPACKER:                              sResult=QString("AHPacker");                                    break;
        case RECORD_NAME_AHTEAMEPPROTECTOR:                     sResult=QString("AHTeam EP Protector");                         break;
        case RECORD_NAME_AINEXE:                                sResult=QString("AINEXE");                                      break;
        case RECORD_NAME_ALCHEMYMINDWORKS:                      sResult=QString("Alchemy Mindworks");                           break;
        case RECORD_NAME_ALEXPROTECTOR:                         sResult=QString("Alex Protector");                              break;
        case RECORD_NAME_ALIASOBJ:                              sResult=QString("ALIASOBJ");                                    break;
        case RECORD_NAME_ALLOY:                                 sResult=QString("Alloy");                                       break;
        case RECORD_NAME_ANDPAKK2:                              sResult=QString("ANDpakk2");                                    break;
        case RECORD_NAME_ANDROIDGRADLE:                         sResult=QString("Android Gradle");                              break;
        case RECORD_NAME_ANSKYAPOLYMORPHICPACKER:               sResult=QString("Anskya Polymorphic Packer");                   break;
        case RECORD_NAME_ANSLYMPACKER:                          sResult=QString("AnslymPacker");                                break;
        case RECORD_NAME_ANTIDOTE:                              sResult=QString("AntiDote");                                    break;
        case RECORD_NAME_ARCRYPT:                               sResult=QString("AR Crypt");                                    break;
        case RECORD_NAME_ARJ:                                   sResult=QString("ARJ");                                         break;
        case RECORD_NAME_ARMADILLO:                             sResult=QString("Armadillo");                                   break;
        case RECORD_NAME_ARMPROTECTOR:                          sResult=QString("ARM Protector");                               break;
        case RECORD_NAME_ASDPACK:                               sResult=QString("ASDPack");                                     break;
        case RECORD_NAME_ASM:                                   sResult=QString("Asm");                                         break;
        case RECORD_NAME_ASPACK:                                sResult=QString("ASPack");                                      break;
        case RECORD_NAME_ASPROTECT:                             sResult=QString("ASProtect");                                   break;
        case RECORD_NAME_ASSCRYPTER:                            sResult=QString("Ass Crypter");                                 break;
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
        case RECORD_NAME_BAMBAM:                                sResult=QString("bambam");                                      break;
        case RECORD_NAME_BAT2EXEC:                              sResult=QString("BAT2EXEC");                                    break;
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
        case RECORD_NAME_BORLANDOBJECTPASCAL:                   sResult=QString("Borland Object Pascal");                       break;
        case RECORD_NAME_BREAKINTOPATTERN:                      sResult=QString("Break Into Pattern");                          break;
        case RECORD_NAME_BZIP2:                                 sResult=QString("bzip2");                                       break;
        case RECORD_NAME_C:                                     sResult=QString("C");                                           break;
        case RECORD_NAME_CAB:                                   sResult=QString("CAB");                                         break;
        case RECORD_NAME_CARBON:                                sResult=QString("Carbon");                                      break;
        case RECORD_NAME_CAUSEWAY:                              sResult=QString("CauseWay");                                    break;
        case RECORD_NAME_CCBYVORONTSOV:                         sResult=QString("CC by Vorontsov");                             break;
        case RECORD_NAME_CCBYUNIHACKERS:                        sResult=QString("CC by UniHackers");                            break;
        case RECORD_NAME_CCPP:                                  sResult=QString("C/C++");                                       break;
        case RECORD_NAME_CELESTYFILEBINDER:                     sResult=QString("Celesty File Binder");                         break;
        case RECORD_NAME_CEXE:                                  sResult=QString("CExe");                                        break;
        case RECORD_NAME_CIGICIGICRYPTER:                       sResult=QString("Cigicigi Crypter");                            break;
        case RECORD_NAME_CIL:                                   sResult=QString("cil");                                         break;
        case RECORD_NAME_CLICKTEAM:                             sResult=QString("ClickTeam");                                   break;
        case RECORD_NAME_CLISECURE:                             sResult=QString("CliSecure");                                   break;
        case RECORD_NAME_COCOA:                                 sResult=QString("Cocoa");                                       break;
        case RECORD_NAME_CODEGEARCPP:                           sResult=QString("CodeGear C++");                                break;
        case RECORD_NAME_CODEGEARCPPBUILDER:                    sResult=QString("CodeGear C++ Builder");                        break;
        case RECORD_NAME_CODEGEARDELPHI:                        sResult=QString("CodeGear Delphi");                             break;
        case RECORD_NAME_CODEGEAROBJECTPASCAL:                  sResult=QString("Codegear Object Pascal");                      break;
        case RECORD_NAME_CODEVEIL:                              sResult=QString("CodeVeil");                                    break;
        case RECORD_NAME_CODEWALL:                              sResult=QString("CodeWall");                                    break;
        case RECORD_NAME_COFF:                                  sResult=QString("COFF");                                        break;
        case RECORD_NAME_CONFUSER:                              sResult=QString("Confuser");                                    break;
        case RECORD_NAME_CONFUSEREX:                            sResult=QString("ConfuserEx");                                  break;
        case RECORD_NAME_CPP:                                   sResult=QString("C++");                                         break;
        case RECORD_NAME_CREATEINSTALL:                         sResult=QString("CreateInstall");                               break;
        case RECORD_NAME_CRINKLER:                              sResult=QString("Crinkler");                                    break;
        case RECORD_NAME_CRUNCH:                                sResult=QString("Crunch");                                      break;
        case RECORD_NAME_CRYEXE:                                sResult=QString("CryEXE");                                      break;
        case RECORD_NAME_CRYPTABLESEDUCATION:                   sResult=QString("Cryptable Seduction");                         break;
        case RECORD_NAME_CRYPTCOM:                              sResult=QString("CryptCom");                                    break;
        case RECORD_NAME_CRYPTER:                               sResult=QString("Crypter");                                     break;
        case RECORD_NAME_CRYPTIC:                               sResult=QString("Cryptic");                                     break;
        case RECORD_NAME_CRYPTOCRACKPEPROTECTOR:                sResult=QString("CrypToCrack Pe Protector");                    break;
        case RECORD_NAME_CRYPTOOBFUSCATORFORNET:                sResult=QString("Crypto Obfuscator For .Net");                  break;
        case RECORD_NAME_CRYPTORBYDISMEMBER:                    sResult=QString("Cryptor by Dismember");                        break;
        case RECORD_NAME_CRYPTOZ:                               sResult=QString("CRyptOZ");                                     break;
        case RECORD_NAME_CRYPTRROADS:                           sResult=QString("Crypt R.roads");                               break;
        case RECORD_NAME_CVTOMF:                                sResult=QString("CVTOMF");                                      break;
        case RECORD_NAME_CVTPGD:                                sResult=QString("Cvtpgd");                                      break;
        case RECORD_NAME_CVTRES:                                sResult=QString("CVTRES");                                      break;
        case RECORD_NAME_CWSDPMI:                               sResult=QString("CWSDPMI");                                     break;
        case RECORD_NAME_CYGWIN:                                sResult=QString("Cygwin");                                      break;
        case RECORD_NAME_DALKRYPT:                              sResult=QString("DalKrypt");                                    break;
        case RECORD_NAME_DCRYPTPRIVATE:                         sResult=QString("DCrypt Private");                              break;
        case RECORD_NAME_DEB:                                   sResult=QString("DEB");                                         break;
        case RECORD_NAME_DEEPSEA:                               sResult=QString("DeepSea");                                     break;
        case RECORD_NAME_DEPACK:                                sResult=QString("dePack");                                      break;
        case RECORD_NAME_DEPLOYMASTER:                          sResult=QString("DeployMaster");                                break;
        case RECORD_NAME_DEX:                                   sResult=QString("DEX");                                         break;
        case RECORD_NAME_DJVU:                                  sResult=QString("DjVu");                                        break;
        case RECORD_NAME_DIET:                              	sResult=QString("DIET");                                        break;
        case RECORD_NAME_DIRTYCRYPTOR:                          sResult=QString("DirTy Cryptor");                               break;
        case RECORD_NAME_DMD32D:                                sResult=QString("DMD32 D");                                     break;
        case RECORD_NAME_DNGUARD:                               sResult=QString("DNGuard");                                     break;
        case RECORD_NAME_DOS16M:                                sResult=QString("DOS/16M");                                     break;
        case RECORD_NAME_DOTFIXNICEPROTECT:                     sResult=QString("DotFix Nice Protect");                         break;
        case RECORD_NAME_DOTFUSCATOR:                           sResult=QString("Dotfuscator");                                 break;
        case RECORD_NAME_DOTNET:                                sResult=QString(".NET");                                        break;
        case RECORD_NAME_DOTNETREACTOR:                         sResult=QString(".NET Reactor");                                break;
        case RECORD_NAME_DOTNETSHRINK:                          sResult=QString(".netshrink");                                  break;
        case RECORD_NAME_DOTNETSPIDER:                          sResult=QString(".NET Spider");                                 break;
        case RECORD_NAME_DOTNETZ:                               sResult=QString(".NETZ");                                       break;
        case RECORD_NAME_DROPBOX:                               sResult=QString("Dropbox");                                     break;
        case RECORD_NAME_DVCLAL:                                sResult=QString("DVCLAL");                                      break;
        case RECORD_NAME_DYAMAR:                                sResult=QString("DYAMAR");                                      break;
        case RECORD_NAME_EAZFUSCATOR:                           sResult=QString("Eazfuscator");                                 break;
        case RECORD_NAME_EMBARCADEROCPP:                        sResult=QString("Embarcadero C++");                             break;
        case RECORD_NAME_EMBARCADEROCPPBUILDER:                 sResult=QString("Embarcadero C++ Builder");                     break;
        case RECORD_NAME_EMBARCADERODELPHI:                     sResult=QString("Embarcadero Delphi");                          break;
        case RECORD_NAME_EMBARCADERODELPHIDOTNET:               sResult=QString("Embarcadero Delphi .NET");                     break;
        case RECORD_NAME_EMBARCADEROOBJECTPASCAL:               sResult=QString("Embarcadero Object Pascal");                   break;
        case RECORD_NAME_EMPTYFILE:                             sResult=QString("Empty File");                                  break;
        case RECORD_NAME_ENCRYPTPE:                             sResult=QString("EncryptPE");                                   break;
        case RECORD_NAME_ENIGMA:                                sResult=QString("ENIGMA");                                      break;
        case RECORD_NAME_EPEXEPACK:                             sResult=QString("!EP(EXE Pack)");                               break;
        case RECORD_NAME_EPROT:                                 sResult=QString("!EProt");                                      break;
        case RECORD_NAME_EXE32PACK:                             sResult=QString("exe32pack");                                   break;
        case RECORD_NAME_EXECRYPT:                              sResult=QString("EXECrypt");                                    break;
        case RECORD_NAME_EXECRYPTOR:                            sResult=QString("EXECryptor");                                  break;
        case RECORD_NAME_EXEFOG:                                sResult=QString("ExeFog");                                      break;
        case RECORD_NAME_EXEJOINER:                             sResult=QString("ExeJoiner");                                   break;
        case RECORD_NAME_EXEMPLARINSTALLER:                     sResult=QString("Exemplar Installer");                          break;
        case RECORD_NAME_EXEPACK:                                sResult=QString("EXEPACK");                                    break;
        case RECORD_NAME_EXESAX:                                sResult=QString("ExeSax");                                      break;
        case RECORD_NAME_EXESHIELD:                             sResult=QString("Exe Shield");                                  break;
        case RECORD_NAME_EXPORT:                                sResult=QString("Export");                                      break;
        case RECORD_NAME_EXPRESSOR:                             sResult=QString("eXPressor");                                   break;
        case RECORD_NAME_EZIP:                                  sResult=QString("EZIP");                                        break;
        case RECORD_NAME_FAKESIGNATURE:                         sResult=QString("Fake signature");                              break;
        case RECORD_NAME_FAKUSCRYPTOR:                          sResult=QString("Fakus Cryptor");                               break;
        case RECORD_NAME_FASM:                                  sResult=QString("FASM");                                        break;
        case RECORD_NAME_FASTFILECRYPT:                         sResult=QString("Fast File Crypt");                             break;
        case RECORD_NAME_FEARZCRYPTER:                          sResult=QString("fEaRz Crypter");                               break;
        case RECORD_NAME_FEARZPACKER:                           sResult=QString("fEaRz Packer");                                break;
        case RECORD_NAME_FILESHIELD:                            sResult=QString("FileShield");                                   break;
        case RECORD_NAME_FISHNET:                               sResult=QString("FISH .NET");                                   break;
        case RECORD_NAME_FISHPEPACKER:                          sResult=QString("Fish PE Packer");                              break;
        case RECORD_NAME_FISHPESHIELD:                          sResult=QString("Fish PE Shield");                              break;
        case RECORD_NAME_FLEXLM:                                sResult=QString("Flex License Manager");                        break;
        case RECORD_NAME_FLEXNET:                               sResult=QString("FlexNet Licensing");                           break;
        case RECORD_NAME_FPC:                                   sResult=QString("Free Pascal");                                 break;
        case RECORD_NAME_FREECRYPTOR:                           sResult=QString("FreeCryptor");                                 break;
        case RECORD_NAME_FSG:                                   sResult=QString("FSG");                                         break;
        case RECORD_NAME_GCC:                                   sResult=QString("GCC");                                         break;
        case RECORD_NAME_GENERIC:                               sResult=QString("Generic");                                     break;
        case RECORD_NAME_GENERICLINKER:                         sResult=QString("Generic Linker");                              break;
        case RECORD_NAME_GENTEEINSTALLER:                       sResult=QString("Gentee Installer");                            break;
        case RECORD_NAME_GHAZZACRYPTER:                         sResult=QString("GhaZza CryPter");                              break; // st
        case RECORD_NAME_GHOSTINSTALLER:                        sResult=QString("Ghost Installer");                             break;
        case RECORD_NAME_GKRIPTO:                               sResult=QString("GKripto");                                     break;
        case RECORD_NAME_GKSETUPSFX:                            sResult=QString("GkSetup SFX");                                 break;
        case RECORD_NAME_GNULINKER:                             sResult=QString("GNU ld");                                      break;
        case RECORD_NAME_GO:                                    sResult=QString("Go");                                          break;
        case RECORD_NAME_GOASM:                                 sResult=QString("GoAsm");                                       break;
        case RECORD_NAME_GOLIATHNET:                            sResult=QString("Goliath .NET");                                break;
        case RECORD_NAME_GOLINK:                                sResult=QString("GoLink");                                      break;
        case RECORD_NAME_GOOGLE:                                sResult=QString("Google");                                      break;
        case RECORD_NAME_GPINSTALL:                             sResult=QString("GP-Install");                                  break;
        case RECORD_NAME_GUARDIANSTEALTH:                       sResult=QString("Guardian Stealth");                            break;
        case RECORD_NAME_GZIP:                                  sResult=QString("GZIP");                                        break;
        case RECORD_NAME_H4CKY0UORGCRYPTER:                     sResult=QString("H4ck-y0u.org Crypter");                        break;
        case RECORD_NAME_HACCREWCRYPTER:                        sResult=QString("HAC Crew Crypter");                            break;
        case RECORD_NAME_HACKSTOP:                              sResult=QString("HackStop");                                    break;
        case RECORD_NAME_HALVCRYPTER:                           sResult=QString("HaLV Crypter");                                break;
        case RECORD_NAME_HIDEANDPROTECT:                        sResult=QString("Hide&Protect");                                break;
        case RECORD_NAME_HIDEPE:                                sResult=QString("HidePE");                                      break;
        case RECORD_NAME_HMIMYSPACKER:                          sResult=QString("Hmimys Packer");                               break;
        case RECORD_NAME_HMIMYSPROTECTOR:                       sResult=QString("Hmimys's Protector");                          break;
        case RECORD_NAME_HOUNDHACKCRYPTER:                      sResult=QString("Hound Hack Crypter");                          break;
        case RECORD_NAME_HTML:                                  sResult=QString("HTML");                                        break;
        case RECORD_NAME_HXS:                                   sResult=QString("HXS");                                         break;
        case RECORD_NAME_IBMPCPASCAL:                           sResult=QString("IBM PC Pascal");                               break;
        case RECORD_NAME_ICE:                                   sResult=QString("ICE");                                         break;
        case RECORD_NAME_ICRYPT:                                sResult=QString("ICrypt");                                      break;
        case RECORD_NAME_ILASM:                                 sResult=QString("ILAsm");                                       break;
        case RECORD_NAME_IMPORT:                                sResult=QString("Import");                                      break;
        case RECORD_NAME_INFCRYPTOR:                            sResult=QString("INF Cryptor");                                 break;
        case RECORD_NAME_INNOSETUP:                             sResult=QString("Inno Setup");                                  break;
        case RECORD_NAME_INQUARTOSOBFUSCATOR:                   sResult=QString("Inquartos Obfuscator");                        break;
        case RECORD_NAME_INSTALL4J:                             sResult=QString("install4j");                                   break;
        case RECORD_NAME_INSTALLANYWHERE:                       sResult=QString("InstallAnywhere");                             break;
        case RECORD_NAME_INSTALLSHIELD:                         sResult=QString("InstallShield");                               break;
        case RECORD_NAME_IPBPROTECT:                            sResult=QString("iPB Protect");                                 break;
        case RECORD_NAME_ISO9660:                               sResult=QString("ISO 9660");                                    break;
        case RECORD_NAME_JAM:                                   sResult=QString("JAM");                                         break;
        case RECORD_NAME_JAR:                                   sResult=QString("JAR");                                         break;
        case RECORD_NAME_JAVA:                                  sResult=QString("Java");                                        break;
        case RECORD_NAME_JAVACOMPILEDCLASS:                     sResult=QString("Java compiled class");                         break;
        case RECORD_NAME_JDPACK:                                sResult=QString("JDPack");                                      break;
        case RECORD_NAME_JPEG:                                  sResult=QString("JPEG");                                        break;
        case RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER:         sResult=QString("KaOs PE-DLL eXecutable Undetecter");           break;
        case RECORD_NAME_KBYS:                                  sResult=QString("KByS");                                        break;
        case RECORD_NAME_KCRYPTOR:                              sResult=QString("K!Cryptor");                                   break;
        case RECORD_NAME_KGBCRYPTER:                            sResult=QString("KGB Crypter");                                 break;
        case RECORD_NAME_KIAMSCRYPTOR:                          sResult=QString("KiAms Cryptor");                               break;
        case RECORD_NAME_KKRUNCHY:                              sResult=QString("kkrunchy");                                    break;
        case RECORD_NAME_KRATOSCRYPTER:                         sResult=QString("Kratos Crypter");                              break;
        case RECORD_NAME_KRYPTON:                               sResult=QString("Krypton");                                     break;
        case RECORD_NAME_KUR0KX2TO:                             sResult=QString("Kur0k.X2.to");                                 break;
        case RECORD_NAME_LARP64:                                sResult=QString("lARP64");                                      break;
        case RECORD_NAME_LAYHEYFORTRAN90:                       sResult=QString("Lahey Fortran 90");                            break;
        case RECORD_NAME_LAZARUS:                               sResult=QString("Lazarus");                                     break;
        case RECORD_NAME_LCCLNK:                                sResult=QString("lcclnk");                                      break;
        case RECORD_NAME_LCCWIN:                                sResult=QString("lcc-win");                                     break;
        case RECORD_NAME_LGLZ:                                  sResult=QString("LGLZ");                                        break;
        case RECORD_NAME_LHA:                                   sResult=QString("LHA");                                         break;
        case RECORD_NAME_LHASSFX:                               sResult=QString("LHA's SFX");                                   break;
        case RECORD_NAME_LIGHTNINGCRYPTERPRIVATE:               sResult=QString("Lightning Crypter Private");                   break;
        case RECORD_NAME_LIGHTNINGCRYPTERSCANTIME:              sResult=QString("Lightning Crypter ScanTime");                  break;
        case RECORD_NAME_LOCKTITE:                              sResult=QString("LockTite+");                                   break;
        case RECORD_NAME_LSCRYPRT:                              sResult=QString("LSCRYPT");                                     break;
        case RECORD_NAME_LUACOMPILED:                           sResult=QString("Lua compiled");                                break;
        case RECORD_NAME_LUCYPHER:                              sResult=QString("LuCypher");                                    break;
        case RECORD_NAME_LZEXE:                                 sResult=QString("LZEXE");                                       break;
        case RECORD_NAME_MACROBJECT:                            sResult=QString("Macrobject");                                  break;
        case RECORD_NAME_MALPACKER:                             sResult=QString("Mal Packer");                                  break;
        case RECORD_NAME_MASKPE:                                sResult=QString("MaskPE");                                      break;
        case RECORD_NAME_MASM:                                  sResult=QString("MASM");                                        break;
        case RECORD_NAME_MASM32:                                sResult=QString("MASM32");                                      break;
        case RECORD_NAME_MAXTOCODE:                             sResult=QString("MaxtoCode");                                   break;
        case RECORD_NAME_MEW10:                                 sResult=QString("MEW10");                                       break;
        case RECORD_NAME_MEW11SE:                               sResult=QString("MEW11 SE");                                    break;
        case RECORD_NAME_MFC:                                   sResult=QString("MFC");                                         break;
        case RECORD_NAME_MICROSOFTACCESS:                       sResult=QString("Microsoft Access");                            break;
        case RECORD_NAME_MICROSOFTC:                            sResult=QString("Microsoft C");                                 break;
        case RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP:             sResult=QString("Microsoft Compiled HTML Help");                break;
        case RECORD_NAME_MICROSOFTCPP:                          sResult=QString("Microsoft C++");                               break;
        case RECORD_NAME_MICROSOFTDOTNETFRAMEWORK:              sResult=QString("Microsoft .NET Framework");                    break;
        case RECORD_NAME_MICROSOFTEXCEL:                        sResult=QString("Microsoft Excel");                             break;
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
        case RECORD_NAME_MOLEBOX:                               sResult=QString("MoleBox");                                     break;
        case RECORD_NAME_MOLEBOXULTRA:                          sResult=QString("MoleBox Ultra");                               break;
        case RECORD_NAME_MONEYCRYPTER:                          sResult=QString("Money Crypter");                               break;
        case RECORD_NAME_MORPHNAH:                              sResult=QString("Morphnah");                                    break;
        case RECORD_NAME_MORTALTEAMCRYPTER:                     sResult=QString("Mortal Team Crypter");                         break;
        case RECORD_NAME_MORTALTEAMCRYPTER2:                    sResult=QString("Mortal Team Crypter 2");                       break;
        case RECORD_NAME_MORUKCREWCRYPTERPRIVATE:               sResult=QString("MoruK creW Crypter Private");                  break;
        case RECORD_NAME_MP3:                                   sResult=QString("MP3");                                         break;
        case RECORD_NAME_MP4:                                   sResult=QString("MP4");                                         break;
        case RECORD_NAME_MPACK:                                 sResult=QString("mPack");                                       break;
        case RECORD_NAME_MPRESS:                                sResult=QString("MPRESS");                                      break;
        case RECORD_NAME_MRUNDECTETABLE:                        sResult=QString("Mr Undectetable");                             break;
        case RECORD_NAME_MSYS:                                  sResult=QString("Msys");                                        break;
        case RECORD_NAME_MSYS2:                                 sResult=QString("MSYS2");                                       break;
        case RECORD_NAME_MZ0OPE:                                sResult=QString("MZ0oPE");                                      break;
        case RECORD_NAME_NAKEDPACKER:                           sResult=QString("NakedPacker");                                 break;
        case RECORD_NAME_NEOLITE:                               sResult=QString("NeoLite");                                     break;
        case RECORD_NAME_NIDHOGG:                               sResult=QString("Nidhogg");                                     break;
        case RECORD_NAME_NJOINER:                               sResult=QString("N-Joiner");                                    break;
        case RECORD_NAME_NME:                                   sResult=QString("NME");                                         break;
        case RECORD_NAME_NOOBYPROTECT:                          sResult=QString("NoobyProtect");                                break;
        case RECORD_NAME_NORTHSTARPESHRINKER:                   sResult=QString("North Star PE Shrinker");                      break;
        case RECORD_NAME_NOSTUBLINKER:                          sResult=QString("NOSTUBLINKER");                                break;
        case RECORD_NAME_NOXCRYPT:                              sResult=QString("noX Crypt");                                   break;
        case RECORD_NAME_NPACK:                                 sResult=QString("nPack");                                       break;
        case RECORD_NAME_NSIS:                                  sResult=QString("Nullsoft Scriptable Install System");          break;
        case RECORD_NAME_NSPACK:                                sResult=QString("NsPack");                                      break;
        case RECORD_NAME_OBFUSCAR:                              sResult=QString("Obfuscar");                                    break;
        case RECORD_NAME_OBFUSCATORNET2009:                     sResult=QString("Obfuscator.NET 2009");                         break;
        case RECORD_NAME_OBJECTPASCAL:                          sResult=QString("Object Pascal");                               break;
        case RECORD_NAME_OBSIDIUM:                              sResult=QString("Obsidium");                                    break;
        case RECORD_NAME_OPENDOCUMENT:                          sResult=QString("Open Document");                               break;
        case RECORD_NAME_OPENSOURCECODECRYPTER:                 sResult=QString("Open Source Code Crypter");                    break;
        case RECORD_NAME_OPERA:                                 sResult=QString("Opera");                                       break;
        case RECORD_NAME_ORIEN:                                 sResult=QString("ORiEN");                                       break;
        case RECORD_NAME_OSCCRYPTER:                            sResult=QString("OSC-Crypter");                                 break;
        case RECORD_NAME_P0KESCRAMBLER:                         sResult=QString("p0ke Scrambler");                              break;
        case RECORD_NAME_PACKMAN:                               sResult=QString("Packman");                                     break;
        case RECORD_NAME_PACKWIN:                               sResult=QString("PACKWIN");                                     break;
        case RECORD_NAME_PANDORA:                               sResult=QString("Pandora");                                     break;
        case RECORD_NAME_PCGUARD:                               sResult=QString("PC Guard");                                    break;
        case RECORD_NAME_PCOM:                                  sResult=QString("PCOM");                                        break;
        case RECORD_NAME_PDB:                                   sResult=QString("PDB");                                         break;
        case RECORD_NAME_PDBFILELINK:                           sResult=QString("PDB file link");                               break;
        case RECORD_NAME_PDF:                                   sResult=QString("PDF");                                         break;
        case RECORD_NAME_PEARMOR:                               sResult=QString("PE-Armor");                                    break;
        case RECORD_NAME_PEBUNDLE:                              sResult=QString("PEBundle");                                    break;
        case RECORD_NAME_PECOMPACT:                             sResult=QString("PECompact");                                   break;
        case RECORD_NAME_PEENCRYPT:                             sResult=QString("PE Encrypt");                                  break;
        case RECORD_NAME_PELOCK:                                sResult=QString("PELock");                                      break;
        case RECORD_NAME_PEPACK:                                sResult=QString("PE-PACK");                                     break;
        case RECORD_NAME_PEPACKSPROTECT:                        sResult=QString("pepack's Protect");                            break;
        case RECORD_NAME_PEQUAKE:                               sResult=QString("PE Quake");                                    break;
        case RECORD_NAME_PERL:                                  sResult=QString("Perl");                                        break;
        case RECORD_NAME_PESHIELD:                              sResult=QString("PE-SHiELD");                                   break;
        case RECORD_NAME_PESPIN:                                sResult=QString("PESpin");                                      break;
        case RECORD_NAME_PETITE:                                sResult=QString("Petite");                                      break;
        case RECORD_NAME_PEX:                                   sResult=QString("PeX");                                         break;
        case RECORD_NAME_PFECX:                                 sResult=QString("PFE CX");                                      break;
        case RECORD_NAME_PGMPAK:                                sResult=QString("PGMPAK");                                      break;
        case RECORD_NAME_PHOENIXPROTECTOR:                      sResult=QString("Phoenix Protector");                           break;
        case RECORD_NAME_PHP:                                   sResult=QString("PHP");                                         break;
        case RECORD_NAME_PICRYPTOR:                             sResult=QString("PI Cryptor");                                  break;
        case RECORD_NAME_PKLITE:                                sResult=QString("PKLITE");                                      break;
        case RECORD_NAME_PKLITE32:                              sResult=QString("PKLITE32");                                    break;
        case RECORD_NAME_PKZIPMINISFX:                          sResult=QString("PKZIP mini-sfx");                              break;
        case RECORD_NAME_PLAIN:                                 sResult=QString("Plain");                                       break;
        case RECORD_NAME_PMODEW:                                sResult=QString("PMODE/W");                                     break;
        case RECORD_NAME_PNG:                                   sResult=QString("PNG");                                         break;
        case RECORD_NAME_POKECRYPTER:                           sResult=QString("Poke Crypter");                                break;
        case RECORD_NAME_POLYCRYPTPE:                           sResult=QString("PolyCrypt PE");                                break;
        case RECORD_NAME_POWERBASIC:                            sResult=QString("PowerBASIC");                                  break;
        case RECORD_NAME_PRIVATEEXEPROTECTOR:                   sResult=QString("Private EXE Protector");                       break;
        case RECORD_NAME_PROPACK:                               sResult=QString("PRO-PACK");                                    break;
        case RECORD_NAME_PROTECTEXE:                            sResult=QString("PROTECT! EXE");                                break;
        case RECORD_NAME_PUBCRYPTER:                            sResult=QString("Pub Crypter");                                 break;
        case RECORD_NAME_PUNISHER:                              sResult=QString("PUNiSHER");                                    break;
        case RECORD_NAME_PUREBASIC:                             sResult=QString("PureBasic");                                   break;
        case RECORD_NAME_PUSSYCRYPTER:                          sResult=QString("PussyCrypter");                                break;
        case RECORD_NAME_PYTHON:                                sResult=QString("Python");                                      break;
        case RECORD_NAME_QT:                                    sResult=QString("Qt");                                          break;
        case RECORD_NAME_QTINSTALLER:                           sResult=QString("Qt Installer");                                break;
        case RECORD_NAME_QUICKPACKNT:                           sResult=QString("QuickPack NT");                                break;
        case RECORD_NAME_RAR:                                   sResult=QString("RAR");                                         break;
        case RECORD_NAME_RCRYPTOR:                              sResult=QString("RCryptor(Russian Cryptor)");                   break;
        case RECORD_NAME_RDGTEJONCRYPTER:                       sResult=QString("RDG Tejon Crypter");                           break;
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
        case RECORD_NAME_SAFEENGINESHIELDEN:                    sResult=QString("Safengine Shielden");                          break;
        case RECORD_NAME_SCPACK:                                sResult=QString("SC Pack");                                     break;
        case RECORD_NAME_SCRNCH:                                sResult=QString("SCRNCH");                                      break;
        case RECORD_NAME_SDPROTECTORPRO:                        sResult=QString("SDProtector Pro");                             break;
        case RECORD_NAME_SECURESHADE:                           sResult=QString("Secure Shade");                                break;
        case RECORD_NAME_SETUPFACTORY:                          sResult=QString("Setup Factory");                               break;
        case RECORD_NAME_SEXECRYPTER:                           sResult=QString("Sexe Crypter");                                break;
        case RECORD_NAME_SHELL:                                 sResult=QString("Shell");                                       break;
        case RECORD_NAME_SHRINKER:                              sResult=QString("Shrinker");                                    break;
        case RECORD_NAME_SIMBIOZ:                               sResult=QString("SimbiOZ");                                     break;
        case RECORD_NAME_SIMCRYPTER:                            sResult=QString("Sim Crypter");                                 break;
        case RECORD_NAME_SIMPLECRYPTER:                         sResult=QString("Simple Crypter");                              break;
        case RECORD_NAME_SIMPLEPACK:                            sResult=QString("Simple Pack");                                 break;
        case RECORD_NAME_SIXXPACK:                              sResult=QString("Sixxpack");                                    break;
        case RECORD_NAME_SKATER:                                sResult=QString("Skater");                                      break;
        case RECORD_NAME_SMARTASSEMBLY:                         sResult=QString("Smart Assembly");                              break;
        case RECORD_NAME_SMARTINSTALLMAKER:                     sResult=QString("Smart Install Maker");                         break;
        case RECORD_NAME_SMOKESCREENCRYPTER:                    sResult=QString("SmokeScreen Crypter");                         break;
        case RECORD_NAME_SNOOPCRYPT:                            sResult=QString("Snoop Crypt");                                 break;
        case RECORD_NAME_SOFTWARECOMPRESS:                      sResult=QString("Software Compress");                           break;
        case RECORD_NAME_SOFTWAREZATOR:                         sResult=QString("SoftwareZator");                               break;
        case RECORD_NAME_SPICESNET:                             sResult=QString("Spices.Net");                                  break;
        case RECORD_NAME_SPIRIT:                                sResult=QString("$pirit");                                      break;
        case RECORD_NAME_SPOONINSTALLER:                        sResult=QString("Spoon Installer");                             break;
        case RECORD_NAME_SQUEEZSFX:                             sResult=QString("Squeez Self Extractor");                       break;
        case RECORD_NAME_STARFORCE:                             sResult=QString("StarForce");                                   break;
        case RECORD_NAME_STASFODIDOCRYPTOR:                     sResult=QString("StasFodidoCryptor");                           break;
        case RECORD_NAME_SVKPROTECTOR:                          sResult=QString("SVK Protector");                               break;
        case RECORD_NAME_SWF:                                   sResult=QString("SWF");                                         break;
        case RECORD_NAME_TARMAINSTALLER:                        sResult=QString("Tarma Installer");                             break;
        case RECORD_NAME_TELOCK:                                sResult=QString("tElock");                                      break;
        case RECORD_NAME_TGRCRYPTER:                            sResult=QString("TGR Crypter");                                 break;
        case RECORD_NAME_THEBESTCRYPTORBYFSK:                   sResult=QString("The Best Cryptor [by FsK]");                   break;
        case RECORD_NAME_THEMIDAWINLICENSE:                     sResult=QString("Themida/Winlicense");                          break;
        case RECORD_NAME_THEZONECRYPTER:                        sResult=QString("The Zone Crypter");                            break;
        case RECORD_NAME_THINSTALL:                             sResult=QString("Thinstall(VMware ThinApp)");                   break;
        case RECORD_NAME_TINYPROG:                              sResult=QString("TinyProg");                                    break;
        case RECORD_NAME_TOTALCOMMANDERINSTALLER:               sResult=QString("Total Commander Installer");                   break;
        case RECORD_NAME_TPPPACK:                               sResult=QString("TTP Pack");                                    break;
        case RECORD_NAME_TSTCRYPTER:                            sResult=QString("TsT Crypter");                                 break;
        case RECORD_NAME_TTF:                                   sResult=QString("True Type Font");                              break;
        case RECORD_NAME_TTPROTECT:                             sResult=QString("TTprotect");                                   break;
        case RECORD_NAME_TURBOBASIC:                            sResult=QString("Turbo Basic");                                 break;
        case RECORD_NAME_TURBOC:                                sResult=QString("Turbo C");                                     break;
        case RECORD_NAME_TURBOCPP:                              sResult=QString("Turbo C++");                                   break;
        case RECORD_NAME_TURBOLINKER:                           sResult=QString("Turbo linker");                                break;
        case RECORD_NAME_TURKISHCYBERSIGNATURE:                 sResult=QString("Turkish Cyber Signature");                     break;
        case RECORD_NAME_TURKOJANCRYPTER:                       sResult=QString("Turkojan Crypter");                            break;
        case RECORD_NAME_UCEXE:                                 sResult=QString("UCEXE");                                       break;
        case RECORD_NAME_UNDERGROUNDCRYPTER:                    sResult=QString("UnderGround Crypter");                         break;
        case RECORD_NAME_UNDOCRYPTER:                           sResult=QString("UnDo Crypter");                                break;
        case RECORD_NAME_UNICODE:                               sResult=QString("Unicode");                                     break;
        case RECORD_NAME_UNILINK:                               sResult=QString("UniLink");                                     break;
        case RECORD_NAME_UNIVERSALTUPLECOMPILER:                sResult=QString("Universal Tuple Compiler");                    break;
        case RECORD_NAME_UNKOWNCRYPTER:                         sResult=QString("unkOwn Crypter");                              break;
        case RECORD_NAME_UNK_UPXLIKE:                           sResult=QString("(Unknown)UPX-like");                           break;
        case RECORD_NAME_UNOPIX:                                sResult=QString("Unopix");                                      break;
        case RECORD_NAME_UPX:                                   sResult=QString("UPX");                                         break;
        case RECORD_NAME_UTF8:                                  sResult=QString("UTF-8");                                       break;
        case RECORD_NAME_VALVE:                                 sResult=QString("Valve");                                       break;
        case RECORD_NAME_VBNET:                                 sResult=QString("VB .NET");                                     break;
        case RECORD_NAME_VCASMPROTECTOR:                        sResult=QString("VCasm-Protector");                             break;
        case RECORD_NAME_VCL:                                   sResult=QString("Visual Component Library");                    break;
        case RECORD_NAME_VCLPACKAGEINFO:                        sResult=QString("VCL PackageInfo");                             break;
        case RECORD_NAME_VERACRYPT:                             sResult=QString("VeraCrypt");                                   break;
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
        case RECORD_NAME_WATCOMC:                               sResult=QString("Watcom C");                                    break;
        case RECORD_NAME_WATCOMCCPP:                            sResult=QString("Watcom C/C++");                                break;
        case RECORD_NAME_WATCOMLINKER:                          sResult=QString("Watcom linker");                               break;
        case RECORD_NAME_WAV:                                   sResult=QString("WAV");                                         break;
        case RECORD_NAME_WDOSX:                                 sResult=QString("WDOSX");                                       break;
        case RECORD_NAME_WHITELLCRYPT:                          sResult=QString("Whitell Crypt");                               break;
        case RECORD_NAME_WINACE:                                sResult=QString("WinACE");                                      break;
        case RECORD_NAME_WINAUTH:                               sResult=QString("Windows Authenticode");                        break;
        case RECORD_NAME_WINDOFCRYPT:                           sResult=QString("WindOfCrypt");                                 break;
        case RECORD_NAME_WINDOWSBITMAP:                         sResult=QString("Windows Bitmap");                              break;
        case RECORD_NAME_WINDOWSICON:                           sResult=QString("Windows Icon");                                break;
        case RECORD_NAME_WINDOWSINSTALLER:                      sResult=QString("Windows Installer");                           break;
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
        case RECORD_NAME_WWPACK:                                sResult=QString("WWPack");                                      break;
        case RECORD_NAME_WWPACK32:                              sResult=QString("WWPack32");                                    break;
        case RECORD_NAME_WXWIDGETS:                             sResult=QString("wxWidgets");                                   break;
        case RECORD_NAME_XAR:                                   sResult=QString("xar");                                         break;
        case RECORD_NAME_XENOCODE:                              sResult=QString("Xenocode");                                    break;
        case RECORD_NAME_XENOCODEPOSTBUILD:                     sResult=QString("Xenocode Postbuild");                          break;
        case RECORD_NAME_XENOCODEPOSTBUILD2009:                 sResult=QString("Xenocode Postbuild 2009");                     break;
        case RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009:  sResult=QString("Xenocode Virtual Application Studio 2009");    break;
        case RECORD_NAME_XCOMP:                                 sResult=QString("XComp");                                       break;
        case RECORD_NAME_XML:                                   sResult=QString("XML");                                         break;
        case RECORD_NAME_XPACK:                                 sResult=QString("XPack");                                       break;
        case RECORD_NAME_XTREMEPROTECTOR:                       sResult=QString("Xtreme-Protector");                            break;
        case RECORD_NAME_XTREAMLOK:                             sResult=QString("Xtreamlok");                                   break;
        case RECORD_NAME_XVOLKOLAK:                             sResult=QString("XVolkolak");                                   break;
        case RECORD_NAME_YANDEX:                                sResult=QString("Yandex");                                      break;
        case RECORD_NAME_YANO:                                  sResult=QString("Yano");                                        break;
        case RECORD_NAME_YODASCRYPTER:                          sResult=QString("Yoda's Crypter");                              break;
        case RECORD_NAME_YODASPROTECTOR:                        sResult=QString("Yoda's Protector");                            break;
        case RECORD_NAME_YZPACK:                                sResult=QString("YZPack");                                      break;
        case RECORD_NAME_ZELDACRYPT:                            sResult=QString("ZeldaCrypt");                                  break;
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

QString SpecAbstract::heurTypeIdToString(SpecAbstract::HEURTYPE id)
{
    QString sResult=tr("Unknown");

    switch(id)
    {
        case HEURTYPE_UNKNOWN:                          sResult=tr("Unknown");                                      break;
        case HEURTYPE_HEADER:                           sResult=tr("Header");                                       break;
        case HEURTYPE_OVERLAY:                          sResult=tr("Overlay");                                      break;
        case HEURTYPE_ENTRYPOINT:                       sResult=tr("Entry point");                                  break;
        case HEURTYPE_SECTIONNAME:                      sResult=tr("Section name");                                 break;
        case HEURTYPE_IMPORTHASH:                       sResult=QString("Import hash");                             break;
        case HEURTYPE_CODESECTION:                      sResult=tr("Code section");                                 break;
        case HEURTYPE_ENTRYPOINTSECTION:                sResult=tr("Entry point section");                          break;
        case HEURTYPE_NETANSISTRING:                    sResult=QString(".NET ANSI %1").arg(tr("String"));          break;
        case HEURTYPE_RICH:                             sResult=QString("RICH");                                    break;
    }

    return sResult;
}

SpecAbstract::UNPACK_OPTIONS SpecAbstract::getPossibleUnpackOptions(QIODevice *pDevice,bool bIsImage)
{
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

    sResult+=QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name)).arg(pScanStruct->sVersion).arg(pScanStruct->sInfo);

    return sResult;
}

QString SpecAbstract::createResultString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name)).arg(pScanStruct->sVersion).arg(pScanStruct->sInfo);

    return sResult;
}

QString SpecAbstract::createResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name));

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

    sResult+=QString("%1: %2").arg(createTypeString(pScanStruct)).arg(createResultString(pScanStruct));

    return sResult;
}

QString SpecAbstract::createFullResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->bIsHeuristic)
    {
        sResult+="(Heuristic)";
    }

    sResult+=QString("%1: %2").arg(createTypeString(pScanStruct)).arg(createResultString2(pScanStruct));

    return sResult;
}

QString SpecAbstract::createTypeString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult;

    if(pScanStruct->parentId.filepart!=RECORD_FILEPART_HEADER)
    {
        sResult+=SpecAbstract::recordFilepartIdToString(pScanStruct->parentId.filepart);

        if(pScanStruct->parentId.sInfo!="")
        {
            sResult+=QString("(%1)").arg(pScanStruct->parentId.sInfo);
        }

        sResult+=": ";
    }

    sResult+=SpecAbstract::recordFiletypeIdToString(pScanStruct->id.filetype);

    return sResult;
}

SpecAbstract::SCAN_STRUCT SpecAbstract::createHeaderScanStruct(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    SCAN_STRUCT result=*pScanStruct;
    result.id.uuid=QUuid::createUuid();
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

SpecAbstract::BINARYINFO_STRUCT SpecAbstract::getBinaryInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    BINARYINFO_STRUCT result={};

    XBinary binary(pDevice,pOptions->bIsImage);

    result.basic_info.parentId=parentId;
    result.basic_info.id.filetype=RECORD_FILETYPE_BINARY;
    result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
    result.basic_info.id.uuid=QUuid::createUuid();
    result.basic_info.nOffset=nOffset;
    result.basic_info.nSize=pDevice->size();
    result.basic_info.sHeaderSignature=binary.getSignature(0,150);
    result.basic_info.bIsDeepScan=pOptions->bDeepScan;
    result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
    result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
    result.basic_info.bIsTest=pOptions->bIsTest;
    result.basic_info.memoryMap=binary.getMemoryMap();

    // Scan Header
    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_binary_records,sizeof(_binary_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY,&(result.basic_info),HEURTYPE_HEADER);
    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_COM_records,sizeof(_COM_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_COM,&(result.basic_info),HEURTYPE_HEADER);
    signatureExpScan(&binary,&(result.basic_info.memoryMap),&result.basic_info.mapHeaderDetects,0,_COM_Exp_records,sizeof(_COM_Exp_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_COM,&(result.basic_info),HEURTYPE_HEADER);

    if(result.basic_info.parentId.filetype!=RECORD_FILETYPE_UNKNOWN)
    {
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_PE_overlay_records,sizeof(_PE_overlay_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY,&(result.basic_info),HEURTYPE_HEADER);
    }

    result.bIsPlainText=binary.isPlainTextType();
    result.bIsUTF8=binary.isUTF8TextType();
    result.unicodeType=binary.getUnicodeType();

    if(result.unicodeType!=XBinary::UNICODE_TYPE_NONE)
    {
        result.sHeaderText=binary.read_unicodeString(2,qMin(result.basic_info.nSize,(qint64)0x1000),(result.unicodeType==XBinary::UNICODE_TYPE_BE));
        result.basic_info.id.filetype=RECORD_FILETYPE_TEXT;
    }
    else if(result.bIsUTF8)
    {
        result.sHeaderText=binary.read_utf8String(3,qMin(result.basic_info.nSize,(qint64)0x1000));
        result.basic_info.id.filetype=RECORD_FILETYPE_TEXT;
    }
    else if(result.bIsPlainText)
    {
        result.sHeaderText=binary.read_ansiString(0,qMin(result.basic_info.nSize,(qint64)0x1000));
        result.basic_info.id.filetype=RECORD_FILETYPE_TEXT;
    }

    XZip xzip(pDevice);

    result.bIsZip=xzip.isValid();

    if(result.bIsZip)
    {
        result.listArchiveRecords=xzip.getRecords(100000);
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
    Binary_handle_MicrosoftOffice(pDevice,pOptions->bIsImage,&result);
    Binary_handle_OpenOffice(pDevice,pOptions->bIsImage,&result);
    Binary_handle_JAR(pDevice,pOptions->bIsImage,&result,pOptions);

    Binary_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

    result.basic_info.listDetects.append(result.mapResultTexts.values());
    result.basic_info.listDetects.append(result.mapResultArchives.values());
    result.basic_info.listDetects.append(result.mapResultCertificates.values());
    result.basic_info.listDetects.append(result.mapResultDebugData.values());
    result.basic_info.listDetects.append(result.mapResultFormats.values());
    result.basic_info.listDetects.append(result.mapResultInstallerData.values());
    result.basic_info.listDetects.append(result.mapResultSFXData.values());
    result.basic_info.listDetects.append(result.mapResultProtectorData.values());
    result.basic_info.listDetects.append(result.mapResultDatabases.values());
    result.basic_info.listDetects.append(result.mapResultImages.values());
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

    result.basic_info.listDetects.append(result.listRecursiveDetects);

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::MSDOSINFO_STRUCT SpecAbstract::getMSDOSInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    MSDOSINFO_STRUCT result={};

    XMSDOS msdos(pDevice,pOptions->bIsImage);

    result.basic_info.parentId=parentId;
    result.basic_info.id.filetype=RECORD_FILETYPE_MSDOS;
    result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
    result.basic_info.id.uuid=QUuid::createUuid();
    result.basic_info.nOffset=nOffset;
    result.basic_info.nSize=pDevice->size();
    result.basic_info.sHeaderSignature=msdos.getSignature(0,150);
    result.basic_info.bIsDeepScan=pOptions->bDeepScan;
    result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
    result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
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

    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_HEADER);
    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_header_records,sizeof(_MSDOS_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_HEADER);
    signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_MSDOS_entrypoint_records,sizeof(_MSDOS_entrypoint_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_ENTRYPOINT);

    signatureExpScan(&msdos,&(result.basic_info.memoryMap),&result.mapEntryPointDetects,result.nEntryPointOffset,_MSDOS_entrypointExp_records,sizeof(_MSDOS_entrypointExp_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_ENTRYPOINT);

    MSDOS_handle_Borland(pDevice,pOptions->bIsImage,&result);
    MSDOS_handle_Tools(pDevice,pOptions->bIsImage,&result);
    MSDOS_handle_Protection(pDevice,pOptions->bIsImage,&result);
    MSDOS_handle_SFX(pDevice,pOptions->bIsImage,&result);
    MSDOS_handle_DosExtenders(pDevice,pOptions->bIsImage,&result);

    MSDOS_handle_Recursive(pDevice,pOptions->bIsImage,&result,pOptions);

    result.basic_info.listDetects.append(result.mapResultDosExtenders.values());
    result.basic_info.listDetects.append(result.mapResultLinkers.values());
    result.basic_info.listDetects.append(result.mapResultCompilers.values());
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

    result.basic_info.nElapsedTime=timer.elapsed();

    return result;
}

SpecAbstract::ELFINFO_STRUCT SpecAbstract::getELFInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    ELFINFO_STRUCT result={};

    XELF elf(pDevice,pOptions->bIsImage);

    if(elf.isValid())
    {
        result.bIs64=elf.is64();
        result.bIsBigEndian=elf.isBigEndian();

        result.basic_info.parentId=parentId;
        result.basic_info.id.filetype=result.bIs64?RECORD_FILETYPE_ELF64:RECORD_FILETYPE_ELF32;
        result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
        result.basic_info.id.uuid=QUuid::createUuid();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=elf.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
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

        result.nCommentSection=XELF::getSectionNumber(".comment",&result.listSectionRecords);

        if(result.nCommentSection!=-1)
        {
            result.osCommentSection.nOffset=result.listSectionRecords.at(result.nCommentSection).nOffset;
            result.osCommentSection.nSize=result.listSectionRecords.at(result.nCommentSection).nSize;
        }

        ELF_handle_GCC(pDevice,pOptions->bIsImage,&result);
        ELF_handle_Tools(pDevice,pOptions->bIsImage,&result);
        ELF_handle_Protection(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
        result.basic_info.listDetects.append(result.mapResultPackers.values());

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

SpecAbstract::MACHINFO_STRUCT SpecAbstract::getMACHInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    MACHINFO_STRUCT result={};

    XMACH mach(pDevice,pOptions->bIsImage);

    if(mach.isValid())
    {
        result.bIs64=mach.is64();
        result.bIsBigEndian=mach.isBigEndian();

        result.basic_info.parentId=parentId;
        result.basic_info.id.filetype=result.bIs64?RECORD_FILETYPE_MACH64:RECORD_FILETYPE_MACH32;
        result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
        result.basic_info.id.uuid=QUuid::createUuid();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=mach.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=mach.getMemoryMap();

        result.sEntryPointSignature=mach.getSignature(mach.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.listCommandRecords=mach.getCommandRecords();

        result.listLibraryRecords=mach.getLibraryRecords(&result.listCommandRecords);
        result.listSectionRecords=mach.getSectionRecords(&result.listCommandRecords);

        // TODO Segments
        // TODO Sections

        MACH_handle_Tools(pDevice,pOptions->bIsImage,&result);
        MACH_handle_Protection(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultCompilers.values());
        result.basic_info.listDetects.append(result.mapResultLibraries.values());
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

SpecAbstract::LEINFO_STRUCT SpecAbstract::getLEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    LEINFO_STRUCT result={};

    XLE le(pDevice,pOptions->bIsImage);

    if(le.isValid())
    {
        result.basic_info.parentId=parentId;

        if(le.isLX()) // TODO bLX
        {
            result.basic_info.id.filetype=RECORD_FILETYPE_LX;
        }
        else
        {
            result.basic_info.id.filetype=RECORD_FILETYPE_LE;
        }

        result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
        result.basic_info.id.uuid=QUuid::createUuid();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=le.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=le.getMemoryMap();

        result.sEntryPointSignature=le.getSignature(le.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.listRichSignatures=le.getRichSignatureRecords();

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_HEADER);

        LE_handle_Microsoft(pDevice,pOptions->bIsImage,&result);
        LE_handle_Borland(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());

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

SpecAbstract::NEINFO_STRUCT SpecAbstract::getNEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    NEINFO_STRUCT result={};

    XNE ne(pDevice,pOptions->bIsImage);

    if(ne.isValid())
    {
        result.basic_info.parentId=parentId;
        result.basic_info.id.filetype=RECORD_FILETYPE_NE;
        result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
        result.basic_info.id.uuid=QUuid::createUuid();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=ne.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=ne.getMemoryMap();

        result.sEntryPointSignature=ne.getSignature(ne.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_HEADER);

        NE_handle_Borland(pDevice,pOptions->bIsImage,&result);

        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());

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

SpecAbstract::PEINFO_STRUCT SpecAbstract::getPEInfo(QIODevice *pDevice, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions, qint64 nOffset)
{
    QElapsedTimer timer;
    timer.start();

    PEINFO_STRUCT result={};

    XPE pe(pDevice,pOptions->bIsImage);

    if(pe.isValid())
    {
        result.bIs64=pe.is64();

        result.basic_info.parentId=parentId;
        result.basic_info.id.filetype=result.bIs64?RECORD_FILETYPE_PE64:RECORD_FILETYPE_PE32;
        result.basic_info.id.filepart=RECORD_FILEPART_HEADER;
        result.basic_info.id.uuid=QUuid::createUuid();
        result.basic_info.nOffset=nOffset;
        result.basic_info.nSize=pDevice->size();
        result.basic_info.sHeaderSignature=pe.getSignature(0,150);
        result.basic_info.bIsDeepScan=pOptions->bDeepScan;
        result.basic_info.bIsHeuristicScan=pOptions->bHeuristicScan;
        result.basic_info.bShowHeuristic=pOptions->bShowHeuristic;
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
        //        for(int i=0;i<result.listImports.count();i++)
        //        {
        //            qDebug(result.listImports.at(i).sName.toLatin1().data());
        //            for(int j=0;j<result.listImports.at(i).listPositions.count();j++)
        //            {
        //                qDebug("%d %s",j,result.listImports.at(i).listPositions.at(j).sFunction.toLatin1().data());
        //            }
        //        }
        result.nImportHash64=pe.getImportHash64(&(result.basic_info.memoryMap));
        result.nImportHash32=pe.getImportHash32(&(result.basic_info.memoryMap));
        result.listImportPositionHashes=pe.getImportPositionHashes(&(result.basic_info.memoryMap));

#ifdef QT_DEBUG
        QString sDebugString=QString::number(result.nImportHash64,16)+" "+QString::number(result.nImportHash32,16);
        qDebug("Import hash: %s",sDebugString.toLatin1().data());

        QList<XPE::IMPORT_RECORD> listImports=pe.getImportRecords(&(result.basic_info.memoryMap));

        int nCount=listImports.count();

        for(int i=0;i<nCount; i++)
        {
            QString sRecord=listImports.at(i).sLibrary+" "+listImports.at(i).sFunction;

            qDebug("%s",sRecord.toLatin1().data());
        }

        qDebug("=====================================================================");

        QList<XPE::IMPORT_HEADER> _listImports=pe.getImports(&(result.basic_info.memoryMap));

        for(int i=0;i<_listImports.count();i++)
        {
            qDebug("Import hash: %x",result.listImportPositionHashes.at(i));
            for(int j=0;j<_listImports.at(i).listPositions.count();j++)
            {
                qDebug("%s %s",_listImports.at(i).sName.toLatin1().data(),
                       _listImports.at(i).listPositions.at(j).sFunction.toLatin1().data());
            }
        }
#endif
        result.exportHeader=pe.getExport(&(result.basic_info.memoryMap));
        result.listExportFunctionNames=pe.getExportFunctionsList(&(result.exportHeader));
        result.listResources=pe.getResources(&(result.basic_info.memoryMap));
        result.listRichSignatures=pe.getRichSignatureRecords();
        result.cliInfo=pe.getCliInfo(true,&(result.basic_info.memoryMap));
        result.sResourceManifest=pe.getResourceManifest(&result.listResources);
        result.resVersion=pe.getResourceVersion(&result.listResources);

        result.nEntryPointAddress=result.bIs64?result.optional_header.optionalHeader64.AddressOfEntryPoint:result.optional_header.optionalHeader32.AddressOfEntryPoint;
        result.nImageBaseAddress=result.bIs64?result.optional_header.optionalHeader64.ImageBase:result.optional_header.optionalHeader32.ImageBase;
        result.nMinorLinkerVersion=result.bIs64?result.optional_header.optionalHeader64.MinorLinkerVersion:result.optional_header.optionalHeader32.MinorLinkerVersion;
        result.nMajorLinkerVersion=result.bIs64?result.optional_header.optionalHeader64.MajorLinkerVersion:result.optional_header.optionalHeader32.MajorLinkerVersion;
        result.nMinorImageVersion=result.bIs64?result.optional_header.optionalHeader64.MinorImageVersion:result.optional_header.optionalHeader32.MinorImageVersion;
        result.nMajorImageVersion=result.bIs64?result.optional_header.optionalHeader64.MajorImageVersion:result.optional_header.optionalHeader32.MajorImageVersion;

        result.nEntryPointSection=pe.getEntryPointSection(&(result.basic_info.memoryMap));
        result.nResourceSection=pe.getResourcesSection(&(result.basic_info.memoryMap));
        result.nImportSection=pe.getImportSection(&(result.basic_info.memoryMap));
        result.nCodeSection=pe.getNormalCodeSection(&(result.basic_info.memoryMap));
        result.nDataSection=pe.getNormalDataSection(&(result.basic_info.memoryMap));
        result.nConstDataSection=pe.getConstDataSection(&(result.basic_info.memoryMap));
        result.nRelocsSection=pe.getRelocsSection(&(result.basic_info.memoryMap));
        result.nTLSSection=pe.getTLSSection(&(result.basic_info.memoryMap));

        result.bIsNetPresent=((result.cliInfo.bInit)||(pe.isNETPresent()&&(result.basic_info.bIsDeepScan)));

        if(result.nEntryPointSection!=-1)
        {
            result.sEntryPointSectionName=result.listSectionRecords.at(result.nEntryPointSection).sName;
        }

        //        result.mmCodeSectionSignatures=memoryScan(pDevice,nFirstSectionOffset,qMin((qint64)0x10000,nFirstSectionSize),_memory_records,sizeof(_memory_records),_filetype,SpecAbstract::RECORD_FILETYPE_PE);
        //        if(result.nCodeSection!=-1)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.listSections.at(result.nCodeSection).PointerToRawData,result.listSections.at(result.nCodeSection).SizeOfRawData,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
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

        if(result.nResourceSection!=-1)
        {
            result.osResourceSection.nOffset=result.listSectionRecords.at(result.nResourceSection).nOffset;
            result.osResourceSection.nSize=result.listSectionRecords.at(result.nResourceSection).nSize;
        }

        //        if(result.nCodeSectionSize)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.nCodeSectionOffset,result.nCodeSectionSize,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        //        }

        //        if(result.nDataSectionSize)
        //        {
        //            memoryScan(&result.mapDataSectionScanDetects,pDevice,result.nDataSectionOffset,result.nDataSectionSize,_datasectionscan_records,sizeof(_datasectionscan_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        //        }

        //        // TODO Check if resources exists

        //        memoryScan(&result.mapHeaderScanDetects,pDevice,0,qMin(result.basic_info.nSize,(qint64)1024),_headerscan_records,sizeof(_headerscan_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(result.basic_info),HEURTYPE_HEADER);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_PE_header_records,sizeof(_PE_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_HEADER);
        signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_PE_entrypoint_records,sizeof(_PE_entrypoint_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_ENTRYPOINT);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_binary_records,sizeof(_binary_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY,&(result.basic_info),HEURTYPE_OVERLAY);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_PE_overlay_records,sizeof(_PE_overlay_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY,&(result.basic_info),HEURTYPE_OVERLAY);

        stringScan(&result.mapSectionNamesDetects,&result.listSectionNames,_PE_sectionNames_records,sizeof(_PE_sectionNames_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_SECTIONNAME);

        // Import
        constScan(&(result.mapImportDetects),result.nImportHash64,result.nImportHash32,_PE_importhash_records,sizeof(_PE_importhash_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_IMPORTHASH);

        int nNumberOfImports=result.listImportPositionHashes.count();

        for(int i=0;i<nNumberOfImports;i++)
        {
            constScan(&(result.mapImportDetects),i,result.listImportPositionHashes.at(i),_PE_importpositionhash_records,sizeof(_PE_importpositionhash_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_IMPORTHASH);
        }

        signatureExpScan(&pe,&(result.basic_info.memoryMap),&result.mapEntryPointDetects,result.nEntryPointOffset,_PE_entrypointExp_records,sizeof(_PE_entrypointExp_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_ENTRYPOINT);

        // Rich
//        int nNumberOfRichSignatures=result.listRichSignatures.count();

//        for(int i=0;i<nNumberOfRichSignatures;i++)
//        {
//            PE_richScan(&(result.mapRichDetects),result.listRichSignatures.at(i).nId,result.listRichSignatures.at(i).nVersion,_PE_rich_records,sizeof(_PE_rich_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
//        }


        //        for(int i=0;i<result.listImports.count();i++)
        //        {
        //            signatureScan(&result._mapImportDetects,QBinary::stringToHex(result.listImports.at(i).sName.toUpper()),_import_records,sizeof(_import_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        //        }

        //        for(int i=0;i<result.export_header.listPositions.count();i++)
        //        {
        //            signatureScan(&result.mapExportDetects,QBinary::stringToHex(result.export_header.listPositions.at(i).sFunctionName),_export_records,sizeof(_export_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        //        }

        //        resourcesScan(&result.mapResourcesDetects,&result.listResources,_resources_records,sizeof(_resources_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);


        if(result.bIsNetPresent)
        {
            stringScan(&result.mapDotAnsistringsDetects,&result.cliInfo.cliMetadata.listAnsiStrings,_PE_dot_ansistrings_records,sizeof(_PE_dot_ansistrings_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_NETANSISTRING);

            //            for(int i=0;i<result.cliInfo.listUnicodeStrings.count();i++)
            //            {
            //                signatureScan(&result.mapDotUnicodestringsDetects,QBinary::stringToHex(result.cliInfo.listUnicodeStrings.at(i)),_dot_unicodestrings_records,sizeof(_dot_unicodestrings_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
            //            }

            if(result.basic_info.bIsDeepScan)
            {
                if(pe.checkOffsetSize(result.osCodeSection))
                {
                    qint64 nSectionOffset=result.osCodeSection.nOffset;
                    qint64 nSectionSize=result.osCodeSection.nSize;

                    memoryScan(&result.mapCodeSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_dot_codesection_records,sizeof(_PE_dot_codesection_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_CODESECTION);
                }
            }
        }

        if(result.basic_info.bIsDeepScan)
        {
            if(pe.checkOffsetSize(result.osCodeSection))
            {
                qint64 nSectionOffset=result.osCodeSection.nOffset;
                qint64 nSectionSize=result.osCodeSection.nSize;

                memoryScan(&result.mapCodeSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_codesection_records,sizeof(_PE_codesection_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_CODESECTION);
            }

            if(pe.checkOffsetSize(result.osEntryPointSection))
            {
                qint64 nSectionOffset=result.osEntryPointSection.nOffset;
                qint64 nSectionSize=result.osEntryPointSection.nSize;

                memoryScan(&result.mapEntryPointSectionDetects,pDevice,pOptions->bIsImage,nSectionOffset,nSectionSize,_PE_entrypointsection_records,sizeof(_PE_entrypointsection_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(result.basic_info),HEURTYPE_ENTRYPOINTSECTION);
            }
        }

        PE_handle_import(pDevice,pOptions->bIsImage,&result);

        PE_handle_Protection(pDevice,pOptions->bIsImage,&result);
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
        PE_handle_Microsoft(pDevice,pOptions->bIsImage,&result);
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

        PE_handle_FixDetects(pDevice,pOptions->bIsImage,&result);

        PE_handle_Recursive(pDevice,pOptions->bIsImage,&result,pOptions);

        result.basic_info.listDetects.append(result.mapResultLinkers.values());
        result.basic_info.listDetects.append(result.mapResultCompilers.values());
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

SpecAbstract::_SCANS_STRUCT SpecAbstract::getScansStruct(quint32 nVariant, SpecAbstract::RECORD_FILETYPE filetype, SpecAbstract::RECORD_TYPE type, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo, qint64 nOffset)
{
    // TODO bIsHeuristic;
    _SCANS_STRUCT result={};

    result.nVariant=nVariant;
    result.filetype=filetype;
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
//    for(int j=0;j<pPEInfo->listImports.count();j++)
//    {
//        for(int i=0;i<pPEInfo->listImports.at(j).listPositions.count();i++)
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
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ZPROTECT,getScansStruct(0,RECORD_FILETYPE_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ZPROTECT,"","",0));
    }

    if(stDetects.contains("user32_pespina")&&stDetects.contains("comctl32_pespina"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"1.0-1.2","",0));
    }

    if(stDetects.contains("user32_pespin")&&stDetects.contains("comctl32_pespin")&&stDetects.contains("kernel32_pespin"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"","",0));
    }

    if(stDetects.contains("user32_pespin")&&stDetects.contains("comctl32_pespin")&&stDetects.contains("kernel32_pespinx"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_PESPIN,getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PESPIN,"1.3X","",0));
    }

    if(stDetects.contains("kernel32_alloy0"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ALLOY,getScansStruct(0,RECORD_FILETYPE_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ALLOY,"4.X","",0));
    }

    if(stDetects.contains("kernel32_alloy2"))
    {
        pPEInfo->mapImportDetects.insert(RECORD_NAME_ALLOY,getScansStruct(2,RECORD_FILETYPE_PE32,RECORD_TYPE_PROTECTOR,RECORD_NAME_ALLOY,"4.X","",0));
    }

    //    if(stDetects.contains("kernel32_pecompact2"))
    //    {
    //        pPEInfo->mapImportDetects.insert(RECORD_NAME_PECOMPACT,getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PACKER,RECORD_NAME_PECOMPACT,"2.X","",0));
    //    }
}

void SpecAbstract::PE_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        // MPRESS
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MPRESS))
        {
            SpecAbstract::_SCANS_STRUCT recordMPRESS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MPRESS);

            qint64 nOffsetMPRESS=pe.find_ansiString(0x1f0,16,"v");

            if(nOffsetMPRESS!=-1)
            {
                // TODO Check!
                recordMPRESS.sVersion=pe.read_ansiString(nOffsetMPRESS+1,0x1ff-nOffsetMPRESS);
            }

            pPEInfo->mapResultPackers.insert(recordMPRESS.name,scansToScan(&(pPEInfo->basic_info),&recordMPRESS));
        }

        // Xenocode Virtual Application Studio 2009
        if(XPE::getResourceVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2009"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009,"","",0);
            ss.sVersion=XPE::getResourceVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // MoleBox Ultra
        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MOLEBOXULTRA))
        {
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_MOLEBOXULTRA))
            {
                SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MOLEBOXULTRA);
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }

        if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ACTIVEMARK))
        {
            SpecAbstract::_SCANS_STRUCT ssOverlay=pPEInfo->mapOverlayDetects.value(RECORD_NAME_ACTIVEMARK);
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ACTIVEMARK,ssOverlay.sVersion,ssOverlay.sInfo,0);
            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        if(!pPEInfo->cliInfo.bInit)
        {
            // TODO MPRESS import

            // UPX
            // TODO 32-64
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX))
            {
                VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,pPEInfo->osHeader.nOffset,pPEInfo->osHeader.nSize);

                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_UPX))
                {
                    if((viUPX.sVersion!="")) // TODO isValid
                    {
                        SpecAbstract::_SCANS_STRUCT recordUPX={};

                        recordUPX.type=RECORD_TYPE_PACKER;
                        recordUPX.name=RECORD_NAME_UPX;
                        recordUPX.sVersion=viUPX.sVersion;
                        recordUPX.sInfo=viUPX.sInfo;

                        pPEInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pPEInfo->basic_info),&recordUPX));
                    }
                    else
                    {
                        SpecAbstract::_SCANS_STRUCT recordUPX=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_UPX);

                        recordUPX.sInfo=append(recordUPX.sInfo,"modified");

                        pPEInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pPEInfo->basic_info),&recordUPX));
                    }
                }
            }

            // EXPRESSOR
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXPRESSOR))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXPRESSOR))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXPRESSOR);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // ASProtect
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ASPROTECT))
            {
                SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ASPROTECT);

                pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }

            // PECompact
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PECOMPACT))
            {
                SpecAbstract::_SCANS_STRUCT recordPC=pPEInfo->mapImportDetects.value(RECORD_NAME_PECOMPACT);

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
                    if(pPEInfo->listSectionHeaders.count()>=2)
                    {
                        if(pPEInfo->listSectionHeaders.at(0).PointerToRelocations==0x32434550)
                        {
                            quint32 nBuildNumber=pPEInfo->listSectionHeaders.at(0).PointerToLinenumbers;

                            // TODO !!! more build versions
                            switch(nBuildNumber)
                            {
                                case 20206:     recordPC.sVersion="2.70";       break;
                                case 20240:     recordPC.sVersion="2.78a";      break;
                                case 20243:     recordPC.sVersion="2.79b1";     break;
                                case 20245:     recordPC.sVersion="2.79bB";     break;
                                case 20247:     recordPC.sVersion="2.79bD";     break;
                                case 20252:     recordPC.sVersion="2.80b1";     break;
                                case 20256:     recordPC.sVersion="2.80b5";     break;
                                case 20261:     recordPC.sVersion="2.82";       break;
                                case 20285:     recordPC.sVersion="2.92.0";     break;
                                case 20288:     recordPC.sVersion="2.93b3";     break;
                                case 20294:     recordPC.sVersion="2.96.2";     break;
                                case 20295:     recordPC.sVersion="2.97b1";     break;
                                case 20296:     recordPC.sVersion="2.98";       break;
                                case 20300:     recordPC.sVersion="2.98.04";    break;
                                case 20301:     recordPC.sVersion="2.98.05";    break;
                                case 20302:     recordPC.sVersion="2.98.06";    break;
                                case 20303:     recordPC.sVersion="2.99b";      break;
                                case 20308:     recordPC.sVersion="3.00.2";     break;
                                case 20312:     recordPC.sVersion="3.01.3";     break;
                                case 20317:     recordPC.sVersion="3.02.1";     break;
                                case 20318:     recordPC.sVersion="3.02.2";     break;
                                case 20323:     recordPC.sVersion="3.03.5b";    break;
                                case 20327:     recordPC.sVersion="3.03.9b";    break;
                                case 20329:     recordPC.sVersion="3.03.10b";   break;
                                case 20334:     recordPC.sVersion="3.03.12b";   break;
                                case 20342:     recordPC.sVersion="3.03.18b";   break;
                                case 20343:     recordPC.sVersion="3.03.19b";   break;
                                case 20344:     recordPC.sVersion="3.03.20b";   break;
                                case 20345:     recordPC.sVersion="3.03.21b";   break;
                                case 20348:     recordPC.sVersion="3.03.23b";   break;
                                default:
                                {
                                    if(nBuildNumber>20308)
                                    {
                                        recordPC.sVersion=QString("3.X(build %1)").arg(nBuildNumber);
                                    }
                                    else if(nBuildNumber==0)
                                    {
                                        recordPC.sVersion="2.20-2.68";
                                    }
                                    else
                                    {
                                        recordPC.sVersion=QString("2.X(build %1)").arg(nBuildNumber);
                                    }
                                }
                            }

                            //                            qDebug("nVersion: %d",nVersion);

                            // TODO more versions
                            pPEInfo->mapResultPackers.insert(recordPC.name,scansToScan(&(pPEInfo->basic_info),&recordPC));
                        }
                    }
                }
            }

            // NSPack
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NSPACK))
            {
                if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSPACK))
                {
                    SpecAbstract::_SCANS_STRUCT recordNSPack=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSPACK);
                    pPEInfo->mapResultPackers.insert(recordNSPack.name,scansToScan(&(pPEInfo->basic_info),&recordNSPack));
                }
                else if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NSPACK))
                {
                    SpecAbstract::_SCANS_STRUCT recordNSPack=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NSPACK);
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

                    SpecAbstract::_SCANS_STRUCT recordEnigma={};

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
                SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_PESPIN);

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
                    SpecAbstract::_SCANS_STRUCT recordNPACK=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NPACK);

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointSectionDetects.value(RECORD_NAME_MASKPE);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // PE-Armor
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEARMOR))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEARMOR))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEARMOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // DalCrypt
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_DALKRYPT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // YZPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_YZPACK))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_YZPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_YZPACK);
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
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_CRYPTOCRACKPEPROTECTOR);

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
                            // TODO new versions
                            if(pe.compareSignature(&(pPEInfo->basic_info.memoryMap),"'kernel32.dll'00000000'VirtualAlloc'00000000",pPEInfo->listSectionRecords.at(1).nOffset))
                            {
                                SpecAbstract::_SCANS_STRUCT recordZProtect=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ZPROTECT,"1.3-1.4.4","",0);
                                pPEInfo->mapResultProtectors.insert(recordZProtect.name,scansToScan(&(pPEInfo->basic_info),&recordZProtect));
                            }
                        }
                    }
                }

                // ExeFog
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXEFOG))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_EXEFOG);

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AHPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // 12311134
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_12311134))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_12311134);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AZProtect
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AZPROTECT))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AZPROTECT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AverCryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_AVERCRYPTOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_AVERCRYPTOR))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AVERCRYPTOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // WinKript
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WINKRIPT))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_WINKRIPT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // AffilliateEXE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_AFFILLIATEEXE))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AFFILLIATEEXE);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // Advanced UPX Scrammbler
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ADVANCEDUPXSCRAMMBLER))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ADVANCEDUPXSCRAMMBLER);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // BeRoEXEPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_BEROEXEPACKER))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BEROEXEPACKER))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_BEROEXEPACKER);

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
                            SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BEROEXEPACKER);
                            pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }

                // Winupack
                if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINUPACK))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINUPACK);

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
                        SpecAbstract::_SCANS_STRUCT recordANFpakk2=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ANDPAKK2);
                        pPEInfo->mapResultPackers.insert(recordANFpakk2.name,scansToScan(&(pPEInfo->basic_info),&recordANFpakk2));
                    }
                }

                // KByS
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KBYS))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KBYS))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KBYS);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Crunch
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRUNCH))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRUNCH))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRUNCH);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // ASDPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASDPACK))
                {
                    bool bDetected=false;
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ASDPACK);

                    if(pPEInfo->listSectionRecords.count()==2)
                    {
                        if(pPEInfo->nTLSSection!=-1)
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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_VPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // RLP
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RLP))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RLP))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RLP);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Crinkler
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CRINKLER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_CRINKLER))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_CRINKLER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EZIP
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EZIP))
                {
                    if(pPEInfo->nOverlaySize)
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EZIP);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // KKrunchy
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KKRUNCHY))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_KKRUNCHY))
                    {
                        SpecAbstract::_SCANS_STRUCT ss={};

                        if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KKRUNCHY))
                        {
                            ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KKRUNCHY);
                        }
                        else
                        {
                            ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_KKRUNCHY);
                        }

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // QuickPack NT
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_QUICKPACKNT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QUICKPACKNT))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QUICKPACKNT);

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
                            SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_MKFPACK);
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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_32LITE);
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
                                SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPROT);
                                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                            }
                        }
                    }
                }

                // RLPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_RLPACK))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_RLPACK);

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PACKMAN);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Fish PE Packer
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FISHPEPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_FISHPEPACKER))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_FISHPEPACKER);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Inquartos Obfuscator
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_INQUARTOSOBFUSCATOR)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERIC))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_INQUARTOSOBFUSCATOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Hide & Protect
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HIDEANDPROTECT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_HIDEANDPROTECT))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_HIDEANDPROTECT);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // mPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_MPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MPACK);
                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // EncryptPE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ENCRYPTPE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ENCRYPTPE))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ENCRYPTPE);

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_YODASPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                // Xtreme-Protector
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_XTREMEPROTECTOR))
                {
                    if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_XTREMEPROTECTOR))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_XTREMEPROTECTOR);

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
                            SpecAbstract::_SCANS_STRUCT recordACProtect={};
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
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ACPROTECT);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // FSG
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_FSG))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FSG))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FSG);

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
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_MEW10);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_MEW11SE))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MEW11SE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MEW11SE);
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
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ALEXPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PEBundle
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEBUNDLE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEBUNDLE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEBUNDLE);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PE-SHiELD
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PESHIELD))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PESHIELD))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PESHIELD);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PUNiSHER
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PUNISHER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PUNISHER))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PUNISHER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Shrinker
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SHRINKER))
                {
                    if(pe.isImportFunctionPresentI("KERNEL32.DLL","8",&(pPEInfo->listImports)))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SHRINKER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Secure Shade
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SECURESHADE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SECURESHADE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SECURESHADE);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PolyCrypt PE
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_POLYCRYPTPE))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_POLYCRYPTPE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_POLYCRYPTPE);

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
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HMIMYSPROTECTOR);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                {
                    if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                    {
                        // TODO compare entryPoint and import sections
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                    else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_PEPACKSPROTECT))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_HMIMYSPACKER))
                {
                    if(XPE::isSectionNamePresent(".hmimys",&(pPEInfo->listSectionHeaders))) // TODO Check
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PACKER,RECORD_NAME_HMIMYSPACKER,"","",0);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ORIEN))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ORIEN))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ORIEN);

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
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ALLOY);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PeX
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_PEX))
                {
                    // TODO compare entryPoint and import sections
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PEX))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PEX);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // PEVProt
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_REVPROT))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_REVPROT))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_REVPROT);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Software Compress
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SOFTWARECOMPRESS))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SOFTWARECOMPRESS))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SOFTWARECOMPRESS);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // SDProtector Pro
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SDPROTECTORPRO))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SDPROTECTORPRO))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_SDPROTECTORPRO);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // Simple Pack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_SIMPLEPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SIMPLEPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_SIMPLEPACK);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // NakedPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NAKEDPACKER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_NAKEDPACKER)&&(!pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_NAKEDPACKER);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // KaOs PE-DLL eXecutable Undetecter
                // the same as NakedPacker
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)&&pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER);
                        pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // ASPack
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ASPACK))
                {
                    // TODO compare entryPoint and import sections
                    QString _sSignature=pPEInfo->sEntryPointSignature;
                    qint64 _nOffset=0;
                    QString _sVersion;

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
                            signatureScan(&(pPEInfo->mapEntryPointDetects),_sSignature,_PE_entrypoint_records,sizeof(_PE_entrypoint_records),pPEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(pPEInfo->basic_info),HEURTYPE_ENTRYPOINT);
                            signatureExpScan(&pe,&(pPEInfo->basic_info.memoryMap),&(pPEInfo->mapEntryPointDetects),pPEInfo->nEntryPointOffset+_nOffset,_PE_entrypointExp_records,sizeof(_PE_entrypointExp_records),pPEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE,&(pPEInfo->basic_info),HEURTYPE_ENTRYPOINT);
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
                        SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ASPACK);
                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

                // No Import
                // WWPACK32
                // TODO false
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_WWPACK32))
                {
                    SpecAbstract::_SCANS_STRUCT ss={};

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                    else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EPEXEPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPEXEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }

                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EPROT))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EPROT);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // RCryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_RCRYPTOR))
                {
                    SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_RCRYPTOR);
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
                    SpecAbstract::_SCANS_STRUCT recordEP=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PKLITE32);

                    pPEInfo->mapResultPackers.insert(recordEP.name,scansToScan(&(pPEInfo->basic_info),&recordEP));
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
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_THINSTALL))
                {
                    _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_THINSTALL);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }

                // ABC Cryptor
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_ABCCRYPTOR))
                {
                    SpecAbstract::_SCANS_STRUCT recordEP=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_ABCCRYPTOR);

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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_LARP64);
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
        if(!pPEInfo->cliInfo.bInit)
        {
            bool bSuccess=false;

            QSet<QString> stDetects;

            int nImportCount=pPEInfo->listImports.count();

            if(nImportCount>=2)
            {
                if(pPEInfo->listImports.at(nImportCount-2).sName.toUpper()=="KERNEL32.DLL")
                {
                    if(pPEInfo->listImports.at(nImportCount-2).listPositions.count()==12)
                    {
                        if((pPEInfo->listImports.at(nImportCount-2).listPositions.at(0).sName=="LocalAlloc")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(1).sName=="LocalFree")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(2).sName=="GetModuleFileNameW")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(3).sName=="GetProcessAffinityMask")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(4).sName=="SetProcessAffinityMask")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(5).sName=="SetThreadAffinityMask")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(6).sName=="Sleep")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(7).sName=="ExitProcess")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(8).sName=="FreeLibrary")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(9).sName=="LoadLibraryA")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(10).sName=="GetModuleHandleA")&&
                                (pPEInfo->listImports.at(nImportCount-2).listPositions.at(11).sName=="GetProcAddress"))
                        {
                            stDetects.insert("kernel32_3");
                        }
                    }
                }

                if(pPEInfo->listImports.at(nImportCount-1).sName.toUpper()=="USER32.DLL")
                {
                    if(pPEInfo->listImports.at(nImportCount-1).listPositions.count()==2)
                    {
                        if((pPEInfo->listImports.at(nImportCount-1).listPositions.at(0).sName=="GetProcessWindowStation")&&
                                (pPEInfo->listImports.at(nImportCount-1).listPositions.at(1).sName=="GetUserObjectInformationW"))
                        {
                            stDetects.insert("user32_3");
                        }
                    }
                }
            }

            if( stDetects.contains("kernel32_3")&&
                stDetects.contains("user32_3"))
            {
                SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VMPROTECT,"","",0);
                ss.sVersion="3.X";
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));

                bSuccess=true;
            }

            // Import
            if(!bSuccess)
            {
                bSuccess=XPE::isSectionNamePresent(".vmp0",&(pPEInfo->listSectionHeaders));
            }

            if(!bSuccess)
            {
                if(pPEInfo->nEntryPointSection>=3)
                {
                    for(int i=0; i<pPEInfo->listSectionHeaders.count(); i++)
                    {
                        if( (i==pPEInfo->nEntryPointSection)||
                            (i==pPEInfo->nResourceSection)||
                            (i==pPEInfo->nTLSSection)||
                            (i==pPEInfo->nRelocsSection)||
                            (QString((char *)pPEInfo->listSectionHeaders.at(i).Name)==".tls")
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
                    pe.compareEntryPoint("EB$$E9$$$$$$$$68........E8"))
                {
                    // TODO more checks
                    SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VMPROTECT,"","",0);
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
        if(!pPEInfo->cliInfo.bInit)
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
                            SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_VIRTUALIZEPROTECT,"","",0);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            if(pPEInfo->listImportPositionHashes.count()>=1)
            {
                if(pPEInfo->listImportPositionHashes.at(0)==0xf3f52749) // TODO !!!
                {
                    if(pPEInfo->nEntryPointSection>0)
                    {
                        if(pPEInfo->sEntryPointSectionName==".TTP") // TODO !!!
                        {
                            SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_TTPROTECT,"","",0);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_SAFEENGINESHIELDEN))
            {
                if(pPEInfo->nEntryPointSection>0)
                {
                    if(pPEInfo->sEntryPointSectionName==".sedata") // TODO !!!
                    {
                        SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_SAFEENGINESHIELDEN,"2.XX","",0);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            if(pPEInfo->listImports.count()==2)
            {
                bool bKernel32=false;
                bool bUser32=false;

                // TODO !!!
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
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_TELOCK);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            bool bImportDetect=false;

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

            if(bImportDetect)
            {
                bool bDetect=false;

                SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ARMADILLO,"","",0);

                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_ARMADILLO))
                {
                    ss=pPEInfo->mapImportDetects.value(RECORD_NAME_ARMADILLO);

                    bDetect=true;
                }

                if((pPEInfo->nMajorLinkerVersion==0x53)&&(pPEInfo->nMinorLinkerVersion==0x52))
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
        if(!pPEInfo->cliInfo.bInit)
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
                        SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_OBSIDIUM,"","",0);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            if(pPEInfo->listImports.count()==2)
            {
                bool bKernel32=false;
                bool bComctl32=false;

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
                else if(pPEInfo->listImports.at(0).sName=="kernel32.dll")
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
                    SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THEMIDAWINLICENSE,"1.XX-2.XX","",0);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(!pPEInfo->mapResultProtectors.contains(RECORD_NAME_THEMIDAWINLICENSE))
            {
                // New version
                int nNumbersOfImport=pPEInfo->listImports.count();

                bool bSuccess=true;

                for(int i=0;i<nNumbersOfImport;i++)
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

                            SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THEMIDAWINLICENSE,"3.XX","",0);

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

            int nImportCount=pPEInfo->listImports.count();

            for(int i=0; i<nImportCount; i++)
            {
                if(pPEInfo->listImports.at(i).listPositions.count()==1)
                {
                    if(pPEInfo->listImports.at(i).listPositions.at(0).sName=="")
                    {
                        sInfo=pPEInfo->listImports.at(i).sName;
                    }
                }
            }

            SpecAbstract::_SCANS_STRUCT recordSS=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_STARFORCE,sVersion,sInfo,0);
            pPEInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::PE_handle_Petite(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bInit)
        {
            if(!pPEInfo->bIs64)
            {
                bool bKernel32=false;
                bool bUser32=false;
                QString sVersion;

                // TODO !!!
                // TODO Petite 2.4 Check header
                for(int i=0; i<pPEInfo->listImports.count(); i++)
                {
                    if(pPEInfo->listImports.at(i).sName.toUpper()=="USER32.DLL")
                    {
                        if(pPEInfo->listImports.at(i).listPositions.count()==2)
                        {
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="MessageBoxA")&&
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
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
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
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
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
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
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
                            if((pPEInfo->listImports.at(i).listPositions.at(0).sName=="ExitProcess")&&
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

                if(bUser32&&bKernel32)
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PETITE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordPETITE=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        recordPETITE.sVersion=sVersion;
                        pPEInfo->mapResultPackers.insert(recordPETITE.name,scansToScan(&(pPEInfo->basic_info),&recordPETITE));
                    }
                }
                else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_PETITE)) // TODO
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_PETITE))
                    {
                        SpecAbstract::_SCANS_STRUCT recordPETITE=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_PETITE);
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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ENIGMA,viEnigma.sVersion,".NET",0);
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
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_DOTNETREACTOR,"4.8-4.9","",0);
                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // TODO
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_YANO))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_YANO);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DOTFUSCATOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DOTFUSCATOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_AGILENET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_AGILENET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_SKATER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_SKATER);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_BABELNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_BABELNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_GOLIATHNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_GOLIATHNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SPICESNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SPICESNET);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_OBFUSCATORNET2009))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_OBFUSCATORNET2009);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DEEPSEA))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DEEPSEA);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            {
                bool bDetect=false;
                _SCANS_STRUCT ss={};

                if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DEEPSEA))
                {
                    ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DEEPSEA);
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
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_CLISECURE))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_CLISECURE);
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
                            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_CLISECURE,"4.X","",0);
                            pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }
                }
            }

            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_FISHNET))||(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_FISHNET)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_FISHNET,"1.X","",0); // TODO
                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss)); // TODO obfuscator?
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_NSPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_NSPACK);
                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DNGUARD))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DNGUARD);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // .NETZ
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DOTNETZ))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_DOTNETZ))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->mapResultNETCompressors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_MAXTOCODE))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_MAXTOCODE);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_PHOENIXPROTECTOR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            {
                bool bDetect=false;
                _SCANS_STRUCT ss={};

                if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SMARTASSEMBLY))
                {
                    ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SMARTASSEMBLY);
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

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_CONFUSER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_CONFUSER);

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
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_XENOCODEPOSTBUILD))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_XENOCODEPOSTBUILD);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // CodeVeil
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_CODEVEIL))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_CODEVEIL);
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
            // Obfuscar
            if(pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_OBFUSCAR))
            {
                _SCANS_STRUCT ss=pPEInfo->mapCodeSectionDetects.value(RECORD_NAME_OBFUSCAR);
                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            // .NET Spider
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DOTNETSPIDER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DOTNETSPIDER);
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
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SIXXPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SIXXPACK);
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
        if(XPE::getResourceVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Postbuild 2009 for .NET"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_XENOCODEPOSTBUILD2009,"","",0);
            ss.sVersion=XPE::getResourceVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::PE_handle_Microsoft(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    SpecAbstract::_SCANS_STRUCT recordLinker={};
    SpecAbstract::_SCANS_STRUCT recordCompiler={};
    SpecAbstract::_SCANS_STRUCT recordTool={};
    SpecAbstract::_SCANS_STRUCT recordMFC={};
    SpecAbstract::_SCANS_STRUCT recordNET={};

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
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))
        {
            recordLinker.type=RECORD_TYPE_LINKER;
            recordLinker.name=RECORD_NAME_MICROSOFTLINKER;
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
                recordLinker.type=RECORD_TYPE_LINKER;
                recordLinker.name=RECORD_NAME_MICROSOFTLINKER;
            }
        }
        else if((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))&&(pPEInfo->cliInfo.bInit))
        {
            recordLinker.type=RECORD_TYPE_LINKER;
            recordLinker.name=RECORD_NAME_MICROSOFTLINKER;

            recordCompiler.type=RECORD_TYPE_COMPILER;
            recordCompiler.name=RECORD_NAME_VISUALCSHARP;
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
                recordMFC.type=RECORD_TYPE_LIBRARY;
                recordMFC.name=RECORD_NAME_MFC;
                recordMFC.sInfo="Static";
            }
        }

        for(int i=0; i<pPEInfo->listImports.count(); i++)
        {
            // https://en.wikipedia.org/wiki/Microsoft_Foundation_Class_Library
            // TODO eMbedded Visual C++ 4.0 		mfcce400.dll 	MFC 6.0
            if(pPEInfo->listImports.at(i).sName.toUpper().contains(QRegExp("^MFC")))
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
                        recordMFC.type=RECORD_TYPE_LIBRARY;
                        recordMFC.name=RECORD_NAME_MFC;
                        recordMFC.sVersion=QString::number(dVersion,'f',2);

                        if(pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL"))
                        {
                            recordMFC.sInfo="Unicode";
                        }
                    }
                }

                break;
            }
        }

        // Rich
        int nRichSignaturesCount=pPEInfo->listRichSignatures.count();

        QList<SpecAbstract::_SCANS_STRUCT> listRichDescriptions;

        for(int i=0;i<nRichSignaturesCount;i++)
        {
            listRichDescriptions.append(richScan(pPEInfo->listRichSignatures.at(i).nId,pPEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pPEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(pPEInfo->basic_info),HEURTYPE_RICH));
        }

        int nRichDescriptionsCount=listRichDescriptions.count();

        bool bVB=false;
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
                if(!bVB)
                {
                    if(listRichDescriptions.at(i).name==RECORD_NAME_UNIVERSALTUPLECOMPILER)
                    {
                        if(listRichDescriptions.at(i).sInfo!="Basic")
                        {
                            recordCompiler.name=RECORD_NAME_VISUALCCPP;
                            recordCompiler.sVersion=listRichDescriptions.at(i).sVersion;
                            recordCompiler.sInfo=listRichDescriptions.at(i).sInfo;
                            recordCompiler.type=listRichDescriptions.at(i).type;
                        }
                        else
                        {
                            recordCompiler.type=RECORD_TYPE_COMPILER;
                            recordCompiler.name=RECORD_NAME_VISUALBASIC;
                            recordCompiler.sVersion=listRichDescriptions.at(i).sVersion;

                            QString _sVersion=recordCompiler.sVersion.section(".",0,1);
                            QString _sVersionCompiler=mapVersions.key(_sVersion,"");

                            if(_sVersionCompiler!="")
                            {
                                recordCompiler.sVersion=recordCompiler.sVersion.replace(_sVersion,_sVersionCompiler);
                            }

                            recordCompiler.sInfo="Native";
                            bVB=true;
                        }
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

            if(listRichDescriptions.at(i).name==SpecAbstract::RECORD_NAME_IMPORT)
            {
                break;
            }
        }

        // TODO Check MASM for .NET

        if(!pPEInfo->cliInfo.bInit)
        {
            // VB
            bool bVBnew=false;

            SpecAbstract::_SCANS_STRUCT _recordCompiler={};

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

            if(recordCompiler.name!=RECORD_NAME_VISUALBASIC)
            {
                if(_recordCompiler.name==RECORD_NAME_VISUALBASIC)
                {
                    recordCompiler=_recordCompiler;
                }
            }
        }
        else
        {
            recordNET.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordNET.name=SpecAbstract::RECORD_NAME_DOTNET;
            recordNET.sVersion=pPEInfo->cliInfo.cliMetadata.header.sVersion;

            if(pPEInfo->cliInfo.bHidden)
            {
                recordNET.sInfo="Hidden";
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_VBNET))
            {
                recordCompiler.type=RECORD_TYPE_COMPILER;
                recordCompiler.name=RECORD_NAME_VBNET;
            }
        }

        if((recordMFC.name==RECORD_NAME_MFC)&&(recordCompiler.type==RECORD_TYPE_UNKNOWN))
        {
            recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
            recordCompiler.name=SpecAbstract::RECORD_NAME_VISUALCCPP;

            QString _sVersion=mapVersions.value(recordMFC.sVersion);

            if(_sVersion!="")
            {
                recordCompiler.sVersion=_sVersion;
            }
        }

        if(recordCompiler.name!=RECORD_NAME_VISUALCCPP)
        {
            // TODO Check mb MS Linker only

            if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_VISUALCCPP))
            {
                _SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_VISUALCCPP);

                recordCompiler.type=ss.type;
                recordCompiler.name=ss.name;
                recordCompiler.sVersion=ss.sVersion;
            }
        }

        if((recordMFC.name==RECORD_NAME_MFC)&&(recordMFC.sVersion==""))
        {
            if((recordCompiler.name==RECORD_NAME_VISUALCCPP)&&(recordLinker.sVersion!=""))
            {
                recordMFC.sVersion=recordLinker.sVersion.section(".",0,1);
            }
        }

        if((recordMFC.name==RECORD_NAME_MFC)&&(recordLinker.name!=RECORD_NAME_MICROSOFTLINKER))
        {
            recordLinker.type=SpecAbstract::RECORD_TYPE_LINKER;
            recordLinker.name=SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if((recordCompiler.name==RECORD_NAME_VISUALCCPP)&&(recordLinker.name!=RECORD_NAME_MICROSOFTLINKER))
        {
            recordLinker.type=SpecAbstract::RECORD_TYPE_LINKER;
            recordLinker.name=SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if((recordLinker.name==RECORD_NAME_MICROSOFTLINKER)&&(recordLinker.sVersion==""))
        {
            recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
        }

        if((recordMFC.name==RECORD_NAME_MFC)&&(recordLinker.sVersion=="")&&(pPEInfo->nMinorLinkerVersion!=10))
        {
            recordLinker.sVersion=recordMFC.sVersion;
            //            recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
        }

        if(recordLinker.name==RECORD_NAME_MICROSOFTLINKER)
        {
            if( (recordCompiler.name==RECORD_NAME_VISUALCCPP)||
                (recordCompiler.name==RECORD_NAME_VISUALCSHARP))
            {
                if(recordCompiler.sVersion=="")
                {
                    QString sLinkerVersion=recordLinker.sVersion;
                    QString sLinkerMajorVersion=sLinkerVersion.section(".",0,1);

                    QString _sVersion=mapVersions.value(sLinkerMajorVersion);

                    if(_sVersion!="")
                    {
                        recordCompiler.sVersion=_sVersion;
                    }
                }
            }
        }

        if( (recordCompiler.name==RECORD_NAME_VISUALCCPP)||
            (recordCompiler.name==RECORD_NAME_VISUALCSHARP))
        {
            QString sLinkerVersion=recordLinker.sVersion;
            QString sCompilerVersion=recordCompiler.sVersion;
            QString sCompilerMajorVersion=sCompilerVersion.section(".",0,1);

            recordTool.type=SpecAbstract::RECORD_TYPE_TOOL;
            recordTool.name=SpecAbstract::RECORD_NAME_MICROSOFTVISUALSTUDIO;

            // https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warnings-by-compiler-version?view=vs-2019

            if(sCompilerVersion=="12.00.8168")
            {
                recordTool.sVersion="6.0";
            }
            else if(sCompilerVersion=="12.00.8804")
            {
                recordTool.sVersion="6.0 SP5-SP6";
            }
            else if(sCompilerVersion=="12.00.8447")
            {
                recordTool.sVersion="6.0 SP5";
            }
            else if((sLinkerVersion=="7.00.9466")&&(sCompilerVersion=="13.00.9466"))
            {
                recordTool.sVersion="2002";
            }
            else if((sLinkerVersion=="7.10.3052")&&(sCompilerVersion=="13.10.3052"))
            {
                recordTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.3077")&&(sCompilerVersion=="13.10.3077"))
            {
                recordTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.4035")&&(sCompilerVersion=="13.10.4035"))
            {
                recordTool.sVersion="2003";
            }
            else if((sLinkerVersion=="7.10.6030")&&(sCompilerVersion=="13.10.6030"))
            {
                recordTool.sVersion="2003 SP1";
            }
            else if((sLinkerVersion=="8.00.40310")&&(sCompilerVersion=="14.00.40310"))
            {
                recordTool.sVersion="2005";
            }
            else if((sLinkerVersion=="8.00.50727")&&(sCompilerVersion=="14.00.50727"))
            {
                recordTool.sVersion="2005";
            }
            else if((sLinkerVersion=="9.00.21022")&&(sCompilerVersion=="15.00.21022"))
            {
                recordTool.sVersion="2008 RTM";
            }
            else if((sLinkerVersion=="9.00.30411")&&(sCompilerVersion=="15.00.30411"))
            {
                recordTool.sVersion="2008 with Feature Pack";
            }
            else if((sLinkerVersion=="9.00.30729")&&(sCompilerVersion=="15.00.30729"))
            {
                recordTool.sVersion="2008 SP1";
            }
            else if((sLinkerVersion=="10.00.30319")&&(sCompilerVersion=="16.00.30319"))
            {
                recordTool.sVersion="2010 RTM";
            }
            else if((sLinkerVersion=="10.00.40219")&&(sCompilerVersion=="16.00.40219"))
            {
                recordTool.sVersion="2010 SP1";
            }
            else if((sLinkerVersion=="11.00.50727")&&(sCompilerVersion=="17.00.50727"))
            {
                recordTool.sVersion="2012";
            }
            else if((sLinkerVersion=="11.00.51025")&&(sCompilerVersion=="17.00.51025"))
            {
                recordTool.sVersion="2012";
            }
            else if((sLinkerVersion=="11.00.51106")&&(sCompilerVersion=="17.00.51106"))
            {
                recordTool.sVersion="2012 Update 1";
            }
            else if((sLinkerVersion=="11.00.60315")&&(sCompilerVersion=="17.00.60315"))
            {
                recordTool.sVersion="2012 Update 2";
            }
            else if((sLinkerVersion=="11.00.60610")&&(sCompilerVersion=="17.00.60610"))
            {
                recordTool.sVersion="2012 Update 3";
            }
            else if((sLinkerVersion=="11.00.61030")&&(sCompilerVersion=="17.00.61030"))
            {
                recordTool.sVersion="2012 Update 4";
            }
            else if((sLinkerVersion=="12.00.21005")&&(sCompilerVersion=="18.00.21005"))
            {
                recordTool.sVersion="2013 RTM";
            }
            else if((sLinkerVersion=="12.00.30501")&&(sCompilerVersion=="18.00.30501"))
            {
                recordTool.sVersion="2013 Update 2";
            }
            else if((sLinkerVersion=="12.00.30723")&&(sCompilerVersion=="18.00.30723"))
            {
                recordTool.sVersion="2013 Update 3";
            }
            else if((sLinkerVersion=="12.00.31101")&&(sCompilerVersion=="18.00.31101"))
            {
                recordTool.sVersion="2013 Update 4";
            }
            else if((sLinkerVersion=="12.00.40629")&&(sCompilerVersion=="18.00.40629"))
            {
                recordTool.sVersion="2013 SP5";
            }
            else if((sLinkerVersion=="14.00.22215")&&(sCompilerVersion=="19.00.22215"))
            {
                recordTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23007")&&(sCompilerVersion=="19.00.23007"))
            {
                recordTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23013")&&(sCompilerVersion=="19.00.23013"))
            {
                recordTool.sVersion="2015";
            }
            else if((sLinkerVersion=="14.00.23026")&&(sCompilerVersion=="19.00.23026"))
            {
                recordTool.sVersion="2015 RTM";
            }
            else if((sLinkerVersion=="14.00.23506")&&(sCompilerVersion=="19.00.23506"))
            {
                recordTool.sVersion="2015 Update 1";
            }
            else if((sLinkerVersion=="14.00.23918")&&(sCompilerVersion=="19.00.23918"))
            {
                recordTool.sVersion="2015 Update 2";
            }
            else if((sLinkerVersion=="14.00.24103")&&(sCompilerVersion=="19.00.24103"))
            {
                recordTool.sVersion="2015 SP1"; // ???
            }
            else if((sLinkerVersion=="14.00.24118")&&(sCompilerVersion=="19.00.24118"))
            {
                recordTool.sVersion="2015 SP1"; // ???
            }
            else if((sLinkerVersion=="14.00.24123")&&(sCompilerVersion=="19.00.24123"))
            {
                recordTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24210")&&(sCompilerVersion=="19.00.24210"))
            {
                recordTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24212")&&(sCompilerVersion=="19.00.24212"))
            {
                recordTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24213")&&(sCompilerVersion=="19.00.24213"))
            {
                recordTool.sVersion="2015 Update 3";
            }
            else if((sLinkerVersion=="14.00.24215")&&(sCompilerVersion=="19.00.24215"))
            {
                recordTool.sVersion="2015 Update 3.1";
            }
            else if((sLinkerVersion=="14.00.24218")&&(sCompilerVersion=="19.00.24218"))
            {
                recordTool.sVersion="2015 Update 3.1";
            }
            else if((sLinkerVersion=="14.00.24723")&&(sCompilerVersion=="19.00.24723"))
            {
                recordTool.sVersion="2015"; // Update 4? 2017?
            }
            else if((sLinkerVersion=="14.10.25017")&&(sCompilerVersion=="19.10.25017"))
            {
                recordTool.sVersion="2017 RTM";
            }
            else if((sLinkerVersion=="14.10.25019")&&(sCompilerVersion=="19.10.25019"))
            {
                recordTool.sVersion="2017"; // 15.2?
            }
            else if((sLinkerVersion=="14.10.25506")&&(sCompilerVersion=="19.10.25506"))
            {
                recordTool.sVersion="2017 version 15.3";
            }
            else if((sLinkerVersion=="14.11.25547")&&(sCompilerVersion=="19.11.25547"))
            {
                recordTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.11.25830")&&(sCompilerVersion=="19.11.25830"))
            {
                recordTool.sVersion="2017 version 15.5";
            }
            else if((sLinkerVersion=="14.12.25834")&&(sCompilerVersion=="19.12.25834")) // TODO Check v15.5.4
            {
                recordTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.13.26128")&&(sCompilerVersion=="19.13.26128"))
            {
                recordTool.sVersion="2017 version 15.6";
            }
            else if((sLinkerVersion=="14.14.26428")&&(sCompilerVersion=="19.14.26428"))
            {
                recordTool.sVersion="2017 version 15.7";
            }
            else if((sLinkerVersion=="14.15.26726")&&(sCompilerVersion=="19.15.26726"))
            {
                recordTool.sVersion="2017 version 15.8";
            }
            else if((sLinkerVersion=="14.16.26926")&&(sCompilerVersion=="19.16.26926"))
            {
                recordTool.sVersion="2017 version 15.9";
            }
            else if((sLinkerVersion=="14.16.27027")&&(sCompilerVersion=="19.16.27027")) // TODO Check
            {
                recordTool.sVersion="2017";
            }
            else if((sLinkerVersion=="14.20.27004")&&(sCompilerVersion=="19.20.27004"))
            {
                recordTool.sVersion="2019 RTM";
            }
            else if((sLinkerVersion=="14.20.27508")&&(sCompilerVersion=="19.20.27508"))
            {
                recordTool.sVersion="2019";
            }
            else if(sCompilerMajorVersion=="12.00")
            {
                recordTool.sVersion="6.0";
            }
            else if(sCompilerMajorVersion=="13.00")
            {
                recordTool.sVersion="2002";
            }
            else if(sCompilerMajorVersion=="13.10")
            {
                recordTool.sVersion="2003";
            }
            else if(sCompilerMajorVersion=="14.00")
            {
                recordTool.sVersion="2005";
            }
            else if(sCompilerMajorVersion=="15.00")
            {
                recordTool.sVersion="2008";
            }
            else if(sCompilerMajorVersion=="16.00")
            {
                recordTool.sVersion="2010";
            }
            else if(sCompilerMajorVersion=="17.00")
            {
                recordTool.sVersion="2012";
            }
            else if(sCompilerMajorVersion=="18.00")
            {
                recordTool.sVersion="2013";
            }
            else if(sCompilerMajorVersion=="19.00")
            {
                recordTool.sVersion="2015";
            }
            else if(sCompilerMajorVersion=="19.10") // TODO ???
            {
                recordTool.sVersion="2017 RTM";
            }
            else if(sCompilerMajorVersion=="19.11")
            {
                recordTool.sVersion="2017 version 15.3";
            }
            else if(sCompilerMajorVersion=="19.12")
            {
                recordTool.sVersion="2017 version 15.5";
            }
            else if(sCompilerMajorVersion=="19.13")
            {
                recordTool.sVersion="2017 version 15.6";
            }
            else if(sCompilerMajorVersion=="19.14")
            {
                recordTool.sVersion="2017 version 15.7";
            }
            else if(sCompilerMajorVersion=="19.15")
            {
                recordTool.sVersion="2017 version 15.8";
            }
            else if(sCompilerMajorVersion=="19.16")
            {
                recordTool.sVersion="2017 version 15.9";
            }
            else if(sCompilerMajorVersion=="19.20")
            {
                recordTool.sVersion="2019";
            }

            if(recordTool.sVersion=="")
            {
                // TODO
            }
        }
        else if(recordCompiler.name==SpecAbstract::RECORD_NAME_MASM)
        {
            QString sCompilerVersion=recordCompiler.sVersion;
            QString sLinkerVersion=recordLinker.sVersion;

            if((sLinkerVersion=="5.12.8078")&&(sCompilerVersion=="6.14.8444"))
            {
                recordTool.type=SpecAbstract::RECORD_TYPE_TOOL;
                recordTool.name=SpecAbstract::RECORD_NAME_MASM32;
                recordTool.sVersion="8-11";
            }
        }

        if(pe.isImportLibraryPresentI("MSVCRT.dll",&(pPEInfo->listImports)))
        {
            // TODO
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pPEInfo->basic_info),&recordLinker));
        }

        if(recordCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pPEInfo->basic_info),&recordCompiler));
        }

        if(recordTool.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultTools.insert(recordTool.name,scansToScan(&(pPEInfo->basic_info),&recordTool));
        }

        if(recordMFC.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLibraries.insert(recordMFC.name,scansToScan(&(pPEInfo->basic_info),&recordMFC));
        }

        if(recordNET.type!=RECORD_TYPE_UNKNOWN)
        {
            pPEInfo->mapResultLibraries.insert(recordNET.name,scansToScan(&(pPEInfo->basic_info),&recordNET));
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

        if(!pPEInfo->cliInfo.bInit)
        {
            qint64 nOffset_string=-1;
            qint64 nOffset_Boolean=-1;
            qint64 nOffset_String=-1;
            qint64 nOffset_TObject=-1;
            //        qint64 nOffset_AnsiString=-1;
            //        qint64 nOffset_WideString=-1;

            qint64 nOffset_BorlandCPP=-1;
            qint64 nOffset_CodegearCPP=-1;
            qint64 nOffset_EmbarcaderoCPP=-1;

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
                        nOffset_EmbarcaderoCPP=pe.find_ansiString(_nOffset,_nSize,"Embarcadero RAD Studio - Copyright "); // Embarcadero RAD Studio - Copyright 2009 Embarcadero Technologies, Inc.
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
                    (nOffset_EmbarcaderoCPP!=-1)||
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
                        (nOffset_EmbarcaderoCPP!=-1)||
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
                    else if(nOffset_EmbarcaderoCPP!=-1)
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

                if(nOffset_EmbarcaderoCPP!=-1)
                {
                    sCppCompilerVersion=pe.read_ansiString(nOffset_EmbarcaderoCPP+35,4);
                }

                if(sCppCompilerVersion=="2009")
                {
                    sBuilderVersion="2009";
                }
                else if(sCppCompilerVersion=="2015")
                {
                    sBuilderVersion="2015";
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
                            sDelphiVersion="XE7+";

                            QString sMajorVersion=sObjectPascalCompilerVersion.section(" ",0,0);

                            if(sMajorVersion=="28.0")
                            {
                               sDelphiVersion="XE7";
                            }
                            else if(sMajorVersion=="29.0")
                            {
                               sDelphiVersion="XE8";
                            }
                            else if(sMajorVersion=="30.0")
                            {
                               sDelphiVersion="10 Seattle";
                            }
                            else if(sMajorVersion=="31.0")
                            {
                               sDelphiVersion="10.1 Berlin";
                            }
                            else if(sMajorVersion=="32.0")
                            {
                               sDelphiVersion="10.2 Tokyo";
                            }
                            else if(sMajorVersion=="33.0")
                            {
                               sDelphiVersion="10.3 Rio";
                            }
                        }
                    }
                }

                recordCompiler.type=RECORD_TYPE_COMPILER;
                recordTool.type=RECORD_TYPE_TOOL;

                if(!bCpp)
                {
                    if(company==COMPANY_BORLAND)
                    {
                        recordCompiler.name=RECORD_NAME_BORLANDOBJECTPASCAL;
                        recordTool.name=RECORD_NAME_BORLANDDELPHI;
                    }
                    else if(company==COMPANY_CODEGEAR)
                    {
                        recordCompiler.name=RECORD_NAME_CODEGEAROBJECTPASCAL;
                        recordTool.name=RECORD_NAME_CODEGEARDELPHI;
                    }
                    else if(company==COMPANY_EMBARCADERO)
                    {
                        recordCompiler.name=RECORD_NAME_EMBARCADEROOBJECTPASCAL;
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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LINKER,RECORD_NAME_TURBOLINKER,"","",0);
                    recordLinker=ss;
                }
            }
        }
        else
        {
            // .NET TODO: Check!!!!
            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_EMBARCADERODELPHIDOTNET))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_EMBARCADERODELPHIDOTNET);
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
            ssCompiler=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_WATCOMCCPP,"","",0);
        }

        if((ssLinker.type==RECORD_TYPE_UNKNOWN)&&(ssCompiler.type!=RECORD_TYPE_UNKNOWN))
        {
            ssLinker=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LINKER,RECORD_NAME_WATCOMLINKER,"","",0);
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
        if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_GO)||pPEInfo->mapCodeSectionDetects.contains(RECORD_NAME_GO))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_GO,"1.X","",0);

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
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_VISUALOBJECTS,"2.XX","",0);
            ss.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // FASM
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASM))
        {
            // TODO correct Version
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FASM,"","",0);
            ss.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // Valve
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VALVE))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_STUB,RECORD_NAME_VALVE,"","",0);
            pPEInfo->mapResultTools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // UniLink
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UNILINK))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LINKER,RECORD_NAME_UNILINK,"","",0);
            pPEInfo->mapResultLinkers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // DMD32 D
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DMD32D))
        {
            // TODO correct Version
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_DMD32D,"","",0);
            pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

        // GoLink, GoAsm
        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GOLINK))
        {
            _SCANS_STRUCT ssLinker=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LINKER,RECORD_NAME_GOLINK,"","",0);
            ssLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            pPEInfo->mapResultLinkers.insert(ssLinker.name,scansToScan(&(pPEInfo->basic_info),&ssLinker));

            _SCANS_STRUCT ssCompiler=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_GOASM,"","",0);
            pPEInfo->mapResultCompilers.insert(ssCompiler.name,scansToScan(&(pPEInfo->basic_info),&ssCompiler));
        }

        if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LAYHEYFORTRAN90))
        {
            QString sLFString=pe.read_ansiString(0x200);

            if(sLFString=="This program must be run under Windows 95, NT, or Win32s\r\nPress any key to exit.$")
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_LAYHEYFORTRAN90,"","",0);
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
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_FLEXLM,"","",0);

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
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_FLEXNET,"","",0);

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

        if(!pPEInfo->cliInfo.bInit)
        {
            // Qt
            // mb TODO upper
            // TODO Find Strings QObject
            if(XPE::isImportLibraryPresentI("QtCore4.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"4.X","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("QtCored4.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"4.X","Debug",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt5Core.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"5.X","",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::isImportLibraryPresentI("Qt5Cored.dll",&(pPEInfo->listImports)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_QT,"5.X","Debug",0);
                pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_QT))
            {
                // TODO Version!
                _SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_QT);;
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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);
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
                        _SCANS_STRUCT ssLazarus=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_TOOL,RECORD_NAME_LAZARUS,"","",0);

                        ssLazarus.sVersion=sLazarusVersion;

                        pPEInfo->mapResultTools.insert(ssLazarus.name,scansToScan(&(pPEInfo->basic_info),&ssLazarus));
                    }
                }
                else
                {
                    //                    qint64 nOffset_TObject=pe.find_array(_nOffset,_nSize,"\x07\x54\x4f\x62\x6a\x65\x63\x74",8); // TObject

                    //                    if(nOffset_TObject!=-1)
                    //                    {

                    //                        SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                    //                        // TODO Version
                    //                        pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    //                    }
                    qint64 nOffset_RunTimeError=pe.find_array(_nOffset,_nSize,"\x0e\x52\x75\x6e\x74\x69\x6d\x65\x20\x65\x72\x72\x6f\x72\x20",15); // Runtime Error TODO: use findAnsiString

                    if(nOffset_RunTimeError!=-1)
                    {

                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                        // TODO Version
                        pPEInfo->mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // Python
            for(int i=0; i<pPEInfo->listImports.count(); i++)
            {
                if(pPEInfo->listImports.at(i).sName.toUpper().contains(QRegExp("^PYTHON")))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_PYTHON,"","",0);

                            ss.sVersion=QString::number(dVersion/10,'f',1);
                            pPEInfo->mapResultLibraries.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                        }
                    }

                    break;
                }
            }

            // Perl
            for(int i=0; i<pPEInfo->listImports.count(); i++)
            {
                if(pPEInfo->listImports.at(i).sName.toUpper().contains(QRegExp("^PERL")))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_PERL,"","",0);

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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_VIRTUALPASCAL,"","",0);

                    // TODO Version???
                    ss.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_COMPILER,RECORD_NAME_POWERBASIC,"","",0);

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
                    SpecAbstract::_SCANS_STRUCT recordLinker={};
                    recordLinker.name=RECORD_NAME_LCCLNK;
                    recordLinker.type=RECORD_TYPE_LINKER;
                    recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
                    pPEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pPEInfo->basic_info),&recordLinker));
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
    }
}

void SpecAbstract::PE_handle_wxWidgets(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bInit)
        {
            bool bDynamic=false;
            bool bStatic=false;
            QString sVersion;
            QString sInfo;

            for(int i=0; i<pPEInfo->listImports.count(); i++)
            {
                if(pPEInfo->listImports.at(i).sName.toUpper().contains(QRegExp("^WX")))
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
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_LIBRARY,RECORD_NAME_WXWIDGETS,"","",0);

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
    SpecAbstract::_SCANS_STRUCT recordLinker={};
    SpecAbstract::_SCANS_STRUCT recordCompiler={};
    SpecAbstract::_SCANS_STRUCT recordTool={};

    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bInit)
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
                recordTool.type=RECORD_TYPE_TOOL;
                recordTool.name=RECORD_NAME_MSYS;
                recordTool.sVersion="1.0";
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

                    recordCompiler.sVersion=viStruct.sVersion;

                    // TODO MinGW-w64
                    if(viStruct.sInfo.contains("MinGW"))
                    {
                        recordTool.type=RECORD_TYPE_TOOL;
                        recordTool.name=RECORD_NAME_MINGW;
                    }
                    else if(viStruct.sInfo.contains("MSYS2"))
                    {
                        recordTool.type=RECORD_TYPE_TOOL;
                        recordTool.name=RECORD_NAME_MSYS2;
                    }
                    else if(viStruct.sInfo.contains("Cygwin"))
                    {
                        recordTool.type=RECORD_TYPE_TOOL;
                        recordTool.name=RECORD_NAME_CYGWIN;
                    }

                    if(recordCompiler.sVersion=="")
                    {
                        QString _sGCCVersion;

                        if(pe.checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                        {
                            _sGCCVersion=get_GCC_vi2(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize).sVersion;

                            if(_sGCCVersion!="")
                            {
                                recordCompiler.sVersion=_sGCCVersion;
                            }
                        }

                        if(_sGCCVersion=="")
                        {
                            if(pe.checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                            {
                                _sGCCVersion=get_GCC_vi2(pDevice,bIsImage,pPEInfo->osDataSection.nOffset,pPEInfo->osDataSection.nSize).sVersion;

                                if(_sGCCVersion!="")
                                {
                                    recordCompiler.sVersion=_sGCCVersion;
                                }
                            }
                        }
                    }

                    if((recordTool.type==RECORD_TYPE_UNKNOWN)&&(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_GCC)))
                    {
                        if(pPEInfo->mapEntryPointDetects.value(RECORD_NAME_GCC).sInfo.contains("MinGW"))
                        {
                            recordTool.type=RECORD_TYPE_TOOL;
                            recordTool.name=RECORD_NAME_MINGW;
                        }
                    }
                }

                if(recordCompiler.sVersion!="")
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
                            recordTool.type=RECORD_TYPE_TOOL;
                            recordTool.name=RECORD_NAME_MINGW;

                            bDetectGCC=true;
                        }
                    }
                }

                if(bDetectGCC)
                {
                    recordCompiler.type=RECORD_TYPE_COMPILER;
                    recordCompiler.name=RECORD_NAME_GCC;
                }
            }

            for(int i=0; i<pPEInfo->listImports.count(); i++)
            {
                if(pPEInfo->listImports.at(i).sName.toUpper().contains(QRegExp("^CYGWIN")))
                {
                    QString sVersion=XBinary::regExp("(\\d+)",pPEInfo->listImports.at(i).sName.toUpper(),0);

                    if(sVersion!="")
                    {
                        double dVersion=sVersion.toDouble();

                        if(dVersion)
                        {
                            recordTool.sVersion=QString::number(dVersion,'f',2);
                        }
                    }

                    recordTool.type=RECORD_TYPE_TOOL;
                    recordTool.name=RECORD_NAME_CYGWIN;

                    break;
                }
            }

            if(recordCompiler.type==RECORD_TYPE_UNKNOWN)
            {
                if(XPE::isSectionNamePresent(".stabstr",&(pPEInfo->listSectionHeaders))) // TODO
                {
                    XPE_DEF::IMAGE_SECTION_HEADER sh=XPE::getSectionByName(".stabstr",&(pPEInfo->listSectionHeaders));

                    if(sh.SizeOfRawData)
                    {
                        qint64 _nOffset=sh.PointerToRawData;
                        qint64 _nSize=sh.SizeOfRawData;

                        bool bSuccess=false;

                        if(!bSuccess)
                        {
                            qint64 nGCC_MinGW=pe.find_ansiString(_nOffset,_nSize,"/gcc/mingw32/");

                            if(nGCC_MinGW!=-1)
                            {
                                recordTool.type=RECORD_TYPE_TOOL;
                                recordTool.name=RECORD_NAME_MINGW;

                                bSuccess=true;
                            }
                        }

                        if(!bSuccess)
                        {
                            qint64 nCygwin=pe.find_ansiString(_nOffset,_nSize,"/gcc/i686-pc-cygwin/");

                            if(nCygwin!=-1)
                            {
                                recordTool.type=RECORD_TYPE_TOOL;
                                recordTool.name=RECORD_NAME_CYGWIN;

                                bSuccess=true;
                            }
                        }
                    }
                }
            }

            if(recordCompiler.type==RECORD_TYPE_UNKNOWN)
            {
                if( (recordTool.name==RECORD_NAME_MINGW)||
                    (recordTool.name==RECORD_NAME_MSYS)||
                    (recordTool.name==RECORD_NAME_MSYS2)||
                    (recordTool.name==RECORD_NAME_CYGWIN))
                {
                    recordCompiler.type=RECORD_TYPE_COMPILER;
                    recordCompiler.name=RECORD_NAME_GCC;
                }
            }

            if((recordCompiler.name==RECORD_NAME_GCC)&&(recordTool.type==RECORD_TYPE_UNKNOWN))
            {
                recordTool.type=RECORD_TYPE_TOOL;
                recordTool.name=RECORD_NAME_MINGW;
            }

            if((recordCompiler.name==RECORD_NAME_GCC)&&(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)))
            {
                recordLinker.type=RECORD_TYPE_LINKER;
                recordLinker.name=RECORD_NAME_GNULINKER;
                recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            }

            if(recordTool.name==RECORD_NAME_MINGW)
            {
                if(recordTool.sVersion=="")
                {
                    switch(pPEInfo->nMajorLinkerVersion)
                    {
                    case 2:
                        switch(pPEInfo->nMinorLinkerVersion)
                        {
                            case 23:    recordTool.sVersion="4.7.0-4.8.0";      break;
                            case 24:    recordTool.sVersion="4.8.2-4.9.2";      break;
                            case 25:    recordTool.sVersion="5.3.0";            break;
                            case 29:    recordTool.sVersion="7.3.0";            break;
                            case 30:    recordTool.sVersion="7.3.0";            break; // TODO Check
                        }
                        break;
                    }
                }
            }

            // TODO Check overlay debug

            if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pPEInfo->basic_info),&recordLinker));
            }
            if(recordCompiler.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pPEInfo->basic_info),&recordCompiler));
            }
            if(recordTool.type!=RECORD_TYPE_UNKNOWN)
            {
                pPEInfo->mapResultTools.insert(recordTool.name,scansToScan(&(pPEInfo->basic_info),&recordTool));
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

            if(pe.compareSignature(&(pPEInfo->basic_info.memoryMap),"........00020200",dd.VirtualAddress))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SIGNTOOL,RECORD_NAME_GENERIC,"2.0","PKCS #7",0);
                pPEInfo->mapResultSigntools.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_Installers(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if(!pPEInfo->cliInfo.bInit)
        {
            // Inno Setup
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INNOSETUP)||pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INNOSETUP,"","",0);

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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WIXTOOLSET,"","",0);
                    ss.sVersion="3.X"; // TODO check "E:\delivery\Dev\wix37\build\ship\x86\burn.pdb"
                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // CAB SFX
            if(pPEInfo->sResourceManifest.contains("sfxcab.exe"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_CAB,"","",0);

                if(pe.checkOffsetSize(pPEInfo->osResourceSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 nSectionOffset=  pPEInfo->listSectionHeaders.at(pPEInfo->nResourceSection).PointerToRawData+
                                            pPEInfo->listSectionHeaders.at(pPEInfo->nResourceSection).Misc.VirtualSize;

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
                if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion))=="InstallAnywhere")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLANYWHERE,"","",0);
                    ss.sVersion=XPE::getResourceVersionValue("ProductVersion",&(pPEInfo->resVersion));
                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_GHOSTINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GHOSTINSTALLER,"","",0);
                ss.sVersion="1.0";
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_QTINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_QTINSTALLER,"","",0);
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INSTALL4J))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALL4J,"","",0);
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SMARTINSTALLMAKER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SMARTINSTALLMAKER,"","",0);
                ss.sVersion=XBinary::hexToString(pPEInfo->sOverlaySignature.mid(46,14)); // TODO make 1 function
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_TARMAINSTALLER))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_TARMAINSTALLER,"","",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_CLICKTEAM))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_CLICKTEAM,"","",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // NSIS
            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_NSIS))||(pPEInfo->sResourceManifest.contains("Nullsoft.NSIS")))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_NSIS,"","",0);

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
            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ",".");
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->sResourceManifest.contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);

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
                    ss.sVersion=XPE::getResourceVersionValue("ISInternalVersion",&(pPEInfo->resVersion));
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_INSTALLSHIELD))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","PackageForTheWeb",0);
                // TODO version
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else if(XPE::getResourceVersionValue("CompanyName",&(pPEInfo->resVersion)).contains("InstallShield"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_INSTALLSHIELD,"","",0);

                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion));

                if(XPE::getResourceVersionValue("CompanyName",&(pPEInfo->resVersion)).contains("PackageForTheWeb"))
                {
                    ss.sInfo="PackageForTheWeb";
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->sResourceManifest.contains("AdvancedInstallerSetup"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ADVANCEDINSTALLER,"","",0);

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
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SPOONINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->sResourceManifest.contains("DeployMaster Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_DEPLOYMASTER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( (pPEInfo->sResourceManifest.contains("Gentee.Installer.Install"))||
                (pPEInfo->sResourceManifest.contains("name=\"gentee\"")))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GENTEEINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }
            else
            {
                if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_GENTEEINSTALLER))
                {
                    if(XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,"SETUP_TEMP",&(pPEInfo->listResources)))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GENTEEINSTALLER,"","",0);

                        pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            if(pPEInfo->sResourceManifest.contains("BitRock Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_BITROCKINSTALLER,"","",0);

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("GP-Install")&&
                XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("TASPro6-Install"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GPINSTALL,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ",".");
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Total Commander Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_TOTALCOMMANDERINSTALLER,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("Comments",&(pPEInfo->resVersion)).contains("Actual Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ACTUALINSTALLER,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("Comments",&(pPEInfo->resVersion)).contains("Avast Antivirus"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_AVASTANTIVIRUS,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Opera Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_OPERA,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Yandex Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_YANDEX,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Google Update"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_GOOGLE,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Visual Studio Installer"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_MICROSOFTVISUALSTUDIO,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("Dropbox Update Setup"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_DROPBOX,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("VeraCrypt"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_VERACRYPT,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Microsoft .NET Framework"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_MICROSOFTDOTNETFRAMEWORK,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(XPE::getResourceVersionValue("LegalTrademarks",&(pPEInfo->resVersion)).contains("Setup Factory"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SETUPFACTORY,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("ProductVersion",&(pPEInfo->resVersion)).trimmed();

                if(ss.sVersion.contains(","))
                {
                    ss.sVersion=ss.sVersion.remove(" ");
                    ss.sVersion=ss.sVersion.replace(",",".");
                }

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if( XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Java")&&
                XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("Setup Launcher"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_JAVA,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_VMWARE)||XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("VMware installation"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_VMWARE,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Windows Installer
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_MICROSOFTOFFICE))
            {
                VI_STRUCT vi=get_WindowsInstaller_vi(pDevice,bIsImage,pPEInfo->nOverlayOffset,pPEInfo->nOverlaySize);

                if(vi.sVersion!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WINDOWSINSTALLER,"","",0);

                    ss.sVersion=vi.sVersion;
                    ss.sInfo=vi.sInfo;

                    pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
               }
            }

            // Alchemy Mindworks
            if( XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,4001,&(pPEInfo->listResources))&&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA,5001,&(pPEInfo->listResources)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_ALCHEMYMINDWORKS,"","",0);
                // TODO versions

                pPEInfo->mapResultInstallers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(!pPEInfo->mapResultInstallers.contains(RECORD_NAME_WINDOWSINSTALLER))
            {
                for(int i=0; i<pPEInfo->listResources.count(); i++)
                {
                    qint64 _nOffset=pPEInfo->listResources.at(i).nOffset;
                    qint64 _nSize=pPEInfo->listResources.at(i).nSize;
                    qint64 _nSignatureSize=qMin(_nSize,(qint64)8);

                    if(_nSignatureSize)
                    {
                        QString sSignature=pe.getSignature(_nOffset,_nSignatureSize);

                        if(sSignature=="D0CF11E0A1B11AE1") // DOC File
                        {
                            VI_STRUCT vi=get_WindowsInstaller_vi(pDevice,bIsImage,_nOffset,_nSize);

                            if(vi.sVersion!="")
                            {
                                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WINDOWSINSTALLER,"","",0);

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
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WISE,"","",0);

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
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_WISE,"","",0);

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
        if(!pPEInfo->cliInfo.bInit)
        {
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_RAR))
            {
                if( XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG,"STARTDLG",&(pPEInfo->listResources))&&
                    XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG,"LICENSEDLG",&(pPEInfo->listResources)))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_WINRAR,"","",0);
                    // TODO Version
                    pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            if((pPEInfo->mapOverlayDetects.contains(RECORD_NAME_WINRAR))||(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_ZIP)))
            {
                if(pPEInfo->sResourceManifest.contains("WinRAR"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_WINRAR,"","",0);
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
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_ZIP,"","",0);
                        // TODO Version
                        pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                }
            }

            // 7z SFX
            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("7-Zip"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_7Z,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("ProductVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if((!pPEInfo->mapResultSFX.contains(RECORD_NAME_7Z))&&(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_7Z)))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_7Z,"","",0);
                ss.sInfo="modified";
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // SQUEEZ SFX
            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_SQUEEZSFX))
            {
                if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("Squeez"))
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_SQUEEZSFX,"","",0);
                    ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion)).trimmed();
                    pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
            }

            // WinACE
            if(     XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("WinACE")||
                    XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("WinAce")||
                    XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("UNACE"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_WINACE,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("ProductVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // WinZip
            if( (pPEInfo->sResourceManifest.contains("WinZipComputing.WinZip"))||
                (XPE::isSectionNamePresent("_winzip_",&(pPEInfo->listSectionHeaders)))) // TODO
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_WINZIP,"","",0);

                QString _sManifest=pPEInfo->sResourceManifest.section("assemblyIdentity",1,1);
                ss.sVersion=XBinary::regExp("version=\"(.*?)\"",_sManifest,1);
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // Cab
            if(XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Self-Extracting Cabinet"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_CAB,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("FileVersion",&(pPEInfo->resVersion));
                pPEInfo->mapResultSFX.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            // GkSetup SFX
            if(XPE::getResourceVersionValue("ProductName",&(pPEInfo->resVersion)).contains("GkSetup Self extractor"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_SFX,RECORD_NAME_GKSETUPSFX,"","",0);
                ss.sVersion=XPE::getResourceVersionValue("ProductVersion",&(pPEInfo->resVersion));
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
        if(pPEInfo->listImports.at(0).sName.toUpper().contains(QRegExp("^NOVEX")))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_DONGLEPROTECTION,RECORD_NAME_GUARDIANSTEALTH,"","",0);
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
//                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PACKER,RECORD_NAME_ANSLYMPACKER,"","",0);
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
        if(!pPEInfo->cliInfo.bInit)
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
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PACKER,RECORD_NAME_NEOLITE,"1.0","",0);
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
        if(!pPEInfo->cliInfo.bInit)
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

            int nCount=pPEInfo->listSectionHeaders.count();

            for(int i=0;i<nCount;i++)
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
                SpecAbstract::_SCANS_STRUCT ss=pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PRIVATEEXEPROTECTOR);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(bKernel32&&bCharacteristics&&bTurboLinker)
            {
                SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PRIVATEEXEPROTECTOR,"2.25","",0);

                pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(bKernel32&&bUser32&&bCharacteristics&&bTurboLinker)
            {
                SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_PRIVATEEXEPROTECTOR,"2.30-2.70","",0);

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
                SpecAbstract::_SCANS_STRUCT ssOverlay=pPEInfo->mapOverlayDetects.value(RECORD_NAME_1337EXECRYPTER);
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_1337EXECRYPTER,ssOverlay.sVersion,ssOverlay.sInfo,0);
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
//                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_AASE);
//                        pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//                    }

            SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_AASE);
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

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DCRYPTPRIVATE)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DCRYPTPRIVATE);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }

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
                    SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_BLADEJOINER);
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
                    SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXEJOINER);
                    pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                }
            }
        }

        // Celesty File Binder
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_CELESTYFILEBINDER))
        {
            if(pe.isResourcePresent("RBIND",-1,&(pPEInfo->listResources)))
            {
                SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_CELESTYFILEBINDER);
                pPEInfo->mapResultJoiners.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
            }
        }

        // N-Joiner
        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_NJOINER))
        {
            if(pe.isResourcePresent("NJ",-1,&(pPEInfo->listResources))||pe.isResourcePresent("NJOY",-1,&(pPEInfo->listResources)))
            {
                SpecAbstract::_SCANS_STRUCT recordSS=pPEInfo->mapImportDetects.value(RECORD_NAME_NJOINER);
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
        if(!PE_isProtectionPresent(pPEInfo))
        {
            if(pPEInfo->listSectionRecords.count())
            {
                if(pPEInfo->listSectionRecords.at(0).nSize==0)
                {
                    if( pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX)&&
                        (pPEInfo->mapImportDetects.value(RECORD_NAME_UPX).nVariant==0))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS={};

                        recordSS.type=RECORD_TYPE_PACKER;
                        recordSS.name=RECORD_NAME_UNK_UPXLIKE;
                        recordSS.bIsHeuristic=true;

                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
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

                if((recordSS.name!=RECORD_NAME_GENERIC)&&(recordSS.name!=RECORD_NAME_PESHIELD))
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
        pPEInfo->mapResultCompilers.contains(RECORD_NAME_BORLANDOBJECTPASCAL))
    {
        pPEInfo->mapResultCompilers.remove(RECORD_NAME_BORLANDOBJECTPASCAL);
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

void SpecAbstract::PE_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo, SpecAbstract::SCAN_OPTIONS *pOptions)
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
                _parentId.filepart=SpecAbstract::RECORD_FILEPART_OVERLAY;
                scan(pDevice,&scanResult,pPEInfo->nOverlayOffset,pPEInfo->nOverlaySize,_parentId,pOptions);

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
        int nSignaturesCount=sizeof(_TEXT_records)/sizeof(STRING_RECORD);

        for(int i=0; i<nSignaturesCount; i++) // TODO move to an own function
        {
            if(XBinary::isRegExpPresent(_TEXT_records[i].pszString,pBinaryInfo->sHeaderText))
            {
                SpecAbstract::_SCANS_STRUCT record={};
                record.nVariant=_TEXT_records[i].basicInfo.nVariant;
                record.filetype=_TEXT_records[i].basicInfo.filetype;
                record.type=_TEXT_records[i].basicInfo.type;
                record.name=_TEXT_records[i].basicInfo.name;
                record.sVersion=_TEXT_records[i].basicInfo.pszVersion;
                record.sInfo=_TEXT_records[i].basicInfo.pszInfo;
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

            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!\\/usr\\/bin\\/env (\\w+)",    pBinaryInfo->sHeaderText,1); // #!/usr/bin/env perl
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!.*/(\\w+)",                    pBinaryInfo->sHeaderText,1); // #!/usr/bin/perl
            if(sInterpreter=="") sInterpreter=XBinary::regExp("#!(\\w+)",                       pBinaryInfo->sHeaderText,1); // #!perl

            if(sInterpreter=="perl")
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_PERL,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="sh")
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_SHELL,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="ruby")
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_RUBY,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
            else if(sInterpreter=="python")
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_TEXT,RECORD_TYPE_SOURCECODE,RECORD_NAME_PYTHON,"","",0);
                pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
            }
        }

        if(pBinaryInfo->mapResultTexts.count()==0)
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_TEXT,RECORD_TYPE_FORMAT,RECORD_NAME_PLAIN,"","",0);

            if(pBinaryInfo->unicodeType!=XBinary::UNICODE_TYPE_NONE)
            {
                ss.name=RECORD_NAME_UNICODE;

                if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_BE)
                {
                    ss.sVersion="Big Endian";
                }
                else if(pBinaryInfo->unicodeType==XBinary::UNICODE_TYPE_LE)
                {
                    ss.sVersion="Little Endian";
                }
            }
            else if(pBinaryInfo->bIsUTF8)
            {
                ss.name=RECORD_NAME_UTF8;
            }
            else if(pBinaryInfo->bIsPlainText)
            {
                ss.name=RECORD_NAME_PLAIN;
            }

            pBinaryInfo->mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
}

void SpecAbstract::Binary_handle_COM(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PKLITE))
    {
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_COM;
        SpecAbstract::_SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PKLITE);
        pBinaryInfo->mapResultPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UPX))
    {
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_COM;
        SpecAbstract::_SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_UPX);
        pBinaryInfo->mapResultPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_HACKSTOP))
    {
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_COM;
        SpecAbstract::_SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_HACKSTOP);
        pBinaryInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPIRIT))
    {
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_COM;
        SpecAbstract::_SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPIRIT);
        pBinaryInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }

    if(pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ICE))
    {
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_COM;
        SpecAbstract::_SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ICE);
        pBinaryInfo->mapResultPackers.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
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
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // xar
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XAR))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XAR);

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
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

            ss.sVersion=xcab.getVersion();
            ss.sInfo=QString("%1 records").arg(xcab.getNumberOfRecords());

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
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // ARJ
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARJ))&&(pBinaryInfo->basic_info.nSize>=4))
    {
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
            // TODO options
            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // BZIP2
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BZIP2))&&(pBinaryInfo->basic_info.nSize>=9))
    {
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
        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_EMPTYFILE,"","",0);
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDF))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // PDF
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDF);
        ss.sVersion=XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5*2,6));
        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTOFFICE))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // Microsoft Office
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTOFFICE);
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

    if(pBinaryInfo->basic_info.nSize>=0x8010)
    {
        if(binary.compareSignature("01'CD001'01",0x8000))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_ISO9660,"","",0);;
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
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JPEG);
        quint32 nMajor=pBinaryInfo->basic_info.sHeaderSignature.mid(11*2,2).toUInt(nullptr,16);
        quint32 nMinor=pBinaryInfo->basic_info.sHeaderSignature.mid(12*2,2).toUInt(nullptr,16);
        ss.sVersion=QString("%1.%2").arg(nMajor).arg(nMinor,2,10,QChar('0'));
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSICON))&&(pBinaryInfo->basic_info.nSize>=40))
    {
        // Windows Icon
        // TODO more information
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSICON);
        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSBITMAP))&&(pBinaryInfo->basic_info.nSize>=40))
    {
        // Windows Bitmap
        // TODO more information
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
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PNG);

        ss.sInfo=QString("%1x%2").arg(binary.read_uint32(16,true)).arg(binary.read_uint32(20,true));

        pBinaryInfo->mapResultImages.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DJVU))&&(pBinaryInfo->basic_info.nSize>=8))
    {
        // DJVU
        // TODO options
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
}

void SpecAbstract::Binary_handle_MicrosoftOffice(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->bIsZip)
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            XArchive::RECORD record=XArchive::getArchiveRecord("docProps/app.xml",&(pBinaryInfo->listArchiveRecords));

            if(!record.sFileName.isEmpty())
            {
                if((record.nUncompressedSize)&&(record.nUncompressedSize<=0x4000))
                {
                    QString sData=xzip.decompress(&record).data();
                    QString sApplication=XBinary::regExp("<Application>(.*?)</Application>",sData,1);

                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_MICROSOFTOFFICE,"","",0);

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
                    pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_OpenOffice(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->bIsZip)
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            XArchive::RECORD record=XArchive::getArchiveRecord("meta.xml",&(pBinaryInfo->listArchiveRecords));

            if(!record.sFileName.isEmpty())
            {
                if((record.nUncompressedSize)&&(record.nUncompressedSize<=0x4000))
                {
                    QString sData=xzip.decompress(&record).data();

                    // TODO
                    if(sData.contains(":opendocument:"))
                    {
                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_BINARY,RECORD_TYPE_FORMAT,RECORD_NAME_OPENDOCUMENT,"","",0);

                        pBinaryInfo->mapResultFormats.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_JAR(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,SpecAbstract::SCAN_OPTIONS *pOptions)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->bIsZip)
    {
        XZip xzip(pDevice);

        if(xzip.isValid())
        {
            XArchive::RECORD record=XArchive::getArchiveRecord("META-INF/MANIFEST.MF",&(pBinaryInfo->listArchiveRecords));

            if(!record.sFileName.isEmpty())
            {
                if(record.nUncompressedSize)
                {
                    QString sData=xzip.decompress(&record).data();

                    QString sVendor=XBinary::regExp("Specification-Vendor: (.*?)\n",sData,1).remove("\r");
                    QString sVersion=XBinary::regExp("Specification-Version: (.*?)\n",sData,1).remove("\r");
                    QString sImpVendor=XBinary::regExp("Implementation-Vendor: (.*?)\n",sData,1).remove("\r");
                    QString sImpVersion=XBinary::regExp("Implementation-Version: (.*?)\n",sData,1).remove("\r");
                    QString sBuildBy=XBinary::regExp("Built-By: (.*?)\n",sData,1).remove("\r");
                    QString sCreatedBy=XBinary::regExp("Created-By: (.*?)\n",sData,1).remove("\r");

                    bool bIsAPK=XArchive::isArchiveRecordPresent("classes.dex",&(pBinaryInfo->listArchiveRecords));

                    if(bIsAPK)
                    {
                        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_APK;

                        if(sCreatedBy.contains("Android Gradle"))
                        {
                            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_APK,RECORD_TYPE_TOOL,RECORD_NAME_ANDROIDGRADLE,"","",0);
                            ss.sVersion=XBinary::regExp("Android Gradle (.*?)$",sCreatedBy,1);
                            pBinaryInfo->mapResultTools.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
                        }

//                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_APK,RECORD_TYPE_TOOL,RECORD_NAME_APK,"","",0);
//                        ss.sVersion=sVersion;
//                        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
                    }
                    else
                    {
//                        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_JAR;

                        _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_BINARY,RECORD_TYPE_ARCHIVE,RECORD_NAME_JAR,"","",0);
                        ss.sVersion=sCreatedBy;
                        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
                    }

                    if((bIsAPK)&&(pOptions->bRecursiveScan))
                    {
                        XArchive::RECORD recordClasses=XArchive::getArchiveRecord("classes.dex",&(pBinaryInfo->listArchiveRecords));

                        QByteArray baData=xzip.decompress(&recordClasses);

                        QBuffer buffer(&baData);

                        if(buffer.open(QIODevice::ReadOnly))
                        {
                            SpecAbstract::SCAN_RESULT scanResult={0};

                            SpecAbstract::ID _parentId=pBinaryInfo->basic_info.id;
                            _parentId.filepart=SpecAbstract::RECORD_FILEPART_ARCHIVERECORD;
                            _parentId.sInfo=QString("classes.dex");
                            _parentId.bVirtual=true; // TODO Check
                            scan(&buffer,&scanResult,0,buffer.size(),_parentId,pOptions);

                            pBinaryInfo->listRecursiveDetects.append(scanResult.listRecords);

                            buffer.close();
                        }
                    }

//                    if((sVersion=="")&&sCreatedBy.contains("JetBrains"))
//                    {
//                        sVersion=sCreatedBy;
//                    }

//                    if((sVersion=="")&&(sImpVendor!="")&&(sImpVersion!=""))
//                    {
//                        sVersion=sImpVendor+"-"+sImpVersion;
//                    }

//                    if((sVersion=="")&&(sVendor!="")&&(sImpVersion!=""))
//                    {
//                        sVersion=sVendor+"-"+sImpVersion;
//                    }
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_FixDetects(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(     (pBinaryInfo->basic_info.id.filetype==RECORD_FILETYPE_APK)||
            (pBinaryInfo->mapResultFormats.contains(RECORD_NAME_MICROSOFTOFFICE))||
            (pBinaryInfo->mapResultFormats.contains(RECORD_NAME_MICROSOFTOFFICEWORD))||
            (pBinaryInfo->mapResultFormats.contains(RECORD_NAME_MICROSOFTEXCEL))||
            (pBinaryInfo->mapResultFormats.contains(RECORD_NAME_MICROSOFTVISIO))||
            (pBinaryInfo->mapResultFormats.contains(RECORD_NAME_OPENDOCUMENT))||
            (pBinaryInfo->mapResultArchives.contains(RECORD_NAME_JAR)))
    {
        pBinaryInfo->mapResultArchives.remove(RECORD_NAME_ZIP);
    }

    if(pBinaryInfo->mapResultFormats.contains(RECORD_NAME_PDF))
    {
        pBinaryInfo->mapResultTexts.clear();

        pBinaryInfo->mapResultFormats[RECORD_NAME_PDF].id.filetype=RECORD_FILETYPE_BINARY;
        pBinaryInfo->basic_info.id.filetype=RECORD_FILETYPE_BINARY;
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
        SpecAbstract::_SCANS_STRUCT recordLinker={};
        SpecAbstract::_SCANS_STRUCT recordCompiler={};

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi=get_TurboLinker_vi(pDevice,bIsImage);

            if(vi.bIsValid)
            {
                ss.sVersion=vi.sVersion;
            }

            recordLinker=ss;
        }

        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            qint64 _nOffset=0;
            qint64 _nSize=pMSDOSInfo->basic_info.nSize;

            qint64 nOffsetTurboC=-1;
            qint64 nOffsetTurboCPP=-1;
            qint64 nOffsetBorlandCPP=-1;

            nOffsetTurboC=msdos.find_ansiString(_nOffset,_nSize,"Turbo-C - ");

            if(nOffsetTurboC!=-1)
            {
                QString sBorlandString=msdos.read_ansiString(nOffsetTurboC);
                // TODO version
                _SCANS_STRUCT ssCompiler=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_TURBOC,"","",0);

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
                _SCANS_STRUCT ssCompiler=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_TURBOCPP,"","",0);

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
                _SCANS_STRUCT ssCompiler=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_COMPILER,RECORD_NAME_BORLANDCPP,"","",0);

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

        if(recordCompiler.type==RECORD_TYPE_UNKNOWN)
        {
            if(pMSDOSInfo->mapEntryPointDetects.contains(RECORD_NAME_TURBOCPP))
            {
                recordCompiler=pMSDOSInfo->mapEntryPointDetects.value(RECORD_NAME_TURBOCPP);
            }
        }

        if(recordLinker.type==RECORD_TYPE_UNKNOWN)
        {
            if( (recordCompiler.name==RECORD_NAME_TURBOC)||
                (recordCompiler.name==RECORD_NAME_TURBOCPP)||
                (recordCompiler.name==RECORD_NAME_BORLANDCPP))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_LINKER,RECORD_NAME_TURBOLINKER,"","",0);

                // TODO Version
                // Turbo-C 1987 1.0
                // Turbo-C 1988 2.0
                // Borland C++ 1991 3.0-7.00?

                recordLinker=ss;
            }
        }

        if(recordLinker.type!=RECORD_TYPE_UNKNOWN)
        {
            pMSDOSInfo->mapResultLinkers.insert(recordLinker.name,scansToScan(&(pMSDOSInfo->basic_info),&recordLinker));
        }

        if(recordCompiler.type!=RECORD_TYPE_UNKNOWN)
        {
            pMSDOSInfo->mapResultCompilers.insert(recordCompiler.name,scansToScan(&(pMSDOSInfo->basic_info),&recordCompiler));
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

            VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,0,pMSDOSInfo->basic_info.nSize);

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
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_CWSDPMI,"","",0);

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
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_PMODEW,"","",0);

            ss.sVersion=sPMODEW.section(" ",1,1).remove("v");

            pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        QString sWDOSX=msdos.read_ansiString(0x34);

        if(sWDOSX.section(" ",0,0)=="WDOSX")
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_WDOSX,"","",0);

            ss.sVersion=sWDOSX.section(" ",1,1);

            pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
        }

        // DOS/16M
        if(pMSDOSInfo->basic_info.bIsDeepScan)
        {
            qint64 nVersionOffset=msdos.find_ansiString(0,qMin(pMSDOSInfo->basic_info.nSize,(qint64)0x1000),"DOS/16M Copyright (C) Tenberry Software Inc");

            if(nVersionOffset!=-1)
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_MSDOS,RECORD_TYPE_DOSEXTENDER,RECORD_NAME_DOS16M,"","",0);
                // TODO Version
                pMSDOSInfo->mapResultDosExtenders.insert(ss.name,scansToScan(&(pMSDOSInfo->basic_info),&ss));
            }
        }
    }
}

void SpecAbstract::MSDOS_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::MSDOSINFO_STRUCT *pMSDOSInfo,SpecAbstract::SCAN_OPTIONS *pOptions)
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
                _parentId.filepart=SpecAbstract::RECORD_FILEPART_OVERLAY;
                scan(pDevice,&scanResult,pMSDOSInfo->nOverlayOffset,pMSDOSInfo->nOverlaySize,_parentId,pOptions);

                pMSDOSInfo->listRecursiveDetects.append(scanResult.listRecords);
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
        if(XELF::isSectionNamePresent(".qtversion",&(pELFInfo->listSectionRecords))) // TODO
        {
            SpecAbstract::_SCANS_STRUCT recordSS={};

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
                recordSS.sVersion=XBinary::get_uint32_version(nVersion);
            }

            pELFInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }
        else if(XELF::isSectionNamePresent(".qtplugin",&(pELFInfo->listSectionRecords)))
        {
            XELF::SECTION_RECORD record=XELF::getSectionRecord(".qtplugin",&(pELFInfo->listSectionRecords));

            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_QT;

            QString sVersionString=elf.read_ansiString(record.nOffset);
            recordSS.sVersion=XBinary::regExp("version=(.*?)\\\n",sVersionString,1);

            pELFInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pELFInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::ELF_handle_GCC(QIODevice *pDevice, bool bIsImage, SpecAbstract::ELFINFO_STRUCT *pELFInfo)
{
    XELF elf(pDevice,bIsImage);

    if(elf.isValid())
    {
        SpecAbstract::_SCANS_STRUCT recordCompiler={};
        // GCC
        if(XELF::isSectionNamePresent(".gcc_except_table",&(pELFInfo->listSectionRecords)))  // TODO
        {
            recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
            recordCompiler.name=SpecAbstract::RECORD_NAME_GCC;
        }

        if(elf.checkOffsetSize(pELFInfo->osCommentSection))
        {
            VI_STRUCT viStruct=get_GCC_vi1(pDevice,bIsImage,pELFInfo->osCommentSection.nOffset,pELFInfo->osCommentSection.nSize);

            if(viStruct.sVersion!="")
            {
                recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
                recordCompiler.name=SpecAbstract::RECORD_NAME_GCC;
                recordCompiler.sVersion=viStruct.sVersion;
            }
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
        VI_STRUCT viUPX1=get_UPX_vi(pDevice,bIsImage,pELFInfo->basic_info.nSize-0x24,0x24);
        VI_STRUCT viUPX2=get_UPX_vi(pDevice,bIsImage,0,pELFInfo->basic_info.nSize);

        if((viUPX1.bIsValid)||(viUPX2.bIsValid))
        {
            SpecAbstract::_SCANS_STRUCT recordUPX={};

            recordUPX.type=RECORD_TYPE_PACKER;
            recordUPX.name=RECORD_NAME_UPX;

            if(viUPX1.sVersion!="") recordUPX.sVersion=viUPX1.sVersion;
            if(viUPX2.sVersion!="") recordUPX.sVersion=viUPX2.sVersion;

            if(viUPX1.sInfo!="") recordUPX.sInfo=viUPX1.sInfo;
            if(viUPX2.sInfo!="") recordUPX.sInfo=viUPX2.sInfo;

            pELFInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pELFInfo->basic_info),&recordUPX));
        }
    }
}

void SpecAbstract::MACH_handle_Tools(QIODevice *pDevice, bool bIsImage, SpecAbstract::MACHINFO_STRUCT *pMACHInfo)
{
    XMACH mach(pDevice,bIsImage);

    if(mach.isValid())
    {
        // GCC
        if(XMACH::isSectionNamePresent("__gcc_except_tab",&(pMACHInfo->listSectionRecords)))  // TODO
        {
            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_COMPILER;
            recordSS.name=SpecAbstract::RECORD_NAME_GCC;

            pMACHInfo->mapResultCompilers.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
        // Qt
        if(XMACH::isLibraryRecordNamePresent("QtCore",&(pMACHInfo->listLibraryRecords)))
        {
            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName("QtCore",&(pMACHInfo->listLibraryRecords));

            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_QT;
            recordSS.sVersion=XBinary::get_uint32_version(lr.current_version);

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
        // Carbon
        if(XMACH::isLibraryRecordNamePresent("Carbon",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Carbon");

            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_CARBON;

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
        // Cocoa
        if(XMACH::isLibraryRecordNamePresent("Cocoa",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"Cocoa");

            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_LIBRARY;
            recordSS.name=SpecAbstract::RECORD_NAME_COCOA;

            pMACHInfo->mapResultLibraries.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::MACH_handle_Protection(QIODevice *pDevice, bool bIsImage, SpecAbstract::MACHINFO_STRUCT *pMACHInfo)
{
    XMACH mach(pDevice,bIsImage);

    if(mach.isValid())
    {
        // VMProtect
        if(XMACH::isLibraryRecordNamePresent("libVMProtectSDK.dylib",&(pMACHInfo->listLibraryRecords)))
        {
//            XMACH::LIBRARY_RECORD lr=XMACH::getLibraryRecordByName(&(pMACHInfo->listLibraryRecords),"libVMProtectSDK.dylib");

            SpecAbstract::_SCANS_STRUCT recordSS={};

            recordSS.type=SpecAbstract::RECORD_TYPE_PROTECTOR;
            recordSS.name=SpecAbstract::RECORD_NAME_VMPROTECT;

            pMACHInfo->mapResultProtectors.insert(recordSS.name,scansToScan(&(pMACHInfo->basic_info),&recordSS));
        }
    }
}

void SpecAbstract::LE_handle_Microsoft(QIODevice *pDevice, bool bIsImage, LEINFO_STRUCT *pLEInfo)
{
    XLE le(pDevice,bIsImage);

    if(le.isValid())
    {
        SpecAbstract::_SCANS_STRUCT recordLinker={};
        SpecAbstract::_SCANS_STRUCT recordCompiler={};

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

        QList<SpecAbstract::_SCANS_STRUCT> listRichDescriptions;

        for(int i=0;i<nRichSignaturesCount;i++)
        {
            listRichDescriptions.append(richScan(pLEInfo->listRichSignatures.at(i).nId,pLEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pLEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS,&(pLEInfo->basic_info),HEURTYPE_RICH));
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
        SpecAbstract::_SCANS_STRUCT recordLinker={};

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

void SpecAbstract::NE_handle_Borland(QIODevice *pDevice, bool bIsImage, SpecAbstract::NEINFO_STRUCT *pNEInfo)
{
    XNE ne(pDevice,bIsImage);

    if(ne.isValid())
    {
        SpecAbstract::_SCANS_STRUCT recordLinker={};

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

void SpecAbstract::updateVersion(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *map, SpecAbstract::RECORD_NAME name, QString sVersion)
{
    if(map->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=map->value(name);
        record.sVersion=sVersion;
        map->insert(name,record);
    }
}

void SpecAbstract::updateInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *map, SpecAbstract::RECORD_NAME name, QString sInfo)
{
    if(map->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=map->value(name);
        record.sInfo=sInfo;
        map->insert(name,record);
    }
}

void SpecAbstract::updateVersionAndInfo(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::SCAN_STRUCT> *map, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo)
{
    if(map->contains(name))
    {
        SpecAbstract::SCAN_STRUCT record=map->value(name);
        record.sVersion=sVersion;
        record.sInfo=sInfo;
        map->insert(name,record);
    }
}

bool SpecAbstract::isScanStructPresent(QList<SpecAbstract::SCAN_STRUCT> *pList, SpecAbstract::RECORD_FILETYPE filetype, SpecAbstract::RECORD_TYPE type, SpecAbstract::RECORD_NAME name, QString sVersion, QString sInfo)
{
    bool bResult=false;

    for(int i=0; i<pList->count(); i++)
    {
        if((pList->at(i).id.filetype==filetype)
                &&(pList->at(i).type==type)
                &&(pList->at(i).name==name)
                &&(pList->at(i).sVersion==sVersion)
                &&(pList->at(i).sInfo==sInfo))
        {
            bResult=true;
            break;
        }
    }

    return bResult;
}

bool SpecAbstract::checkVersionString(QString sVersion)
{
    bool bResult=true;

    // TODO
    for(int i=0; i<sVersion.size(); i++)
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

    return bResult;
}

SpecAbstract::VI_STRUCT SpecAbstract::get_UPX_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    // TODO PE
    // TODO unknown vesrion
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
        result.bIsValid=true;
        // TODO 1 function
        if(result.sVersion=="")
        {
            result.sVersion=binary.read_ansiString(nStringOffset2-5,4);
        }

        quint8 nMethod=binary.read_uint8(nStringOffset2+4+2);
        quint8 nLevel=binary.read_uint8(nStringOffset2+4+3);

        switch(nMethod) // From http://sourceforge.net/p/upx/code/ci/default/tree/src/conf.h
        {
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
            case 9:
            case 10:
                if(result.sInfo=="")
                {
                    result.sInfo="NRV";
                }

                break;

            case 14:
                result.sInfo="LZMA";
                break;

            case 15:
                result.sInfo="zlib";
                break;
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
    }

    if(!checkVersionString(result.sVersion))
    {
        result.sVersion="";
    }

    // TODO modified

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
        result.bIsValid=true;

        QString sVersionString=binary.read_ansiString(nOffset_Version);

        // TODO MinGW-w64
        if(sVersionString.contains("MinGW"))
        {
            result.sInfo="MinGW";
        }
        else if(sVersionString.contains("MSYS2"))
        {
            result.sInfo="MSYS2";
        }
        else if(sVersionString.contains("Cygwin"))
        {
            result.sInfo="Cygwin";
        }

        if((sVersionString.contains("(experimental)"))||
                (sVersionString.contains("(prerelease)")))
        {
            result.sVersion=sVersionString.section(" ",-3,-1); // TODO Check
        }
        else if(sVersionString.contains("GNU"))
        {
            result.sVersion=sVersionString.section(" ",2,-1);
        }
        else if(sVersionString.contains("Rev1, Built by MSYS2 project"))
        {
            result.sVersion=sVersionString.section(" ",-2,-1);
        }
        else
        {
            result.sVersion=sVersionString.section(" ",-1,-1);
        }
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

SpecAbstract::VI_STRUCT SpecAbstract::get_WindowsInstaller_vi(QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize)
{
    VI_STRUCT result;

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

SpecAbstract::VI_STRUCT SpecAbstract::get_TurboLinker_vi(QIODevice *pDevice, bool bIsImage)
{
    VI_STRUCT result;

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
        if((pPEInfo->listSectionHeaders.at(0).SizeOfRawData==0)&&((pPEInfo->nResourceSection==-1)||(pPEInfo->nResourceSection==2)))
        {
            bResult=true;
        }
    }

    return bResult;
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

void SpecAbstract::memoryScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMmREcords, QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize, SIGNATURE_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2, BASIC_INFO *pBasicInfo, HEURTYPE heurType)
{
    if(nSize)
    {
        XBinary binary(pDevice,bIsImage);

        int nSignaturesCount=nRecordsSize/sizeof(SIGNATURE_RECORD);

        for(int i=0; i<nSignaturesCount; i++)
        {
            if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
            {
                if((!pMmREcords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
                {
                    qint64 _nOffset=binary.find_signature(&(pBasicInfo->memoryMap),nOffset,nSize,(char *)pRecords[i].pszSignature);

                    if(_nOffset!=-1)
                    {
                        if(!pMmREcords->contains(pRecords[i].basicInfo.name))
                        {
                            SpecAbstract::_SCANS_STRUCT record={};
                            record.nVariant=pRecords[i].basicInfo.nVariant;
                            record.filetype=pRecords[i].basicInfo.filetype;
                            record.type=pRecords[i].basicInfo.type;
                            record.name=pRecords[i].basicInfo.name;
                            record.sVersion=pRecords[i].basicInfo.pszVersion;
                            record.sInfo=pRecords[i].basicInfo.pszInfo;
                            record.nOffset=_nOffset;

                            pMmREcords->insert(record.name,record);
                        }

                        if(pBasicInfo->bShowHeuristic)
                        {
                            HEUR_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                            heurRecord.filetype=pRecords[i].basicInfo.filetype;
                            heurRecord.type=pRecords[i].basicInfo.type;
                            heurRecord.name=pRecords[i].basicInfo.name;
                            heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                            heurRecord.nOffset=_nOffset;
                            heurRecord.filepart=pBasicInfo->id.filepart;
                            heurRecord.heurType=heurType;
                            heurRecord.sValue=pRecords[i].pszSignature;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::signatureScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QString sSignature, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
            {
                if(XBinary::compareSignatureStrings(sSignature,pRecords[i].pszSignature))
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        SpecAbstract::_SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.filetype=pRecords[i].basicInfo.filetype;
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

                    if(pBasicInfo->bShowHeuristic)
                    {
                        HEUR_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.filetype=pRecords[i].basicInfo.filetype;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filepart;
                        heurRecord.heurType=heurType;
                        heurRecord.sValue=pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::resourcesScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, SpecAbstract::RESOURCES_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2, BASIC_INFO *pBasicInfo, HEURTYPE heurType)
{
    int nSignaturesCount=nRecordsSize/sizeof(RESOURCES_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
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
                        SpecAbstract::_SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.filetype=pRecords[i].basicInfo.filetype;
                        record.type=pRecords[i].basicInfo.type;
                        record.name=pRecords[i].basicInfo.name;
                        record.sVersion=pRecords[i].basicInfo.pszVersion;
                        record.sInfo=pRecords[i].basicInfo.pszInfo;
                        record.nOffset=0;

                        pMapRecords->insert(record.name,record);
                    }

                    if(pBasicInfo->bShowHeuristic)
                    {
                        HEUR_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.filetype=pRecords[i].basicInfo.filetype;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filepart;
                        heurRecord.heurType=heurType;
                        heurRecord.sValue=sValue;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::stringScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, SpecAbstract::STRING_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType)
{
    QList<quint32> listStringCRC;
    QList<quint32> listSignatureCRC;

    int nCount=pListStrings->count();
    int nSignaturesCount=nRecordsSize/sizeof(STRING_RECORD);

    for(int i=0; i<nCount; i++)
    {
        quint32 nCRC=XBinary::getStringCustomCRC32(pListStrings->at(i));
        listStringCRC.append(nCRC);
    }

    for(int i=0; i<nSignaturesCount; i++)
    {
        quint32 nCRC=XBinary::getStringCustomCRC32(pRecords[i].pszString);
        listSignatureCRC.append(nCRC);
    }

    for(int i=0; i<nCount; i++)
    {
        for(int j=0; j<nSignaturesCount; j++)
        {
            if((pRecords[j].basicInfo.filetype==fileType1)||(pRecords[j].basicInfo.filetype==fileType2))
            {
                if((!pMapRecords->contains(pRecords[j].basicInfo.name))||(pBasicInfo->bShowHeuristic))
                {
                    quint32 nCRC1=listStringCRC[i];
                    quint32 nCRC2=listSignatureCRC[j];

                    if(nCRC1==nCRC2)
                    {
                        if(!pMapRecords->contains(pRecords[j].basicInfo.name))
                        {
                            SpecAbstract::_SCANS_STRUCT record={};
                            record.nVariant=pRecords[j].basicInfo.nVariant;
                            record.filetype=pRecords[j].basicInfo.filetype;
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

                        if(pBasicInfo->bShowHeuristic)
                        {
                            HEUR_RECORD heurRecord={};

                            heurRecord.nVariant=pRecords[j].basicInfo.nVariant;
                            heurRecord.filetype=pRecords[j].basicInfo.filetype;
                            heurRecord.type=pRecords[j].basicInfo.type;
                            heurRecord.name=pRecords[j].basicInfo.name;
                            heurRecord.sVersion=pRecords[j].basicInfo.pszVersion;
                            heurRecord.sInfo=pRecords[j].basicInfo.pszInfo;
                            heurRecord.nOffset=0;
                            heurRecord.filepart=pBasicInfo->id.filepart;
                            heurRecord.heurType=heurType;
                            heurRecord.sValue=pRecords[j].pszString;

                            pBasicInfo->listHeurs.append(heurRecord);
                        }
                    }
                }
            }
        }
    }
}

void SpecAbstract::constScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, SpecAbstract::CONST_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2, BASIC_INFO *pBasicInfo, HEURTYPE heurType)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(CONST_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
            {
                bool bSuccess=false;

                bSuccess=   ((pRecords[i].nConst1==nCost1)||(pRecords[i].nConst1==0xFFFFFFFF))&&
                            ((pRecords[i].nConst2==nCost2)||(pRecords[i].nConst2==0xFFFFFFFF));

                if(bSuccess)
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        SpecAbstract::_SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.filetype=pRecords[i].basicInfo.filetype;
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

                    if(pBasicInfo->bShowHeuristic)
                    {
                        HEUR_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.filetype=pRecords[i].basicInfo.filetype;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filepart;
                        heurRecord.heurType=heurType;
                        heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nConst1)).arg(XBinary::valueToHex(pRecords[i].nConst2));

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

void SpecAbstract::richScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
        {
            SpecAbstract::_SCANS_STRUCT record={};

            if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
            {
                if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                {
                    pMapRecords->insert(record.name,record);
                }

                if(pBasicInfo->bShowHeuristic)
                {
                    HEUR_RECORD heurRecord={};

                    heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                    heurRecord.filetype=pRecords[i].basicInfo.filetype;
                    heurRecord.type=pRecords[i].basicInfo.type;
                    heurRecord.name=pRecords[i].basicInfo.name;
                    heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                    heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                    heurRecord.nOffset=0;
                    heurRecord.filepart=pBasicInfo->id.filepart;
                    heurRecord.heurType=heurType;
                    heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID)).arg(XBinary::valueToHex(pRecords[i].nBuild));

                    pBasicInfo->listHeurs.append(heurRecord);
                }
            }
        }
    }
}

void SpecAbstract::signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, qint64 nOffset, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if((!pMapRecords->contains(pRecords[i].basicInfo.name))||(pBasicInfo->bShowHeuristic))
            {
                if(pXBinary->compareSignature(pMemoryMap,pRecords[i].pszSignature,nOffset))
                {
                    if(!pMapRecords->contains(pRecords[i].basicInfo.name))
                    {
                        SpecAbstract::_SCANS_STRUCT record={};
                        record.nVariant=pRecords[i].basicInfo.nVariant;
                        record.filetype=pRecords[i].basicInfo.filetype;
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

                    if(pBasicInfo->bShowHeuristic)
                    {
                        HEUR_RECORD heurRecord={};

                        heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                        heurRecord.filetype=pRecords[i].basicInfo.filetype;
                        heurRecord.type=pRecords[i].basicInfo.type;
                        heurRecord.name=pRecords[i].basicInfo.name;
                        heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                        heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                        heurRecord.nOffset=0;
                        heurRecord.filepart=pBasicInfo->id.filepart;
                        heurRecord.heurType=heurType;
                        heurRecord.sValue=pRecords[i].pszSignature;

                        pBasicInfo->listHeurs.append(heurRecord);
                    }
                }
            }
        }
    }
}

QList<SpecAbstract::_SCANS_STRUCT> SpecAbstract::richScan(quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType)
{
    QList<SpecAbstract::_SCANS_STRUCT> listResult;

    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        SpecAbstract::_SCANS_STRUCT record={};

        if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
        {
            listResult.append(record);

            if(pBasicInfo->bShowHeuristic)
            {
                HEUR_RECORD heurRecord={};

                heurRecord.nVariant=pRecords[i].basicInfo.nVariant;
                heurRecord.filetype=pRecords[i].basicInfo.filetype;
                heurRecord.type=pRecords[i].basicInfo.type;
                heurRecord.name=pRecords[i].basicInfo.name;
                heurRecord.sVersion=pRecords[i].basicInfo.pszVersion;
                heurRecord.sInfo=pRecords[i].basicInfo.pszInfo;
                heurRecord.nOffset=0;
                heurRecord.filepart=pBasicInfo->id.filepart;
                heurRecord.heurType=heurType;
                heurRecord.sValue=QString("%1 %2").arg(XBinary::valueToHex(pRecords[i].nID)).arg(XBinary::valueToHex(pRecords[i].nBuild));

                pBasicInfo->listHeurs.append(heurRecord);
            }
        }
    }

    return listResult;
}

QByteArray SpecAbstract::serializeScanStruct(SCAN_STRUCT ssRecord, bool bIsHeader)
{
    QByteArray baResult;

    QDataStream ds(baResult);

    ds << ssRecord.nSize;
    ds << ssRecord.nOffset;
    ds << ssRecord.id.uuid;
    ds << (quint32)ssRecord.id.filetype;
    ds << (quint32)ssRecord.id.filepart;
    ds << ssRecord.parentId.uuid;
    ds << (quint32)ssRecord.parentId.filetype;
    ds << (quint32)ssRecord.parentId.filepart;
    ds << (quint32)ssRecord.type;
    ds << (quint32)ssRecord.name;
    ds << ssRecord.sVersion;
    ds << ssRecord.sInfo;
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
    ds >> ssResult.id.uuid;
    ds >> nTemp;
    ssResult.id.filetype=(RECORD_FILETYPE)nTemp;
    ds >> nTemp;
    ssResult.id.filepart=(RECORD_FILEPART)nTemp;
    ds >> ssResult.parentId.uuid;
    ds >> nTemp;
    ssResult.parentId.filetype=(RECORD_FILETYPE)nTemp;
    ds >> nTemp;
    ssResult.parentId.filepart=(RECORD_FILEPART)nTemp;
    ds >> nTemp;
    ssResult.type=(RECORD_TYPE)nTemp;
    ds >> nTemp;
    ssResult.name=(RECORD_NAME)nTemp;
    ds >> ssResult.sVersion;
    ds >> ssResult.sInfo;
    ds >> *pbIsHeader;

    return ssResult;
}

bool SpecAbstract::PE_compareRichRecord(_SCANS_STRUCT *pResult,SpecAbstract::MSRICH_RECORD *pRecord, quint16 nID, quint32 nBuild, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    bool bResult=false;

    if((pRecord->basicInfo.filetype==fileType1)||(pRecord->basicInfo.filetype==fileType2))
    {
        bool bCheck=false;

        bCheck= ((pRecord->nID==nID)||(pRecord->nID==(quint16)-1))&&
                ((pRecord->nBuild==nBuild)||(pRecord->nBuild==(quint32)-1));

        if(bCheck)
        {
            SpecAbstract::_SCANS_STRUCT record={};
            record.nVariant=pRecord->basicInfo.nVariant;
            record.filetype=pRecord->basicInfo.filetype;
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
            for(int i=0; i<20; i++)
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

                for(int i=0; i<nCount; i++)
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
    SpecAbstract::_SCANS_STRUCT result={};

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

void SpecAbstract::_errorMessage(QString sMessage)
{
#ifdef QT_DEBUG
    qDebug("Error: %s",sMessage.toLatin1().data());
#endif
    emit errorMessage(sMessage);
}

void SpecAbstract::_infoMessage(QString sMessage)
{
#ifdef QT_DEBUG
    qDebug("Info: %s",sMessage.toLatin1().data());
#endif
    emit infoMessage(sMessage);
}
