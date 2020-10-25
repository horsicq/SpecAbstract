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
#ifndef SPECABSTRACT_H
#define SPECABSTRACT_H

#include <QObject>
#include <QSet>
#include <QDataStream>
#include <QElapsedTimer>
#include <QUuid>
#include "xformats.h"
#include "xzip.h" // Mb TODO xarchives
#include "xcab.h"
#include "xrar.h"
#include "xsevenzip.h"
#include "xdex.h"
#include "xandroidbinary.h"

class SpecAbstract : public QObject
{
    Q_OBJECT

public:

    enum RECORD_FILEPART
    {
        RECORD_FILEPART_UNKNOWN=0,
        RECORD_FILEPART_HEADER,
        RECORD_FILEPART_OVERLAY,
        RECORD_FILEPART_ARCHIVERECORD
    };

    enum RECORD_TYPE
    {
        RECORD_TYPE_UNKNOWN=0,
        RECORD_TYPE_APKOBFUSCATOR,
        RECORD_TYPE_APKTOOL,
        RECORD_TYPE_CERTIFICATE,
        RECORD_TYPE_COMPILER,
        RECORD_TYPE_CONVERTER,
        RECORD_TYPE_CRYPTOR,
        RECORD_TYPE_DATABASE,
        RECORD_TYPE_DEBUGDATA,
        RECORD_TYPE_DONGLEPROTECTION,
        RECORD_TYPE_DOSEXTENDER,
        RECORD_TYPE_FORMAT,
        RECORD_TYPE_GENERIC,
        RECORD_TYPE_IMAGE,
        RECORD_TYPE_INSTALLER,
        RECORD_TYPE_INSTALLERDATA,
        RECORD_TYPE_JAROBFUSCATOR,
        RECORD_TYPE_JOINER,
        RECORD_TYPE_LANGUAGE, // TODO !!!
        RECORD_TYPE_LIBRARY,
        RECORD_TYPE_LINKER,
        RECORD_TYPE_NETCOMPRESSOR,
        RECORD_TYPE_NETOBFUSCATOR,
        RECORD_TYPE_PACKER,
        RECORD_TYPE_PETOOL,
        RECORD_TYPE_PROTECTOR,
        RECORD_TYPE_PROTECTORDATA,
        RECORD_TYPE_SFX,
        RECORD_TYPE_SFXDATA,
        RECORD_TYPE_SIGNTOOL,
        RECORD_TYPE_SOURCECODE,
        RECORD_TYPE_STUB,
        RECORD_TYPE_TOOL
    };

    enum RECORD_NAME
    {
        RECORD_NAME_UNKNOWN=0,
        RECORD_NAME_12311134,
        RECORD_NAME_1337EXECRYPTER,
        RECORD_NAME_32LITE,
        RECORD_NAME_7Z,
        RECORD_NAME_AASE,
        RECORD_NAME_ABCCRYPTOR,
        RECORD_NAME_ACPROTECT,
        RECORD_NAME_ACTIVEMARK,
        RECORD_NAME_ACTUALINSTALLER,
        RECORD_NAME_ADVANCEDINSTALLER,
        RECORD_NAME_ADVANCEDUPXSCRAMMBLER,
        RECORD_NAME_AFFILLIATEEXE,
        RECORD_NAME_AGAINNATIVITYCRYPTER,
        RECORD_NAME_AGILENET,
        RECORD_NAME_AHPACKER,
        RECORD_NAME_AHTEAMEPPROTECTOR,
        RECORD_NAME_AINEXE,
        RECORD_NAME_ALCHEMYMINDWORKS,
        RECORD_NAME_ALEXPROTECTOR,
        RECORD_NAME_ALIASOBJ,
        RECORD_NAME_ALIPAYOBFUSCATOR,
        RECORD_NAME_ALLOY,
        RECORD_NAME_ANDPAKK2,
        RECORD_NAME_ANDROIDARSC,
        RECORD_NAME_ANDROIDCLANG,
        RECORD_NAME_ANDROIDJETPACK,
        RECORD_NAME_ANDROIDGRADLE,
        RECORD_NAME_ANDROIDMAVENPLUGIN,
        RECORD_NAME_ANDROIDSDK,
        RECORD_NAME_ANDROIDSIGNAPK,
        RECORD_NAME_ANDROIDXML,
        RECORD_NAME_ANSKYAPOLYMORPHICPACKER,
        RECORD_NAME_ANSLYMPACKER,
        RECORD_NAME_ANTIDOTE,
        RECORD_NAME_ANTILVL,
        RECORD_NAME_APACHEANT,
        RECORD_NAME_APKEDITOR,
        RECORD_NAME_APKPROTECT,
        RECORD_NAME_APKPROTECTOR,
        RECORD_NAME_APKSIGNER,
        RECORD_NAME_APPGUARD,
        RECORD_NAME_APPLEJDK,
        RECORD_NAME_APPLELLVM,
        RECORD_NAME_APPORTABLECLANG,
        RECORD_NAME_ARCRYPT,
        RECORD_NAME_ARJ,
        RECORD_NAME_ARMADILLO,
        RECORD_NAME_ARMASSEMBLER,
        RECORD_NAME_ARMC,
        RECORD_NAME_ARMCCPP,
        RECORD_NAME_ARMLINKER,
        RECORD_NAME_ARMNEONCCPP,
        RECORD_NAME_ARMPROTECTOR,
        RECORD_NAME_ARMTHUMBCCPP,
        RECORD_NAME_ARMTHUMBMACROASSEMBLER,
        RECORD_NAME_ASDPACK,
        RECORD_NAME_ASM,
        RECORD_NAME_ASPACK,
        RECORD_NAME_ASPROTECT,
        RECORD_NAME_ASSCRYPTER,
        RECORD_NAME_ASSEMBLYINVOKE,
        RECORD_NAME_AU,
        RECORD_NAME_AUTOIT,
        RECORD_NAME_AVASTANTIVIRUS,
        RECORD_NAME_AVERCRYPTOR,
        RECORD_NAME_AVI,
        RECORD_NAME_AVPACK,
        RECORD_NAME_AZPROTECT,
        RECORD_NAME_BABELNET,
        RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,
        RECORD_NAME_BAMBAM,
        RECORD_NAME_BAT2EXEC,
        RECORD_NAME_BEAWEBLOGIC,
        RECORD_NAME_BEROEXEPACKER,
        RECORD_NAME_BIOHAZARDCRYPTER,
        RECORD_NAME_BITROCKINSTALLER,
        RECORD_NAME_BITSHAPEPECRYPT,
        RECORD_NAME_BLADEJOINER,
        RECORD_NAME_BORLANDCCPP,
        RECORD_NAME_BORLANDCPP,
        RECORD_NAME_BORLANDCPPBUILDER,
        RECORD_NAME_BORLANDDELPHI,
        RECORD_NAME_BORLANDDELPHIDOTNET,
        RECORD_NAME_BORLANDOBJECTPASCAL,
        RECORD_NAME_BREAKINTOPATTERN,
        RECORD_NAME_BTWORKSCODEGUARD,
        RECORD_NAME_BYTEDANCESECCOMPILER,
        RECORD_NAME_BYTEGUARD,
        RECORD_NAME_BZIP2,
        RECORD_NAME_C,
        RECORD_NAME_CAB,
        RECORD_NAME_CARBON,
        RECORD_NAME_CAUSEWAY,
        RECORD_NAME_CCBYVORONTSOV,
        RECORD_NAME_CCBYUNIHACKERS,
        RECORD_NAME_CCPP,
        RECORD_NAME_CELESTYFILEBINDER,
        RECORD_NAME_CEXE,
        RECORD_NAME_CIGICIGICRYPTER,
        RECORD_NAME_CIL,
        RECORD_NAME_CLANG,
        RECORD_NAME_CLICKTEAM,
        RECORD_NAME_CLISECURE,
        RECORD_NAME_COCOA,
        RECORD_NAME_CODEGEARCPP,
        RECORD_NAME_CODEGEARCPPBUILDER,
        RECORD_NAME_CODEGEARDELPHI,
        RECORD_NAME_CODEGEAROBJECTPASCAL,
        RECORD_NAME_CODEVEIL,
        RECORD_NAME_CODEWALL,
        RECORD_NAME_COFF,
        RECORD_NAME_COMEXSIGNAPK,
        RECORD_NAME_CONFUSER,
        RECORD_NAME_CONFUSEREX,
        RECORD_NAME_COPYMINDER,
        RECORD_NAME_CPP,
        RECORD_NAME_CREATEINSTALL,
        RECORD_NAME_CRINKLER,
        RECORD_NAME_CRUNCH,
        RECORD_NAME_CRYEXE,
        RECORD_NAME_CRYPTABLESEDUCATION,
        RECORD_NAME_CRYPTCOM,
        RECORD_NAME_CRYPTER,
        RECORD_NAME_CRYPTIC,
        RECORD_NAME_CRYPTOCRACKPEPROTECTOR,
        RECORD_NAME_CRYPTOOBFUSCATORFORNET,
        RECORD_NAME_CRYPTORBYDISMEMBER,
        RECORD_NAME_CRYPTOZ,
        RECORD_NAME_CRYPTRROADS,
        RECORD_NAME_CVTOMF,
        RECORD_NAME_CVTPGD,
        RECORD_NAME_CVTRES,
        RECORD_NAME_CWSDPMI,
        RECORD_NAME_CYGWIN,
        RECORD_NAME_D2JAPKSIGN,
        RECORD_NAME_DALKRYPT,
        RECORD_NAME_DBPE,
        RECORD_NAME_DCRYPTPRIVATE,
        RECORD_NAME_DEB,
        RECORD_NAME_DEEPSEA,
        RECORD_NAME_DEPACK,
        RECORD_NAME_DEPLOYMASTER,
        RECORD_NAME_DEX,
        RECORD_NAME_DEX2JAR,
        RECORD_NAME_DEXGUARD,
        RECORD_NAME_DEXLIB,
        RECORD_NAME_DEXLIB2,
        RECORD_NAME_DEXMERGE,
        RECORD_NAME_DEXPROTECTOR,
        RECORD_NAME_DJVU,
        RECORD_NAME_DIET,
        RECORD_NAME_DINGBAOZENGNATIVEOBFUSCATOR,
        RECORD_NAME_DIRTYCRYPTOR,
        RECORD_NAME_DMD32D,
        RECORD_NAME_DNGUARD,
        RECORD_NAME_DOS16M,
        RECORD_NAME_DOTBJFNT,
        RECORD_NAME_DOTFIXNICEPROTECT,
        RECORD_NAME_DOTFUSCATOR,
        RECORD_NAME_DOTNET,
        RECORD_NAME_DOTNETREACTOR,
        RECORD_NAME_DOTNETSHRINK,
        RECORD_NAME_DOTNETSPIDER,
        RECORD_NAME_DOTNETZ,
        RECORD_NAME_DRAGONARMOR,
        RECORD_NAME_DROPBOX,
        RECORD_NAME_DVCLAL,
        RECORD_NAME_DX,
        RECORD_NAME_DXSHIELD,
        RECORD_NAME_DYAMAR,
        RECORD_NAME_DYNASM,
        RECORD_NAME_EAZFUSCATOR,
        RECORD_NAME_ECLIPSE,
        RECORD_NAME_EMBARCADEROCPP,
        RECORD_NAME_EMBARCADEROCPPBUILDER,
        RECORD_NAME_EMBARCADERODELPHI,
        RECORD_NAME_EMBARCADERODELPHIDOTNET,
        RECORD_NAME_EMBARCADEROOBJECTPASCAL,
        RECORD_NAME_EMPTYFILE,
        RECORD_NAME_ENCRYPTPE,
        RECORD_NAME_ENIGMA,
        RECORD_NAME_EPEXEPACK,
        RECORD_NAME_EPROT,
        RECORD_NAME_EXCELSIORJET,
        RECORD_NAME_EXE32PACK,
        RECORD_NAME_EXECRYPT,
        RECORD_NAME_EXECRYPTOR,
        RECORD_NAME_EXEFOG,
        RECORD_NAME_EXEJOINER,
        RECORD_NAME_EXEMPLARINSTALLER,
        RECORD_NAME_EXEPACK,
        RECORD_NAME_EXEPASSWORDPROTECTOR,
        RECORD_NAME_EXESAX,
        RECORD_NAME_EXESHIELD,
        RECORD_NAME_EXESTEALTH,
        RECORD_NAME_EXPORT,
        RECORD_NAME_EXPRESSOR,
        RECORD_NAME_EZIP,
        RECORD_NAME_FAKESIGNATURE,
        RECORD_NAME_FAKUSCRYPTOR,
        RECORD_NAME_FASM,
        RECORD_NAME_FASTFILECRYPT,
        RECORD_NAME_FASTPROXY,
        RECORD_NAME_FEARZCRYPTER,
        RECORD_NAME_FEARZPACKER,
        RECORD_NAME_FILESHIELD,
        RECORD_NAME_FISHNET,
        RECORD_NAME_FISHPEPACKER,
        RECORD_NAME_FISHPESHIELD,
        RECORD_NAME_FLEXLM,
        RECORD_NAME_FLEXNET,
        RECORD_NAME_FPC,
        RECORD_NAME_FREECRYPTOR,
        RECORD_NAME_FSG,
        RECORD_NAME_GCC,
        RECORD_NAME_GENERIC,
        RECORD_NAME_GENERICLINKER,
        RECORD_NAME_GENTEEINSTALLER,
        RECORD_NAME_GHAZZACRYPTER,
        RECORD_NAME_GHOSTINSTALLER,
        RECORD_NAME_GIF,
        RECORD_NAME_GIXPROTECTOR,
        RECORD_NAME_GKRIPTO,
        RECORD_NAME_GKSETUPSFX,
        RECORD_NAME_GNULINKER,
        RECORD_NAME_GO,
        RECORD_NAME_GOASM,
        RECORD_NAME_GOATSPEMUTILATOR,
        RECORD_NAME_GOLD,
        RECORD_NAME_GOLIATHNET,
        RECORD_NAME_GOLINK,
        RECORD_NAME_GOOGLE,
        RECORD_NAME_GPINSTALL,
        RECORD_NAME_GUARDIANSTEALTH,
        RECORD_NAME_GZIP,
        RECORD_NAME_H4CKY0UORGCRYPTER,
        RECORD_NAME_HACCREWCRYPTER,
        RECORD_NAME_HACKSTOP,
        RECORD_NAME_HALVCRYPTER,
        RECORD_NAME_HIDEANDPROTECT,
        RECORD_NAME_HIDEPE,
        RECORD_NAME_HIKARIOBFUSCATOR,
        RECORD_NAME_HMIMYSPACKER,
        RECORD_NAME_HMIMYSPROTECTOR,
        RECORD_NAME_HOODLUM,
        RECORD_NAME_HOUNDHACKCRYPTER,
        RECORD_NAME_HTML,
        RECORD_NAME_HXS,
        RECORD_NAME_IBMJDK,
        RECORD_NAME_IBMPCPASCAL,
        RECORD_NAME_ICE,
        RECORD_NAME_ICRYPT,
        RECORD_NAME_IJIAMI,
        RECORD_NAME_IJIAMILLVM,
        RECORD_NAME_IKVMDOTNET,
        RECORD_NAME_ILASM,
        RECORD_NAME_IMPORT,
        RECORD_NAME_INFCRYPTOR,
        RECORD_NAME_INNOSETUP,
        RECORD_NAME_INQUARTOSOBFUSCATOR,
        RECORD_NAME_INSTALL4J,
        RECORD_NAME_INSTALLANYWHERE,
        RECORD_NAME_INSTALLSHIELD,
        RECORD_NAME_IPBPROTECT,
        RECORD_NAME_ISO9660,
        RECORD_NAME_JAM,
        RECORD_NAME_JAR,
        RECORD_NAME_JAVA,
        RECORD_NAME_JAVACOMPILEDCLASS,
        RECORD_NAME_JDK,
        RECORD_NAME_JDPACK,
        RECORD_NAME_JETBRAINS,
        RECORD_NAME_JIAGU,
        RECORD_NAME_JPEG,
        RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,
        RECORD_NAME_KBYS,
        RECORD_NAME_KCRYPTOR,
        RECORD_NAME_KGBCRYPTER,
        RECORD_NAME_KIAMSCRYPTOR,
        RECORD_NAME_KIRO,
        RECORD_NAME_KKRUNCHY,
        RECORD_NAME_KOTLIN,
        RECORD_NAME_KRATOSCRYPTER,
        RECORD_NAME_KRYPTON,
        RECORD_NAME_KUR0KX2TO,
        RECORD_NAME_LAMECRYPT,
        RECORD_NAME_LARP64,
        RECORD_NAME_LAYHEYFORTRAN90,
        RECORD_NAME_LAZARUS,
        RECORD_NAME_LCCLNK,
        RECORD_NAME_LCCWIN,
        RECORD_NAME_LGLZ,
        RECORD_NAME_LHA,
        RECORD_NAME_LHASSFX,
        RECORD_NAME_LIGHTNINGCRYPTERPRIVATE,
        RECORD_NAME_LIGHTNINGCRYPTERSCANTIME,
        RECORD_NAME_LLD,
        RECORD_NAME_LOCKTITE,
        RECORD_NAME_LSCRYPRT,
        RECORD_NAME_LUACOMPILED,
        RECORD_NAME_LUCYPHER,
        RECORD_NAME_LZEXE,
        RECORD_NAME_MACROBJECT,
        RECORD_NAME_MALPACKER,
        RECORD_NAME_MASKPE,
        RECORD_NAME_MASM,
        RECORD_NAME_MASM32,
        RECORD_NAME_MAXTOCODE,
        RECORD_NAME_MEW10,
        RECORD_NAME_MEW11SE,
        RECORD_NAME_MFC,
        RECORD_NAME_MICROSOFTACCESS,
        RECORD_NAME_MICROSOFTC,
        RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP,
        RECORD_NAME_MICROSOFTCPP,
        RECORD_NAME_MICROSOFTDOTNETFRAMEWORK,
        RECORD_NAME_MICROSOFTEXCEL,
        RECORD_NAME_MICROSOFTLINKER,
        RECORD_NAME_MICROSOFTLINKERDATABASE,
        RECORD_NAME_MICROSOFTOFFICE,
        RECORD_NAME_MICROSOFTOFFICEWORD,
        RECORD_NAME_MICROSOFTPHOENIX,
        RECORD_NAME_MICROSOFTVISIO,
        RECORD_NAME_MICROSOFTVISUALSTUDIO,
        RECORD_NAME_MICROSOFTWINHELP,
        RECORD_NAME_MINGW,
        RECORD_NAME_MINKE,
        RECORD_NAME_MKFPACK,
        RECORD_NAME_MOBILETENCENTPROTECT,
        RECORD_NAME_MOLEBOX,
        RECORD_NAME_MOLEBOXULTRA,
        RECORD_NAME_MONEYCRYPTER,
        RECORD_NAME_MORPHNAH,
        RECORD_NAME_MORTALTEAMCRYPTER,
        RECORD_NAME_MORTALTEAMCRYPTER2,
        RECORD_NAME_MORUKCREWCRYPTERPRIVATE,
        RECORD_NAME_MP3,
        RECORD_NAME_MP4,
        RECORD_NAME_MPACK,
        RECORD_NAME_MPRESS,
        RECORD_NAME_MRUNDECTETABLE,
        RECORD_NAME_MSLRH,
        RECORD_NAME_MSYS,
        RECORD_NAME_MSYS2,
        RECORD_NAME_MZ0OPE,
        RECORD_NAME_NAGAINLLVM,
        RECORD_NAME_NAKEDPACKER,
        RECORD_NAME_NASM, // The Netwide Assembler
        RECORD_NAME_NCODE,
        RECORD_NAME_NEOLITE,
        RECORD_NAME_NETEASEAPKSIGNER,
        RECORD_NAME_NJOINER,
        RECORD_NAME_NJOY,
        RECORD_NAME_NIDHOGG,
        RECORD_NAME_NME,
        RECORD_NAME_NOOBYPROTECT,
        RECORD_NAME_NOODLECRYPT,
        RECORD_NAME_NORTHSTARPESHRINKER,
        RECORD_NAME_NOSTUBLINKER,
        RECORD_NAME_NOXCRYPT,
        RECORD_NAME_NPACK,
        RECORD_NAME_NSIS,
        RECORD_NAME_NSPACK,
        RECORD_NAME_OBFUSCAR,
        RECORD_NAME_OBFUSCATORLLVM,
        RECORD_NAME_OBFUSCATORNET2009,
        RECORD_NAME_OBJECTPASCAL,
        RECORD_NAME_OBSIDIUM,
        RECORD_NAME_OPENDOCUMENT,
        RECORD_NAME_OPENJDK,
        RECORD_NAME_OPENSOURCECODECRYPTER,
        RECORD_NAME_OPERA,
        RECORD_NAME_ORIEN,
        RECORD_NAME_OSCCRYPTER,
        RECORD_NAME_P0KESCRAMBLER,
        RECORD_NAME_PACKMAN,
        RECORD_NAME_PACKWIN,
        RECORD_NAME_PANDORA,
        RECORD_NAME_PCGUARD,
        RECORD_NAME_PCOM,
        RECORD_NAME_PCSHRINK,
        RECORD_NAME_PDB,
        RECORD_NAME_PDBFILELINK,
        RECORD_NAME_PDF,
        RECORD_NAME_PEARMOR,
        RECORD_NAME_PEBUNDLE,
        RECORD_NAME_PECRYPT32,
        RECORD_NAME_PECOMPACT,
        RECORD_NAME_PEDIMINISHER,
        RECORD_NAME_PEENCRYPT,
        RECORD_NAME_PELOCK,
        RECORD_NAME_PENGUINCRYPT,
        RECORD_NAME_PEPACK,
        RECORD_NAME_PEPACKSPROTECT,
        RECORD_NAME_PEQUAKE,
        RECORD_NAME_PERL,
        RECORD_NAME_PESHIELD,
        RECORD_NAME_PESPIN,
        RECORD_NAME_PETITE,
        RECORD_NAME_PETITE_KERNEL32,
        RECORD_NAME_PETITE_USER32,
        RECORD_NAME_PEX,
        RECORD_NAME_PFECX,
        RECORD_NAME_PGMPAK,
        RECORD_NAME_PHOENIXPROTECTOR,
        RECORD_NAME_PHP,
        RECORD_NAME_PICRYPTOR,
        RECORD_NAME_PKLITE,
        RECORD_NAME_PKLITE32,
        RECORD_NAME_PKZIPMINISFX,
        RECORD_NAME_PLAIN,
        RECORD_NAME_PLEXCLANG,
        RECORD_NAME_PMODEW,
        RECORD_NAME_PNG,
        RECORD_NAME_POKECRYPTER,
        RECORD_NAME_POLYCRYPTPE,
        RECORD_NAME_POWERBASIC,
        RECORD_NAME_PRIVATEEXEPROTECTOR,
        RECORD_NAME_PROPACK,
        RECORD_NAME_PROTECTEXE,
        RECORD_NAME_PSEUDOAPKSIGNER,
        RECORD_NAME_PUBCRYPTER,
        RECORD_NAME_PUNISHER,
        RECORD_NAME_PUSSYCRYPTER,
        RECORD_NAME_PUREBASIC,
        RECORD_NAME_PYTHON,
        RECORD_NAME_QRYPT0R,
        RECORD_NAME_QT,
        RECORD_NAME_QTINSTALLER,
        RECORD_NAME_QUICKPACKNT,
        RECORD_NAME_R8,
        RECORD_NAME_RAR,
        RECORD_NAME_RCRYPTOR,
        RECORD_NAME_RDGTEJONCRYPTER,
        RECORD_NAME_RELPACK,
        RECORD_NAME_RENETPACK,
        RECORD_NAME_RESOURCE,
        RECORD_NAME_REVPROT,
        RECORD_NAME_RJCRUSH,
        RECORD_NAME_RLP,
        RECORD_NAME_RLPACK,
        RECORD_NAME_ROGUEPACK,
        RECORD_NAME_ROSASM,
        RECORD_NAME_RTF,
        RECORD_NAME_RUBY,
        RECORD_NAME_SAFEENGINESHIELDEN,
        RECORD_NAME_SAFEENGINELLVM,
        RECORD_NAME_SCOBFUSCATOR,
        RECORD_NAME_SCPACK,
        RECORD_NAME_SCRNCH,
        RECORD_NAME_SDPROTECTORPRO,
        RECORD_NAME_SECSHELL,
        RECORD_NAME_SECURESHADE,
        RECORD_NAME_SETUPFACTORY,
        RECORD_NAME_SEXECRYPTER,
        RECORD_NAME_SHELL,
        RECORD_NAME_SHRINKER,
        RECORD_NAME_SIMBIOZ,
        RECORD_NAME_SIMCRYPTER,
        RECORD_NAME_SIMPLECRYPTER,
        RECORD_NAME_SIMPLEPACK,
        RECORD_NAME_SINGLEJAR,
        RECORD_NAME_SIXXPACK,
        RECORD_NAME_SKATER,
        RECORD_NAME_SMARTASSEMBLY,
        RECORD_NAME_SMARTINSTALLMAKER,
        RECORD_NAME_SMOKESCREENCRYPTER,
        RECORD_NAME_SNAPDRAGONLLVMARM,
        RECORD_NAME_SNOOPCRYPT,
        RECORD_NAME_SOFTDEFENDER,
        RECORD_NAME_SOFTSENTRY,
        RECORD_NAME_SOFTWARECOMPRESS,
        RECORD_NAME_SOFTWAREZATOR,
        RECORD_NAME_SPICESNET,
        RECORD_NAME_SPIRIT,
        RECORD_NAME_SPOONINSTALLER,
        RECORD_NAME_SPOONSTUDIO,
        RECORD_NAME_SQUEEZSFX,
        RECORD_NAME_STARFORCE,
        RECORD_NAME_STASFODIDOCRYPTOR,
        RECORD_NAME_STONESPEENCRYPTOR, // TODO Check name from .Stone Section // TODO EP
        RECORD_NAME_SVKPROTECTOR,
        RECORD_NAME_SWF,
        RECORD_NAME_TARMAINSTALLER,
        RECORD_NAME_TELOCK,
        RECORD_NAME_TENCENTOBFUSCATION,
        RECORD_NAME_TENCENTLEGU,
        RECORD_NAME_TGRCRYPTER,
        RECORD_NAME_THEBESTCRYPTORBYFSK,
        RECORD_NAME_THEMIDAWINLICENSE,
        RECORD_NAME_THEZONECRYPTER,
        RECORD_NAME_THINSTALL,
        RECORD_NAME_THUMBC,
        RECORD_NAME_TIFF,
        RECORD_NAME_TINYPROG,
        RECORD_NAME_TOTALCOMMANDERINSTALLER,
        RECORD_NAME_TPPPACK,
        RECORD_NAME_TSTCRYPTER,
        RECORD_NAME_TTF,
        RECORD_NAME_TTPROTECT,
        RECORD_NAME_TURBOBASIC,
        RECORD_NAME_TURBOC,
        RECORD_NAME_TURBOCPP,
        RECORD_NAME_TURBOLINKER,
        RECORD_NAME_TURKISHCYBERSIGNATURE,
        RECORD_NAME_TURKOJANCRYPTER,
        RECORD_NAME_UBUNTUCLANG,
        RECORD_NAME_UCEXE,
        RECORD_NAME_UNDERGROUNDCRYPTER,
        RECORD_NAME_UNDOCRYPTER,
        RECORD_NAME_UNICODE,
        RECORD_NAME_UNILINK,
        RECORD_NAME_UNIVERSALTUPLECOMPILER,
        RECORD_NAME_UNKOWNCRYPTER,
        RECORD_NAME_UNK_UPXLIKE,
        RECORD_NAME_UNOPIX,
        RECORD_NAME_UPX,
        RECORD_NAME_UTF8,
        RECORD_NAME_VALVE,
        RECORD_NAME_VBNET,
        RECORD_NAME_VCASMPROTECTOR,
        RECORD_NAME_VCL,
        RECORD_NAME_VCLPACKAGEINFO,
        RECORD_NAME_VERACRYPT,
        RECORD_NAME_VIRTUALIZEPROTECT,
        RECORD_NAME_VIRTUALPASCAL,
        RECORD_NAME_VISE,
        RECORD_NAME_VISUALBASIC,
        RECORD_NAME_VISUALCCPP,
        RECORD_NAME_VISUALCSHARP,
        RECORD_NAME_VISUALOBJECTS,
        RECORD_NAME_VMPROTECT,
        RECORD_NAME_VMUNPACKER,
        RECORD_NAME_VMWARE,
        RECORD_NAME_VPACKER,
        RECORD_NAME_WANGZEHUALLVM,
        RECORD_NAME_WATCOMC,
        RECORD_NAME_WATCOMCCPP,
        RECORD_NAME_WATCOMLINKER,
        RECORD_NAME_WAV,
        RECORD_NAME_WDOSX,
        RECORD_NAME_WHITELLCRYPT,
        RECORD_NAME_WINACE,
        RECORD_NAME_WINAUTH,
        RECORD_NAME_WINDOFCRYPT,
        RECORD_NAME_WINDOWSBITMAP,
        RECORD_NAME_WINDOWSICON,
        RECORD_NAME_WINDOWSINSTALLER,
        RECORD_NAME_WINGSCRYPT,
        RECORD_NAME_WINKRIPT,
        RECORD_NAME_WINRAR,
        RECORD_NAME_WINUPACK,
        RECORD_NAME_WINZIP,
        RECORD_NAME_WISE,
        RECORD_NAME_WIXTOOLSET,
        RECORD_NAME_WLCRYPT,
        RECORD_NAME_WLGROUPCRYPTER,
        RECORD_NAME_WOUTHRSEXECRYPTER,
        RECORD_NAME_WWPACK,
        RECORD_NAME_WWPACK32,
        RECORD_NAME_WXWIDGETS,
        RECORD_NAME_XAR,
        RECORD_NAME_XENOCODE,
        RECORD_NAME_XENOCODEPOSTBUILD,
        RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET,
        RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION,
        RECORD_NAME_XCOMP,
        RECORD_NAME_XML,
        RECORD_NAME_XPACK,
        RECORD_NAME_XTREMEPROTECTOR,
        RECORD_NAME_XTREAMLOK,
        RECORD_NAME_XVOLKOLAK,
        RECORD_NAME_XZ,
        RECORD_NAME_YANDEX,
        RECORD_NAME_YANO,
        RECORD_NAME_YODASCRYPTER,
        RECORD_NAME_YODASPROTECTOR,
        RECORD_NAME_YZPACK,
        RECORD_NAME_ZELDACRYPT,
        RECORD_NAME_ZIP,
        RECORD_NAME_ZLIB,
        RECORD_NAME_ZPROTECT,
        RECORD_NAME_UNKNOWN0,
        RECORD_NAME_UNKNOWN1,
        RECORD_NAME_UNKNOWN2,
        RECORD_NAME_UNKNOWN3,
        RECORD_NAME_UNKNOWN4,
        RECORD_NAME_UNKNOWN5,
        RECORD_NAME_UNKNOWN6,
        RECORD_NAME_UNKNOWN7,
        RECORD_NAME_UNKNOWN8,
        RECORD_NAME_UNKNOWN9
    };

    struct ID
    {
        QUuid uuid;
        XBinary::FT fileType;
        RECORD_FILEPART filePart;
        QString sVersion;
        QString sInfo;
        bool bVirtual;
    };

    // TODO flags(static scan/emul/heur)
    struct SCAN_STRUCT
    {
        qint64 nSize;
        qint64 nOffset;
        ID id;
        ID parentId;
        QString sArch;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        bool bIsHeuristic;
    };

    enum HEURTYPE
    {
        HEURTYPE_UNKNOWN=0,
        HEURTYPE_HEADER,
        HEURTYPE_ENTRYPOINT,
        HEURTYPE_OVERLAY,
        HEURTYPE_SECTIONNAME,
        HEURTYPE_IMPORTHASH,
        HEURTYPE_CODESECTION,
        HEURTYPE_ENTRYPOINTSECTION,
        HEURTYPE_NETANSISTRING,
        HEURTYPE_NETUNICODESTRING,
        HEURTYPE_RICH,
        HEURTYPE_ARCHIVE,
        HEURTYPE_RESOURCES
    };

    struct HEUR_RECORD
    {
        qint64 nOffset; // memory scan
        RECORD_FILEPART filepart;
        HEURTYPE heurType;
        QString sValue; // mb TODO variant
        quint32 nVariant;
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    struct SCAN_RESULT
    {
        qint64 nScanTime;
        QString sFileName;
        QList<SCAN_STRUCT> listRecords;
        QList<HEUR_RECORD> listHeurs;
    };

    struct _SCANS_STRUCT
    {
        qint64 nOffset;
        quint32 nVariant;
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        bool bIsHeuristic;
    };

    struct SCAN_RECORD
    {
        XBinary::FT fileType;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
    };

    struct BASIC_PE_INFO
    {
        quint32 nEntryPoint;
    };

    struct BASIC_INFO
    {
        qint64 nElapsedTime;
        ID parentId;
        ID id;
        qint64 nOffset;
        qint64 nSize;
        QString sHeaderSignature;
        XBinary::_MEMORY_MAP memoryMap;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapHeaderDetects;
        QList<SCAN_STRUCT> listDetects;
        bool bIsDeepScan;
        bool bIsHeuristicScan;
        bool bShowHeuristic;
        bool bIsUnknown;
        bool bIsTest;
        QList<HEUR_RECORD> listHeurs;
    };

    struct BINARYINFO_STRUCT
    {
        BASIC_INFO basic_info;

        bool bIsPlainText;
        bool bIsUTF8;
        XBinary::UNICODE_TYPE unicodeType;
        QString sHeaderText;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapTextHeaderDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTexts;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLanguages;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultArchives;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCertificates;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDebugData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultInstallerData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSFXData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultFormats;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDatabases;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultImages;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectorData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraryData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCOMPackers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCOMProtectors;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct DEXINFO_STRUCT
    {
        BASIC_INFO basic_info;

        QList<QString> listStrings;
        QList<QString> listTypeItemStrings;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
    };

    struct ZIPINFO_STRUCT
    {
        BASIC_INFO basic_info;

        QList<XArchive::RECORD> listArchiveRecords;

        bool bIsJAR=false;
        bool bIsAPK=false;
        bool bIsJava=false;
        bool bIsKotlin=false;

        DEXINFO_STRUCT dexInfoClasses;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapArchiveDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapMetainfosDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSigntools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLanguages;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultArchives;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultFormats;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultAPKProtectors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct MSDOSINFO_STRUCT
    {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDosExtenders;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPackers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSFX;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct ELFINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;

        bool bIs64;
        bool bIsBigEndian; // TODO move to basic

        QList<XELF::TAG_STRUCT> listTags;
        QList<QString> listLibraries;
        QList<QString> listComments;

        QList<XELF_DEF::Elf_Shdr> listSectionHeaders;
        QList<XELF_DEF::Elf_Phdr> listProgramHeaders;
        QList<XELF::SECTION_RECORD> listSectionRecords;

        qint32 nCommentSection;
        qint32 nStringTableSection;
        QByteArray baStringTable;

        XBinary::OFFSETSIZE osCommentSection;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapCommentSectionDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPackers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
    };

    struct LEINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;

        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct NEINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct MACHINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;
        QList<XMACH::COMMAND_RECORD> listCommandRecords;
        QList<XMACH::LIBRARY_RECORD> listLibraryRecords;
        QList<XMACH::SECTION_RECORD> listSectionRecords;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectors;
    };

    struct PEINFO_STRUCT
    {
        BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
        XMSDOS_DEF::IMAGE_DOS_HEADEREX dosHeader;
        XPE_DEF::S_IMAGE_FILE_HEADER fileHeader;
        union OPTIONAL_HEADER
        {
            XPE_DEF::IMAGE_OPTIONAL_HEADER32 optionalHeader32;
            XPE_DEF::IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        } optional_header;
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSectionHeaders;
        QList<XPE::SECTION_RECORD> listSectionRecords;
        QList<QString> listSectionNames;
        QList<XPE::IMPORT_HEADER> listImports;
        quint64 nImportHash64;
        quint32 nImportHash32;
        QList<quint32> listImportPositionHashes;
        XPE::EXPORT_HEADER exportHeader;
        QList<QString> listExportFunctionNames;
        QList<XPE::RESOURCE_RECORD> listResources;
        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
        QString sResourceManifest;
        XPE::RESOURCE_VERSION resVersion;
        XPE::CLI_INFO cliInfo;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapOverlayDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapImportDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapDotAnsiStringsDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapDotUnicodeStringsDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapCodeSectionDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointSectionDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapSectionNamesDetects;
//        QMap<RECORD_NAME,_SCANS_STRUCT> mapRichDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapResourcesDetects;

        qint32 nEntryPointSection;
        qint32 nResourceSection;
        qint32 nImportSection;
        qint32 nCodeSection;
        qint32 nDataSection;
        qint32 nConstDataSection;
        qint32 nRelocsSection;
        qint32 nTLSSection;
        QString sEntryPointSectionName;
        qint64 nEntryPointAddress;
        qint64 nImageBaseAddress;
        quint8 nMinorLinkerVersion;
        quint8 nMajorLinkerVersion;
        quint16 nMinorImageVersion;
        quint16 nMajorImageVersion;
        bool bIs64;
        bool bIsNetPresent;

        XBinary::OFFSETSIZE osHeader;
        XBinary::OFFSETSIZE osEntryPointSection;
        XBinary::OFFSETSIZE osCodeSection;
        XBinary::OFFSETSIZE osDataSection;
        XBinary::OFFSETSIZE osConstDataSection;
        XBinary::OFFSETSIZE osImportSection;
        XBinary::OFFSETSIZE osResourceSection;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLinkers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPETools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSigntools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultJoiners;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPackers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultInstallers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSFX;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultNETObfuscators;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultNETCompressors;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDongleProtection;

        QList<SCAN_STRUCT> listRecursiveDetects;
    };

    struct SCAN_OPTIONS
    {
        //        bool bEmulate;
        bool bRecursiveScan;
        bool bDeepScan;
        bool bHeuristicScan;
        bool bShowHeuristic;
        bool bResultAsXML;
        bool bResultAsJSON;
        bool bSubdirectories;
        bool bIsImage;
        bool bIsTest;
        XBinary::FT fileType; // Optional
    };

    struct UNPACK_OPTIONS
    {
        // PE/PE+
        bool bCopyOverlay;     // In
    };

    struct _BASICINFO
    {
        quint32 nVariant;
        const XBinary::FT fileType;
        const RECORD_TYPE type;
        const RECORD_NAME name;
        const char *pszVersion;
        const char *pszInfo;
    };

    struct SIGNATURE_RECORD
    {
        _BASICINFO basicInfo;
        const char *pszSignature;
    };

    struct STRING_RECORD
    {
        _BASICINFO basicInfo;
        const char *pszString;
    };

    struct PE_RESOURCES_RECORD
    {
        _BASICINFO basicInfo;
        bool bIsString1;
        const char *pszName1;
        quint32 nID1;
        bool bIsString2;
        const char *pszName2;
        quint32 nID2;
    };

    struct CONST_RECORD
    {
        _BASICINFO basicInfo;
        quint64 nConst1;
        quint64 nConst2;
    };

    struct MSRICH_RECORD
    {
        _BASICINFO basicInfo;
        quint16 nID;
        quint32 nBuild;
    };

    struct VCL_STRUCT
    {
        quint32 nValue;
        qint64 nOffset;
        bool bIs64;
    };

    struct VCL_PACKAGEINFO_MODULE
    {
        quint8 nFlags;
        quint8 nHashCode;
        QString sName;
    };

    struct VCL_PACKAGEINFO
    {
        quint32 nFlags;
        quint32 nUnknown;
        quint32 nRequiresCount;
        QList<VCL_PACKAGEINFO_MODULE> listModules;
    };

    struct VI_STRUCT
    {
        bool bIsValid;
        QString sVersion;
        QString sInfo;
    };

    explicit SpecAbstract(QObject *pParent=nullptr);

    static void scan(QIODevice *pDevice,SpecAbstract::SCAN_RESULT *pScanResult,qint64 nOffset,qint64 nSize,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,bool bInit=false,bool *pbIsStop=nullptr);

    static QString append(QString sResult,QString sString);
    static QString recordFilePartIdToString(RECORD_FILEPART id);
    static QString recordTypeIdToString(RECORD_TYPE id);
    static QString recordNameIdToString(RECORD_NAME id);
    static QString heurTypeIdToString(HEURTYPE id);

    static SpecAbstract::UNPACK_OPTIONS getPossibleUnpackOptions(QIODevice *pDevice,bool bIsImage); // TODO Check

    static QString _SCANS_STRUCT_toString(const _SCANS_STRUCT *pScanStruct);

    static QString createResultString(const SCAN_STRUCT *pScanStruct);
    static QString createResultString2(const SCAN_STRUCT *pScanStruct);
    static QString createFullResultString(const SCAN_STRUCT *pScanStruct);
    static QString createFullResultString2(const SCAN_STRUCT *pScanStruct);
    static QString createTypeString(const SCAN_STRUCT *pScanStruct);
    static SCAN_STRUCT createHeaderScanStruct(const SCAN_STRUCT *pScanStruct);

    static BINARYINFO_STRUCT getBinaryInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static MSDOSINFO_STRUCT getMSDOSInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static ELFINFO_STRUCT getELFInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static MACHINFO_STRUCT getMACHInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static LEINFO_STRUCT getLEInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static NEINFO_STRUCT getNEInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static PEINFO_STRUCT getPEInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static DEXINFO_STRUCT getDEXInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);
    static ZIPINFO_STRUCT getZIPInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset,bool *pbIsStop);

    static _SCANS_STRUCT getScansStruct(quint32 nVariant,XBinary::FT fileType,RECORD_TYPE type,RECORD_NAME name,QString sVersion,QString sInfo,qint64 nOffset);

    static void PE_handle_import(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Protection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_VMProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_VProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo); // TODO move to protection
    static void PE_handle_TTProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo); // TODO move to protection
    static void PE_handle_SafeengineShielden(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_tElock(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Armadillo(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Obsidium(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Themida(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_StarForce(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Petite(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_NETProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Microsoft(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Borland(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Watcom(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Tools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_PETools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_wxWidgets(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_GCC(QIODevice *pDevice,bool bIsImage,SpecAbstract::PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Signtools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Installers(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_SFX(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_PolyMorph(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_DongleProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_NeoLite(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_PrivateEXEProtector(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_VisualBasicCryptors(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_DelphiCryptors(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_Joiners(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static bool PE_isProtectionPresent(PEINFO_STRUCT *pPEInfo);
    static void PE_handle_UnknownProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_FixDetects(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_Recursive(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop);

    static void Binary_handle_Texts(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_COM(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Archives(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Certificates(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_DebugData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Formats(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Databases(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Images(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_InstallerData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_SFXData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_ProtectorData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_LibraryData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);

    static void Binary_handle_FixDetects(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);

    static void MSDOS_handle_Tools(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Borland(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Protection(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_SFX(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_DosExtenders(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Recursive(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop);

    static void ELF_handle_CommentSection(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_Tools(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_GCC(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_Protection(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_UnknownProtection(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);

    static void ELF_handle_FixDetects(QIODevice *pDevice,bool bIsImage,ELFINFO_STRUCT *pELFInfo);

    static void MACH_handle_Tools(QIODevice *pDevice,bool bIsImage,MACHINFO_STRUCT *pMACHInfo);
    static void MACH_handle_Protection(QIODevice *pDevice,bool bIsImage,MACHINFO_STRUCT *pMACHInfo);

    static void LE_handle_Microsoft(QIODevice *pDevice,bool bIsImage,LEINFO_STRUCT *pLEInfo);
    static void LE_handle_Borland(QIODevice *pDevice,bool bIsImage,LEINFO_STRUCT *pLEInfo);

    static void NE_handle_Borland(QIODevice *pDevice,bool bIsImage,NEINFO_STRUCT *pNEInfo);

    static void DEX_handle_Tools(QIODevice *pDevice,DEXINFO_STRUCT *pDEXInfo);

    static void Zip_handle_Microsoftoffice(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo);
    static void Zip_handle_OpenOffice(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo);
    static void Zip_handle_Metainfos(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo);
    static void Zip_handle_JAR(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop);
    static void Zip_handle_APK(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo);
    static void Zip_handle_Recursive(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop);
    static void Zip_handle_FixDetects(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo);

    static DEXINFO_STRUCT Zip_scan_DEX(QIODevice *pDevice,bool bIsImage,ZIPINFO_STRUCT *pZipInfo,SpecAbstract::SCAN_OPTIONS *pOptions,bool *pbIsStop,QString sFileName);

    static void updateVersion(QMap<RECORD_NAME,SCAN_STRUCT> *pMap,RECORD_NAME name,QString sVersion);
    static void updateInfo(QMap<RECORD_NAME,SCAN_STRUCT> *pMap,RECORD_NAME name,QString sInfo);
    static void updateVersionAndInfo(QMap<RECORD_NAME,SCAN_STRUCT> *pMap,RECORD_NAME name,QString sVersion,QString sInfo);

    static bool isScanStructPresent(QList<SpecAbstract::SCAN_STRUCT> *pListScanStructs,XBinary::FT fileType,RECORD_TYPE type,RECORD_NAME name,QString sVersion,QString sInfo);

    static bool checkVersionString(QString sVersion);
    static VI_STRUCT get_UPX_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_GCC_vi1(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize); // TODO Check
    static VI_STRUCT get_GCC_vi2(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT _get_GCC_string(QString sString);
    static VI_STRUCT get_WindowsInstaller_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_gold_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_TurboLinker_vi(QIODevice *pDevice,bool bIsImage);
    static VI_STRUCT get_Enigma_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_DeepSea_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_SmartAssembly_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_R8_marker_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_Go_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_ObfuscatorLLVM_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT _get_ObfuscatorLLVM_string(QString sString);
    static VI_STRUCT get_AndroidClang_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT _get_AndroidClang_string(QString sString);
    static VI_STRUCT _get_PlexClang_string(QString sString);
    static VI_STRUCT _get_UbuntuClang_string(QString sString);
    static VI_STRUCT _get_AlipayObfuscator_string(QString sString);
    static VI_STRUCT _get_wangzehuaLLVM_string(QString sString);
    static VI_STRUCT _get_ByteGuard_string(QString sString);
    static VI_STRUCT _get_TencentObfuscation_string(QString sString);
    static VI_STRUCT _get_HikariObfuscator_string(QString sString);
    static VI_STRUCT _get_ByteDanceSecCompiler_string(QString sString);
    static VI_STRUCT _get_DingbaozengNativeObfuscator_string(QString sString);
    static VI_STRUCT _get_SafeengineLLVM_string(QString sString);
    static VI_STRUCT _get_NagainLLVM_string(QString sString);
    static VI_STRUCT _get_iJiami_string(QString sString);
    static VI_STRUCT _get_AppleLLVM_string(QString sString);
    static VI_STRUCT _get_ApportableClang_string(QString sString);
    static VI_STRUCT _get_ARMAssembler_string(QString sString);
    static VI_STRUCT _get_ARMLinker_string(QString sString);
    static VI_STRUCT _get_ARMC_string(QString sString);
    static VI_STRUCT _get_ARMCCPP_string(QString sString);
    static VI_STRUCT _get_ARMNEONCCPP_string(QString sString);
    static VI_STRUCT _get_ARMThumbCCPP_string(QString sString);
    static VI_STRUCT _get_ARMThumbMacroAssembler_string(QString sString);
    static VI_STRUCT _get_ThumbC_string(QString sString);
    static VI_STRUCT _get_clang_string(QString sString);
    static VI_STRUCT _get_DynASM_string(QString sString);
    static VI_STRUCT _get_Delphi_string(QString sString);
    static VI_STRUCT _get_LLD_string(QString sString);
    static VI_STRUCT _get_SnapdragonLLVMARM_string(QString sString);
    static VI_STRUCT _get_NASM_string(QString sString);

    static VI_STRUCT _get_DelphiVersionFromCompiler(QString sString);

    static bool PE_isValid_UPX(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_x86Emul(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static VI_STRUCT PE_get_PECompact_vi(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static QList<VCL_STRUCT> PE_getVCLstruct(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize,bool bIs64);
    static VCL_PACKAGEINFO PE_getVCLPackageInfo(QIODevice *pDevice,bool bIsImage,QList<XPE::RESOURCE_RECORD> *pListResources);
    static SpecAbstract::_SCANS_STRUCT PE_getRichSignatureDescription(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo,quint32 nRichID);

    static QList<SCAN_STRUCT> mapToList(QMap<RECORD_NAME,SCAN_STRUCT> *pMapRecords);

    static SCAN_STRUCT scansToScan(BASIC_INFO *pBasicInfo,_SCANS_STRUCT *pScansStruct);

    static QByteArray _BasicPEInfoToArray(BASIC_PE_INFO *pInfo);
    static BASIC_PE_INFO _ArrayToBasicPEInfo(const QByteArray *pbaArray);

    static void memoryScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize,SpecAbstract::SIGNATURE_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);
    static void signatureScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QString sSignature,SIGNATURE_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);
    static void PE_resourcesScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QList<XPE::RESOURCE_RECORD> *pListResources,PE_RESOURCES_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);
    static void stringScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QList<QString> *pListStrings,STRING_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);
    static void constScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,quint64 nCost1,quint64 nCost2,CONST_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);
    static void MSDOS_richScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,quint16 nID,quint32 nBuild,MSRICH_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);

    static void archiveScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QList<XArchive::RECORD> *pListArchiveRecords,STRING_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);

    static void signatureExpScan(XBinary *pXBinary,XBinary::_MEMORY_MAP *pMemoryMap,QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,qint64 nOffset,SIGNATURE_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);

    static QList<_SCANS_STRUCT> MSDOS_richScan(quint16 nID,quint32 nBuild,MSRICH_RECORD *pRecords,int nRecordsSize,XBinary::FT fileType1,XBinary::FT fileType2,BASIC_INFO *pBasicInfo,HEURTYPE heurType);

    static QByteArray serializeScanStruct(SCAN_STRUCT scanStruct,bool bIsHeader=false);
    static SCAN_STRUCT deserializeScanStruct(QByteArray baData,bool *pbIsHeader=nullptr);

private:
    static bool PE_compareRichRecord(_SCANS_STRUCT *pResult,MSRICH_RECORD *pRecord,quint16 nID,quint32 nBuild,XBinary::FT fileType1,XBinary::FT fileType2);
    static void filterResult(QList<SCAN_STRUCT> *pListRecords,QSet<RECORD_TYPE> stRecordTypes);

protected:
    void _errorMessage(QString sErrorMessage);
    void _infoMessage(QString sInfoMessage);

signals:
    void errorMessage(QString sErrorMessage);
    void infoMessage(QString sInfoMessage);
};

#endif // SPECABSTRACT_H
