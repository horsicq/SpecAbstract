// copyright (c) 2017-2019 hors<horsicq@gmail.com>
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
#include "xpe.h"
#include "xelf.h"
#include "xmach.h"
#include "xzip.h"

class SpecAbstract : public QObject
{
    Q_OBJECT

public:
    enum RECORD_FILETYPE
    {
        RECORD_FILETYPE_UNKNOWN=0,
        RECORD_FILETYPE_BINARY,
        RECORD_FILETYPE_MSDOS,
        RECORD_FILETYPE_PE,
        RECORD_FILETYPE_PE32,
        RECORD_FILETYPE_PE64,
        RECORD_FILETYPE_ELF,
        RECORD_FILETYPE_ELF32,
        RECORD_FILETYPE_ELF64,
        RECORD_FILETYPE_MACH,
        RECORD_FILETYPE_MACH32,
        RECORD_FILETYPE_MACH64,
        RECORD_FILETYPE_TEXT,
//        RECORD_FILETYPE_JAR,
        RECORD_FILETYPE_APK
    };
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
        RECORD_TYPE_ARCHIVE,
        RECORD_TYPE_CERTIFICATE,
        RECORD_TYPE_COMPILER,
        RECORD_TYPE_CONVERTER,
        RECORD_TYPE_DATABASE,
        RECORD_TYPE_DEBUGDATA,
        RECORD_TYPE_DONGLEPROTECTION,
        RECORD_TYPE_DOSEXTENDER,
        RECORD_TYPE_FORMAT,
        RECORD_TYPE_GENERIC,
        RECORD_TYPE_IMAGE,
        RECORD_TYPE_INSTALLER,
        RECORD_TYPE_INSTALLERDATA,
        RECORD_TYPE_LIBRARY,
        RECORD_TYPE_LINKER,
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
        RECORD_NAME_ACTUALINSTALLER,
        RECORD_NAME_ADVANCEDINSTALLER,
        RECORD_NAME_ADVANCEDUPXSCRAMMBLER,
        RECORD_NAME_AFFILLIATEEXE,
        RECORD_NAME_AGAINNATIVITYCRYPTER,
        RECORD_NAME_AGILENET,
        RECORD_NAME_AHPACKER,
        RECORD_NAME_AHTEAMEPPROTECTOR,
        RECORD_NAME_AINEXE,
        RECORD_NAME_ALEXPROTECTOR,
        RECORD_NAME_ALIASOBJ,
        RECORD_NAME_ALLOY,
        RECORD_NAME_ANDPAKK2,
        RECORD_NAME_ANDROIDGRADLE,
        RECORD_NAME_ANSKYAPOLYMORPHICPACKER,
        RECORD_NAME_ANSLYMPACKER,
        RECORD_NAME_ANTIDOTE,
        RECORD_NAME_ARCRYPT,
        RECORD_NAME_ARJ,
        RECORD_NAME_ARMADILLO,
        RECORD_NAME_ARMPROTECTOR,
        RECORD_NAME_ASDPACK,
        RECORD_NAME_ASM,
        RECORD_NAME_ASPACK,
        RECORD_NAME_ASPROTECT,
        RECORD_NAME_ASSCRYPTER,
        RECORD_NAME_ASSEMBLYINVOKE,
        RECORD_NAME_AUTOIT,
        RECORD_NAME_AVASTANTIVIRUS,
        RECORD_NAME_AVERCRYPTOR,
        RECORD_NAME_AZPROTECT,
        RECORD_NAME_BABELNET,
        RECORD_NAME_BAMBAM,
        RECORD_NAME_BEROEXEPACKER,
        RECORD_NAME_BIOHAZARDCRYPTER,
        RECORD_NAME_BITROCKINSTALLER,
        RECORD_NAME_BITSHAPEPECRYPT,
        RECORD_NAME_BORLANDCPP,
        RECORD_NAME_BORLANDCPPBUILDER,
        RECORD_NAME_BORLANDDELPHI,
        RECORD_NAME_BORLANDDELPHIDOTNET,
        RECORD_NAME_BORLANDOBJECTPASCAL,
        RECORD_NAME_BREAKINTOPATTERN,
        RECORD_NAME_C,
        RECORD_NAME_CAB,
        RECORD_NAME_CARBON,
        RECORD_NAME_CAUSEWAY,
        RECORD_NAME_CCPP,
        RECORD_NAME_CEXE,
        RECORD_NAME_CIGICIGICRYPTER,
        RECORD_NAME_CIL,
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
        RECORD_NAME_CONFUSER,
        RECORD_NAME_CONFUSEREX,
        RECORD_NAME_CPP,
        RECORD_NAME_CREATEINSTALL,
        RECORD_NAME_CRINKLER,
        RECORD_NAME_CRUNCH,
        RECORD_NAME_CRYEXE,
        RECORD_NAME_CRYPTABLESEDUCATION,
        RECORD_NAME_CRYPTER,
        RECORD_NAME_CRYPTIC,
        RECORD_NAME_CRYPTOCRACKPEPROTECTOR,
        RECORD_NAME_CRYPTOOBFUSCATORFORNET,
        RECORD_NAME_CRYPTOZ,
        RECORD_NAME_CRYPTRROADS,
        RECORD_NAME_CVTOMF,
        RECORD_NAME_CVTPGD,
        RECORD_NAME_CVTRES,
        RECORD_NAME_CWSDPMI,
        RECORD_NAME_CYGWIN,
        RECORD_NAME_DEB,
        RECORD_NAME_DEEPSEA,
        RECORD_NAME_DEPACK,
        RECORD_NAME_DEX,
        RECORD_NAME_DJVU,
        RECORD_NAME_DIRTYCRYPTOR,
        RECORD_NAME_DMD32D,
        RECORD_NAME_DNGUARD,
        RECORD_NAME_DOS16M,
        RECORD_NAME_DOTFIXNICEPROTECT,
        RECORD_NAME_DOTFUSCATOR,
        RECORD_NAME_DOTNET,
        RECORD_NAME_DOTNETZ,
        RECORD_NAME_DROPBOX,
        RECORD_NAME_DVCLAL,
        RECORD_NAME_DYAMAR,
        RECORD_NAME_EAZFUSCATOR,
        RECORD_NAME_EMBARCADEROCPP,
        RECORD_NAME_EMBARCADEROCPPBUILDER,
        RECORD_NAME_EMBARCADERODELPHI,
        RECORD_NAME_EMBARCADERODELPHIDOTNET,
        RECORD_NAME_EMBARCADEROOBJECTPASCAL,
        RECORD_NAME_EMPTYFILE,
        RECORD_NAME_ENIGMA,
        RECORD_NAME_EPROT,
        RECORD_NAME_EXE32PACK,
        RECORD_NAME_EXECRYPT,
        RECORD_NAME_EXECRYPTOR,
        RECORD_NAME_EXEFOG,
        RECORD_NAME_EXEMPLARINSTALLER,
        RECORD_NAME_EXEPACK,
        RECORD_NAME_EXESAX,
        RECORD_NAME_EXESHIELD,
        RECORD_NAME_EXPORT,
        RECORD_NAME_EXPRESSOR,
        RECORD_NAME_EZIP,
        RECORD_NAME_FAKESIGNATURE,
        RECORD_NAME_FAKUSCRYPTOR,
        RECORD_NAME_FASM,
        RECORD_NAME_FASTFILECRYPT,
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
        RECORD_NAME_GKRIPTO,
        RECORD_NAME_GNULINKER,
        RECORD_NAME_GOASM,
        RECORD_NAME_GOLIATHNET,
        RECORD_NAME_GOLINK,
        RECORD_NAME_GOOGLE,
        RECORD_NAME_GPINSTALL,
        RECORD_NAME_GUARDIANSTEALTH,
        RECORD_NAME_GZIP,
        RECORD_NAME_H4CKY0UORGCRYPTER,
        RECORD_NAME_HACCREWCRYPTER,
        RECORD_NAME_HALVCRYPTER,
        RECORD_NAME_HIDEPE,
        RECORD_NAME_HMIMYSPACKER,
        RECORD_NAME_HMIMYSPROTECTOR,
        RECORD_NAME_HOUNDHACKCRYPTER,
        RECORD_NAME_HTML,
        RECORD_NAME_HXS,
        RECORD_NAME_IBMPCPASCAL,
        RECORD_NAME_ICRYPT,
        RECORD_NAME_ILASM,
        RECORD_NAME_IMPORT,
        RECORD_NAME_INFCRYPTOR,
        RECORD_NAME_INNOSETUP,
        RECORD_NAME_INSTALLANYWHERE,
        RECORD_NAME_INSTALLSHIELD,
        RECORD_NAME_IPBPROTECT,
        RECORD_NAME_JAR,
        RECORD_NAME_JAVA,
        RECORD_NAME_JAVACOMPILEDCLASS,
        RECORD_NAME_JDPACK,
        RECORD_NAME_JPEG,
        RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,
        RECORD_NAME_KBYS,
        RECORD_NAME_KGBCRYPTER,
        RECORD_NAME_KIAMSCRYPTOR,
        RECORD_NAME_KKRUNCHY,
        RECORD_NAME_KRATOSCRYPTER,
        RECORD_NAME_KRYPTON,
        RECORD_NAME_KUR0KX2TO,
        RECORD_NAME_LARP64,
        RECORD_NAME_LAYHEYFORTRAN90,
        RECORD_NAME_LAZARUS,
        RECORD_NAME_LCCLNK,
        RECORD_NAME_LCCWIN,
        RECORD_NAME_LHA,
        RECORD_NAME_LHASSFX,
        RECORD_NAME_LIGHTNINGCRYPTERPRIVATE,
        RECORD_NAME_LIGHTNINGCRYPTERSCANTIME,
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
        RECORD_NAME_MICROSOFTVISIO,
        RECORD_NAME_MICROSOFTVISUALSTUDIO,
        RECORD_NAME_MINGW,
        RECORD_NAME_MINKE,
        RECORD_NAME_MKFPACK,
        RECORD_NAME_MOLEBOX,
        RECORD_NAME_MOLEBOXULTRA,
        RECORD_NAME_MONEYCRYPTER,
        RECORD_NAME_MORPHNAH,
        RECORD_NAME_MORTALTEAMCRYPTER,
        RECORD_NAME_MORTALTEAMCRYPTER2,
        RECORD_NAME_MORUKCREWCRYPTERPRIVATE,
        RECORD_NAME_MPACK,
        RECORD_NAME_MPRESS,
        RECORD_NAME_MRUNDECTETABLE,
        RECORD_NAME_MSYS,
        RECORD_NAME_MSYS2,
        RECORD_NAME_MZ0OPE,
        RECORD_NAME_NAKEDPACKER,
        RECORD_NAME_NEOLITE,
        RECORD_NAME_NIDHOGG,
        RECORD_NAME_NME,
        RECORD_NAME_NOOBYPROTECT,
        RECORD_NAME_NORTHSTARPESHRINKER,
        RECORD_NAME_NOSTUBLINKER,
        RECORD_NAME_NOXCRYPT,
        RECORD_NAME_NPACK,
        RECORD_NAME_NSIS,
        RECORD_NAME_NSPACK,
        RECORD_NAME_OBFUSCAR,
        RECORD_NAME_OBFUSCATORNET2009,
        RECORD_NAME_OBJECTPASCAL,
        RECORD_NAME_OBSIDIUM,
        RECORD_NAME_OPENDOCUMENT,
        RECORD_NAME_OPENSOURCECODECRYPTER,
        RECORD_NAME_OPERA,
        RECORD_NAME_ORIEN,
        RECORD_NAME_OSCCRYPTER,
        RECORD_NAME_P0KESCRAMBLER,
        RECORD_NAME_PACKMAN,
        RECORD_NAME_PACKWIN,
        RECORD_NAME_PANDORA,
        RECORD_NAME_PCGUARD,
        RECORD_NAME_PDB,
        RECORD_NAME_PDBFILELINK,
        RECORD_NAME_PDF,
        RECORD_NAME_PEARMOR,
        RECORD_NAME_PEBUNDLE,
        RECORD_NAME_PECOMPACT,
        RECORD_NAME_PEENCRYPT,
        RECORD_NAME_PELOCK,
        RECORD_NAME_PEPACK,
        RECORD_NAME_PEPACKSPROTECT,
        RECORD_NAME_PEQUAKE,
        RECORD_NAME_PERL,
        RECORD_NAME_PESPIN,
        RECORD_NAME_PETITE,
        RECORD_NAME_PEX,
        RECORD_NAME_PFECX,
        RECORD_NAME_PHOENIXPROTECTOR,
        RECORD_NAME_PHP,
        RECORD_NAME_PICRYPTOR,
        RECORD_NAME_PKLITE,
        RECORD_NAME_PKLITE32,
        RECORD_NAME_PLAIN,
        RECORD_NAME_PMODEW,
        RECORD_NAME_PNG,
        RECORD_NAME_POKECRYPTER,
        RECORD_NAME_POLYCRYPTPE,
        RECORD_NAME_POWERBASIC,
        RECORD_NAME_PRIVATEEXEPROTECTOR,
        RECORD_NAME_PUBCRYPTER,
        RECORD_NAME_PUSSYCRYPTER,
        RECORD_NAME_PUREBASIC,
        RECORD_NAME_PYTHON,
        RECORD_NAME_QT,
        RECORD_NAME_QTINSTALLER,
        RECORD_NAME_QUICKPACKNT,
        RECORD_NAME_RAR,
        RECORD_NAME_RCRYPTOR,
        RECORD_NAME_RDGTEJONCRYPTER,
        RECORD_NAME_RENETPACK,
        RECORD_NAME_RESOURCE,
        RECORD_NAME_REVPROT,
        RECORD_NAME_PGMPAK,
        RECORD_NAME_RLP,
        RECORD_NAME_RLPACK,
        RECORD_NAME_ROSASM,
        RECORD_NAME_RTF,
        RECORD_NAME_SAFEENGINESHIELDEN,
        RECORD_NAME_SCPACK,
        RECORD_NAME_SDPROTECTORPRO,
        RECORD_NAME_SETUPFACTORY,
        RECORD_NAME_SHELL,
        RECORD_NAME_SIMBIOZ,
        RECORD_NAME_SIMCRYPTER,
        RECORD_NAME_SIMPLECRYPTER,
        RECORD_NAME_SIMPLEPACK,
        RECORD_NAME_SIXXPACK,
        RECORD_NAME_SKATER,
        RECORD_NAME_SMARTASSEMBLY,
        RECORD_NAME_SMARTINSTALLMAKER,
        RECORD_NAME_SMOKESCREENCRYPTER,
        RECORD_NAME_SNOOPCRYPT,
        RECORD_NAME_SOFTWARECOMPRESS,
        RECORD_NAME_SOFTWAREZATOR,
        RECORD_NAME_SPICESNET,
        RECORD_NAME_SQUEEZSFX,
        RECORD_NAME_STARFORCE,
        RECORD_NAME_STASFODIDOCRYPTOR,
        RECORD_NAME_SVKPROTECTOR,
        RECORD_NAME_TARMAINSTALLER,
        RECORD_NAME_TELOCK,
        RECORD_NAME_TGRCRYPTER,
        RECORD_NAME_THEBESTCRYPTORBYFSK,
        RECORD_NAME_THEMIDAWINLICENSE,
        RECORD_NAME_THEZONECRYPTER,
        RECORD_NAME_TOTALCOMMANDERINSTALLER,
        RECORD_NAME_TPPPACK,
        RECORD_NAME_TSTCRYPTER,
        RECORD_NAME_TTPROTECT,
        RECORD_NAME_TURBOC,
        RECORD_NAME_TURBOCPP,
        RECORD_NAME_TURBOLINKER,
        RECORD_NAME_TURKISHCYBERSIGNATURE,
        RECORD_NAME_TURKOJANCRYPTER,
        RECORD_NAME_UNICODE,
        RECORD_NAME_UNILINK,
        RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,
        RECORD_NAME_UNDERGROUNDCRYPTER,
        RECORD_NAME_UNDOCRYPTER,
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
        RECORD_NAME_VPACKER,
        RECORD_NAME_WATCOMC,
        RECORD_NAME_WATCOMCCPP,
        RECORD_NAME_WATCOMLINKER,
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
        RECORD_NAME_XENOCODE,
        RECORD_NAME_XENOCODEPOSTBUILD,
        RECORD_NAME_XENOCODEPOSTBUILD2009,
        RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009,
        RECORD_NAME_XCOMP,
        RECORD_NAME_XML,
        RECORD_NAME_XPACK,
        RECORD_NAME_XVOLKOLAK,
        RECORD_NAME_YANDEX,
        RECORD_NAME_YANO,
        RECORD_NAME_YODASCRYPTER,
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
        RECORD_FILETYPE filetype;
        RECORD_FILEPART filepart;
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
    };

    struct _SCANS_STRUCT
    {
        quint32 nVariant;
        RECORD_FILETYPE filetype;
        RECORD_TYPE type;
        RECORD_NAME name;
        QString sVersion;
        QString sInfo;
        qint64 nOffset;
    };

    struct SCAN_RECORD
    {
        RECORD_FILETYPE filetype;
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
        QMap<RECORD_NAME,_SCANS_STRUCT> mapHeaderDetects;
        QList<SpecAbstract::SCAN_STRUCT> listDetects;
        bool bIsDeepScan;
        bool bIsUnknown;
    };

    struct BINARYINFO_STRUCT
    {
        BASIC_INFO basic_info;

        bool bIsPlainText;
        bool bIsUTF8;
        XBinary::UNICODE_TYPE unicodeType;
        QString sHeaderText;

        bool bIsZip;
        QList<XArchive::RECORD> listArchiveRecords;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapTextHeaderDetects;

        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTexts;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultTools;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultArchives;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCertificates;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDebugData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultInstallerData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSFXData;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultFormats;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDatabases;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultImages;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultProtectorData;

        QList<SpecAbstract::SCAN_STRUCT> listRecursiveDetects;
    };

    struct MSDOSINFO_STRUCT
    {
        BASIC_INFO basic_info;
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

        QList<SpecAbstract::SCAN_STRUCT> listRecursiveDetects;
    };

    struct ELFINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;

        bool bIs64;
        bool bIsBigEndian;

        QList<XELF::TAG_STRUCT> listTags;
        QList<QString> listLibraries;

        QList<XELF_DEF::Elf_Shdr> listSectionHeaders;
        QList<XELF_DEF::Elf_Phdr> listProgramHeaders;
        QList<XELF::SECTION_RECORD> listSectionRecords;

        qint32 nCommentSection;
        qint32 nStringTableSection;
        QByteArray baStringTable;

        XBinary::OFFSETSIZE osCommentSection;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultCompilers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultLibraries;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPackers;
    };

    struct MACHINFO_STRUCT
    {
        BASIC_INFO basic_info;
        QString sEntryPointSignature;
        // TODO
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
        QList<XPE::SECTIONFILE_RECORD> listSectionRecords;
        QList<QString> listSectionNames;
        QList<XPE::IMPORT_HEADER> listImports;
        quint64 nImportHash64;
        quint32 nImportHash32;
        QList<quint32> listImportPositionHashes;
        XPE::EXPORT_HEADER exportHeader;
        QList<XPE::RESOURCE_RECORD> listResources;
        QList<XPE::RICH_RECORD> listRichSignatures;
        QString sResourceManifest;
        XPE::RESOURCE_VERSION resVersion;

        XPE::CLI_INFO cliInfo;

        QMap<RECORD_NAME,_SCANS_STRUCT> mapOverlayDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapEntryPointDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapImportDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapDotAnsistringsDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapDotUnicodestringsDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapSectionNamesDetects;
        QMap<RECORD_NAME,_SCANS_STRUCT> mapRichDetects;

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
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultPackers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultInstallers;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultSFX;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultNETObfuscators;
        QMap<RECORD_NAME,SCAN_STRUCT> mapResultDongleProtection;

        QList<SpecAbstract::SCAN_STRUCT> listRecursiveDetects;
    };

    struct SCAN_OPTIONS
    {
        //        bool bEmulate;
        bool bRecursive;
        bool bDeepScan;
        bool bResultAsXML;
        bool bResultAsJSON;
        bool bSubdirectories;
        bool bIsImage;
    };

    struct UNPACK_OPTIONS
    {
        // PE/PE+
        bool bCopyOverlay;     // In
    };

    struct _BASICINFO
    {
        quint32 nVariant;
        const RECORD_FILETYPE filetype;
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

    struct SCANMEMORY_RECORD
    {
        _BASICINFO basicInfo;
        const char *pData;
        int nSize;
    };

    struct RESOURCES_RECORD
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
        QString sVersion;
        QString sInfo;
    };

    explicit SpecAbstract(QObject *parent=nullptr);

    static void scan(QIODevice *pDevice, SpecAbstract::SCAN_RESULT *pScanResult, qint64 nOffset, qint64 nSize, SpecAbstract::ID parentId, SpecAbstract::SCAN_OPTIONS *pOptions,bool bInit=false);

    static QString append(QString sResult,QString sString);
    static QString recordFiletypeIdToString(RECORD_FILETYPE id);
    static QString recordFilepartIdToString(RECORD_FILEPART id);
    static QString recordTypeIdToString(RECORD_TYPE id);
    static QString recordNameIdToString(RECORD_NAME id);

    static SpecAbstract::UNPACK_OPTIONS getPossibleUnpackOptions(QIODevice *pDevice, bool bIsImage);

    static QString _SCANS_STRUCT_toString(const _SCANS_STRUCT *pScanStruct);

    static QString createResultString(const SCAN_STRUCT *pScanStruct);
    static QString createResultString2(const SCAN_STRUCT *pScanStruct);
    static QString createFullResultString(const SCAN_STRUCT *pScanStruct);
    static QString createFullResultString2(const SCAN_STRUCT *pScanStruct);
    static QString createTypeString(const SCAN_STRUCT *pScanStruct);
    static SCAN_STRUCT createHeaderScanStruct(const SCAN_STRUCT *pScanStruct);

    static QString findEnigmaVersion(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);

    static BINARYINFO_STRUCT getBinaryInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset);
    static MSDOSINFO_STRUCT getMSDOSInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset);
    static ELFINFO_STRUCT getELFInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset);
    static MACHINFO_STRUCT getMACHInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset);
    static PEINFO_STRUCT getPEInfo(QIODevice *pDevice,SpecAbstract::ID parentId,SpecAbstract::SCAN_OPTIONS *pOptions,qint64 nOffset);

    static _SCANS_STRUCT getScansStruct(quint32 nVariant,RECORD_FILETYPE filetype,RECORD_TYPE type,RECORD_NAME name,QString sVersion,QString sInfo,qint64 nOffset);

    static void PE_handle_import(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Protection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_VMProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_VProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_TTProtect(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_SafeengineShielden(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_CExe(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_tElock(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Armadillo(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Obsidium(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Themida(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_eXPressor(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_StarForce(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Petite(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_NETProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Microsoft(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Borland(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Watcom(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Tools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_PETools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_wxWidgets(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_GCC(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Signtools(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_Installers(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_SFX(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_PolyMorph(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_DongleProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_NeoLite(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_VisualBasicCryptors(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);
    static void PE_handle_DelphiCryptors(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_UnknownProtection(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_FixDetects(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static void PE_handle_Recursive(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo,SpecAbstract::SCAN_OPTIONS *pOptions);

    static void Binary_handle_Texts(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Archives(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Certificates(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_DebugData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Formats(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Databases(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_Images(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_InstallerData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_SFXData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_ProtectorData(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_MicrosoftOffice(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_OpenOffice(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);
    static void Binary_handle_JAR(QIODevice *pDevice, bool bIsImage, BINARYINFO_STRUCT *pBinaryInfo,SpecAbstract::SCAN_OPTIONS *pOptions);

    static void Binary_handle_FixDetects(QIODevice *pDevice,bool bIsImage,BINARYINFO_STRUCT *pBinaryInfo);

    static void MSDOS_handle_Tools(QIODevice *pDevice, bool bIsImage, MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Borland(QIODevice *pDevice, bool bIsImage, MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Protection(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_SFX(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_DosExtenders(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo);
    static void MSDOS_handle_Recursive(QIODevice *pDevice,bool bIsImage,MSDOSINFO_STRUCT *pMSDOSInfo,SpecAbstract::SCAN_OPTIONS *pOptions);

    static void ELF_handle_Tools(QIODevice *pDevice, bool bIsImage, ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_GCC(QIODevice *pDevice,bool bIsImage, ELFINFO_STRUCT *pELFInfo);
    static void ELF_handle_Protection(QIODevice *pDevice,bool bIsImage, ELFINFO_STRUCT *pELFInfo);

    static void MACH_handle_Tools(QIODevice *pDevice,bool bIsImage, MACHINFO_STRUCT *pMACHInfo);
    static void MACH_handle_Protection(QIODevice *pDevice,bool bIsImage, MACHINFO_STRUCT *pMACHInfo);

    static void updateVersion(QMap<RECORD_NAME,SCAN_STRUCT> *map,RECORD_NAME name,QString sVersion);
    static void updateInfo(QMap<RECORD_NAME,SCAN_STRUCT> *map,RECORD_NAME name,QString sInfo);
    static void updateVersionAndInfo(QMap<RECORD_NAME,SCAN_STRUCT> *map,RECORD_NAME name,QString sVersion,QString sInfo);

    static bool isScanStructPresent(QList<SpecAbstract::SCAN_STRUCT> *pList,RECORD_FILETYPE filetype,RECORD_TYPE type,RECORD_NAME name,QString sVersion,QString sInfo);

    static bool checkVersionString(QString sVersion);
    static VI_STRUCT get_UPX_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_GCC_vi1(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_GCC_vi2(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);
    static VI_STRUCT get_WindowsInstaller_vi(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize);

    static bool PE_isValid_UPX(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo);

    static QList<VCL_STRUCT> PE_getVCLstruct(QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize,bool bIs64);
    static VCL_PACKAGEINFO PE_getVCLPackageInfo(QIODevice *pDevice,bool bIsImage,QList<XPE::RESOURCE_RECORD> *pListResources);
    static SpecAbstract::_SCANS_STRUCT PE_getRichSignatureDescription(QIODevice *pDevice,bool bIsImage,PEINFO_STRUCT *pPEInfo,quint32 nRichID);

    static QList<SCAN_STRUCT> mapToList(QMap<RECORD_NAME,SCAN_STRUCT> *pMapRecords);
    //    static SCAN_STRUCT getScanStruct(QMap<RECORD_NAMES,SCANS_STRUCT> *pMapDetects,BASIC_INFO *pBasicInfo,RECORD_NAMES recordName);

    static SCAN_STRUCT scansToScan(BASIC_INFO *pBasicInfo,_SCANS_STRUCT *pScansStruct);

    static QByteArray _BasicPEInfoToArray(BASIC_PE_INFO *pInfo);
    static BASIC_PE_INFO _ArrayToBasicPEInfo(const QByteArray *pbaArray);

    static void memoryScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QIODevice *pDevice,bool bIsImage,qint64 nOffset,qint64 nSize,SpecAbstract::SCANMEMORY_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2); // TODO Check
    static void signatureScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QString sSignature,SIGNATURE_RECORD *pRecords,int nRecordsSize,RECORD_FILETYPE fileType1,RECORD_FILETYPE fileType2);
    static void resourcesScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QList<XPE::RESOURCE_RECORD> *pListResources,RESOURCES_RECORD *pRecords,int nRecordsSize,RECORD_FILETYPE fileType1,RECORD_FILETYPE fileType2); // TODO Check
    static void stringScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,QList<QString> *pListStrings,STRING_RECORD *pRecords,int nRecordsSize,RECORD_FILETYPE fileType1,RECORD_FILETYPE fileType2);
    static void constScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,quint64 nCost1,quint64 nCost2,CONST_RECORD *pRecords,int nRecordsSize,RECORD_FILETYPE fileType1,RECORD_FILETYPE fileType2);
    static void PE_richScan(QMap<RECORD_NAME,_SCANS_STRUCT> *pMapRecords,quint16 nID,quint32 nBuild,MSRICH_RECORD *pRecords,int nRecordsSize,RECORD_FILETYPE fileType1,RECORD_FILETYPE fileType2);

    static QByteArray serializeScanStruct(SCAN_STRUCT ssRecord,bool bIsHeader=false);
    static SCAN_STRUCT deserializeScanStruct(QByteArray baData,bool *pbIsHeader=nullptr);

protected:
    void _errorMessage(QString sMessage);
    void _infoMessage(QString sMessage);

signals:
    void errorMessage(QString sMessage);
    void infoMessage(QString sMessage);
};

#endif // SPECABSTRACT_H
