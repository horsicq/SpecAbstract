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

SpecAbstract::SIGNATURE_RECORD _binary_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INNOSETUP,                    "",                 "Install"},             "'idska32'1A"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INNOSETUP,                    "",                 "Install"},             "'zlb'1A"}, // TODO none
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INNOSETUP,                    "",                 "Uninstall"},           "'Inno Setup Messages'"},  // TODO check
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_CAB,                          "",                 ""},                    "'MSCF'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZLIB,                         "",                 "level 1(no/low)"},     "7801"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZLIB,                         "",                 "level 2-5"},           "785E"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZLIB,                         "",                 "level 6(default)"},    "789C"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZLIB,                         "",                 "level 7-9(best)"},     "78DA"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_7Z,                           "",                 ""},                    "'7z'BCAF271C"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ARJ,                          "",                 ""},                    "60EA"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_LHA,                          "",                 ""},                    "....'-lh'..2D"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_LHA,                          "",                 ""},                    "....'-lz'..2D"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_CERTIFICATE,      SpecAbstract::RECORD_NAME_WINAUTH,                      "2.0",              "PKCS #7"},             "........00020200"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DEBUGDATA,        SpecAbstract::RECORD_NAME_MINGW,                        "",                 ""},                    "'.file'000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DEBUGDATA,        SpecAbstract::RECORD_NAME_PDBFILELINK,                  "2.0",              ""},                    "'NB10'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DEBUGDATA,        SpecAbstract::RECORD_NAME_PDBFILELINK,                  "7.0",              ""},                    "'RSDS'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZIP,                          "",                 ""},                    "'PK'0304"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_ZIP,                          "",                 "Empty"},               "'PK'0506"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_PDF,                          "",                 ""},                    "'%PDF'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DATABASE,         SpecAbstract::RECORD_NAME_PDB,                          "2.00",             ""},                    "'Microsoft C/C++ program database 2.00\r\n'1A'JG'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DATABASE,         SpecAbstract::RECORD_NAME_PDB,                          "7.00",             ""},                    "'Microsoft C/C++ MSF 7.00\r\n'1A'DS'000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DATABASE,         SpecAbstract::RECORD_NAME_MICROSOFTLINKERDATABASE,      "",                 ""},                    "'Microsoft Linker Database\n\n'071A"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_GZIP,                         "",                 ""},                    "1F8B08"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_RAR,                          "1.4",              ""},                    "'RE~^'"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_RAR,                          "4.X-5.X",          ""},                    "'Rar!'1A07"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_AVASTANTIVIRUS,               "",                 ""},                    "'ASWsetupFPkgFil3'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_OPERA,                        "",                 ""},                    "'OPR7z'BCAF271C"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INSTALLANYWHERE,              "",                 ""},                    "5B3E"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_GHOSTINSTALLER,               "1.0",              "Xored MSCF, mask: 8D"},"C0DECECB8D8D8D8D"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_NSIS,                         "",                 ""},                    "EFBEADDE'Null'..'oftInst'"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_NSIS,                         "",                 ""},                    "EFBEADDE'nsisinstall'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_NSIS,                         "",                 "Install"},             "00000000EFBEADDE'NullsoftInst'"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_NSIS,                         "",                 "Uninstall"},           "01000000EFBEADDE'NullsoftInst'"},
    {{3, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_NSIS,                         "",                 "Install"},             "02000000EFBEADDE'NullsoftInst'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_FISHNET,                      "1.X",              ""},                    "0800'FISH_NET'0100"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_FISHNET,                      "1.X",              ""},                    "000800'FISH_NET'0100"},
    {{2, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_FISHNET,                      "1.X",              ""},                    "00000800'FISH_NET'0100"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_SMARTINSTALLMAKER,            "",                 ""},                    "'Smart Install Maker v'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_TARMAINSTALLER,               "",                 "zlib"},                "'tiz1'........78da'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_CLICKTEAM,                    "",                 ""},                    "'wwgT)'"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_CLICKTEAM,                    "",                 ""},                    "..120100....0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_SFXDATA,          SpecAbstract::RECORD_NAME_WINRAR,                       "",                 ""},                    "'***messages***'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INSTALLSHIELD,                "",                 ""},                    "'ISSetupStream'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_INSTALLSHIELD,                "",                 "PackageForTheWeb"},    "....0000dcedbd"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_SETUPFACTORY,                 "4.X-7.X",          ""},                    "E0E1E2E3E4E5E6"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_SETUPFACTORY,                 "8.X-9.X",          ""},                    "E0E0E1E1E2E2E3E3E4E4E5E5E6E6E7E7"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_SFXDATA,          SpecAbstract::RECORD_NAME_SQUEEZSFX,                    "",                 ""},                    "'SQ5SFX'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_SFXDATA,          SpecAbstract::RECORD_NAME_7Z,                           "",                 ""},                    "';!@Install@!UTF-8!'"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_SFXDATA,          SpecAbstract::RECORD_NAME_7Z,                           "",                 ""},                    "EFBBBF';!@Install@!UTF-8!'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_QTINSTALLER,                  "",                 ""},                    "'qres'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_MICROSOFTOFFICE,              "97-2003",          ""},                    "D0CF11E0A1B11AE1"},
    {{1, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_ADVANCEDINSTALLER,            "",                 ""},                    "2F30EE1F5E4EE51E"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_GPINSTALL,                    "",                 ""},                    "........'SPIS'1a'LH5'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_INSTALLERDATA,    SpecAbstract::RECORD_NAME_ACTUALINSTALLER,              "",                 ""},                    "....................'MSCF'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_IMAGE,            SpecAbstract::RECORD_NAME_JPEG,                         "",                 ""},                    "FFD8FFE0....'JFIF'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_IMAGE,            SpecAbstract::RECORD_NAME_PNG,                          "",                 ""},                    "89'PNG\r\n'1A0A........'IHDR'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_IMAGE,            SpecAbstract::RECORD_NAME_WINDOWSICON,                  "",                 ""},                    "00000100"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_IMAGE,            SpecAbstract::RECORD_NAME_WINDOWSBITMAP,                "",                 ""},                    "'BM'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DATABASE,         SpecAbstract::RECORD_NAME_MICROSOFTACCESS,              "",                 ""},                    "00010000'Standard Jet DB'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_DATABASE,         SpecAbstract::RECORD_NAME_MICROSOFTACCESS,              "2010",             ""},                    "00010000'Standard ACE DB'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP,    "",                 ""},                    "'ITSF'03000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_AUTOIT,                       "3.X",              "Compiled script"},     "A3484BBE986C4AA9"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_RTF,                          "",                 ""},                    "'{'5C'rtf'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_LUACOMPILED,                  "",                 ""},                    "1B'Lua'..000104040408"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_COFF,                         "",                 ""},                    "'!<arch>'0A2F"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_DEX,                          "",                 ""},                    "'dex\n'......00"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_IMAGE,            SpecAbstract::RECORD_NAME_DJVU,                         "",                 ""},                    "'AT&T'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_XENOCODE,                     "",                 ""},                    "'xvm'0001"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_JAVACOMPILEDCLASS,            "",                 ""},                    "CAFEBABE"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_MOLEBOXULTRA,                 "",                 ""},                    "'XOJUMANJ'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_1337EXECRYPTER,               "1",                ""},                    "60'*[S-P-L-I-T]*'60"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_1337EXECRYPTER,               "2",                ""},                    "'~SPLIT~'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_ARCHIVE,          SpecAbstract::RECORD_NAME_BZIP2,                        "",                 ""},                    "'BZh'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_ACTIVEMARK,                   "",                 ""},                    "00'TMSAMVOH"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_AGAINNATIVITYCRYPTER,         "",                 ""},                    "'<%*#%>'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_ARCRYPT,                      "",                 ""},                    "'@@##@@'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_NOXCRYPT,                     "",                 ""},                    "'|||'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_FASTFILECRYPT,                "",                 ""},                    "'(==#==)'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME,     "",                 ""},                    "'F3B14NVA'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_ZELDACRYPT,                   "",                 ""},                    "2F232F2B5C235C"}, // '/#/+\#\'
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_WOUTHRSEXECRYPTER,            "",                 ""},                    "'<%>'"},
    {{0, SpecAbstract::RECORD_FILETYPE_BINARY,  SpecAbstract::RECORD_TYPE_PROTECTORDATA,    SpecAbstract::RECORD_NAME_WLCRYPT,                      "",                 ""},                    "'[Crypted Key]'"},
};

// TODO MSDOS COM!

// MSDOS,NE,LE,PE
SpecAbstract::SIGNATURE_RECORD _MSDOS_linker_header_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_TURBOLINKER,                  "",                 ""},                    "'MZ'50000200000004000F00FFFF0000B80000000000000040001A000000000000000000000000000000000000000000000000000000000000000000....0000BA10000E1FB409CD21B8014CCD219090'This program must be run under Win'....'\r\n$'370000000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_TURBOLINKER,                  "",                 "Patched"},             "'MZ'............................................................................................................................BA10000E1FB409CD21B8014CCD219090'This program must be run under Win'....'\r\n$'370000000000"},
    {{1, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_TURBOLINKER,                  "",                 "MSDOS"},               "'MZ'........................................................FB..'jr'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "",                 ""},                    "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000....00000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.\r\r\n$'00000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_GENERICLINKER,                "",                 ""},                    "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.\r\r\n$'00000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "",                 "Patched"},             "'MZ'90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000....000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
};

SpecAbstract::SIGNATURE_RECORD _PE_header_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_FASM,                         "",                 ""},                    "'MZ'80000100000004001000FFFF00004001000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'This program cannot be run in DOS mode.\r\n$'0000000000000000'PE'0000"}, // TODO patched
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_DMD32D,                       "",                 ""},                    "'MZ'60000100000004001000FFFF0000FE0000001200000040000000000000000000000000000000000000000000000000000000000000000000000060000000'Requires Win32   $'161F33D2B409CD21B8014CCD2100'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_FORMAT,           SpecAbstract::RECORD_NAME_HXS,                          "",                 ""},                    "'MZ'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000'PE'00004C010200000000000000000000000000E00001200B010000000000000000000000000000000000000000000000000000000040000000000000"},
    {{1, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_NOSTUBLINKER,                 "",                 ""},                    "'MZ'....................................................................................................................40000000'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PRIVATEEXEPROTECTOR,          "1.90-1.95",        ""},                    "'MZ'90000300000004000000FFFF0000B80000000000000040000000000000000000000000000000000000000000000000000000000000000000000078000000BA10000E1FB409CD21B8014CCD219090'This program must be run under Win32\r\n$'37'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PRIVATEEXEPROTECTOR,          "1.7-1.8",          ""},                    "'MZ'50000200000004000F00FFFF0000B80000000000000040001A00000000000000000000000000000000000000000000000000000000000000000078000000BA10000E1FB409CD21B8014CCD219090'This program must be run under Win32\r\n$'37'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "0.1X-0.24",        ""},                    "'MZKERNEL32.DLL'0000'PE'0000........'UpackByDwing'"},
    {{1, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "0.24-0.32",        ""},                    "'MZKERNEL32.DLL'0000'LoadLibraryA'00000000'GetProcAddress'............................40000000"},
    {{2, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "0.33",             ""},                    "'MZLoadLibraryA'0000'PE'0000........'KERNEL32'"},
    {{3, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "0.36",             ""},                    "'MZLoadLibraryA'0000'PE'0000............................................'KERNEL32.DLL'"},
    {{4, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "0.37-0.399",       ""},                    "'MZKERNEL32.DLL'0000'PE'0000............................................'LoadLibraryA'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "0.71-0.97",        "Win32/exe"},           "'MZ'........................................................................................'Is Win32 EXE.'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "0.71-0.97",        "Win64/exe"},           "'MZ'........................................................................................'Is Win64 EXE.'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "0.71-0.97",        "Win32/dll"},           "'MZ'........................................................................................'Is Win32 DLL.'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "0.71-0.97",        "Win64/dll"},           "'MZ'........................................................................................'Is Win64 DLL.'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "1.27-2.12",        "Win32/exe"},           "'MZ'........................................................................................'Win32 .EXE.\r\n'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "1.27-2.12",        "Win64/exe"},           "'MZ'........................................................................................'Win64 .EXE.\r\n'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "1.27-2.12",        "Win32/dll"},           "'MZ'........................................................................................'Win32 .DLL.\r\n'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "1.27-2.12",        "Win64/dll"},           "'MZ'........................................................................................'Win64 .DLL.\r\n'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "1.27-2.12",        ".NET"},                "'MZ'........................................................................................'It'27's .NET EXE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_INSTALLER,        SpecAbstract::RECORD_NAME_INNOSETUP,                    "1.XX-5.1.X",       "Install"},             "'MZ'............................................................................................496E6E6F"}, // TODO Versions
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_INSTALLER,        SpecAbstract::RECORD_NAME_INNOSETUP,                    "",                 "Uninstall"},           "'MZ'............................................................................................496E556E"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ANDPAKK2,                     "0.18",             ""},                    "'MZ'00'ANDpakk2'00'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_GOLINK,                       "",                 ""},                    "'MZ'6c000100000002000000ffff000000000000110000004000000000000000'Win32 Program!\r\n$'b409ba0001cd21b44ccd2160000000'GoLink, GoAsm www.GoDevTool.com'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_GOLINK,                       "",                 ""},                    "'MZ'6c000100000002000000ffff000000000000110000004000000000000000'Win64 Program!\r\n$'b409ba0001cd21b44ccd2160000000'GoLink, GoAsm www.GoDevTool.com'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "2.0-2.4",          ""},                    "'MZ'40000100000002000000FFFF00000002000000000000400000....................CD21B44CCD21'packed by nspack$'40000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_LAYHEYFORTRAN90,              "",                 ""},                    "'MZ'....................................................................................................................6C030000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HMIMYSPROTECTOR,              "0.1",              ""},                    "'MZ'............................................................'hmimys'27's ProtectV0.1'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEPACKSPROTECT,               "2.3",              ""},                    "'MZ'............................................................'pepack'27's ProtectV2.3'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.00-1.20",        ""},                    "'MZ'....................................................................................................................600000000E1FBA0E00B409CD21B8014CCD21'Windows Program'0D0A24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.30-1.32",        ""},                    "'MZ'....................................................................................................................40000000'PE'00004C01....'FSG!'"},
    {{1, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.33-2.00",        ""},                    "'MZ'....................'PE'00004C01....'FSG!'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW10,                        "1.0",              ""},                    "'MZ'00000000000000000000'PE'00004C010200000000000000000000000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW11SE,                      "1.0",              ""},                    "'MZkernel32.dll'0000'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW11SE,                      "1.1-1.2",          ""},                    "'MZ'00000000000000000000'PE'00004C010200000000000000000000000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             ""},                    "'MZ'52C3'(C)BeRo!PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "0.23",             "farbraush"},           "'MZfarbrauschPE'"},
    {{1, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "",                 "conspiracy"},          "'MZconspiracyPE'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_QUICKPACKNT,                  "0.1",              ""},                    "'MZ'90EB010052E9........'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_GENERIC,                      "",                 ""},                    "'MZ'....................'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "1.1",              ""},                    "'MZ'40000100000002000400FFFF0200400000000E0000001C00000000000000'(c) UsAr 2oo6$'0EB409BA00001FCD21B8014CCD2140000000'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "1.2",              ""},                    "'MZ'52456083EC188BEC8BFC33C0648B4030780C8B400C8B701CAD8B4008EB098B403483C07C8B403CABE9........B409BA00001FCD21B8014CCD2140000000'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "2.0",              ""},                    "'MZKERNEL32'0000'PE'0000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_WATCOMLINKER,                 "",                 "WinNT/dll"},           "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'this is a Windows NT dynamic link library\r\n'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_WATCOMLINKER,                 "",                 "WinNT/RTL/dll"},       "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000900000000E1FBA0E00B409CD21B8014CCD21'this is a Windows NT (own RTL) dynamic link library\r\n'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_WATCOMLINKER,                 "",                 "WinNT/RTLexe"},        "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000900000000E1FBA0E00B409CD21B8014CCD21'this is a Windows NT character-mode (own RTL) executable\r\n'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_WATCOMLINKER,                 "",                 "WinNT/exe"},           "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'this is a Windows NT character-mode executable\r\n'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_WATCOMLINKER,                 "",                 "Win95/exe"},           "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000700000000E1FBA0E00B409CD21B8014CCD21'This is a Windows 95 executable\r\n'24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_STUB,             SpecAbstract::RECORD_NAME_VALVE,                        "",                 ""},                    "'MZ'............................................................................................................................'VLV'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_UNILINK,                      "",                 ""},                    "'MZ'....................................................'UniLink!'"},
};

SpecAbstract::SIGNATURE_RECORD _PE_entrypoint_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.59",             "exe"},                 "60E8000000005883E83D50"}, // mb TODO
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.60-0.69",        "exe"},                 "60E8........68........8BE88DBD........33DB033C248BF7"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.71-0.72",        "exe"},                 "60E80000000083CDFF31DB5E"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.71-0.72",        "dll"},                 "807C2408010F85........60E80000000083CDFF31DB5E"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.81-3.81+",       "exe"},                 "60BE........8DBE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.81-3.81+",       "dll"},                 "807C2408010F85........60BE........8DBE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "3.81+",            "exe"},                 "53565755488D35........488DBE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "3.81+",            "dll"},                 "48894C240848895424104C8944241880FA010F85........53565755488D35........488DBE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WWPACK32,                     "1.01-1.12",        ""},                    "53558be833dbeb60'\r\n\r\nWWPack32 decompression routine version '........'\r\n(c) 1998 Piotr Warezak and Rafal Wierzbicki\r\n\r\n'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_BORLANDCPP,                   "",                 ""},                    "EB10'fb:C++HOOK'90"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ANDPAKK2,                     "0.06",             ""},                    "60FCBE........BF........5783CDFF33C9F9EB05A402DB7505"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ANDPAKK2,                     "0.18",             ""},                    "FCBE........BF........5783CDFF33C9F9EB05A402DB7505"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASDPACK,                      "2.0",              ""},                    "8B442404565753E8CD010000C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_REVPROT,                      "0.1a",             ""},                    "E8........8B4C240CC701........C781................31C089411489411880A1..........C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_32LITE,                       "0.03a",            ""},                    "6006FC1E07BE........6A0468........68"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ACPROTECT,                    "2.0.X",            ""},                    "68........68........C3C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALEXPROTECTOR,                "1.0",              ""},                    "60E8000000005D81ED........E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALLOY,                        "4.X",              ""},                    "9C60E8........33C08BC483C0..938BE3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_GCC,                          "3.X-4.X",          "MinGW"},               "5589E583EC08C70424..000000FF15........E8....FFFF................55"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "0.X-1.X",          ""},                    "EB0668........C39C60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "2.9-3.7",          ""},                    "9C60E8000000005D"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "2.9-3.7",          ""},                    "4881ECC00000004883C4404889042448894C2408488954241048895C241848896C2420488974242848897C24304C894424384C894C24404C895424484C895C24504C896424584C896C24604C897424684C897C24704883EC40E8000000005D"}, // TODO version
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENIGMA,                       "1.2",              ""},                    "60E8000000005D83....81ED"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "1994",             ""},                    "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. '"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "1995",             ""},                    "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. '"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "2000",             ""},                    "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by Sybase, Inc. 1988-2000. All rights reserved'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "2002",             ""},                    "..................'Open Watcom C/C++32 Run-Time system. Portions Copyright (C) Sybase, Inc. 1988-2002'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "2002",             ""},                    "..................'Open Watcom C/C++32 Run-Time system. Portions Copyright (c) Sybase, Inc. 1988-2002'"}, // Check
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ORIEN,                        "",                 ""},                    "E95D010000CED1CE..'\r\n--------------------------------------------\r\n- ORiEN executable files protection system'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_VPACKER,                      "0.02.10",          ""},                    "60E8........C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ASPROTECT,                    "1.23-2.77",        ""},                    "6801......E801000000C3C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.0-1.2",          ""},                    "6068........B8........FF1068........50B8........FF10"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.4",              ""},                    "33C08BC068........68........E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.4",              ""},                    "EB01909068........68........E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PESPIN,                       "",                 ""},                    "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "",                 "Alt stub"},            "60E809000000..................33C95E870E"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "",                 ""},                    "BE........AD50FF7634EB7C4801"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_AHPACKER,                     "0.1",              ""},                    "6068........B8........FF10"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZBRR"},               "60BE........BF........FCB28033DBA4B302E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZBRS"},               "60BE........BF........FCAD8D1C07B0803BFB733BE8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZMA"},                "6068........68........68........E8........BE........B9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZBRR/dll"},           "837C2408010F85........60BE........BF........FCB28033DBA4B302E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZBRS/dll"},           "837C2408010F85........60BE........BF........FCAD8D1C07B0803BFB733BE8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             "LZMA/dll"},            "837C2408010F85........6068........68........68........E8........BE........B9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NPACK,                        "",                 ""},                    "833D........007505E9........C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.02",             ""},                    "60E8........6168........C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.03",             ""},                    "60E8........EB"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.04",             ""},                    "60B8........FFD0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "0.23 alpha 1",     ""},                    "BD........C74500........FF4D08C6450C05"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "0.23 alpha 2",     ""},                    "BD........C74500........B8........89450489455450C74510"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "0.23 alpha 3-4",   ""},                    "BD........C74500........B8........89450489455850C74510"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PACKMAN,                      "0.0.0.1",          ""},                    "60E800000000588D..........8D..........8D"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PACKMAN,                      "1.0",              ""},                    "60E8000000005B8D5BC6011B8B138D73146A08590116AD4975FA"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "2.4",              ""},                    "B8........60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "2.2-2.3",          ""},                    "B8........6A0068........64FF350000000064892500000000669C60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "2.3",              ""},                    "B8........68........64FF350000000064892500000000669C60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "1.3-1.4",          ""},                    "B8........669C60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "1.2",              ""},                    "669C60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEPACK,                       "0.99",             ""},                    "60E8000000005D83ED..80BD..........0F84........C685..........8BC52B..........89..........89"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEPACK,                       "1.0",              ""},                    "7400e9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_XCOMP,                        "0.97-0.98",        ""},                    "68........9C60E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_XPACK,                        "0.97-0.98",        ""},                    "68........9C60E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ABCCRYPTOR,                   "1.0",              ""},                    "68FF6424F0685858585890FFD4"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXE32PACK,                    "1.4X",             ""},                    "3BC07402"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_GENERIC,                      "",                 ""},                    "60"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SOFTWARECOMPRESS,             "1.2",              ""},                    "E9........608B7424248B7C2428FC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SOFTWARECOMPRESS,             "1.4 LITE",         ""},                    "E800000000812C24........5DE800000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SDPROTECTORPRO,               "1.1X",             ""},                    "558BEC6AFF68........688888880864A1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SIMPLEPACK,                   "1.0",              ""},                    "60E8000000005B8D5BFA"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NAKEDPACKER,                  "1.0",              ""},                    "60FC0FB605........85C075"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,"",                 ""},                    "60FC0FB605........85C075"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,"",                 "Modified"},            "FC0FB605........85C075"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "",                 ""},                    "60E8000000008B2C2483C404"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "",                 "dll"},                 "807C2408010F85........60E8000000008B2C2483C404"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "1.20.1",           ""},                    "57C7C7........8D3D"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLP,                          "0.7.4b",           ""},                    "68........E8........C3C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "ASPacker 2.12"},       "60E803000000E9EB045D4555C3E801"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "BJFNT 1.3"},           "EB033A4D3A1EEB02CD209CEB02CD20EB02CD2060"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "EXE Shield 0.3"},      "E8040000008360EB0C5DEB05"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "ExeCryptor 1.5.1"},    "E8240000008B4C240CC70117000100C781B80000000000000031C089411489411880A1C1000000FEC3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "PC-Guard 4.xx"},       "FC5550E8000000005DEB01E360E803000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "PEBundle 2.x"},        "9C60E802......33C08BC483C004938BE38B5BFC81EB........87DD"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "PEX 0.99"},            "60E8........E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "SVKP_1.x"},            "60E8........5D81ED06......64A023"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "Yoda's Crypter1.2"},   "60E8000000005D81ED........B9....00008DBD........8BF7"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "UPX 0.8x-1.2"},        "60BE........8DBE........5783"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "PECompact 1.4x"},      "EB06..........C39C60E80200000033C08BC483C004"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "PE-Lock Phantasm 1.0"},"5557565251536681C3EB02EBFC6681C3EB02EBFC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "Obsidium 1.3.0.4"},    "EB02....E825000000EB04........EB01..8B54240CEB01"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "Themida 1.8.0.0"},     "B8........600BC074..E8000000005805..0000008038E975"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FAKESIGNATURE,                "",                 "Visual Basic 5.0-6.0"},"6800000000E8........C0EB0F000000300000004000000000000000485858E9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EZIP,                         "1.0",              ""},                    "E9........E9........E9........E9........E9........E9........E9........E9........E9........E9........E9........CC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_PUREBASIC,                    "4.X",              ""},                    "68....0000680000000068......00E8......0083C40C6800000000E8......00A3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_LCCWIN,                       "1.X-3.X",          ""},                    "64A1........5589E56A..68........68........506489..........83EC..53565789"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.90",             ""},                    "....E802000000E800E8000000005E2B"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.92a",            ""},                    "E97EE9FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.95",             ""},                    "E9D5E4FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.96",             ""},                    "E959E4FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.98b1",           ""},                    "E925E4FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.98b2",           ""},                    "E91BE4FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.98",             "Special Build"},       "E999D7FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.99",             ""},                    "E95EDFFFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "0.99c",            ""},                    "E93FDFFFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "1.00",             ""},                    "E9E5E2FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "0.28 Beta",        ""},                    "60E8000000005E83EE0A8B0603C28B08894EF383EE0F56528BF0ADAD03C28BD86A04BF00100000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "0.28",             ""},                    "68........E801000000C3C3608B7424248B7C2428FCB28033DBA4"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "0.28",             ""},                    "B8........BA........03C2FFE0........60E800000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "0.28 Beta",        ""},                    "68........90B8........C3608B7424..8B7C24"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SAFEENGINESHIELDEN,           "",                 ""},                    "E8........53"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTOCRACKPEPROTECTOR,       "0.9.2",            ""},                    "E801000000E8585B81E300FFFFFF66813B4D5A753784DB75338BF303....813E504500007526"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTOCRACKPEPROTECTOR,       "0.9.3",            ""},                    "5B81E300FFFFFF66813B4D5A75338BF303733C813E5045000075260FB746188BC869C0AD0B0000F7E02DAB5D414B69C9DEC0000003C1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRUNCH,                       "1.0",              ""},                    "55E8000000005D83ED068BC55560"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MOLEBOXULTRA,                 "4.X",              ""},                    "5589E5E8........5DC3CC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.XX",             ""},                    "90589050908B00903C5090580F8567D6EF115068"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.1",              ""},                    "8B042483E84F68........FFD0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.3-1.4",          ""},                    "558BEC8B44240483E84F68........FFD0585950"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.3b",             ""},                    "6183EF4F6068........FFD7"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.5",              ""},                    "832C244F68........FF542404834424044F"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.6",              ""},                    "33D068........FFD2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.6b-1.6c",        ""},                    "8BC70304242BC78038500F851B8B1FFF68"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "1.6d",             ""},                    "60906161807FF04590600F851B8B1FFF68"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "2.0",              ""},                    "F7D183F1FF6A00F7D183F1FF810424........F7D183F1FF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.2",              ""},                    "8B0C24E90A7C01..AD4240BDBE9D7A04"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.3",              ""},                    "8B0C24E9C08D01..C13A6ECA5D7E796DB3645A71EA"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.4",              ""},                    "54E8000000005D8BC581ED........2B85........83E806"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.5",              ""},                    "54E8000000005D8BC581ED........2B85........EB"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SVKPROTECTOR,                 "1.3X-1.4X",        ""},                    "60E8000000005D81ED06000000EB05B8........64A023"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_THEBESTCRYPTORBYFSK,          "1.0",              ""},                    "EB06'VRULZ'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASCRYPTER,                 "1.X",              ""},                    "60E8000000005D81ED........B9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASCRYPTER,                 "1.3",              ""},                    "558BEC53565760E8000000005D81ED........B9"}, // 1.3??? TODO Check
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_TPPPACK,                      "",                 ""},                    "E8000000005D81ED"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FISHPESHIELD,                 "1.12-1.16",        ""},                    "60E8........FFD0C3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.2",              ""},                    "558BEC81EC....0000535657EB0C'ExPr-v.1.2.'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.3",              ""},                    "558BEC83EC..535657EB0C'ExPr-v.1.3.'"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.4.5.X",          ""},                    "558BEC83EC..5356578365..00F3EB0C'eXPr-v.1.4.'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.5.0.X",          ""},                    "558BEC81EC........53565783A5..........F3EB0C'eXPr-v.1.5.'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.6",              ""},                    "558BEC81EC........53565783A5..........F3EB0C'eXPr-v.1.6.'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BAMBAM,                       "0.1-0.4",          ""},                    "6A14E89A050000....5368........E86CFDFFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DOTFIXNICEPROTECT,            "2.1-2.5",          ""},                    "E9FF000000608B7424248B7C2428FCB28033DBA4B302E86D00000073F633C9E864000000731C33C0E85B0000007323B30241B010E84F00000012C073F7753FAAEBD4E84D0000002BCB7510E842000000EB28ACD1E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_JDPACK,                       "1.01",             ""},                    "60E8000000005D8BD581ED........2B95........81EA06......8995........83BD"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_JDPACK,                       "2.00",             ""},                    "558BEC6AFF68........68........64A1000000005064892500000000......E801000000"},
//    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VCASMPROTECTOR,               "1.0",              ""},                    "558BEC6AFF68........68........64A1000000005064892500000000E803000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VCASMPROTECTOR,               "1.X",              ""},                    "EB..'[VProtect]'00"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ADVANCEDUPXSCRAMMBLER,        "0.5",              ""},                    "B8........B9........803408..E2FAEB"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AZPROTECT,                    "0001",             ""},                    "EB70FC608C804D110070258100400D91BB608C804D11007021811D610D810040CE608C804D11007025812581258125812961418131611D610040B730"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WINKRIPT,                     "1.0",              ""},                    "33C08BB8........8B90........85FF74..33C950EB..8A0439C0C8..34..880439413BCA72..58"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.0",              ""},                    "BB........BF........BE........53E80A00000002D275058A164612D2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.31",             ""},                    "BE........BF........BB........53BB........B280"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.31",             ""},                    "BB........BF........BE........53BB........B280A4B680FFD373F9"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "1.33",             ""},                    "BE........AD93AD97AD5696B280A4B680FF1373"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "2.0",              ""},                    "8725......00619455A4B680FF13"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEBUNDLE,                     "",                 ""},                    "9C60E802......33C08BC483C004938BE38B5BFC81EB........87DD"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_BLADEJOINER,                  "1.5",              ""},                    "558BEC81C4E4FEFFFF53565733C08945F08985"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_NJOINER,                      "0.1",              ""},                    "6A0068........68........6A00E8140000006A00E813000000CCFF25........FF25........FF25........FF25"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_CELESTYFILEBINDER,            "1.0",              "C++ Dynamic library"}, "E896040000E963FDFFFF8BFF558BEC81EC28030000A3E8514000890DE45140008915E0514000891DDC5140008935D8514000893DD4514000668C1500"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_CELESTYFILEBINDER,            "1.0",              "C++ Static library"},  "E8261F0000E989FEFFFF8BFF558BEC83EC208B450856576A0859BE0C9240008D7DE0F3A58945F88B450C5F8945FC5E85C074"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PESHIELD,                     "0.25-0.26",        ""},                    "60E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_POLYCRYPTPE,                  "",                 ""},                    "60E8........EB"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PUNISHER,                     "1.5 demo",         ""},                    "EB0483A4BCCE60EB0480BC0411E800000000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SECURESHADE,                  "1.8",              ""},                    "558BEC81EC........535657BE........8D7D..8D45..A5A5A5A56A..50A4E8........8B1D........595968........FFD3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.2",              ""},                    "833D..........558BEC565775..68........E8........83....8B....A3........85F674..68"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.5",              ""},                    "833D..........558BEC565775..68........E8........83....8B....A3........85F674..83"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "1.0-1.1",          ""},                    "6033C08D480750E2FD8BEC648B4030780C8B400C"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HIDEANDPROTECT,               "1.016",            ""},                    "909090E9D8..050095..5300954A5000"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPACK,                        "0.0.3",            ""},                    "558BEC83....33C08945F0B8........E867C4FFFF33C05568........64FF306489208D55F033C0E893C8FFFF"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENCRYPTPE,                    "1.XX-2.XX",        ""},                    "609C64FF3500000000E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_EXEJOINER,                    "1.0",              ""},                    "68........6804010000E83903000005........C6005C680401000068"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "1.0b",             ""},                    "558BEC53565760E8000000005D81ED4C324000E803000000EB01"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "1.02-1.03",        ""},                    "E803000000EB01"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AVERCRYPTOR,                  "1.XX",             ""},                    "60E8000000005D81ED........8BBD........8B8D........B8"},
};

SpecAbstract::SIGNATURE_RECORD _PE_entrypointExp_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEX,                          "0.99",             ""},                    "E9$$$$$$$$60E8$$$$$$$$83C404E8"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PKLITE32,                     "1.1",              ""},                    "68........68........68........E8$$$$$$$$558BECA1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW10,                        "1.0",              ""},                    "33C0E9$$$$$$$$BE........AC91AD95AD92AD515687F297FCB2..33DBA4B3..FF55"},
};

SpecAbstract::CONST_RECORD _PE_importhash_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "",                 ""},                    0x134c8cd1e,    0x29188619},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ANDPAKK2,                     "0.18",             ""},                    0x134c8cd1e,    0x29188619},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "",                 ""},                    0x134c8cd1e,    0x29188619},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FSG,                          "",                 ""},                    0x0ee8cb83a,    0xa4083f58},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SCPACK,                       "0.2",              ""},                    0x184210a7f,    0x0faef25b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "1.XX-2.XX",        ""},                    0x1eb276f62,    0xdb8fbb75},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTOCRACKPEPROTECTOR,       "",                 ""},                    0xf8d21b48,     0x8137a62},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ACPROTECT,                    "1.XX-2.XX",        ""},                    0x26d690da0,    0x2301e49c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_AHPACKER,                     "0.1",              ""},                    0x263ed9b5a,    0x117f896a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASDPACK,                      "1.00",             ""},                    0x55706e12,     0xc7af1b6},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASDPACK,                      "2.00",             ""},                    0xc3068d5e,     0x3f603725},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.02",             ""},                    0x1eb276f62,    0xdb8fbb75},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.03",             ""},                    0x13e215a53,    0xdf3c1e0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW10,                        "1.0",              ""},                    0x13e215a53,    0x381aae8d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW11SE,                      "",                 ""},                    0x13e215a53,    0xdf3c1e0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "1.00",             ""},                    0x13e215a53,    0xdf3c1e0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEFOG,                       "1.1",              ""},                    0x13e215a53,    0xdf3c1e0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEFOG,                       "1.2",              ""},                    0x134c8cd1e,    0x29188619},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALEXPROTECTOR,                "1.0",              ""},                    0x1d6f34b26,    0x63fe4ff9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRUNCH,                       "1.0",              ""},                    0x90c17bc0b,    0x5e67bbdd},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALLOY,                        "4.X",              ""},                    0x6c83794a6,    0xc50dde33},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "",                 ""},                    0x347ecf0ec,    0x4acfe8ec},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DYAMAR,                       "1.3.5",            ""},                    0xb3de9edba,    0x9346ebcd},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEX,                          "0.99",             ""},                    0x312ac0c03,    0xbc79739a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_REVPROT,                      "0.1a",             ""},                    0x312ac0c03,    0xbc79739a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SVKPROTECTOR,                 "1.3X-1.4X",        ""},                    0x22234c932,    0xc8f3a96f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_TPPPACK,                      "",                 ""},                    0x3f288856,     0xb8a07cc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASCRYPTER,                 "1.X",              ""},                    0xa7382d76,     0x1303a51b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "1.0b",              ""},                    0xa7382d76,     0x1303a51b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FISHPESHIELD,                 "1.12-1.16",        ""},                    0xc485c9e2,     0xff2d65f9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.2",              ""},                    0x5b000b292,    0x66b35c6e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.2",              ""},                    0x6f561d023,    0x32f4466c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.3",              ""},                    0x5ca1becb0,    0x921d0280},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.3",              ""},                    0x7441e5986,    0xf51eba68},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.3",              ""},                    0x751f43a61,    0xbc84ce09},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.4.5.X",          ""},                    0x50b93d55a,    0x3c705cae},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.4.5.X",          ""},                    0x69e399a9b,    0x4d02e093}, // TODO Check
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.4.5.X",          ""},                    0x605d4706c,    0x958a9ea2}, // VB6
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.5.0.X",          ""},                    0x50b93d55a,    0x7ababb5a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.5.0.X",          ""},                    0x72af15d4f,    0x95ca15e4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.5.0.X",          ""},                    0x76a19e5a5,    0xbd41da20},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "1.6",              ""},                    0x5d589502a,    0xca58fa0c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,  "1.0",              ""},                    0x3404eaa9b,    0x3789c118},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,  "",                 ""},                    0x231271f8e,    0x986028bf},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BAMBAM,                       "0.1-0.4",          ""},                    0x241c3b6a6,    0x81a3d66b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DOTFIXNICEPROTECT,            "",                 ""},                    0x263ed9b5a,    0x117f896a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HMIMYSPROTECTOR,              "0.1",              ""},                    0x1db028dca,    0x50ca53fc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEPACKSPROTECT,               "2.3",              ""},                    0x1db028dca,    0x50ca53fc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_JDPACK,                       "1.01",             ""},                    0x240d976a2,    0x10c77c1b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NAKEDPACKER,                  "1.0",              ""},                    0x241c3b6a6,    0xbf363f04},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,"",                 ""},                    0x241c3b6a6,    0xbf363f04},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VCASMPROTECTOR,               "1.X",              ""},                    0x9c94674d4,    0x6d738d20},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.0-1.4",          ""},                    0x263ed9b5a,    0x117f896a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AFFILLIATEEXE,                "1.0",              "TEST"},                0xaad68a6e94,   0xe7046691},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LARP64,                       "1.0.3",            "TEST"},                0x1a89b5f0f,    0xf44517d8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_VPACKER,                      "0.02.10",          ""},                    0x3404eaa9b,    0x3789c118},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_XCOMP,                        "0.97-0.98",        ""},                    0x2f6afb438,    0xea1e66e4},
    //{{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "2.40-3.XX",        ""},                    0x1eb276f62,    0xdb8fbb75},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_THEMIDAWINLICENSE,            "",                 ""},                    0x16a45c345,    0x108edf16},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NPACK,                        "",                 ""},                    0x2d86e7bf1,    0xd0c4c278},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEPACK,                       "0.99",             ""},                    0x341f3f6e9,    0xeaf00a09},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PEPACK,                       "1.0",              ""},                    0x3be698dd2,    0x41708a45}, // 0.99?
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SIMPLEPACK,                   "1.0",              ""},                    0x42f4ff4ba,    0x00d0e26d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SIMPLEPACK,                   "1.11",             ""},                    0x385a630a6,    0xc1e807a4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SIMPLEPACK,                   "1.2-1.3",          ""},                    0x473022e77,    0xa9e261a2},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_XPACK,                        "0.97-0.98",        ""},                    0x22224caef,    0x2ac44dd2},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ORIEN,                        "",                 ""},                    0x16fde75ea,    0xb4923b63},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SDPROTECTORPRO,               "",                 ""},                    0x193d36193,    0xcde019bc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_HMIMYSPACKER,                 "",                 ""},                    0x27a6db491,    0xcee2ac8e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SOFTWARECOMPRESS,             "1.2-1.4",          ""},                    0x2b72496f4,    0x6bfc6671},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_32LITE,                       "0.03a",            ""},                    0x20953b667,    0xf053f402},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "1.16",             ""},                    0x286d926ce,    0x4f2ced58},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "1.17",             ""},                    0x1eb276f62,    0xdb8fbb75},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "1.19-1.21",        ""},                    0x231271f8e,    0x986028bf},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "1.20.1",           ""},                    0x286d926ce,    0x69e04866},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "1.1",              ""},                    0xb5ec8ac1,     0x54f51579},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "1.2",              ""},                    0x4eb19904,     0x48ea1201},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "2.0",              ""},                    0xc6f6fec9,     0x23333b97},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_QUICKPACKNT,                  "0.1",              ""},                    0x22224caef,    0x3778aab9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLP,                          "0.7.4b",           ""},                    0x193d36193,    0x30c63d98},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "0.90-0.91",        ""},                    0x186ad3682,    0xbea416d1},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "0.92-0.94",        ""},                    0x1917b3afe,    0x93312c2e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "0.97-0.971b",      ""},                    0x13e443f64,    0xe6aa8495},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "0.975-1.10b3",     ""},                    0x134c8cd1e,    0x29188619},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "1.10b7-1.34",      ""},                    0x212cf28ad,    0xe4c11305},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEBUNDLE,                     "",                 ""},                    0x778a92ee8,    0x6f2c367e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_BLADEJOINER,                  "1.5",              ""},                    0x1a905fabfb,   0x05877992},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_CELESTYFILEBINDER,            "1.0",              "C++ Dynamic library"}, 0x2625a9db1f,   0x7c76448a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_CELESTYFILEBINDER,            "1.0",              "C++ Static library"},  0x245138f5a4,   0x8a50a75e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PESHIELD,                     "0.25-0.26",        ""},                    0x16410b804,    0xf922f724},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_POLYCRYPTPE,                  "",                 ""},                    0x2870982b,     0x15bfcac8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PUNISHER,                     "1.5 demo",         ""},                    0x1f9e3b7a1,    0x12e15bcc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SECURESHADE,                  "1.8",              ""},                    0x8c9f7bdc8,    0x21ce458d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_INQUARTOSOBFUSCATOR,          "",                 ""},                    0x1046a0029,    0xf3f52749},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "",                 ""},                    0x1046a0029,    0xf3f52749},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_NJOINER,                      "0.1",              ""},                    0x76b28c3da,    0x8c42943c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HIDEANDPROTECT,               "1.016",            ""},                    0x26ff222837,   0xb136eb55},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPACK,                        "0.0.3",            ""},                    0x1d07e94aa3,   0x5c0a3750},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENCRYPTPE,                    "1.XX-2.XX",        ""},                    0x4d37b2166,    0x556688b8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENCRYPTPE,                    "2.XX",             ""},                    0x4e0ec6281,    0x87857386},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_JOINER,           SpecAbstract::RECORD_NAME_EXEJOINER,                    "1.0",              ""},                    0x6704c9452,    0x29aaa397},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_XTREMEPROTECTOR,              "1.06",             "TEST"},                0x12261bcdc,    0xa8689d85},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_CEXE,                         "1.0",              ""},                    0xcda93f5a0,    0x6ad5f3a1},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_CEXE,                         "1.0",              ""},                    0xd97446c35,    0x95065b94},
    // VB cryptors
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARCRYPT,                      "",                 ""},                    0x608b5ca5f,    0x27f8d01f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AGAINNATIVITYCRYPTER,         "",                 ""},                    0x21bae50da1,   0xab934456},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WINGSCRYPT,                   "1.0",              "TEST"},                0x216906261a,   0x86d73370},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTRROADS,                  "1.0",              "TEST"},                0x216906261a,   0x86d73370},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TSTCRYPTER,                   "1.0",              "TEST"},                0x216906261a,   0x86d73370},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TURKOJANCRYPTER,              "1.0",              "TEST"},                0x216906261a,   0x86d73370},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WHITELLCRYPT,                 "",                 "TEST"},                0x27e360241a,   0x69740a38},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MORTALTEAMCRYPTER2,           "",                 "TEST"},                0x27e360241a,   0x69740a38},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PUSSYCRYPTER,                 "1.0",              "TEST"},                0x27e360241a,   0x69740a38},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ZELDACRYPT,                   "1.0",              ""},                    0x27e360241a,   0xffacb503},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_BIOHAZARDCRYPTER,             "",                 "TEST"},                0x341d510008,   0x4c51ceec},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTABLESEDUCATION,          "1.0",              ""},                    0x379caa9586,   0x497a33ab},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTIC,                      "2.1",              ""},                    0x2551095bcf,   0x28ee87cc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTOZ,                      "3",                "TEST"},                0x32a797d70b,   0x9ce9bc9d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DIRTYCRYPTOR,                 "",                 "TEST"},                0x2d5043f921,   0x1278f5f4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KIAMSCRYPTOR,                 "1.4",              "TEST"},                0x2d5043f921,   0x1278f5f4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FAKUSCRYPTOR,                 "1.4",              "TEST"},                0x1c5896cc05,   0x660aa806},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FASTFILECRYPT,                "1.6",              ""},                    0x54fe70e1c,    0x12125e9a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FILESHIELD,                   "1.0",              "TEST"},                0x369ad56c1b,   0x907d472a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_GHAZZACRYPTER,                "1.0",              ""},                    0x2de302f688,   0x1d13438c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_H4CKY0UORGCRYPTER,            "",                 "TEST"},                0x68ec019f4,    0x182303e5},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HACCREWCRYPTER,               "",                 "TEST"},                0x3161aded4d,   0x02d8fada},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HALVCRYPTER,                  "",                 "TEST"},                0x3c92864a7,    0x1921b4b9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KGBCRYPTER,                   "1.0",              "TEST"},                0x8fdee2084,    0x12e6f129},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRATOSCRYPTER,                "",                 "TEST"},                0xFFFFFFFFFF,   0xFFFFFFFF}, // TODO
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KUR0KX2TO,                    "",                 "TEST"},                0x36d46acf30,   0xcf3805f3},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LIGHTNINGCRYPTERPRIVATE,      "1.0",              "TEST"},                0x25a8480de5,   0x208c1618},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME,     "1.0",              ""},                    0x24bfbff151,   0xea84dab2},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LUCYPHER,                     "1.1",              "TEST"},                0x202da672fb,   0x3343405e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MONEYCRYPTER,                 "1.0",              "TEST"},                0x353acba6b3,   0x53908533},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_NOXCRYPT,                     "1.1",              ""},                    0x36d2a71d08,   0x9b536657},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RDGTEJONCRYPTER,              "0.1",              "TEST"},                0xFFFFFFFFFF,   0xFFFFFFFF}, // TODO
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RDGTEJONCRYPTER,              "0.8",              "TEST"},                0x2c078d7e86,   0x3c328f0c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SMOKESCREENCRYPTER,           "2.0",              "TEST"},                0x87606a2bd,    0xcfe4cd48},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SNOOPCRYPT,                   "1.0",              "TEST"},                0x8bb735ad5,    0x22823ed8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_STASFODIDOCRYPTOR,            "1.0",              "TEST"},                0x339880106,    0xe8805018},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TURKISHCYBERSIGNATURE,        "1.0",              "TEST"},                0x216ef51472,   0xfaacabe5},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_UNDOCRYPTER,                  "1.0",              "TEST"},                0x37b90cd5a,    0xaab92c4c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WLCRYPT,                      "1.0",              ""},                    0xeaeea9a42,    0x0f0642ae},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WOUTHRSEXECRYPTER,            "1.0",              ""},                    0x1d8a9e5e20,   0xc9e08d88},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ROGUEPACK,                    "1.1",              "TEST"},                0xbb132a76d,    0xe23394a8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ROGUEPACK,                    "3.3.1",            "TEST"},                0x855d9788c,    0x96ed2351},
    // Delphi cryptors
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ASSCRYPTER,                   "1.0",              "TEST"},                0x12d94ca858,   0x36fb88c9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AASE,                         "1.0",              ""},                    0xc06abc0fa,    0x77035a90},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ANSKYAPOLYMORPHICPACKER,      "1.3",              ""},                    0x120bc5fc6c,   0x50822fc0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ANSLYMPACKER,                 "",                 "TEST"},                0xaf2e74867b,   0x51a4c42b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CIGICIGICRYPTER,              "1.0",              ""},                    0x12998dbdd9,   0xf75643a6},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FEARZCRYPTER,                 "1.0",              ""},                    0x18fc31e7a1,   0xba67afd7},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FEARZPACKER,                  "0.3",              ""},                    0xbeb44c9f3,    0xf7a7ee23},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_GKRIPTO,                      "1.0",              "TEST"},                0x105df99f74,   0x2d62ed5d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HOUNDHACKCRYPTER,             "1.0.4",            "TEST"},                0xc4b2710d8,    0x6c4aee3f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ICRYPT,                       "1.0",              ""},                    0x151f5b424a,   0xdc6b4478},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_INFCRYPTOR,                   "",                 "TEST"},                0x14921fe579,   0x06dfef0b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_UNDERGROUNDCRYPTER,           "1.0",              ""},                    0x14921fe579,   0x06dfef0b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MALPACKER,                    "1.2",              "TEST"},                0xd0983ca0a,    0xb82a3f7c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MINKE,                        "1.01",             "TEST"},                0x161bc831e3,   0xb1440658},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_OPENSOURCECODECRYPTER,        "1.0",              "TEST"},                0x1e843722ad,   0x6061e509},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MORTALTEAMCRYPTER,            "",                 "TEST"},                0x1e843722ad,   0x6061e509},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MORUKCREWCRYPTERPRIVATE,      "",                 "TEST"},                0x1e843722ad,   0x6061e509},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MRUNDECTETABLE,               "1.0",              "TEST"},                0x149b74637d,   0x2b12c49f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_NIDHOGG,                      "1.0",              "TEST"},                0xda5d3bb1f,    0xa52e27cc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_NME,                          "1.1",              "TEST"},                0x84313106b,    0x8d73a5b4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_OSCCRYPTER,                   "",                 "TEST"},                0x1e67f9aa68,   0xc45e88cf},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_P0KESCRAMBLER,                "1.2",              "TEST"},                0x14017ccc57,   0x6766361e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PANDORA,                      "1.0",              "TEST"},                0x1aa111e7ea,   0x5ee89fbb},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PFECX,                        "0.1",              ""},                    0x37c8dbb1e7,   0x161cb3f4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PICRYPTOR,                    "3.0",              ""},                    0x22d7f64fb1,   0xfcde90f0},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_POKECRYPTER,                  "",                 "TEST"},                0x3abfae0702,   0xb99acbcc},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PUBCRYPTER,                   "",                 "TEST"},                0xFFFFFFFFFF,   0xFFFFFFFF}, // TODO
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SEXECRYPTER,                  "1.1",              "TEST"},                0x144c4ac3f1,   0xb1309fe4},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SIMCRYPTER,                   "",                 "TEST"},                0x10c6960150,   0x3070a531},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SIMPLECRYPTER,                "1.2",              "TEST"},                0x23932eb2ab,   0x01e5337f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TGRCRYPTER,                   "1.0",              "TEST"},                0x1a0adc8c41,   0xc26df3a5},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_THEZONECRYPTER,               "",                 "TEST"},                0x316e900676,   0x67850921},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_UNKOWNCRYPTER,                "1.0",              ""},                    0x19d3b4b92a,   0xeb51c252},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WINDOFCRYPT,                  "1.0",              ""},                    0x124c114b87,   0xf7c9cbe1},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WLGROUPCRYPTER,               "",                 ""},                    0x13bf0f6720,   0xb0f58a0d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DCRYPTPRIVATE,                "0.9b",             "TEST"},                0xde741440ed,   0x16bbbe82},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DALKRYPT,                     "1.0",              "TEST"},                0xde741440ed,   0x16bbbe82},
    // Armadillo
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX-2.XX",        ""},                    0x2973050b33,   0x1a0c885c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX-2.XX",        ""},                    0x2f2f1df1d1,   0x8623cf54},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.XX-3.XX",        ""},                    0x3010e1d59e,   0x834a7ecf}, // Check
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.XX-3.XX",        ""},                    0x48c1ac32d5,   0x3f2559bb}, // MSVCRT.dll
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.50Beta3",        ""},                    0x31f48f8367,   0x59d53246},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.51",             ""},                    0x32bbf3aafe,   0x5a037362}, // 2.51 28Feb2002
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX-2.XX",        ""},                    0x32c7a9336f,   0x6762fc6d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.52",             ""},                    0x341358d6d9,   0xb256a26f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX-2.XX",        ""},                    0x35e237026a,   0x419bf128},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.52",             ""},                    0x3606885219,   0x1d8a69ae}, // 2.52 05Apr2002 (Build 1164)
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.52",             ""},                    0x3606885219,   0x15114198}, // 2.52 05Apr2002
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.74-1.84",        ""},                    0x3635cf517b,   0xe6ce8a9e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX",             ""},                    0x3b258f0a90,   0xe4bcc578},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.XX",             ""},                    0x3b6c8abc7b,   0x604ac20f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.90",             ""},                    0x3b6e96f260,   0x927ddbdb},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "1.91c",            ""},                    0x3c61329b29,   0x7177627b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.00",             ""},                    0x3c61329b29,   0x412e26ca},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.53",             ""},                    0x3d32f719da,   0x9de5348d}, // 2.53 15May2002 (Build 1232)
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.XX-3.XX",        ""},                    0x3d983cd830,   0xa61b1778},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.60",             ""},                    0x3fa882c0da,   0xaece7e99}, // 2.60 30Jul2002 (Build 1312)
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.60c",            ""},                    0x404c97c5fa,   0x4470cea0}, // 2.60c 17Aug2002 (Build 1431)
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.XX-3.XX",        ""},                    0x3fb526760f,   0x72359c40},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "2.XX-3.XX",        ""},                    0x3fb526760f,   0xf9f173fb},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.00-3.10",        ""},                    0x40666b9f00,   0x64c37e91},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.05",             ""},                    0x43d1d2c52f,   0xac05a698}, // 3.05 06Jun2003
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.30a",            ""},                    0x43d1d2c52f,   0x82883188},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.40",             ""},                    0x4518d21e36,   0xff5cf01b}, // 3.40 21Oct2003
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.60",             ""},                    0x4518d21e36,   0x228301a9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.61",             ""},                    0x4518d21e36,   0xb79df9fe},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.70",             ""},                    0x4518d21e36,   0x774538e7},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.75 Beta-1.3",    ""},                    0x4580f4b95c,   0x363baa89},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.75a",            ""},                    0x4610da601a,   0x5a7b25e5},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.76a",            ""},                    0x4b5345e36c,   0x5f6ae2cf},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.76",             ""},                    0x4c0ed4e9ea,   0x251722e7},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.78",             ""},                    0x4c0ed4e9ea,   0xccda289c},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "3.78",             ""},                    0x4bdf485221,   0x21ff4a57}, // 3.78 22Sep2004
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.20",             ""},                    0x4fc78bc010,   0x047e53e2}, // 4.20 23May2005
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.00-4.40",        ""},                    0x4fc78bc010,   0x807db698},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.42-4.54",        ""},                    0x508175d00e,   0xb50f60e8},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.48",             ""},                    0x508175d00e,   0xb034772c}, // 4.48 14August2006
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.66",             ""},                    0x508175d00e,   0x5ca4890e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.66",             ""},                    0x508175d00e,   0x1a14aa82},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "4.66",             ""},                    0x506972b7dd,   0xd09a4dc7},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.02",             ""},                    0x56fa69e1fe,   0xdb61d809},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.02",             ""},                    0x56e266c9cd,   0xd756b3c1}, // 5.02 11-07-2007
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.20Beta1",        ""},                    0x5670adeaf6,   0x1e178fd2},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.20",             ""},                    0x5670adeaf6,   0xc791b70b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.20",             ""},                    0x56698f2e57,   0x56b916d1}, // 5.20 30-10-2007
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.40",             ""},                    0x56fa69e1fe,   0x7b44517b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "5.42",             ""},                    0x56fa69e1fe,   0x503225ce}, // 5.42 20-02-2008
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.00Beta1",        ""},                    0x56fa69e1fe,   0xf35bbfc1},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.00",             ""},                    0x57770751cb,   0xd8505c97},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.04",             ""},                    0x57770751cb,   0x65f6ce6f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.60-7.00",        ""},                    0x5cee9acb73,   0xa6f43b6d},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.24",             ""},                    0x600594c96e,   0xad072543}, // 6.24 02-12-2008
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.40",             ""},                    0x5f7a50e70b,   0x0ecbdf27},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.40",             ""},                    0x5f7a50e70b,   0xae4aa460}, // 6.40 11-02-2009
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "6.60-7.00",        ""},                    0x5d069de3a4,   0x34512142},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "7.20",             ""},                    0x79deb2e3e4,   0x2a3627b7},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ARMADILLO,                    "8.60",             ""},                    0x263ed9b5a,    0x804c7692},
};

SpecAbstract::CONST_RECORD _PE_importpositionhash_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.59-1.93",        ""},                    0,              0x29188619}, // TODO !!! // 0.59-0.93 exe
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "0.94-1.93",        "exe"},                 0,              0xe6aa8495},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "1.94-2.03",        "exe"},                 0,              0xe28a6a4f},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "1.94-2.03",        "dll"},                 0,              0x3778aab9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "2.90-3.XX",        "exe"},                 0,              0x7bc87a20},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "2.90-3.XX",        "dll"},                 0,              0x5d22f587},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "3.91+",            "dll"},                 0,              0x5d22f587}, // TODO Check!
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "3.91+",            "exe"},                 0xFFFFFFFF,     0xc0d43f71},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "3.91+",            "dll"},                 0xFFFFFFFF,     0x3778aab9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "",                 ""},                    0,              0x7bc87a20},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASPACK,                       "2.XX",             ""},                    0,              0xd4631f92},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ASPROTECT,                    "1.XX-2.XX",        ""},                    0,              0xd4631f92},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MKFPACK,                      "",                 ""},                    0,              0xe6146bc9},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "",                 ""},                    0,              0xf6c9318b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "",                 ""},                    0,              0xd7061c7b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PACKMAN,                      "0.0.0.1",          ""},                    0,              0xf6c9318b},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PACKMAN,                      "1.0",              ""},                    0,              0x7d84ff86},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "1.30-1.40",        ""},                    0,              0xe4c11305},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "1.40-1.84",        ""},                    0,              0x2df20f40},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PECOMPACT,                    "2.40-3.XX",        ""},                    0,              0xdb8fbb75},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXE32PACK,                    "1.3X-1.4X",        ""},                    0,              0x0df29c01},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EZIP,                         "1.0",              ""},                    0xFFFFFFFF,     0xf0a41228}, // KERNEL32.DLL
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EZIP,                         "1.0",              ""},                    0xFFFFFFFF,     0x0df29c01}, // KERNEL32.dll
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EZIP,                         "1.0",              ""},                    0xFFFFFFFF,     0x6639a206}, // KERNEL32.dll
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EZIP,                         "1.0",              ""},                    0xFFFFFFFF,     0x528281ff}, // kernel32.dll
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_JDPACK,                       "2.00",             ""},                    0,              0x45d48065},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.2",              ""},                    0,              0x3eed31e3},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.2",              ""},                    0,              0x47ce503a},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.2",              ""},                    0,              0xb9d96a3e},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.5",              ""},                    0,              0x2bc39e03},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.5",              ""},                    0,              0x8155e514},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "3.5",              ""},                    0,              0x0471beb2},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENIGMA,                       "1.00-3.60",        ""},                    0,              0x45d48065},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENIGMA,                       "3.70+",            ""},                    0,              0x756476d1},
};

SpecAbstract::MSRICH_RECORD _MS_rich_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "",                 ""},                    0x0001,         0},             // Linker generated import object version 0
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "5.10",             ""},                    0x0002,         (quint32)-1},   // LINK 5.10 (Visual Studio 97 SP3)
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "5.10",             ""},                    0x0003,         (quint32)-1},   // LINK 5.10 (Visual Studio 97 SP3) OMF to COFF conversion
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.00",             ""},                    0x0004,         (quint32)-1},   // LINK 6.00 (Visual Studio 98)
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.00",             ""},                    0x0005,         (quint32)-1},   // LINK 6.00 (Visual Studio 98) OMF to COFF conversion
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "5.00",             ""},                    0x0006,         (quint32)-1},   // CVTRES 5.00
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "11.00",            "Basic"},               0x0007,         (quint32)-1},   // VB 5.0 native code
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "11.00",            "C/C++"},               0x0008,         (quint32)-1},   // VC++ 5.0 C/C++
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "Basic"},               0x0009,         (quint32)-1},   // VB 6.0 native code
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C"},                   0x000a,         (quint32)-1},   // VC++ 6.0 C
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++"},                 0x000b,         (quint32)-1},   // VC++ 6.0 C++
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "6.00",             ""},                    0x000c,         (quint32)-1},   // ALIASOBJ.EXE (CRT Tool that builds OLDNAMES.LIB)
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_VISUALBASIC,                  "6.00",             ""},                    0x000d,         (quint32)-1},   // VB 6.0 generated object
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "6.13",             ""},                    0x000e,         (quint32)-1},   // MASM 6.13
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "7.01",             ""},                    0x000f,         (quint32)-1},   // MASM 7.01
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "5.11",             ""},                    0x0010,         (quint32)-1},   // LINK 5.11
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "5.11",             ""},                    0x0011,         (quint32)-1},   // LINK 5.11 OMF to COFF conversion
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "6.14",             "MMX2 support"},        0x0012,         (quint32)-1},   // MASM 6.14 (MMX2 support)
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "5.12",             ""},                    0x0013,         (quint32)-1},   // LINK 5.12
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "5.12",             ""},                    0x0014,         (quint32)-1},   // LINK 5.12 OMF to COFF conversion
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C/std"},               0x0015,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++/std"},             0x0016,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C/book"},              0x0017,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.00",            "C++/book"},            0x0018,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "7.00",             ""},                    0x0019,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "7.00",             ""},                    0x001a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "Basic"},               0x001b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C"},                   0x001c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C++"},                 0x001d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.10",             ""},                    0x001e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.10",             ""},                    0x001f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.01",             ""},                    0x0020,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.01",             ""},                    0x0021,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "Basic"},               0x0022,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "C"},                   0x0023,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.10",            "C++"},                 0x0024,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.20",             ""},                    0x0025,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.20",             ""},                    0x0026,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "7.00",             ""},                    0x0027,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.21",             ""},                    0x0028,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.21",             ""},                    0x0029,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "6.15",             ""},                    0x002a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "LTCG/C"},              0x002b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "LTCG/C++"},            0x002c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "6.20",             ""},                    0x002d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_ILASM,                        "1.00",             ""},                    0x002e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "Basic"},               0x002f,         (quint32)-1}, // 6.20 ???
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C"},                   0x0030,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++"},                 0x0031,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C/std"},               0x0032,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++/std"},             0x0033,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C/book"},              0x0034,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "12.20",            "C++/book"},            0x0035,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "6.22",             ""},                    0x0036,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.22",             ""},                    0x0037,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "5.01",             ""},                    0x0038,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C/std"},               0x0039,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "C++/std"},             0x003a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "13.00",            ""},                    0x003b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.22",             ""},                    0x003c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "7.00",             ""},                    0x003d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "6.22",             ""},                    0x003e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "7.00",             ""},                    0x003f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "7.00",             ""},                    0x0040,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_I_C"},            0x0041,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_I_CPP"},          0x0042,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_O_C"},            0x0043,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.00",            "POGO_O_CPP"},          0x0044,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "7.00",             ""},                    0x0045,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "7.10p",            ""},                    0x0046,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "7.10p",            ""},                    0x0047,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "7.10p",            ""},                    0x0048,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "7.10p",            ""},                    0x0049,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "7.10p",            ""},                    0x004a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "7.10p",            ""},                    0x004b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C"},                   0x004c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C++"},                 0x004d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C/std"},               0x004e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "C++/std"},             0x004f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "LTCG/C"},              0x0050,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "LTCG/C++"},            0x0051,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_I_C"},            0x0052,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_I_CPP"},          0x0053,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_O_C"},            0x0054,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10p",           "POGO_O_CPP"},          0x0055,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "6.24",             ""},                    0x0056,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "6.24",             ""},                    0x0057,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "6.24",             ""},                    0x0058,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "6.24",             ""},                    0x0059,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "7.10",             ""},                    0x005a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "7.10",             ""},                    0x005b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "7.10",             ""},                    0x005c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "7.10",             ""},                    0x005d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "7.10",             ""},                    0x005e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C"},                   0x005f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C++"},                 0x0060,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C/std"},               0x0061,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "C++/std"},             0x0062,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "LTCG/C"},              0x0063,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "LTCG/C++"},            0x0064,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_I_C"},            0x0065,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_I_CPP"},          0x0066,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_O_C"},            0x0067,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "13.10",            "POGO_O_CPP"},          0x0068,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "7.10",             ""},                    0x0069,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "7.10p",            ""},                    0x006a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "13.10",            ""},                    0x006b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "13.10p",           ""},                    0x006c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C"},                   0x006d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C++"},                 0x006e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C/std"},               0x006f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "C++/std"},             0x0070,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/C"},              0x0071,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/C++"},            0x0072,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_I_C"},            0x0073,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_I_CPP"},          0x0074,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_O_C"},            0x0075,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "POGO_O_CPP"},          0x0076,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "14.00",            ""},                    0x0077,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "8.00",             ""},                    0x0078,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTOMF,                       "8.00",             ""},                    0x0079,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "8.00",             ""},                    0x007a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "8.00",             ""},                    0x007b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "8.00",             ""},                    0x007c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "8.00",             ""},                    0x007d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "8.00",             ""},                    0x007e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "Prerelease",       ""},                    0x007f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "CVTCIL/C"},            0x0080,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "CVTCIL/C++"},          0x0081,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "14.00",            "LTCG/MSIL"},           0x0082,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C"},                   0x0083,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C++"},                 0x0084,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C/std"},               0x0085,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "C++/std"},             0x0086,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "CVTCIL/C"},            0x0087,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "CVTCIL/C++"},          0x0088,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/C"},              0x0089,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/C++"},            0x008a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "LTCG/MSIL"},           0x008b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_I_C"},            0x008c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_I_CPP"},          0x008d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_O_C"},            0x008e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "15.00",            "POGO_O_CPP"},          0x008f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "15.00",            ""},                    0x0090,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "9.00",             ""},                    0x0091,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "9.00",             ""},                    0x0092,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "9.00",             ""},                    0x0093,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "9.00",             ""},                    0x0094,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "9.00",             ""},                    0x0095,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "9.00",             ""},                    0x0096,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_RESOURCE,                     "9.00",             ""},                    0x0097,         (quint32)-1}, // Manifest
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "10.00",            ""},                    0x0098,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "16.00",            ""},                    0x0099,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "10.00",            ""},                    0x009a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "10.00"             ""},                    0x009b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "10.00"             ""},                    0x009c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "10.00",            ""},                    0x009d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "10.00",            ""},                    0x009e,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "C"},                   0x009f,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "C++"},                 0x00a0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "CVTCIL/C"},            0x00a1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "CVTCIL/C++"},          0x00a2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/C"},              0x00a3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/C++"},            0x00a4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "LTCG/MSIL"},           0x00a5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_I_C"},            0x00a6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_I_CPP"},          0x00a7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_O_C"},            0x00a8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MICROSOFTPHOENIX,             "16.00",            "POGO_O_CPP"},          0x00a9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "C"},                   0x00aa,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "C++"},                 0x00ab,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "CVTCIL/C"},            0x00ac,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "CVTCIL/C++"},          0x00ad,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/C"},              0x00ae,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/C++"},            0x00af,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "LTCG/MSIL"},           0x00b0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_I_C"},            0x00b1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_I_CPP"},          0x00b2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_O_C"},            0x00b3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.00",            "POGO_O_CPP"},          0x00b4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "10.10",            ""},                    0x00b5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "16.10",            ""},                    0x00b6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "10.10",            ""},                    0x00b7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "10.10",            ""},                    0x00b8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "10.10",            ""},                    0x00b9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "10.10",            ""},                    0x00ba,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "10.10",            ""},                    0x00bb,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "C"},                   0x00bc,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "C++"},                 0x00bd,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "CVTCIL/C"},            0x00be,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "CVTCIL/C++"},          0x00bf,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/C"},              0x00c0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/C++"},            0x00c1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "LTCG/MSIL"},           0x00c2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_I_C"},            0x00c3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_I_CPP"},          0x00c4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_O_C"},            0x00c5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "16.10",            "POGO_O_CPP"},          0x00c6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "11.00",            ""},                    0x00c7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "17.00",            ""},                    0x00c8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "11.00",            ""},                    0x00c9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "11.00",            ""},                    0x00ca,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "11.00",            ""},                    0x00cb,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "11.00",            ""},                    0x00cc,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "11.00",            ""},                    0x00cd,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "C"},                   0x00ce,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "C++"},                 0x00cf,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "CVTCIL/C"},            0x00d0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "CVTCIL/C++"},          0x00d1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/C"},              0x00d2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/C++"},            0x00d3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "LTCG/MSIL"},           0x00d4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_I_C"},            0x00d5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_I_CPP"},          0x00d6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_O_C"},            0x00d7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "17.00",            "POGO_O_CPP"},          0x00d8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "12.00",            ""},                    0x00d9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "18.00",            ""},                    0x00da,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "12.00",            ""},                    0x00db,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "12.00",            ""},                    0x00dc,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "12.00",            ""},                    0x00dd,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "12.00",            ""},                    0x00de,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "12.00",            ""},                    0x00df,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "C"},                   0x00e0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "C++"},                 0x00e1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "CVTCIL/C"},            0x00e2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "CVTCIL/C++"},          0x00e3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/C"},              0x00e4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/C++"},            0x00e5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "LTCG/MSIL"},           0x00e6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_I_C"},            0x00e7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_I_CPP"},          0x00e8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_O_C"},            0x00e9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.00",            "POGO_O_CPP"},          0x00ea,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "12.10",            ""},                    0x00eb,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "18.10",            ""},                    0x00ec,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "12.10",            ""},                    0x00ed,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "12.10",            ""},                    0x00ee,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "12.10",            ""},                    0x00ef,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "12.10",            ""},                    0x00f0,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "12.10",            ""},                    0x00f1,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "C"},                   0x00f2,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "C++"},                 0x00f3,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "CVTCIL/C"},            0x00f4,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "CVTCIL/C++"},          0x00f5,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/C"},              0x00f6,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/C++"},            0x00f7,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "LTCG/MSIL"},           0x00f8,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_I_C"},            0x00f9,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_I_CPP"},          0x00fa,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_O_C"},            0x00fb,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "18.10",            "POGO_O_CPP"},          0x00fc,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_ALIASOBJ,                     "14.00",            ""},                    0x00fd,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTPGD,                       "19.00",            ""},                    0x00fe,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_CVTRES,                       "14.00",            ""},                    0x00ff,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_EXPORT,                       "14.00",            ""},                    0x0100,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_IMPORT,                       "14.00",            ""},                    0x0101,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_MICROSOFTLINKER,              "14.00",            ""},                    0x0102,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_MASM,                         "14.00",            ""},                    0x0103,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "C"},                   0x0104,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "C++"},                 0x0105,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "CVTCIL/C"},            0x0106,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "CVTCIL/C++"},          0x0107,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/C"},              0x0108,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/C++"},            0x0109,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "LTCG/MSIL"},           0x010a,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_I_C"},            0x010b,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_I_CPP"},          0x010c,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_O_C"},            0x010d,         (quint32)-1},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_UNIVERSALTUPLECOMPILER,       "19.00",            "POGO_O_CPP"},          0x010e,         (quint32)-1},
};

// .snaker ??? tool
// .ultra custom packer?
SpecAbstract::STRING_RECORD _PE_sectionNames_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_12311134,                     "",                 "TEST"},                "Xiao"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ABCCRYPTOR,                   "",                 ""},                    ".aBc  "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ACPROTECT,                    "",                 ""},                    ".perplex"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALEXPROTECTOR,                "1.0",              ""},                    ".alex"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ALLOY,                        "",                 ""},                    ".alloy32"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ANDPAKK2,                     "",                 ""},                    "ANDpakk2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASPACK,                       "1.08-2.XX",        ""},                    ".adata"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASPACK,                       "2.XX",             ""},                    ".aspack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_ASPROTECT,                    "",                 ""},                    ".adata"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AVERCRYPTOR,                  "1.0-1.02",         ""},                    ".avc"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_AZPROTECT,                    "0001",             ""},                    "AZPR0001"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR,  "1.0",              ""},                    ".BCPack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BAMBAM,                       "",                 ""},                    ".bedrock"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "",                 ""},                    "bero^fr "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_BEROEXEPACKER,                "",                 ""},                    "packerBY"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRUNCH,                       "1.0",              ""},                    "BitArts"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYPTOCRACKPEPROTECTOR,       "",                 ""},                    ".ccp3p"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_DEPACK,                       "",                 ""},                    ".depack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DOTFIXNICEPROTECT,            "",                 ""},                    ".dotfix"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DYAMAR,                       "1.3.5",            ""},                    ".dyamarC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_DYAMAR,                       "1.3.5",            ""},                    ".dyamarD"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENCRYPTPE,                    "1.XX-2.XX",        ""},                    "EPE0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_ENCRYPTPE,                    "1.XX-2.XX",        ""},                    "EPE1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EPROT,                        "0.01",             ""},                    "!eprot"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.0",              ""},                    "!EPack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_EXEPACK,                      "1.4",              ""},                    ".!ep"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR                     ,"",                ""},                    ".ex_cod"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_EXPRESSOR,                    "",                 ""},                    ".ex_rsc"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.02-1.04",        ""},                    ".FISHPEP"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_FISHPEPACKER,                 "1.02-1.03",        ""},                    ".PEDATA"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_FISHPESHIELD,                 "",                 ""},                    ".FishPE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_INSTALLER,        SpecAbstract::RECORD_NAME_GENTEEINSTALLER,              "",                 ""},                    ".gentee"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_HMIMYSPROTECTOR,              "0.1",              ""},                    "hmimys"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_INQUARTOSOBFUSCATOR,          "",                 ""},                    ".inq"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_JDPACK,                       "",                 ""},                    ".jdpack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,"",                 ""},                    ".Kaos12"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER,"",                 ""},                    ".Kaos2 "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KBYS,                         "",                 ""},                    ".shoooo"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_KKRUNCHY,                     "",                 ""},                    "kkrunchy"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.4-0.5",          ""},                    "_!_!_!_"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.2-0.5",          ""},                    "krypton"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_KRYPTON,                      "0.2-0.5",          ""},                    "YADO"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE64,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LARP64,                       "1.0.3",            "TEST"},                ".LARP"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_MOLEBOXULTRA,                 "",                 ""},                    ".ultra"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW10,                        "",                 ""},                    ".decode"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MEW11SE,                      "",                 ""},                    "MEW"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "",                 ""},                    ".MPRESS1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_MPRESS,                       "",                 ""},                    ".MPRESS2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NAKEDPACKER,                  "1.0",              ""},                    ".naked1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NAKEDPACKER,                  "1.0",              ""},                    ".naked2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NEOLITE,                      "1.0",              ""},                    ".neolit"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NPACK,                        "",                 ""},                    ".nPack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "",                 ""},                    ".nsp0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "",                 ""},                    ".nsp1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "",                 ""},                    ".nsp2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEBUNDLE,                     "",                 ""},                    "pebundle"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PEPACKSPROTECT,               "2.3",              ""},                    "okpack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PESHIELD,                     "0.25-0.26",        ""},                    "PESHiELD"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PESHIELD,                     "0.25-0.26",        ""},                    "ANAKIN2K"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PETITE,                       "",                 ""},                    ".petite"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PUNISHER,                     "1.5 demo",         ""},                    "PUNiSHER"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_RCRYPTOR,                     "",                 ""},                    "RCryptor"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLP,                          "",                 ""},                    ".rlp"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "",                 ""},                    ".packed"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RLPACK,                       "",                 ""},                    ".RLPack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SAFEENGINESHIELDEN,           "",                 ""},                    ".sedata"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SCPACK,                       "",                 ""},                    ".scpack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "",                 ""},                    ".shrink0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "",                 ""},                    ".shrink1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SHRINKER,                     "",                 ""},                    ".shrink2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SOFTWARECOMPRESS,             "",                 ""},                    "SoftComp"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_STARFORCE,                    "3.XX",             ""},                    ".sforce3"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_STARFORCE,                    "4.XX-5.XX",        ""},                    ".ps4"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SVKPROTECTOR,                 "1.3X-1.4X",        ""},                    ".svkp "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_SVKPROTECTOR,                 "1.1X",             ""},                    "SVKP"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TELOCK,                       "",                 ""},                    "UPX!"}, // ???
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_TPPPACK,                      "",                 ""},                    ".Np"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_TTPROTECT,                    "",                 ""},                    ".TTP"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "",                 ""},                    ".UPX0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "",                 ""},                    ".UPX1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_UPX,                          "",                 ""},                    ".UPX2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VCASMPROTECTOR,               "1.X",              ""},                    "vcasm"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VIRTUALIZEPROTECT,            "",                 ""},                    "VProtect"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VMPROTECT,                    "",                 ""},                    ".vmp0"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VMPROTECT,                    "",                 ""},                    ".vmp1"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_VMPROTECT,                    "",                 ""},                    ".vmp2"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PETOOL,           SpecAbstract::RECORD_NAME_VMUNPACKER,                   "",                 ""},                    ".dswlab"},// TODO Check
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_WINKRIPT,                     "1.0",              ""},                    ".wkt0"},// TODO Check!
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WINUPACK,                     "",                 ""},                    ".Upack"}, // TODO Version
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_INSTALLER,        SpecAbstract::RECORD_NAME_WISE,                         "",                 ""},                    ".WISE"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_INSTALLER,        SpecAbstract::RECORD_NAME_WIXTOOLSET,                   "",                 ""},                    ".wixburn"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_XTREMEPROTECTOR,              "",                 ""},                    "CODE    "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_XTREMEPROTECTOR,              "",                 ""},                    ".idata  "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_XTREMEPROTECTOR,              "",                 ""},                    "XPROT   "},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_XTREAMLOK,                    "",                 ""},                    ".xlok"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PETOOL,           SpecAbstract::RECORD_NAME_XVOLKOLAK,                    "",                 ""},                    ".xvlk"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASCRYPTER,                 "1.X",              ""},                    "yC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "1.0b",             ""},                    "yC"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_YODASPROTECTOR,               "",                 ""},                    ".yP"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE32,    SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_YZPACK,                       "",                 ""},                    ".yzpack"},
};

SpecAbstract::STRING_RECORD _PE_dot_ansistrings_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_DOTFUSCATOR,                  "",                 ""},                    "DotfuscatorAttribute"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_LIBRARY,          SpecAbstract::RECORD_NAME_VCL,                          "",                 ".NET"},                 "Borland.Vcl.Types"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_VBNET,                        "",                 ""},                    "Microsoft.VisualBasic"},
    //    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_TOOL,              SpecAbstract::RECORD_NAME_EMBARCADERODELPHIDOTNET,  "",                 ""},                    "Embarcadero."},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_YANO,                         "1.X",              ""},                    "YanoAttribute"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_AGILENET,                     "",                 ""},                    "ObfuscatedByAgileDotNetAttribute"},
    //    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_SKATERNET,                    "",             ""},                    "Skater_NET_Obfuscator"},
    //    {1, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_SKATERNET,                    "",             ""},                    "RustemSoft.Skater"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_BABELNET,                     "3.X",              ""},                    "BabelAttribute"}, // TODO Version
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_BABELNET,                     "1.X-2.X",         ""},                     "BabelObfuscatorAttribute"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_CLISECURE,                    "4.X-5.X",          ""},                    "ObfuscatedByCliSecureAttribute"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_CLISECURE,                    "3.X",              ""},                    "CliSecureRd.dll"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_CLISECURE,                    "3.X",              ""},                    "CliSecureRd64.dll"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_EMBARCADERODELPHIDOTNET,      "XE*",             ""},                     "Borland.Studio.Delphi"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_TOOL,             SpecAbstract::RECORD_NAME_EMBARCADERODELPHIDOTNET,      "8",                ""},                    "Borland.Vcl.Types"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_CRYPTOOBFUSCATORFORNET,       "",                 ""},                    "CryptoObfuscator"}, // TODO Version, die
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_DEEPSEA,                      "4.X",              ""},                    "DeepSeaObfuscator"}, // TODO Version, die
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_GOLIATHNET,                   "",                 ""},                    "ObfuscatedByGoliath"}, // TODO Version, die
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_MACROBJECT,                   "",                 ""},                    "Obfuscated by Macrobject Obfuscator.NET"}, // TODO Version
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_SOFTWAREZATOR,                "",                 ""},                    "ObfuscatedBySoftwareZatorAttribute"}, // TODO Version
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_NSPACK,                       "2.X-3.X",          ".NET"},                "nsnet"}, // TODO Version
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_DNGUARD,                      "",                 ""},                    "ZYXDNGuarder"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_DNGUARD,                      "",                 ""},                    "HVMRuntm.dll"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_DOTNETZ,                      "",                 ""},                    "NetzStarter"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_MAXTOCODE,                    "",                 ""},                    "InfaceMaxtoCode"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_PHOENIXPROTECTOR,             "",                 ""},                    "?1?.?9?.resources"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_SIXXPACK,                     "",                 ""},                    "Sixxpack"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_SMARTASSEMBLY,                "",                 ""},                    "SmartAssembly.Attributes"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_CONFUSER,                     "1.X",              ""},                    "ConfusedByAttribute"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_SPICESNET,                    "",                 ""},                    "NineRays.Obfuscator"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_OBFUSCATORNET2009,            "",                 ""},                    "Macrobject.Obfuscator"},
    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_NETOBFUSCATOR,    SpecAbstract::RECORD_NAME_XENOCODEPOSTBUILD,            "",                 ""},                    "Xenocode.Client.Attributes.AssemblyAttributes"},
};

//// TODO
//SpecAbstract::SIGNATURE_RECORD _dot_unicodestrings_records[]={
//    {{0, SpecAbstract::RECORD_FILETYPE_PE,      SpecAbstract::RECORD_TYPE_PROTECTOR,    SpecAbstract::RECORD_NAME_DOTFUSCATOR,                  "",             ""},                    "'DotfuscatorAttribute'"}
//};


SpecAbstract::STRING_RECORD _TEXT_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_CCPP,                         "",                 ""},                    "#include [\"<].*?[>\"]"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_CCPP,                         "",                 "header"},              "#ifndef (\\w+).*\\s+#define \\1"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_HTML,                         "",                 ""},                    "^<(!DOCTYPE )?[Hh][Tt][Mm][Ll]"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_PHP,                          "",                 ""},                    "^<\\?php"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_PYTHON,                       "",                 ""},                    "import"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_XML,                          "",                 ""},                    "^<\\?xml"},
    {{0, SpecAbstract::RECORD_FILETYPE_TEXT,    SpecAbstract::RECORD_TYPE_SOURCECODE,       SpecAbstract::RECORD_NAME_SHELL,                        "",                 ""},                    "#!"},
};

SpecAbstract::SIGNATURE_RECORD _MSDOS_header_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_CRYEXE,                       "4.0",              ""},                    "'MZ'....................................................'CryEXE 4.0 By Iosco^DaTo!'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_LSCRYPRT,                     "1.21",             ""},                    "'MZ'....................................................'L.S.    Crypt By'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PACKWIN,                      "1.0",              ""},                    "'MZ'........................................................'YRZLITE (C) 1993 WYellow Rose'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_LINKER,           SpecAbstract::RECORD_NAME_TURBOLINKER,                  "",                 ""},                    "'MZ'........................................................FB"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PKLITE,                       "1.0",              ""},                    "'MZ'........................................................'PKLITE Copr. 1990 PKWARE Inc. All Rights Reserved'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_WWPACK,                       "",                 ""},                    "'MZ'....................................................'WWP'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_LZEXE,                        "0.90",             ""},                    "'MZ'....................................................'LZ09'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_LZEXE,                        "0.91",             ""},                    "'MZ'....................................................'LZ91'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RJCRUSH,                      "1.00",             ""},                    "'MZ'....................................................'RJS1'"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_SFX,              SpecAbstract::RECORD_NAME_LHASSFX,                      "2.11S",            ""},                    "'MZ'....................................................................'LHA'27's SFX 2.11S (c) Yoshi, 1991'"},
};

SpecAbstract::SIGNATURE_RECORD _MSDOS_entrypoint_records[]=
{
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_IBMPCPASCAL,                  "1.00(1981)",       ""},                    "B8....8ED88C06....BA....D1EAB9....2BCAD1EA"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_IBMPCPASCAL,                  "2.00(1984)",       ""},                    "B8....8ED88C06....FA8ED0268B1E....2BD881FB....7E..BB....D1E3"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_IBMPCPASCAL,                  "2.02(1987)",       ""},                    "2E8E1E....8CD08CDB2BC3D1E0"}, // TODO Check
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_IBMPCPASCAL,                  "2.05(1987)",       ""},                    "B8....8ED88BD08C06....268B1E....891E....2BD8F7C3....75..B1..D3E3"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PROTECTOR,        SpecAbstract::RECORD_NAME_PACKWIN,                      "1.0",              ""},                    "8CC0FA8ED0BC....FB060E1F2E8B0E....8BF14E8BFE8CDB2E031E....8EC3FDF3A453B8....50CB"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "1994",             ""},                    "......'WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. '"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_WATCOMCCPP,                   "1995",             ""},                    "......'WATCOM C/C++16 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. '"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_DOSEXTENDER,      SpecAbstract::RECORD_NAME_CAUSEWAY,                     "3.1X-3.4X",        ""},                    "FA161F26A1....83E8..8ED0FB061607BE....8BFEB9....F3A407368C......8BD88CCA3603......368B......FD8BC53D....76"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_LZEXE,                        "0.90",             ""},                    "060E1F8B0E....8BF14E89F78CDB03......8EC3B4..31EDFDAC01C5AAE2"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_LZEXE,                        "0.91",             ""},                    "060E1F8B0E....8BF14E89F78CDB03......8EC3FDF3A453B8....50CB"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_AINEXE,                       "2.1",              ""},                    "A1....2D....8ED0BC....8CD836A3....05....36A3....2EA1....8AD4B1..D2EAFEC9D3E08CD336"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_AINEXE,                       "2.3",              ""},                    "0E07B9....BE....33FFFCF3A4A1....2D....8ED0BC....8CD836......05....36......2E"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_AINEXE,                       "2.22",             ""},                    "A1....2D....8ED0BC....8CD836A3....05....36A3....2EA1....8AD4B1..D2EAD3E08CD3368B2E....2E032E....FDFECA"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PGMPAK,                       "0.13",             ""},                    "FA1E1750B430CD213C..73..B44CCD21FCBE....BF....E8....E8....BB....BA....8AC38BF3"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_PGMPAK,                       "0.15",             ""},                    "1E1750B430CD213C..73..B44CCD21FCBE....BF....E8....E8....BB....BA....8AC38BF3"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_COMPILER,         SpecAbstract::RECORD_NAME_TURBOCPP,                     "1988",             ""},                    "BA....2E8916....B430CD218B2E....8B1E....8EDAA3....8C06....891E....892E....C43E....8BC78BD8"},
    {{0, SpecAbstract::RECORD_FILETYPE_MSDOS,   SpecAbstract::RECORD_TYPE_PACKER,           SpecAbstract::RECORD_NAME_RJCRUSH,                      "1.00",             ""},                    "06FC8CC8BA....03D052BA....52BA....03C28BD805....8EDB8EC033F633FFB9"},
};

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
        }
        else if(stTypes.contains(XBinary::FT_ELF32)||stTypes.contains(XBinary::FT_ELF64))
        {
            SpecAbstract::ELFINFO_STRUCT elf_info=SpecAbstract::getELFInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(elf_info.basic_info.listDetects);
        }
        else if(stTypes.contains(XBinary::FT_MACH32)||stTypes.contains(XBinary::FT_MACH64))
        {
            SpecAbstract::MACHINFO_STRUCT mach_info=SpecAbstract::getMACHInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(mach_info.basic_info.listDetects);
        }
        else if(stTypes.contains(XBinary::FT_LE)||stTypes.contains(XBinary::FT_LX))
        {
            SpecAbstract::LEINFO_STRUCT le_info=SpecAbstract::getLEInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(le_info.basic_info.listDetects);
        }
        else if(stTypes.contains(XBinary::FT_NE))
        {
            SpecAbstract::NEINFO_STRUCT ne_info=SpecAbstract::getNEInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(ne_info.basic_info.listDetects);
        }
        else if(stTypes.contains(XBinary::FT_MSDOS))
        {
            SpecAbstract::MSDOSINFO_STRUCT msdos_info=SpecAbstract::getMSDOSInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(msdos_info.basic_info.listDetects);
        }
        else
        {
            SpecAbstract::BINARYINFO_STRUCT binary_info=SpecAbstract::getBinaryInfo(&sd,parentId,pOptions,nOffset);

            pScanResult->listRecords.append(binary_info.basic_info.listDetects);
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
        case RECORD_FILEPART_UNKNOWN:                           sResult=QString("Unknown");                                     break;
        case RECORD_FILEPART_HEADER:                            sResult=QString("Header");                                      break;
        case RECORD_FILEPART_OVERLAY:                           sResult=QString("Overlay");                                     break;
        case RECORD_FILEPART_ARCHIVERECORD:                     sResult=QString("Archive record");                              break;
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
        case RECORD_TYPE_DONGLEPROTECTION:                      sResult=tr("Dongle protection");                                break;
        case RECORD_TYPE_DOSEXTENDER:                           sResult=tr("DOS extender");                                     break;
        case RECORD_TYPE_FORMAT:                                sResult=tr("Format");                                           break;
        case RECORD_TYPE_GENERIC:                               sResult=tr("Generic");                                          break;
        case RECORD_TYPE_IMAGE:                                 sResult=tr("Image");                                            break;
        case RECORD_TYPE_INSTALLER:                             sResult=tr("Installer");                                        break;
        case RECORD_TYPE_INSTALLERDATA:                         sResult=tr("Installer data");                                   break;
        case RECORD_TYPE_JOINER:                                sResult=tr("Joiner");                                           break;
        case RECORD_TYPE_LIBRARY:                               sResult=tr("Library");                                          break;
        case RECORD_TYPE_LINKER:                                sResult=tr("Linker");                                           break;
        case RECORD_TYPE_NETOBFUSCATOR:                         sResult=tr(".NET obfuscator");                                  break;
        case RECORD_TYPE_PACKER:                                sResult=tr("Packer");                                           break;
        case RECORD_TYPE_PETOOL:                                sResult=tr("PE tool");                                          break;
        case RECORD_TYPE_PROTECTOR:                             sResult=tr("Protector");                                        break;
        case RECORD_TYPE_PROTECTORDATA:                         sResult=tr("Protector data");                                   break;
        case RECORD_TYPE_SFX:                                   sResult=tr("SFX");                                              break;
        case RECORD_TYPE_SFXDATA:                               sResult=tr("SFX data");                                         break;
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
        case RECORD_NAME_AUTOIT:                                sResult=QString("AutoIt");                                      break;
        case RECORD_NAME_AVASTANTIVIRUS:                        sResult=QString("Avast Antivirus");                             break;
        case RECORD_NAME_AVERCRYPTOR:                           sResult=QString("AverCryptor");                                 break;
        case RECORD_NAME_AZPROTECT:                             sResult=QString("AZProtect");                                   break;
        case RECORD_NAME_BABELNET:                              sResult=QString("Babel .NET");                                  break;
        case RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR:           sResult=QString("Backdoor PE Compress Protector");              break;
        case RECORD_NAME_BAMBAM:                                sResult=QString("bambam");                                      break;
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
        case RECORD_NAME_CRYPTER:                               sResult=QString("Crypter");                                     break;
        case RECORD_NAME_CRYPTIC:                               sResult=QString("Cryptic");                                     break;
        case RECORD_NAME_CRYPTOCRACKPEPROTECTOR:                sResult=QString("CrypToCrack Pe Protector");                    break;
        case RECORD_NAME_CRYPTOOBFUSCATORFORNET:                sResult=QString("Crypto Obfuscator For .Net");                  break;
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
        case RECORD_NAME_DIRTYCRYPTOR:                          sResult=QString("DirTy Cryptor");                               break;
        case RECORD_NAME_DMD32D:                                sResult=QString("DMD32 D");                                     break;
        case RECORD_NAME_DNGUARD:                               sResult=QString("DNGuard");                                     break;
        case RECORD_NAME_DOS16M:                                sResult=QString("DOS/16M");                                     break;
        case RECORD_NAME_DOTFIXNICEPROTECT:                     sResult=QString("DotFix Nice Protect");                         break;
        case RECORD_NAME_DOTFUSCATOR:                           sResult=QString("Dotfuscator");                                 break;
        case RECORD_NAME_DOTNET:                                sResult=QString(".NET");                                        break;
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
        case RECORD_NAME_EPROT:                                 sResult=QString("!EProt");                                      break;
        case RECORD_NAME_EXE32PACK:                             sResult=QString("exe32pack");                                   break;
        case RECORD_NAME_EXECRYPT:                              sResult=QString("EXECrypt");                                    break;
        case RECORD_NAME_EXECRYPTOR:                            sResult=QString("EXECryptor");                                  break;
        case RECORD_NAME_EXEFOG:                                sResult=QString("ExeFog");                                      break;
        case RECORD_NAME_EXEJOINER:                             sResult=QString("ExeJoiner");                                   break;
        case RECORD_NAME_EXEMPLARINSTALLER:                     sResult=QString("Exemplar Installer");                          break;
        case RECORD_NAME_EXEPACK:                               sResult=QString("!EP(EXE Pack)");                               break;
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
        case RECORD_NAME_GOASM:                                 sResult=QString("GoAsm");                                       break;
        case RECORD_NAME_GOLIATHNET:                            sResult=QString("Goliath .NET");                                break;
        case RECORD_NAME_GOLINK:                                sResult=QString("GoLink");                                      break;
        case RECORD_NAME_GOOGLE:                                sResult=QString("Google");                                      break;
        case RECORD_NAME_GPINSTALL:                             sResult=QString("GP-Install");                                  break;
        case RECORD_NAME_GUARDIANSTEALTH:                       sResult=QString("Guardian Stealth");                            break;
        case RECORD_NAME_GZIP:                                  sResult=QString("GZIP");                                        break;
        case RECORD_NAME_H4CKY0UORGCRYPTER:                     sResult=QString("H4ck-y0u.org Crypter");                        break;
        case RECORD_NAME_HACCREWCRYPTER:                        sResult=QString("HAC Crew Crypter");                            break;
        case RECORD_NAME_HALVCRYPTER:                           sResult=QString("HaLV Crypter");                                break;
        case RECORD_NAME_HIDEANDPROTECT:                        sResult=QString("Hide&Protect");                                break;
        case RECORD_NAME_HIDEPE:                                sResult=QString("HidePE");                                      break;
        case RECORD_NAME_HMIMYSPACKER:                          sResult=QString("Hmimys Packer");                               break;
        case RECORD_NAME_HMIMYSPROTECTOR:                       sResult=QString("Hmimys's Protector");                          break;
        case RECORD_NAME_HOUNDHACKCRYPTER:                      sResult=QString("Hound Hack Crypter");                          break;
        case RECORD_NAME_HTML:                                  sResult=QString("HTML");                                        break;
        case RECORD_NAME_HXS:                                   sResult=QString("HXS");                                         break;
        case RECORD_NAME_IBMPCPASCAL:                           sResult=QString("IBM PC Pascal");                               break;
        case RECORD_NAME_ICRYPT:                                sResult=QString("ICrypt");                                      break;
        case RECORD_NAME_ILASM:                                 sResult=QString("ILAsm");                                       break;
        case RECORD_NAME_IMPORT:                                sResult=QString("Import");                                      break;
        case RECORD_NAME_INFCRYPTOR:                            sResult=QString("INF Cryptor");                                 break;
        case RECORD_NAME_INNOSETUP:                             sResult=QString("Inno Setup");                                  break;
        case RECORD_NAME_INQUARTOSOBFUSCATOR:                   sResult=QString("Inquartos Obfuscator");                        break;
        case RECORD_NAME_INSTALLANYWHERE:                       sResult=QString("InstallAnywhere");                             break;
        case RECORD_NAME_INSTALLSHIELD:                         sResult=QString("InstallShield");                               break;
        case RECORD_NAME_IPBPROTECT:                            sResult=QString("iPB Protect");                                 break;
        case RECORD_NAME_JAR:                                   sResult=QString("JAR");                                         break;
        case RECORD_NAME_JAVA:                                  sResult=QString("Java");                                        break;
        case RECORD_NAME_JAVACOMPILEDCLASS:                     sResult=QString("Java compiled class");                         break;
        case RECORD_NAME_JDPACK:                                sResult=QString("JDPack");                                      break;
        case RECORD_NAME_JPEG:                                  sResult=QString("JPEG");                                        break;
        case RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER:         sResult=QString("KaOs PE-DLL eXecutable Undetecter");           break;
        case RECORD_NAME_KBYS:                                  sResult=QString("KByS");                                        break;
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
        case RECORD_NAME_LHA:                                   sResult=QString("LHA");                                         break;
        case RECORD_NAME_LHASSFX:                               sResult=QString("LHA's SFX");                                   break;
        case RECORD_NAME_LIGHTNINGCRYPTERPRIVATE:               sResult=QString("Lightning Crypter Private");                   break;
        case RECORD_NAME_LIGHTNINGCRYPTERSCANTIME:              sResult=QString("Lightning Crypter ScanTime");                  break;
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
        case RECORD_NAME_PLAIN:                                 sResult=QString("Plain");                                       break;
        case RECORD_NAME_PMODEW:                                sResult=QString("PMODE/W");                                     break;
        case RECORD_NAME_PNG:                                   sResult=QString("PNG");                                         break;
        case RECORD_NAME_POKECRYPTER:                           sResult=QString("Poke Crypter");                                break;
        case RECORD_NAME_POLYCRYPTPE:                           sResult=QString("PolyCrypt PE");                                break;
        case RECORD_NAME_POWERBASIC:                            sResult=QString("PowerBASIC");                                  break;
        case RECORD_NAME_PRIVATEEXEPROTECTOR:                   sResult=QString("Private EXE Protector");                       break;
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
        case RECORD_NAME_RENETPACK:                             sResult=QString("ReNET-pack");                                  break;
        case RECORD_NAME_RESOURCE:                              sResult=QString("Resource");                                    break;
        case RECORD_NAME_REVPROT:                               sResult=QString("REVProt");                                     break;
        case RECORD_NAME_RJCRUSH:                               sResult=QString("RJcrush");                                     break;
        case RECORD_NAME_RLP:                                   sResult=QString("RLP");                                         break;
        case RECORD_NAME_RLPACK:                                sResult=QString("RLPack");                                      break;
        case RECORD_NAME_ROGUEPACK:                             sResult=QString("RoguePack");                                   break;
        case RECORD_NAME_ROSASM:                                sResult=QString("RosAsm");                                      break;
        case RECORD_NAME_RTF:                                   sResult=QString("Rich Text Format");                            break;
        case RECORD_NAME_SAFEENGINESHIELDEN:                    sResult=QString("Safengine Shielden");                          break;
        case RECORD_NAME_SCPACK:                                sResult=QString("SC Pack");                                     break;
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
        case RECORD_NAME_SPOONINSTALLER:                        sResult=QString("Spoon Installer");                             break;
        case RECORD_NAME_SQUEEZSFX:                             sResult=QString("Squeez Self Extractor");                       break;
        case RECORD_NAME_STARFORCE:                             sResult=QString("StarForce");                                   break;
        case RECORD_NAME_STASFODIDOCRYPTOR:                     sResult=QString("StasFodidoCryptor");                           break;
        case RECORD_NAME_SVKPROTECTOR:                          sResult=QString("SVK Protector");                               break;
        case RECORD_NAME_TARMAINSTALLER:                        sResult=QString("Tarma Installer");                             break;
        case RECORD_NAME_TELOCK:                                sResult=QString("tElock");                                      break;
        case RECORD_NAME_TGRCRYPTER:                            sResult=QString("TGR Crypter");                                 break;
        case RECORD_NAME_THEBESTCRYPTORBYFSK:                   sResult=QString("The Best Cryptor [by FsK]");                   break;
        case RECORD_NAME_THEMIDAWINLICENSE:                     sResult=QString("Themida/Winlicense");                          break;
        case RECORD_NAME_THEZONECRYPTER:                        sResult=QString("The Zone Crypter");                            break;
        case RECORD_NAME_TOTALCOMMANDERINSTALLER:               sResult=QString("Total Commander Installer");                   break;
        case RECORD_NAME_TPPPACK:                               sResult=QString("TTP Pack");                                    break;
        case RECORD_NAME_TSTCRYPTER:                            sResult=QString("TsT Crypter");                                 break;
        case RECORD_NAME_TTPROTECT:                             sResult=QString("TTprotect");                                   break;
        case RECORD_NAME_TURBOC:                                sResult=QString("Turbo C");                                     break;
        case RECORD_NAME_TURBOCPP:                              sResult=QString("Turbo C++");                                   break;
        case RECORD_NAME_TURBOLINKER:                           sResult=QString("Turbo linker");                                break;
        case RECORD_NAME_TURKISHCYBERSIGNATURE:                 sResult=QString("Turkish Cyber Signature");                     break;
        case RECORD_NAME_TURKOJANCRYPTER:                       sResult=QString("Turkojan Crypter");                            break;
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
        case RECORD_NAME_VPACKER:                               sResult=QString("VPacker");                                     break;
        case RECORD_NAME_WATCOMC:                               sResult=QString("Watcom C");                                    break;
        case RECORD_NAME_WATCOMCCPP:                            sResult=QString("Watcom C/C++");                                break;
        case RECORD_NAME_WATCOMLINKER:                          sResult=QString("Watcom linker");                               break;
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
    return QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name)).arg(pScanStruct->sVersion).arg(pScanStruct->sInfo);
}

QString SpecAbstract::createResultString(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    return QString("%1: %2(%3)[%4]").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name)).arg(pScanStruct->sVersion).arg(pScanStruct->sInfo);
}

QString SpecAbstract::createResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    QString sResult=QString("%1: %2").arg(SpecAbstract::recordTypeIdToString(pScanStruct->type)).arg(SpecAbstract::recordNameIdToString(pScanStruct->name));

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
    return QString("%1: %2").arg(createTypeString(pScanStruct)).arg(createResultString(pScanStruct));
}

QString SpecAbstract::createFullResultString2(const SpecAbstract::SCAN_STRUCT *pScanStruct)
{
    return QString("%1: %2").arg(createTypeString(pScanStruct)).arg(createResultString2(pScanStruct));
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

// TODO VI
QString SpecAbstract::findEnigmaVersion(QIODevice *pDevice,bool bIsImage, qint64 nOffset, qint64 nSize)
{
    QString sResult;

    XBinary binary(pDevice,bIsImage);

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

        sResult=QString("%1.%2 build %3.%4.%5 %6:%7:%8").arg(nMajor).arg(nMinor,2,10,QChar('0')).arg(nYear,4,10,QChar('0')).arg(nMonth,2,10,QChar('0')).arg(nDay,2,10,QChar('0')).arg(nHour,2,10,QChar('0')).arg(nMin,2,10,QChar('0')).arg(nSec,2,10,QChar('0'));
    }

    return sResult;
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
    result.basic_info.bIsTest=pOptions->bIsTest;
    result.basic_info.memoryMap=binary.getMemoryMap();

    // Scan Header
    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_binary_records,sizeof(_binary_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY);

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

    result.bIsZip=xzip.isVaild();

    if(result.bIsZip)
    {
        result.listArchiveRecords=xzip.getRecords(100000);
    }

    Binary_handle_Texts(pDevice,pOptions->bIsImage,&result);
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
    result.basic_info.bIsTest=pOptions->bIsTest;
    result.basic_info.memoryMap=msdos.getMemoryMap();

    result.nOverlayOffset=msdos.getOverlayOffset(&(result.basic_info.memoryMap));
    result.nOverlaySize=msdos.getOverlaySize(&(result.basic_info.memoryMap));

    if(result.nOverlaySize)
    {
        result.sOverlaySignature=msdos.getSignature(result.nOverlayOffset,150);
    }

    result.sEntryPointSignature=msdos.getSignature(msdos.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

    signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_header_records,sizeof(_MSDOS_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS);
    signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_MSDOS_entrypoint_records,sizeof(_MSDOS_entrypoint_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS);

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
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=elf.getMemoryMap();

        result.sEntryPointSignature=elf.getSignature(elf.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.nStringTableSection=elf.getSectionStringTable(result.bIs64);
        result.baStringTable=elf.getSection(result.nStringTableSection);

        result.listTags=elf.getTagStructs();
        result.listLibraries=elf.getLibraries(&result.listTags);

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
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=le.getMemoryMap();

        result.sEntryPointSignature=le.getSignature(le.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

        result.listRichSignatures=le.getRichSignatureRecords();

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS);

        LE_handle_Microsoft(pDevice,pOptions->bIsImage,&result);

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
        result.basic_info.bIsTest=pOptions->bIsTest;
        result.basic_info.memoryMap=ne.getMemoryMap();

        result.sEntryPointSignature=ne.getSignature(ne.getEntryPointOffset(&(result.basic_info.memoryMap)),150);

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
            result.osCodeSection.nOffset=result.listSectionRecords.at(result.nCodeSection).nOffset; // mb TODO for image
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

        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_MSDOS_linker_header_records,sizeof(_MSDOS_linker_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS);
        signatureScan(&result.basic_info.mapHeaderDetects,result.basic_info.sHeaderSignature,_PE_header_records,sizeof(_PE_header_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        signatureScan(&result.mapEntryPointDetects,result.sEntryPointSignature,_PE_entrypoint_records,sizeof(_PE_entrypoint_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        signatureScan(&result.mapOverlayDetects,result.sOverlaySignature,_binary_records,sizeof(_binary_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_BINARY);

        stringScan(&result.mapSectionNamesDetects,&result.listSectionNames,_PE_sectionNames_records,sizeof(_PE_sectionNames_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);

        // Import
        constScan(&(result.mapImportDetects),result.nImportHash64,result.nImportHash32,_PE_importhash_records,sizeof(_PE_importhash_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);

        int nNumberOfImports=result.listImportPositionHashes.count();

        for(int i=0;i<nNumberOfImports;i++)
        {
            constScan(&(result.mapImportDetects),i,result.listImportPositionHashes.at(i),_PE_importpositionhash_records,sizeof(_PE_importpositionhash_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
        }

        signatureExpScan(&pe,&(result.basic_info.memoryMap),&result.mapEntryPointDetects,result.nEntryPointOffset,_PE_entrypointExp_records,sizeof(_PE_entrypointExp_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);

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


        if(result.cliInfo.bInit)
        {
            stringScan(&result.mapDotAnsistringsDetects,&result.cliInfo.listAnsiStrings,_PE_dot_ansistrings_records,sizeof(_PE_dot_ansistrings_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);

            //            for(int i=0;i<result.cliInfo.listUnicodeStrings.count();i++)
            //            {
            //                signatureScan(&result.mapDotUnicodestringsDetects,QBinary::stringToHex(result.cliInfo.listUnicodeStrings.at(i)),_dot_unicodestrings_records,sizeof(_dot_unicodestrings_records),result.basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_PE);
            //            }
        }

        PE_handle_import(pDevice,pOptions->bIsImage,&result);

        PE_handle_Protection(pDevice,pOptions->bIsImage,&result);
        PE_handle_SafeengineShielden(pDevice,pOptions->bIsImage,&result);
        PE_handle_VProtect(pDevice,pOptions->bIsImage,&result);
        PE_handle_TTProtect(pDevice,pOptions->bIsImage,&result);
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

        PE_handle_UnknownProtection(pDevice,pOptions->bIsImage,&result);

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

            VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,pPEInfo->osHeader.nOffset,pPEInfo->osHeader.nSize);

            // UPX
            // TODO 32-64
            if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX))
            {
                if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_UPX))
                {
                    if((viUPX.sVersion!=""))
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
                int nVariant=pPEInfo->mapImportDetects.value(RECORD_NAME_ENIGMA).nVariant;

                if(XBinary::checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 nSectionOffset=pPEInfo->osImportSection.nOffset;
                    qint64 nSectionSize=pPEInfo->osImportSection.nSize;

                    bool bDetect=false;

                    SpecAbstract::_SCANS_STRUCT recordEnigma={};

                    recordEnigma.type=SpecAbstract::RECORD_TYPE_PROTECTOR;
                    recordEnigma.name=SpecAbstract::RECORD_NAME_ENIGMA;

                    // mb TODO ENIGMA string
                    if((!bDetect)&&(nVariant==0))
                    {
                        qint64 nOffset=pe.find_array(nSectionOffset,nSectionSize," *** Enigma protector v",23);

                        if(nOffset!=-1)
                        {
                            recordEnigma.sVersion=pe.read_ansiString(nOffset+23).section(" ",0,0);
                            bDetect=true;
                        }

                        if(!bDetect)
                        {
                            nOffset=pe.find_ansiString(nSectionOffset,nSectionSize,"The Enigma Protector version");

                            if(nOffset!=-1)
                            {
                                recordEnigma.sVersion=pe.read_ansiString(nOffset+29,8).section("\r\n",0,0);
                                bDetect=true;
                            }
                        }
                    }

                    //                    if((!bDetect)&&(nVariant==1))
                    if(!bDetect)
                    {
                        QString sEnigmaVersion=findEnigmaVersion(pDevice,bIsImage,nSectionOffset,nSectionSize);

                        if(sEnigmaVersion!="")
                        {
                            recordEnigma.sVersion=sEnigmaVersion;
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

                    if(XBinary::checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                    if((pPEInfo->fileHeader.TimeDateStamp==0)&&
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

                // AHPacker
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
                        default:    ss.sVersion="";
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
                    if(XBinary::checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                            if(XBinary::checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                        if(XBinary::compareSignatureStrings(_sSignature,"60E8000000005D81ED........B8........03C5"))
                        {
                            _sVersion="1.00b-1.07b";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60EB..5DEB..FF..........E9"))
                        {
                            _sVersion="1.08.01-1.08.02";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E8000000005D............BB........03DD"))
                        {
                            _sVersion="1.08.03";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E8000000005D81ed........BB........01eb"))
                        {
                            _sVersion="1.08.X";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E841060000EB41"))
                        {
                            _sVersion="1.08.04";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60EB..5DFFE5E8........81ED........BB........03DD2B9D"))
                        {
                            _sVersion="1.08.X";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E870050000EB4C"))
                        {
                            _sVersion="2.000";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E872050000EB4C"))
                        {
                            _sVersion="2.001";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E872050000EB3387DB9000"))
                        {
                            _sVersion="2.1";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E93D040000"))
                        {
                            _sVersion="2.11";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E802000000EB095D5581ED39394400C3E93D040000"))
                        {
                            _sVersion="2.11b";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E802000000EB095D5581ED39394400C3E959040000"))
                        {
                            _sVersion="2.11c-2.11d";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E802000000EB095D55"))
                        {
                            _sVersion="2.11d";
                        }
                        else if(XBinary::compareSignatureStrings(_sSignature,"60E803000000E9EB045D4555C3E801"))
                        {
                            _sVersion="2.12-2.42";
                        }

                        if(_nOffset>20)
                        {
                            break;
                        }

                        if(!bContinue)
                        {
                            break;
                        }

                        if(_sVersion!="")
                        {
                            break;
                        }
                    }

                    if(_sVersion!="")
                    {
                        SpecAbstract::_SCANS_STRUCT recordASPack={};

                        recordASPack.type=RECORD_TYPE_PACKER;
                        recordASPack.name=RECORD_NAME_ASPACK;
                        recordASPack.sVersion=_sVersion;
                        //recordAndpakk.sInfo;

                        pPEInfo->mapResultPackers.insert(recordASPack.name,scansToScan(&(pPEInfo->basic_info),&recordASPack));
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
                if(pPEInfo->mapImportDetects.contains(RECORD_NAME_EXEPACK))
                {
                    if(pPEInfo->mapEntryPointDetects.contains(RECORD_NAME_EXEPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapEntryPointDetects.value(RECORD_NAME_EXEPACK);

                        pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    }
                    else if(pPEInfo->mapSectionNamesDetects.contains(RECORD_NAME_EXEPACK))
                    {
                        SpecAbstract::_SCANS_STRUCT ss=pPEInfo->mapSectionNamesDetects.value(RECORD_NAME_EXEPACK);

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

                        if(XBinary::checkOffsetSize(pPEInfo->osImportSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                    if(XBinary::checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                if(pPEInfo->sEntryPointSectionName=="VProtect")
                {
                    if(XBinary::checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                        if(pPEInfo->sEntryPointSectionName==".TTP")
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
                    if(pPEInfo->sEntryPointSectionName==".sedata")
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
                    SpecAbstract::_SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_THEMIDAWINLICENSE,"","",0);

                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
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
                else if(XPE::isSectionNamePresent(".petite",&(pPEInfo->listSectionHeaders))) // TODO
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
        if(pPEInfo->cliInfo.bInit)
        {
            // .NET
            // Enigma
            if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 nSectionOffset=pPEInfo->osCodeSection.nOffset;
                qint64 nSectionSize=pPEInfo->osCodeSection.nSize;

                QString sEnigmaVersion=findEnigmaVersion(pDevice,bIsImage,nSectionOffset,nSectionSize);

                if(sEnigmaVersion!="")
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_ENIGMA,sEnigmaVersion,".NET",0);
                    pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
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

            //            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SKATERNET))
            //            {
            //                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SKATERNET);
            //                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            //            }

            if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
            {
                qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                qint64 _nSize=pPEInfo->osCodeSection.nSize;

                qint64 nOffset_String=pe.find_ansiString(_nOffset,_nSize,"RustemSoft.Skater");

                if(nOffset_String!=-1)
                {
                    _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_SKATER,"","",0);
                    pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                }
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

            if(pPEInfo->mapOverlayDetects.contains(RECORD_NAME_FISHNET))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_PROTECTOR,RECORD_NAME_FISHNET,"1.X","",0); // TODO
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

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_DOTNETZ))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
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

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SIXXPACK))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_SMARTASSEMBLY))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_SMARTASSEMBLY);

                if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize=pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_Confuser=pe.find_ansiString(_nOffset,_nSize,"Powered by SmartAssembly ");

                    if(nOffset_Confuser!=-1)
                    {
                        ss.sVersion=pe.read_ansiString(nOffset_Confuser+25);
                    }
                }

                pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            }

            if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_CONFUSER))
            {
                _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_CONFUSER);


                if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 _nOffset=pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize=pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_Confuser=pe.find_ansiString(_nOffset,_nSize,"Confuser v");

                    if(nOffset_Confuser!=-1)
                    {
                        ss.sVersion=pe.read_ansiString(nOffset_Confuser+10);
                    }

                    if(nOffset_Confuser==-1)
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
        }

        // Xenocode Virtual Application Studio 2009
        if(XPE::getResourceVersionValue("Packager",&(pPEInfo->resVersion)).contains("Xenocode Postbuild 2009 for .NET"))
        {
            _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_NETOBFUSCATOR,RECORD_NAME_XENOCODEPOSTBUILD2009,"","",0);
            ss.sVersion=XPE::getResourceVersionValue("PackagerVersion",&(pPEInfo->resVersion)).trimmed();
            pPEInfo->mapResultNETObfuscators.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
        // Xenocode Postbuild
        if(pPEInfo->mapDotAnsistringsDetects.contains(RECORD_NAME_XENOCODEPOSTBUILD))
        {
            _SCANS_STRUCT ss=pPEInfo->mapDotAnsistringsDetects.value(RECORD_NAME_XENOCODEPOSTBUILD);
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
        if((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER))&&(!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)))
        {
            recordLinker.type=RECORD_TYPE_LINKER;
            recordLinker.name=RECORD_NAME_MICROSOFTLINKER;
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
        if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
            listRichDescriptions.append(richScan(pPEInfo->listRichSignatures.at(i).nId,pPEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pPEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS));
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
                if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
            recordNET.sVersion=pPEInfo->cliInfo.sCLI_MetaData_Version;

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

            if(!pPEInfo->bIs64)
            {
                if(pe.compareEntryPoint("E8......00E9$$$$$$$$6A..68........E8"))
                {
                    recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    recordCompiler.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                }
            }
            else
            {
                if( pe.compareEntryPoint("4883EC28E8........4883C428E9$$$$$$$$48895C24")||
                    pe.compareEntryPoint("4883EC28E8........4883C428E9$$$$$$$$488BC44889580848897010488978184C896020"))
                {
                    recordCompiler.type=SpecAbstract::RECORD_TYPE_COMPILER;
                    recordCompiler.name=SpecAbstract::RECORD_NAME_VISUALCCPP;
                }
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

            if(recordTurboLinker.nVariant==0)
            {
                recordTurboLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion,2,10,QChar('0'));
            }
            else if(recordTurboLinker.nVariant==1)
            {
                recordTurboLinker.sVersion=QString::number((double)pe.read_uint8(0x1F)/16,'f',1); // TODO PE-MSDOS
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

            if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

            if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                    if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
        if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

            if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                        if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
            if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
            if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

            if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                        if(XBinary::checkOffsetSize(pPEInfo->osConstDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
                        {
                            _sGCCVersion=get_GCC_vi2(pDevice,bIsImage,pPEInfo->osConstDataSection.nOffset,pPEInfo->osConstDataSection.nSize).sVersion;

                            if(_sGCCVersion!="")
                            {
                                recordCompiler.sVersion=_sGCCVersion;
                            }
                        }

                        if(_sGCCVersion=="")
                        {
                            if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                    if(XBinary::checkOffsetSize(pPEInfo->osCodeSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

                if(XBinary::checkOffsetSize(pPEInfo->osResourceSection)&&(pPEInfo->basic_info.bIsDeepScan))
                {
                    qint64 nSectionOffset=pPEInfo->listSectionHeaders.at(pPEInfo->nResourceSection).PointerToRawData+
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

                if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

            if(XPE::getResourceVersionValue("FileDescription",&(pPEInfo->resVersion)).contains("Java")&&
                    XPE::getResourceVersionValue("InternalName",&(pPEInfo->resVersion)).contains("Setup Launcher"))
            {
                _SCANS_STRUCT ss=getScansStruct(0,RECORD_FILETYPE_PE,RECORD_TYPE_INSTALLER,RECORD_NAME_JAVA,"","",0);
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
                if(XBinary::checkOffsetSize(pPEInfo->osDataSection)&&(pPEInfo->basic_info.bIsDeepScan))
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
                if(XBinary::checkOffsetSize(pPEInfo->osEntryPointSection)&&(pPEInfo->basic_info.bIsDeepScan))
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

        if(pPEInfo->mapImportDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
        {
            _SCANS_STRUCT ss=pPEInfo->mapImportDetects.value(RECORD_NAME_DALKRYPT);

            pPEInfo->mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        }
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

void SpecAbstract::PE_handle_UnknownProtection(QIODevice *pDevice,bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    XPE pe(pDevice,bIsImage);

    if(pe.isValid())
    {
        if((pPEInfo->mapResultPackers.count()==0)&&
                (pPEInfo->mapResultProtectors.count()==0)&&
                (pPEInfo->mapResultSFX.count()==0)&&
                (pPEInfo->mapResultInstallers.count()==0)&&
                (pPEInfo->mapResultNETObfuscators.count()==0)&&
                (pPEInfo->mapResultDongleProtection.count()==0))
        {
            if(pPEInfo->listSectionRecords.count())
            {
                if(pPEInfo->listSectionRecords.at(0).nSize==0)
                {
                    if(pPEInfo->mapImportDetects.contains(RECORD_NAME_UPX)&&
                            (pPEInfo->mapImportDetects.value(RECORD_NAME_UPX).nVariant==0))
                    {
                        SpecAbstract::_SCANS_STRUCT recordSS={};

                        recordSS.type=RECORD_TYPE_PACKER;
                        recordSS.name=RECORD_NAME_UNK_UPXLIKE;

                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
                    }
                }

//            qint64 nSize=pPEInfo->basic_info.nSize;

//            if(pPEInfo->nOverlaySize)
//            {
//                nSize-=pPEInfo->nOverlaySize;
//            }

//            qint64 nProtect=pe.find_ansiString(0,nSize,"Protected");

//            if(nProtect==-1)
//            {
//                nProtect=pe.find_ansiString(0,nSize,"protected");
//            }

//            if(nProtect==-1)
//            {
//                nProtect=pe.find_ansiString(0,nSize,"protect");
//            }

//            if(nProtect==-1)
//            {
//                nProtect=pe.find_ansiString(0,nSize,"Protector");
//            }

//            if(nProtect==-1)
//            {
//                nProtect=pe.find_ansiString(0,nSize,"protector");
//            }

//            if(nProtect!=-1)
//            {
//                SpecAbstract::_SCANS_STRUCT recordSS={};

//                recordSS.type=RECORD_TYPE_PACKER;
//                recordSS.name=RECORD_NAME_UNKNOWN;
//                recordSS.sVersion=QString("%1").arg(pe.read_ansiString(nProtect,32));
//                recordSS.sInfo=QString("%1").arg(pPEInfo->nImportHash32);

//                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
//            }



    //            if(pPEInfo->nEntryPointSection!=0)
    //            {
    //                if(pPEInfo->listImports.count()>0)
    //                {
    //                    if(pPEInfo->nEntryPointSection<pPEInfo->listSectionNames.count())
    //                    {
    //                        SpecAbstract::_SCANS_STRUCT recordSS={};
    //                        recordSS.type=RECORD_TYPE_PACKER;
    //                        recordSS.name=RECORD_NAME_UNKNOWN0;
    //                        recordSS.sVersion=pPEInfo->listSectionNames.at(pPEInfo->nEntryPointSection);
    //                        recordSS.sInfo=QString("%1").arg(pPEInfo->nImportHash32);

    //                        pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
    //                    }
    //                }
    //            }

    //            if(pPEInfo->nEntryPointSection!=0)
    //            {
    //                if(pPEInfo->listImports.count()==1)
    //                {
    //                    SpecAbstract::_SCANS_STRUCT recordSS={};

    //                    recordSS.type=RECORD_TYPE_PACKER;
    //                    recordSS.name=RECORD_NAME_UNKNOWN;
    //                    recordSS.sVersion=QString("%1").arg(pPEInfo->nImportHash32);

    //                    pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
    //                }
    //            }
    //            QList<QString> list=pPEInfo->listSectionNames.toSet().toList();

    //            for(int i=0;i<list.count();i++)
    //            {
    //                if(i>9)
    //                {
    //                    break;
    //                }

    //                SpecAbstract::_SCANS_STRUCT recordSS={};
    //                recordSS.type=RECORD_TYPE_PACKER;
    //                recordSS.name=(RECORD_NAME)(RECORD_NAME_UNKNOWN0+i);
    //                recordSS.sVersion=list.at(i);

    //                pPEInfo->mapResultPackers.insert(recordSS.name,scansToScan(&(pPEInfo->basic_info),&recordSS));
    //            }
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
        pPEInfo->mapResultPackers.contains(RECORD_NAME_EXEPACK))
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

    if( pPEInfo->mapResultPackers.contains(RECORD_NAME_SIMPLEPACK)||
        pPEInfo->mapResultCompilers.contains(RECORD_NAME_FASM))
    {
        pPEInfo->mapResultCompilers.remove(RECORD_NAME_FASM);
    }
}

void SpecAbstract::PE_handle_Recursive(QIODevice *pDevice, bool bIsImage, SpecAbstract::PEINFO_STRUCT *pPEInfo, SpecAbstract::SCAN_OPTIONS *pOptions)
{
    if(pOptions->bRecursive)
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

void SpecAbstract::Binary_handle_Archives(QIODevice *pDevice,bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    // 7-Zip
    if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z))&&(pBinaryInfo->basic_info.nSize>=64))
    {
        // TODO more options
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        if(ss.type==RECORD_TYPE_ARCHIVE)
        {
            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // ZIP
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZIP))&&(pBinaryInfo->basic_info.nSize>=64)) // TODO min size
    {
        XZip xzip(pDevice);

        if(xzip.isVaild())
        {
            // TODO deep scan
            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZIP);
            quint8 nVersion=XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(4*2,2));
            quint8 nFlags=XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2));

            ss.sVersion=QString("%1").arg((double)nVersion/10,0,'f',1);
            ss.sInfo=QString("%1 records").arg(xzip.getNumberOfRecords());

            if(nFlags&0x1)
            {
                ss.sInfo=append(ss.sInfo,"Encrypted");
            }

            // TODO files
            pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        }
    }
    // ZIP
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GZIP))&&(pBinaryInfo->basic_info.nSize>=9))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // CAB
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CAB))&&(pBinaryInfo->basic_info.nSize>=30))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

        quint8 nMinorVersion=binary.read_uint8(0x18);
        quint8 nMajorVersion=binary.read_uint8(0x19);

        ss.sVersion=QString("%1.%2").arg(nMajorVersion).arg(nMinorVersion);

        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
    }
    // RAR
    else if((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RAR))&&(pBinaryInfo->basic_info.nSize>=64))
    {
        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RAR);

        if(ss.nVariant==1)
        {
            quint8 nVersion=XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2));

            if(nVersion==0)
            {
                ss.sVersion="4.X";
            }
            else if(nVersion==1)
            {
                ss.sVersion="5.X";
            }
        }
        // TODO options
        // TODO files
        pBinaryInfo->mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
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
}

void SpecAbstract::Binary_handle_MicrosoftOffice(QIODevice *pDevice, bool bIsImage, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice,bIsImage);

    if(pBinaryInfo->bIsZip)
    {
        XZip xzip(pDevice);

        if(xzip.isVaild())
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

        if(xzip.isVaild())
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

        if(xzip.isVaild())
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

                    if((bIsAPK)&&(pOptions->bRecursive))
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

            ss.sVersion=QString::number((double)msdos.read_uint8(0x1F)/16,'f',1);

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

        if(pMSDOSInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PACKWIN))
        {
            _SCANS_STRUCT ss=pMSDOSInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PACKWIN);
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
    if(pOptions->bRecursive)
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

        if(XBinary::checkOffsetSize(pELFInfo->osCommentSection))
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
        // TODO
//        qint64 nHeaderOffset=0;
//        qint64 nHeaderSize=qMin((qint64)0x1000,pELFInfo->basic_info.nSize);
//        VI_STRUCT viUPX=get_UPX_vi(pDevice,bIsImage,nHeaderOffset,nHeaderSize);

//        if(viUPX.sVersion!="")
//        {
//            SpecAbstract::_SCANS_STRUCT recordUPX={};

//            recordUPX.type=RECORD_TYPE_PACKER;
//            recordUPX.name=RECORD_NAME_UPX;
//            recordUPX.sVersion=viUPX.sVersion;
//            recordUPX.sInfo=viUPX.sInfo;

//            pELFInfo->mapResultPackers.insert(recordUPX.name,scansToScan(&(pELFInfo->basic_info),&recordUPX));
//        }
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
            listRichDescriptions.append(richScan(pLEInfo->listRichSignatures.at(i).nId,pLEInfo->listRichSignatures.at(i).nVersion,_MS_rich_records,sizeof(_MS_rich_records),pLEInfo->basic_info.id.filetype,SpecAbstract::RECORD_FILETYPE_MSDOS));
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
    VI_STRUCT result;

    XBinary binary(pDevice,bIsImage);

    // TODO make both
    qint64 nStringOffset1=binary.find_ansiString(nOffset,nSize,"$Id: UPX");
    qint64 nStringOffset2=binary.find_ansiString(nOffset,nSize,"UPX!");

    if(nStringOffset1!=-1)
    {
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
    VI_STRUCT result;

    XBinary binary(pDevice,bIsImage);

    // TODO get max version
    qint64 nOffset_Version=binary.find_ansiString(nOffset,nSize,"gcc-");

    if(nOffset_Version!=-1)
    {
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

void SpecAbstract::memoryScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMmREcords, QIODevice *pDevice, bool bIsImage, qint64 nOffset, qint64 nSize, SpecAbstract::SCANMEMORY_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    if(nSize)
    {
        XBinary binary(pDevice,bIsImage);

        int nSignaturesCount=nRecordsSize/sizeof(SIGNATURE_RECORD);

        for(int i=0; i<nSignaturesCount; i++)
        {
            if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
            {
                if(!pMmREcords->contains(pRecords[i].basicInfo.name))
                {
                    qint64 _nOffset=binary.find_array(nOffset,nSize,(char *)pRecords[i].pData,pRecords[i].nSize);

                    if(_nOffset!=-1)
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
                }
            }
        }
    }
}

void SpecAbstract::signatureScan(QMap<RECORD_NAME, _SCANS_STRUCT> *pMapRecords, QString sSignature, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if(!pMapRecords->contains(pRecords[i].basicInfo.name))
            {
                if(XBinary::compareSignatureStrings(sSignature,pRecords[i].pszSignature))
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
            }
        }
    }
}

void SpecAbstract::resourcesScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<XPE::RESOURCE_RECORD> *pListResources, SpecAbstract::RESOURCES_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    int nSignaturesCount=nRecordsSize/sizeof(RESOURCES_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if(!pMapRecords->contains(pRecords[i].basicInfo.name))
            {
                bool bSuccess=false;

                if(pRecords[i].bIsString1)
                {
                    if(pRecords[i].bIsString2)
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].pszName1,pRecords[i].pszName2,pListResources);
                    }
                    else
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].pszName1,pRecords[i].nID2,pListResources);
                    }
                }
                else
                {
                    if(pRecords[i].bIsString2)
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].nID1,pRecords[i].pszName2,pListResources);
                    }
                    else
                    {
                        bSuccess=XPE::isResourcePresent(pRecords[i].nID1,pRecords[i].nID2,pListResources);
                    }
                }

                if(bSuccess)
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
            }
        }
    }
}

void SpecAbstract::stringScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, QList<QString> *pListStrings, SpecAbstract::STRING_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
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
                if(!pMapRecords->contains(pRecords[j].basicInfo.name))
                {
                    quint32 nCRC1=listStringCRC[i];
                    quint32 nCRC2=listSignatureCRC[j];

                    if(nCRC1==nCRC2)
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
                }
            }
        }
    }
}

void SpecAbstract::constScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint64 nCost1, quint64 nCost2, SpecAbstract::CONST_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(CONST_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if(!pMapRecords->contains(pRecords[i].basicInfo.name))
            {
                bool bCheck=false;

                bCheck= ((pRecords[i].nConst1==nCost1)||(pRecords[i].nConst1==0xFFFFFFFF))&&
                        ((pRecords[i].nConst2==nCost2)||(pRecords[i].nConst2==0xFFFFFFFF));

                if(bCheck)
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
            }
        }
    }
}

void SpecAbstract::richScan(QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if(!pMapRecords->contains(pRecords[i].basicInfo.name))
        {
            SpecAbstract::_SCANS_STRUCT record={};

            if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
            {
                pMapRecords->insert(record.name,record);
            }
        }
    }
}

void SpecAbstract::signatureExpScan(XBinary *pXBinary, XBinary::_MEMORY_MAP *pMemoryMap, QMap<SpecAbstract::RECORD_NAME, SpecAbstract::_SCANS_STRUCT> *pMapRecords, qint64 nOffset, SpecAbstract::SIGNATURE_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    int nSignaturesCount=nRecordsSize/(int)sizeof(SIGNATURE_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        if((pRecords[i].basicInfo.filetype==fileType1)||(pRecords[i].basicInfo.filetype==fileType2))
        {
            if(!pMapRecords->contains(pRecords[i].basicInfo.name))
            {
                if(pXBinary->compareSignature(pMemoryMap,pRecords[i].pszSignature,nOffset))
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
            }
        }
    }
}

QList<SpecAbstract::_SCANS_STRUCT> SpecAbstract::richScan(quint16 nID, quint32 nBuild, SpecAbstract::MSRICH_RECORD *pRecords, int nRecordsSize, SpecAbstract::RECORD_FILETYPE fileType1, SpecAbstract::RECORD_FILETYPE fileType2)
{
    QList<SpecAbstract::_SCANS_STRUCT> listResult;

    int nSignaturesCount=nRecordsSize/(int)sizeof(MSRICH_RECORD);

    for(int i=0; i<nSignaturesCount; i++)
    {
        SpecAbstract::_SCANS_STRUCT record={};

        if(PE_compareRichRecord(&record,&(pRecords[i]),nID,nBuild,fileType1,fileType2))
        {
            listResult.append(record);
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
