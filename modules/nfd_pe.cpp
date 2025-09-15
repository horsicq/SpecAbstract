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
#include "nfd_pe.h"
#include "../specabstract.h"
// We reference legacy tables in signatures.cpp via extern and expose them through getters here.
// After verification, these tables can be physically moved into this TU.

NFD_Binary::SIGNATURE_RECORD _PE_header_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_FASM, "", ""},
     "'MZ'80000100000004001000FFFF00004001000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'This "
     "program cannot be run in DOS mode.\r\n$'0000000000000000'PE'0000"},  // TODO patched
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_DMD32, "", ""},
     "'MZ'60000100000004001000FFFF0000FE0000001200000040000000000000000000000000000000000000000000000000000000000000000000000060000000'Requires Win32   "
     "$'161F33D2B409CD21B8014CCD2100'PE'0000"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_FORMAT, XScanEngine::XScanEngine::RECORD_NAME_HXS, "", ""},
     "'MZ'0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000'PE'"
     "00004C010200000000000000000000000000E00001200B010000000000000000000000000000000000000000000000000000000040000000000000"},
    {{1, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_NOSTUBLINKER, "", ""},
     "'MZ'....................................................................................................................40000000'PE'0000"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PRIVATEEXEPROTECTOR, "1.90-1.95", ""},
     "'MZ'90000300000004000000FFFF0000B80000000000000040000000000000000000000000000000000000000000000000000000000000000000000078000000BA10000E1FB409CD21B8014CCD219090'"
     "This program must be run under Win32\r\n$'37'PE'0000"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PRIVATEEXEPROTECTOR, "1.7-1.8", ""},
     "'MZ'50000200000004000F00FFFF0000B80000000000000040001A00000000000000000000000000000000000000000000000000000000000000000078000000BA10000E1FB409CD21B8014CCD219090'"
     "This program must be run under Win32\r\n$'37'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.1X-0.24", ""}, "'MZKERNEL32.DLL'0000'PE'0000........'UpackByDwing'"},
    {{1, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.24-0.32", ""},
     "'MZKERNEL32.DLL'0000'LoadLibraryA'00000000'GetProcAddress'"},
    {{2, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.33", ""}, "'MZLoadLibraryA'0000'PE'0000........'KERNEL32'"},
    {{3, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.36", ""},
     "'MZLoadLibraryA'0000'PE'0000............................................'KERNEL32.DLL'"},
    {{4, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.37-0.399", ""},
     "'MZKERNEL32.DLL'0000'PE'0000............................................'LoadLibraryA'"},
    {{4, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "0.37-0.399", "Patched"}, "'MZKERNEL32.DLL'0000'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "0.71-0.97", "Win32/exe"},
     "'MZ'........................................................................................'Is Win32 EXE.'24"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "0.71-0.97", "Win64/exe"},
     "'MZ'........................................................................................'Is Win64 EXE.'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "0.71-0.97", "Win32/dll"},
     "'MZ'........................................................................................'Is Win32 DLL.'24"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "0.71-0.97", "Win64/dll"},
     "'MZ'........................................................................................'Is Win64 DLL.'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "1.27-2.12", "Win32/exe"},
     "'MZ'........................................................................................'Win32 .EXE.\r\n'"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "1.27-2.12", "Win64/exe"},
     "'MZ'........................................................................................'Win64 .EXE.\r\n'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "1.27-2.12", "Win32/dll"},
     "'MZ'........................................................................................'Win32 .DLL.\r\n'"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "1.27-2.12", "Win64/dll"},
     "'MZ'........................................................................................'Win64 .DLL.\r\n'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "1.27-2.12", ".NET"},
     "'MZ'........................................................................................'It'27's .NET EXE"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP, "1.XX-5.1.X", "Install"},
     "'MZ'............................................................................................496E6E6F"},  // TODO Versions
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP, "", "Uninstall"},
     "'MZ'............................................................................................496E556E"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2, "0.18", ""}, "'MZ'00'ANDpakk2'00'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_GOLINK, "", ""},
     "'MZ'6c000100000002000000ffff000000000000110000004000000000000000'Win32 Program!\r\n$'b409ba0001cd21b44ccd2160000000'GoLink, GoAsm www.GoDevTool.com'00"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_GOLINK, "", ""},
     "'MZ'6c000100000002000000ffff000000000000110000004000000000000000'Win64 Program!\r\n$'b409ba0001cd21b44ccd2160000000'GoLink, GoAsm www.GoDevTool.com'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "2.0-2.4", ""},
     "'MZ'40000100000002000000FFFF00000002000000000000400000....................CD21B44CCD21'packed by nspack$'40000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_LAYHEYFORTRAN90, "", ""},
     "'MZ'....................................................................................................................6C030000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR, "0.1", ""},
     "'MZ'............................................................'hmimys'27's ProtectV0.1'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT, "2.3", ""},
     "'MZ'............................................................'pepack'27's ProtectV2.3'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.00-1.20", ""},
     "'MZ'....................................................................................................................600000000E1FBA0E00B409CD21B8014CCD21'"
     "Windows Program'0D0A24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.30-1.32", ""},
     "'MZ'....................................................................................................................40000000'PE'00004C01....'FSG!'"},
    {{1, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.33-2.00", ""}, "'MZ'....................'PE'00004C01....'FSG!'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW10, "1.0", ""},
     "'MZ'00000000000000000000'PE'00004C010200000000000000000000000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "1.0", ""}, "'MZkernel32.dll'0000'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "1.1-1.2", ""},
     "'MZ'00000000000000000000'PE'00004C010200000000000000000000000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", ""}, "'MZ'52C3'(C)BeRo!PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "0.23", "farbraush"}, "'MZfarbrauschPE'"},
    {{1, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "", "conspiracy"}, "'MZconspiracyPE'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_QUICKPACKNT, "0.1", ""}, "'MZ'90EB010052E9........'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_GENERIC, "", ""}, "'MZ'....................'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.1", ""},
     "'MZ'40000100000002000400FFFF0200400000000E0000001C00000000000000'(c) UsAr 2oo6$'0EB409BA00001FCD21B8014CCD2140000000'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.2", ""},
     "'MZ'52456083EC188BEC8BFC33C0648B4030780C8B400C8B701CAD8B4008EB098B403483C07C8B403CABE9........B409BA00001FCD21B8014CCD2140000000'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "2.0", ""}, "'MZKERNEL32'0000'PE'0000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMLINKER, "", "WinNT/dll"},
     "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21'this "
     "is a Windows NT dynamic link library\r\n'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMLINKER, "", "WinNT/RTL/dll"},
     "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000900000000E1FBA0E00B409CD21B8014CCD21'this "
     "is a Windows NT (own RTL) dynamic link library\r\n'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMLINKER, "", "WinNT/RTLexe"},
     "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000900000000E1FBA0E00B409CD21B8014CCD21'this "
     "is a Windows NT character-mode (own RTL) executable\r\n'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMLINKER, "", "WinNT/exe"},
     "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21..'his "
     "is a Windows NT character-mode executable\r\n'24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMLINKER, "", "Win95/exe"},
     "'MZ'80000100000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000700000000E1FBA0E00B409CD21B8014CCD21'This "
     "is a Windows 95 executable\r\n'24"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_STUB, XScanEngine::XScanEngine::RECORD_NAME_VALVE, "", ""},
     "'MZ'............................................................................................................................'VLV'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LINKER, XScanEngine::XScanEngine::RECORD_NAME_UNILINK, "", ""},
     "'MZ'....................................................'UniLink!'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CRINKLER, "", ""}, "'MZ'B80000420031DB43EB58'PE'0000"},
};
const qint32 _PE_header_records_size = sizeof(_PE_header_records);

NFD_Binary::SIGNATURE_RECORD _PE_entrypoint_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.59", "exe"}, "60E8000000005883E83D50"},  // mb TODO
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.60-0.69", "exe"}, "60E8........68........8BE88DBD........33DB033C248BF7"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.71-0.72", "exe"}, "60E80000000083CDFF31DB5E"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.71-0.72", "dll"}, "807C2408010F85........60E80000000083CDFF31DB5E"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.81-3.81+", "exe"}, "60BE........8DBE"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.81-3.81+", "dll"}, "807C2408010F85........60BE........8DBE"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "3.81+", "exe"}, "53565755488D35........488DBE"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "3.81+", "dll"},
     "48894C240848895424104C8944241880FA010F85........53565755488D35........488DBE"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WWPACK32, "1.01-1.12", ""},
     "53558BE833DBEB60'\r\n\r\nWWPack32 decompression routine version '........'\r\n(c) 1998 Piotr Warezak and Rafal Wierzbicki\r\n\r\n'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_BORLANDCPP, "", ""}, "EB10'fb:C++HOOK'90"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2, "0.06", ""}, "60FCBE........BF........5783CDFF33C9F9EB05A402DB7505"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2, "0.18", ""}, "FCBE........BF........5783CDFF33C9F9EB05A402DB7505"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASDPACK, "2.0", ""}, "8B442404565753E8CD010000C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_REVPROT, "0.1a", ""},
     "E8........8B4C240CC701........C781................31C089411489411880A1..........C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_32LITE, "0.03a", ""}, "6006FC1E07BE........6A0468........68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "2.0.X", ""}, "68........68........C3C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR, "1.0", ""}, "60E8000000005D81ED........E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALLOY, "4.X", ""}, "9C60E8........33C08BC483C0..938BE3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_GCC, "3.X-4.X", "MinGW"},
     "5589E583EC08C70424..000000FF15........E8....FFFF................55"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "0.X-1.X", ""}, "EB0668........C39C60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "2.9-3.7", ""}, "9C60E8000000005D"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "2.9-3.7", ""},
     "4881ECC00000004883C4404889042448894C2408488954241048895C241848896C2420488974242848897C24304C894424384C894C24404C895424484C895C24504C896424584C896C24604C897424684C8"
     "97C24704883EC40E8000000005D"},  // TODO version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMA, "1.2", ""}, "60E8000000005D83....81ED"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMCCPP, "1994", ""},
     "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1994. '"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMCCPP, "1995", ""},
     "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by WATCOM International Corp. 1988-1995. '"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMCCPP, "2000", ""},
     "..................'WATCOM C/C++32 Run-Time system. (c) Copyright by Sybase, Inc. 1988-2000. All rights reserved'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMCCPP, "2002", ""},
     "..................'Open Watcom C/C++32 Run-Time system. Portions Copyright (C) Sybase, Inc. 1988-2002'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_WATCOMCCPP, "2002", ""},
     "..................'Open Watcom C/C++32 Run-Time system. Portions Copyright (c) Sybase, Inc. 1988-2002'"},  // Check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ORIEN, "", ""},
     "E95D010000CED1CE..'\r\n--------------------------------------------\r\n- ORiEN executable files protection system'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_VPACKER, "0.02.10", ""}, "60E8........C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "1.23-2.77", ""}, "6801......E801000000C3C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "1.1 BRS", ""}, "60E9..05"},  // TODO check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "1.2", ""}, "6801......C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "1.0", ""}, "60E801000000905D81ED........BB........03DD2B9D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.0-1.2", ""}, "6068........B8........FF1068........50B8........FF10"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.4", ""}, "33C08BC068........68........E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.4", ""}, "EB01909068........68........E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESPIN, "", ""}, "EB016860E8000000008B1C2483C312812BE8B10600FE4BFD822C24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "", "Alt stub"}, "60E809000000..................33C95E870E"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "", ""}, "BE........AD50FF7634EB7C4801"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_AHPACKER, "0.1", ""}, "6068........B8........FF10"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZBRR"}, "60BE........BF........FCB28033DBA4B302E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZBRS"}, "60BE........BF........FCAD8D1C07B0803BFB733BE8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZMA"},
     "6068........68........68........E8........BE........B9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZBRR/dll"},
     "837C2408010F85........60BE........BF........FCB28033DBA4B302E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZBRS/dll"},
     "837C2408010F85........60BE........BF........FCAD8D1C07B0803BFB733BE8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", "LZMA/dll"},
     "837C2408010F85........6068........68........68........E8........BE........B9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NPACK, "", ""}, "833D........007505E9........C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.02", ""}, "60E8........6168........C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.03", ""}, "60E8........EB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.04", ""}, "60B8........FFD0"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "0.23 alpha 1", ""}, "BD........C74500........FF4D08C6450C05"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "0.23 alpha 2", ""},
     "BD........C74500........B8........89450489455450C74510"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "0.23 alpha 3-4", ""},
     "BD........C74500........B8........89450489455850C74510"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PACKMAN, "0.0.0.1", ""}, "60E800000000588D..........8D..........8D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PACKMAN, "1.0", ""}, "60E8000000005B8D5BC6011B8B138D73146A08590116AD4975FA"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "2.4", ""}, "B8........60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "2.2-2.3", ""},
     "B8........6A0068........64FF350000000064892500000000669C60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "2.2-2.3", ""}, "B8........68........64FF35........648925........669C60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "1.3-1.4", ""}, "B8........669C60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "1.2", ""}, "669C60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEPACK, "0.99", ""},
     "60E8000000005D83ED..80BD..........0F84........C685..........8BC52B..........89..........89"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEPACK, "1.0", ""}, "7400e9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XCOMP, "0.97-0.98", ""}, "68........9C60E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XPACK, "0.97-0.98", ""}, "68........9C60E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ABCCRYPTOR, "1.0", ""}, "68FF6424F0685858585890FFD4"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EXE32PACK, "1.4X", ""}, "3BC07402"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_GENERIC, "", ""}, "60"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS, "1.2", ""}, "E9........608B7424248B7C2428FC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS, "1.4 LITE", ""}, "E800000000812C24........5DE800000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SDPROTECTORPRO, "1.1X", ""}, "558BEC6AFF68........688888880864A1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK, "1.0", ""}, "60E8000000005B8D5BFA"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER, "1.0", ""}, "60FC0FB605........85C075"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, "", ""}, "60FC0FB605........85C075"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, "", "Modified"}, "FC0FB605........85C075"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "", ""}, "60E8000000008B2C2483C404"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "", "dll"}, "807C2408010F85........60E8000000008B2C2483C404"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.20.1", ""}, "57C7C7........8D3D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.0 beta", ""}, "60E8000000008D6424048B6C24FC8DB5........8D9D........33FF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLP, "0.7.4b", ""}, "68........E8........C3C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EZIP, "1.0", ""},
     "E9........E9........E9........E9........E9........E9........E9........E9........E9........E9........E9........CC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_PUREBASIC, "4.X", ""},
     "68....0000680000000068......00E8......0083C40C6800000000E8......00A3"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_PUREBASIC, "4.X", ""},
     "4883EC..49C7C0........4831D248B9................E8........4831C9E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_LCCWIN, "1.X-3.X", ""},
     "64A1........5589E56A..68........68........506489..........83EC..53565789"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.90", ""}, "....E802000000E800E8000000005E2B"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.92a", ""}, "E97EE9FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.95", ""}, "E9D5E4FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.96", ""}, "E959E4FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.98b1", ""}, "E925E4FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.98b2", ""}, "E91BE4FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.98", "Special Build"}, "E999D7FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.99", ""}, "E95EDFFFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.99c", ""}, "E93FDFFFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "1.00", ""}, "E9E5E2FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "0.28 Beta", ""},
     "60E8000000005E83EE0A8B0603C28B08894EF383EE0F56528BF0ADAD03C28BD86A04BF00100000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "0.28", ""}, "68........E801000000C3C3608B7424248B7C2428FCB28033DBA4"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "0.28", ""}, "B8........BA........03C2FFE0........60E800000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "0.28 Beta", ""}, "68........90B8........C3608B7424..8B7C24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SAFEENGINESHIELDEN, "", ""}, "E8........53"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR, "0.9.2", ""},
     "E801000000E8585B81E300FFFFFF66813B4D5A753784DB75338BF303....813E504500007526"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR, "0.9.3", ""},
     "5B81E300FFFFFF66813B4D5A75338BF303733C813E5045000075260FB746188BC869C0AD0B0000F7E02DAB5D414B69C9DEC0000003C1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRUNCH, "1.0", ""}, "55E8000000005D83ED068BC55560"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOXULTRA, "4.X", ""}, "5589E5E8........5DC3CC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.XX", ""}, "90589050908B00903C5090580F8567D6EF115068"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.1", ""}, "8B042483E84F68........FFD0"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.3-1.4", ""}, "558BEC8B44240483E84F68........FFD0585950"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.3b", ""}, "6183EF4F6068........FFD7"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.5", ""}, "832C244F68........FF542404834424044F"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.6", ""}, "33D068........FFD2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.6b-1.6c", ""}, "8BC70304242BC78038500F851B8B1FFF68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "1.6d", ""}, "60906161807FF04590600F851B8B1FFF68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "2.0", ""}, "F7D183F1FF6A00F7D183F1FF810424........F7D183F1FF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.2", ""}, "8B0C24E90A7C01..AD4240BDBE9D7A04"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.3", ""}, "8B0C24E9C08D01..C13A6ECA5D7E796DB3645A71EA"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.4", ""}, "54E8000000005D8BC581ED........2B85........83E806"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.5", ""}, "54E8000000005D8BC581ED........2B85........EB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR, "1.3X-1.4X", ""}, "60E8000000005D81ED06000000EB05B8........64A023"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEBESTCRYPTORBYFSK, "1.0", ""}, "EB06'VRULZ'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER, "1.X", ""}, "60E8000000005D81ED........B9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER, "1.3", ""},
     "558BEC53565760E8000000005D81ED........B9"},  // 1.3??? TODO Check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_TPPPACK, "", ""}, "E8000000005D81ED"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD, "1.12-1.16", ""}, "60E8........FFD0C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.2", ""}, "558BEC81EC....0000535657EB0C'ExPr-v.1.2.'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.3", ""}, "558BEC83EC..535657EB0C'ExPr-v.1.3.'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.4.5.X", ""}, "558BEC83EC..5356578365..00F3EB0C'eXPr-v.1.4.'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.5.0.X", ""},
     "558BEC81EC........53565783A5..........F3EB0C'eXPr-v.1.5.'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.6", ""},
     "558BEC81EC........53565783A5..........F3EB0C'eXPr-v.1.6.'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BAMBAM, "0.1-0.4", ""}, "6A14E89A050000....5368........E86CFDFFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT, "2.1-2.5", ""},
     "E9FF000000608B7424248B7C2428FCB28033DBA4B302E86D00000073F633C9E864000000731C33C0E85B0000007323B30241B010E84F00000012C073F7753FAAEBD4E84D0000002BCB7510E842000000EB2"
     "8ACD1E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_JDPACK, "1.01", ""},
     "60E8000000005D8BD581ED........2B95........81EA06......8995........83BD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_JDPACK, "2.00", ""},
     "558BEC6AFF68........68........64A1000000005064892500000000......E801000000"},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR,               "1.0",              ""},
    //    "558BEC6AFF68........68........64A1000000005064892500000000E803000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR, "1.X", ""}, "EB..'[VProtect]'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ADVANCEDUPXSCRAMMBLER, "0.5", ""}, "B8........B9........803408..E2FAEB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AZPROTECT, "0001", ""},
     "EB70FC608C804D110070258100400D91BB608C804D11007021811D610D810040CE608C804D11007025812581258125812961418131611D610040B730"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WINKRIPT, "1.0", ""},
     "33C08BB8........8B90........85FF74..33C950EB..8A0439C0C8..34..880439413BCA72..58"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.0", ""}, "BB........BF........BE........53E80A00000002D275058A164612D2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.31", ""}, "BE........BF........BB........53BB........B280"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.31", ""}, "BB........BF........BE........53BB........B280A4B680FFD373F9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "1.33", ""}, "BE........AD93AD97AD5696B280A4B680FF1373"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "2.0", ""}, "8725......00619455A4B680FF13"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE, "", ""}, "9C60E802......33C08BC483C004938BE38B5BFC81EB........87DD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_BLADEJOINER, "1.5", ""}, "558BEC81C4E4FEFFFF53565733C08945F08985"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_NJOINER, "0.1", ""},
     "6A0068........68........6A00E8140000006A00E813000000CCFF25........FF25........FF25........FF25"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_CELESTYFILEBINDER, "1.0", "C++ Dynamic library"},
     "E896040000E963FDFFFF8BFF558BEC81EC28030000A3E8514000890DE45140008915E0514000891DDC5140008935D8514000893DD4514000668C1500"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_CELESTYFILEBINDER, "1.0", "C++ Static library"},
     "E8261F0000E989FEFFFF8BFF558BEC83EC208B450856576A0859BE0C9240008D7DE0F3A58945F88B450C5F8945FC5E85C074"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_POLYCRYPTPE, "", ""}, "60E8........EB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PUNISHER, "1.5 demo", ""}, "EB0483A4BCCE60EB0480BC0411E800000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SECURESHADE, "1.8", ""},
     "558BEC81EC........535657BE........8D7D..8D45..A5A5A5A56A..50A4E8........8B1D........595968........FFD3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.2", ""},
     "833D..........558BEC565775..68........E8........83....8B....A3........85F674..68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.5", ""},
     "833D..........558BEC565775..68........E8........83....8B....A3........85F674..83"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.0-1.1", ""}, "6033C08D480750E2FD8BEC648B4030780C8B400C"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HIDEANDPROTECT, "1.016", ""}, "909090E9D8..050095..5300954A5000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPACK, "0.0.3", ""},
     "558BEC83....33C08945F0B8........E867C4FFFF33C05568........64FF306489208D55F033C0E893C8FFFF"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE, "1.XX-2.XX", ""}, "609C64FF3500000000E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_EXEJOINER, "1.0", ""}, "68........6804010000E83903000005........C6005C680401000068"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "1.0b", ""},
     "558BEC53565760E8000000005D81ED4C324000E803000000EB01"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "1.02-1.03", ""}, "E803000000EB01"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AVERCRYPTOR, "1.XX", ""},
     "60E8000000005D81ED........8BBD........8B8D........B8"},  // TODO version 1.00 1.02
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VISUALCCPP, "3.0-3.10", ""}, "535657BB........8B7C....553BFB75..011D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.09g", ""},
     "60F950E801000000..58584950E801000000..5858790466B9B872E801000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.41", ""}, "E801000000..83"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.3X", ""}, "6050E801000000..83"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.4X", ""}, "60E801000000..83042406C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.90g", ""}, "600F87020000001BF8E801000000..83042406C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "2.0.X", ""}, "68........68........C3C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.00b-1.07b", ""}, "60E8000000005D81ED........B8........03C5"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08.01-1.08.02", ""}, "60EB..5DEB..FF..........E9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08.03", ""}, "60E8000000005D............BB........03DD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08.04", ""}, "60E841060000EB41"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08.X", ""}, "60E8000000005D81ED........BB........01EB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08.X", ""}, "60EB..5DFFE5E8........81ED........BB........03DD2B9D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.000", ""}, "60E870050000EB4C"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.001", ""}, "60E872050000EB4C"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.1", ""}, "60E872050000EB3387DB9000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.11", ""}, "60E93D040000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.11b", ""}, "60E802000000EB095D5581ED39394400C3E93D040000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.11c-2.11d", ""}, "60E802000000EB095D5581ED39394400C3E959040000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.11d", ""}, "60E802000000EB095D55"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.12-2.42", ""}, "60E803000000E9EB045D4555C3E801"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.2", ""},
     "4D5A52456083EC188BEC8BFC33C0648B4030780C8B400C8B701CAD8B4008EB098B403483C07C8B403CABE9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CRINKLER, "0.3-0.4", ""}, "B8........31DB43EB58"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTER, "3.1", ""}, "68FF6424F06858585858FFD4508B40F205B095F6950F850181BBFF68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THINSTALL, "2.5XX", ""},
     "558BECB8........BB........50E800000000582D..1A0000B9..1A0000BA..1B0000BE00100000BF..530000BD..1A000003E8817500..........7504........817508........81750C........"
     "817510"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KCRYPTOR, "0.11", ""},
     "558BEC83EC..53565733DB53FF15........8B3D........8945..B8........FF30BE........56E8........68........6A..E8........83C4..6A..68........5753FFD0"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DALKRYPT, "1.0", ""},
     "68........5868........5F33DBEB0D8A140380EA0780F2048814034381FB........72EBFFE7"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEARMOR, "0.7X", ""},
     "60E8000000005D81ED........8DB5........555681C5........55C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CEXE, "1.0a", ""},
     "558BEC81EC0C02....56BE........8D85F8FEFFFF56506A..FF15........8A8DF8FEFFFF33D284C98D85F8FEFFFF7416"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NCODE, "0.2", ""},
     "9066BE....6683FE..74..66B8....66BE....6683FE..74..6683E8..66BB....6683C3..66436681FB....74..6683F8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SCOBFUSCATOR, "", ""},
     "6033C98B1D........031D........8A041984C074..3C..74..34..880419413B0D........75..A1........0105........61FF25"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "0.71", ""},
     "9C60BD........01AD........FF..........6A..FF..........50502D........89..........5F8D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEDIMINISHER, "0.1", ""},
     "535152565755E8000000005D8BD581ED........2B95........81EA0B0000008995........80BD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTBJFNT, "1.1b", ""}, "EB01EA9CEB01EA53EB01EA51EB01EA52EB01EA56"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTBJFNT, "1.2 RC", ""}, "EB0269B183EC04EB03CD20EBEB01EB9CEB01EBEB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTBJFNT, "1.3", ""}, "EB033A4D3A1EEB02CD209CEB02CD20EB02CD2060"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "1.0", ""}, "E9........000000020000000C"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "1.1-1.2", ""}, "E9......FF0C"},  // TODO Check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR, "0.0.4.1", ""},
     "BF........83C9FF33C068........F2AEF7D1495168........E8110A000083C40C68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT, "2.0", ""}, "EB019AE8..000000EB019AE8....0000EB019AE8....0000EB01"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT, "1.0", ""},
     "B8........55506764FF360000676489260000BD4B484342B804000000CC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPT, "1.0", ""},
     "909060E8000000005D81ED........B91500000083C10483C101EB05EBFE83C756EB00EB00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR, "1.1", ""},
     "6A606810B54000E82E020000BF940000008BC7E822F4FFFF8965E88BF4893E56FF1510B040008B4E10890D00ED40008B4604"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_GIXPROTECTOR, "1.2", ""}, "60EB05E8EB044000EBFAE80A000000"},  // CHECK MSLRH
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "2.0.1.0-2.1.8.0", ""}, "83EC045053E801000000CC588BD840"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LAMECRYPT, "1.0", ""}, "60669CBB........80B3........904B83FBFF75F3669D61"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "1.1", ""}, "60E8000000005D81ED........B97B0900008BF7AC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.5", ""}, "6090EB22'ExeStealth'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.70-2.71", ""}, "EB0060EB00E8000000005D81ED"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.72-2.73", "Shareware"}, "EB00EB2F'Shareware - ExeStealth'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.74", "Shareware"}, "EB00EB17'Shareware - ExeStealth'00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.75", ""}, "906090E8000000005D81ED........B915000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.75a", "Shareware"}, "EB58'Shareware-Version ExeStealth'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.76", ""}, "EB65'ExeStealth V2 - www'"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.76", "Shareware"}, "EB..'ExeStealth V2 Shareware '"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR, "2.1.X", ""}, "E9........669C60508D88........8D90........8BDC8BE1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_RUST, "", "i686-pc-windows-msvc"}, "E8........E9........CCCCCCCCCC"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_RUST, "", "x86_64-pc-windows-msvc"},
     "4883EC28E8........4883C428E9........CCCCCCCC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ELECKEY, "2.00.X", ""}, "515257535556E8000000005BB8........2BD8"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ELECKEY, "2.00.X", ""},
     "41504151515257535556E8000000005B48B8................482BD8488BEB"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_TINYC, "", ""},
     "5589e581ec........908d45..50e8........83c4..b8........8945..b8........50e8........83c4"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_TINYC, "", ""}, "554889e54881ec........b8........8945..b8........4989c24c89d1e8"},

    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "ASPacker 2.12"}, "60E803000000E9EB045D4555C3E801"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "BJFNT 1.3"}, "EB033A4D3A1EEB02CD209CEB02CD20EB02CD2060"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "EXE Shield 0.3"}, "E8040000008360EB0C5DEB05"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "ExeCryptor 1.5.1"},
     "E8240000008B4C240CC70117000100C781B80000000000000031C089411489411880A1C1000000FEC3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "PC-Guard 4.xx"}, "FC5550E8000000005DEB01E360E803000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "PEBundle 2.x"},
     "9C60E802......33C08BC483C004938BE38B5BFC81EB........87DD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "PEX 0.99"}, "60E8........E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "SVKP_1.x"}, "60E8........5D81ED06......64A023"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "Yoda's Crypter1.2"},
     "60E8000000005D81ED........B9....00008DBD........8BF7"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "UPX 0.8x-1.2"}, "60BE........8DBE........5783"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "PECompact 1.4x"},
     "EB06..........C39C60E80200000033C08BC483C004"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "PE-Lock Phantasm 1.0"},
     "5557565251536681C3EB02EBFC6681C3EB02EBFC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "Obsidium 1.3.0.4"},
     "EB02....E825000000EB04........EB01..8B54240CEB01"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "Themida 1.8.0.0"},
     "B8........600BC074..E8000000005805..0000008038E975"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE, "", "Visual Basic 5.0-6.0"},
     "6800000000E8........C0EB0F000000300000004000000000000000485858E9"},
};
const qint32 _PE_entrypoint_records_size = sizeof(_PE_entrypoint_records);

NFD_Binary::SIGNATURE_RECORD _PE_entrypointExp_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEX, "0.99", ""}, "E9$$$$$$$$60E8$$$$$$$$83C404E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PKLITE32, "1.1", ""}, "68........68........68........E8$$$$$$$$558BECA1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW10, "1.0", ""},
     "33C0E9$$$$$$$$BE........AC91AD95AD92AD515687F297FCB2..33DBA4B3..FF55"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VISUALCCPP, "", ""}, "E8......00E9$$$$$$$$6A..68........E8"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VISUALCCPP, "", ""}, "4883EC28E8........4883C428E9$$$$$$$$48895C24"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VISUALCCPP, "", ""},
     "4883EC28E8........4883C428E9$$$$$$$$488BC44889580848897010488978184C896020"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XPACK, "0.97-0.98", ""}, "68........9C60E8$$$$$$$$E8$$$$$$$$5B5D833B00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XCOMP, "0.97-0.98", ""}, "68........9C60E8$$$$$$$$E8$$$$$$$$5B5D833B00"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.6.1", ""},
     "68########EB$$EB$$558BEC83EC..535657EB$$833D..........74"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.12b", ""}, "60E8$$$$$$$$5D4555C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.1x-2.39", ""}, "60E8$$$$$$$$8B2C2481ED........C3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEQUAKE, "0.06", ""},
     "E8$$$$$$$$5D81ED........8D75..56FF55..8DB5........5650FF55..8985........6A..68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH, "1.0.2", ""},
     "60E8$$$$$$$$5D81ED........8BBD........8B8D........B8........01E88030..83F9..74..817F..........75..8B57"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH, "1.0.3", ""},
     "60E8$$$$$$$$5D81ED........31C04083F0..403D........75..BE........EB..EB..8B85........83F8..75..31C001EE3D"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH, "1.0.7", ""},
     "558BEC87E55DE9$$$$$$$$558BEC83EC..5356576064A1........8B40..8945..64A1........C740"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCGUARD, "5.04-5.05", ""}, "FC5550E8000000005D60E8$$$$$$$$EB$$58EB$$40EB$$FFE0"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER, "1.X", ""}, "74$$74$$78$$68A2AF470159E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32, "1.02", ""},
     "E8000000005B83EB..EB$$85C073..F705................58EB$$56575550E8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CODEVEIL, "1.2", ""}, "E9$$$$$$$$E9$$$$$$$$8BFF60E8$$$$$$$$5EE8"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR, "1.5X", ""}, "E8$$$$$$$$31C064FF30648920CCC3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR, "2.2.4", ""},
     "E8$$$$$$$$E800000000............8B1C2481EB........B8........506A..68"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX, "2.3.3-2.6.4", ""},
     "E80000000060E8$$$$$$$$E8$$$$$$$$E8$$$$$$$$558BEC83EC..56576A..FF15........8945..68........6A..FF15"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX, "2.3.3-2.6.4", ""},
     "E80000000060E8$$$$$$$$E8$$$$$$$$8B4424..508B4424..50E8$$$$$$$$558BEC83EC..5356576A..FF15"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX, "2.0.0-2.3.0", ""},
     "60E8$$$$$$$$E8$$$$$$$$E8$$$$$$$$558BEC83EC..56576A..FF15........8945..68........6A..FF15"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX, "2.36", ""},
     "EB$$B8........8338..74..50FF70..FF3050830424..E8$$$$$$$$558BECA1........53568B75..85C0578BDE75..6A..68........68........FF15"},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX,                      "4.XX",             ""},
    //    "6A2868........E8$$$$$$$$68........64A100000000508B442410896C24108D6C24102BE05356578B45F88965E8"}, // TODO Check CAB
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD, "2.0.1", ""}, "60E8$$$$$$$$558BEC81C470FFFFFF535657"},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT,                     "",                 ""},
    //    "E8$$$$$$$$87..248D..........87..24E9$$$$$$$$60E9$$$$$$$$54E9$$$$$$$$E8$$$$$$$$87..24"},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT,                     "",                 ""},
    //    "E8$$$$$$$$87..248D..........87..24E9$$$$$$$$60EB$$54E9$$$$$$$$E8$$$$$$$$87..24"},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT,                     "",                 ""},
    //    "E9$$$$$$$$E8$$$$$$$$87..248D..........87..24E9$$$$$$$$60E9$$$$$$$$54E9$$$$$$$$E8$$$$$$$$87..24"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, "", ""}, "E8$$$$$$$$87..248D..........87..24E9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, "", ""}, "E9$$$$$$$$E8$$$$$$$$87..248D..........87..24E9"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER, "1.01", ""},
     "558BEC535657E8$$$$$$$$E8$$$$$$$$33C064FF30648920CCC3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_QRYPT0R, "1.0", ""}, "EB$$E8$$$$$$$$64FF3500000000"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DBPE, "2.33", ""}, "EB$$9C5557565251539CE8$$$$$$$$5D81ED"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESHIELD, "0.25-0.26", ""},
     "60E8$$$$$$$$5D83ED..EB$$8D....................8A....32..80....80....88......EB"},  // TODO Check!
    // VMProtect TODO Emul dynamic create signature
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "E9$$$$$$$$E9$$$$$$$$68........0F..$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$E9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "E9$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$E9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "E9$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$0F"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "0F..$$$$$$$$E9$$$$$$$$68........E9$$$$$$$$68........E9$$$$$$$$E9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, "E9$$$$$$$$68........E9$$$$$$$$9CE9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, "9CE9$$$$$$$$C70424........E9$$$$$$$$E9$$$$$$$$68........9C"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, "E9$$$$$$$$9CC70424........60E8$$$$$$$$E8"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "54E8$$$$$$$$60C70424........C7442424........9CC74424..........609C9C9C"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, "9C55C74424..........E8$$$$$$$$C70424........9CC74424"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "60C74424..........E9$$$$$$$$E8$$$$$$$$C74424..........FF7424..8D6424..E9"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, "53C70424........68........E8$$$$$$$$9C"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""},
     "9CE9$$$$$$$$C70424........68........53C74424..........9CC70424"},
};
const qint32 _PE_entrypointExp_records_size = sizeof(_PE_entrypointExp_records);

NFD_Binary::CONST_RECORD _PE_importhash_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KCRYPTOR, "0.11", ""}, 0x0b5c121dc, 0x4dbf4081},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "", ""}, 0x134c8cd1e, 0x29188619},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2, "0.18", ""}, 0x134c8cd1e, 0x29188619},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "", ""}, 0x134c8cd1e, 0x29188619},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FSG, "", ""}, 0x0ee8cb83a, 0xa4083f58},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR, "", ""}, 0x0ee8cb83a, 0xa4083f58},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SCPACK, "0.2", ""}, 0x184210a7f, 0x0faef25b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "1.XX-2.XX", ""}, 0x1eb276f62, 0xdb8fbb75},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR, "", ""}, 0xf8d21b48, 0x8137a62},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "1.XX-2.XX", ""}, 0x26d690da0, 0x2301e49c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_AHPACKER, "0.1", ""}, 0x263ed9b5a, 0x117f896a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASDPACK, "1.00", ""}, 0x55706e12, 0xc7af1b6},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASDPACK, "2.00", ""}, 0xc3068d5e, 0x3f603725},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.02", ""}, 0x1eb276f62, 0xdb8fbb75},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.03", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW10, "1.0", ""}, 0x13e215a53, 0x381aae8d},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "1.00", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPT, "1.0", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EXEFOG, "1.1", ""}, 0x13e215a53, 0xdf3c1e0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EXEFOG, "1.2", ""}, 0x134c8cd1e, 0x29188619},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR, "1.0", ""}, 0x1d6f34b26, 0x63fe4ff9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRUNCH, "1.0", ""}, 0x90c17bc0b, 0x5e67bbdd},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALLOY, "4.X", ""}, 0x6c83794a6, 0xc50dde33},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "", ""}, 0x347ecf0ec, 0x4acfe8ec},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DYAMAR, "1.3.5", ""}, 0xb3de9edba, 0x9346ebcd},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEX, "0.99", ""}, 0x312ac0c03, 0xbc79739a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_REVPROT, "0.1a", ""}, 0x312ac0c03, 0xbc79739a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR, "1.3X-1.4X", ""}, 0x22234c932, 0xc8f3a96f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_TPPPACK, "", ""}, 0x3f288856, 0xb8a07cc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER, "1.X", ""}, 0xa7382d76, 0x1303a51b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "1.0b", ""}, 0xa7382d76, 0x1303a51b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD, "1.12-1.16", ""}, 0xc485c9e2, 0xff2d65f9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD, "1.12-1.16", ""}, 0xc485c9e2, 0x860b9cf0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.2", ""}, 0x5b000b292, 0x66b35c6e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.2", ""}, 0x6f561d023, 0x32f4466c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.3", ""}, 0x5ca1becb0, 0x921d0280},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.3", ""}, 0x7441e5986, 0xf51eba68},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.3", ""}, 0x751f43a61, 0xbc84ce09},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.4.5.X", ""}, 0x50b93d55a, 0x3c705cae},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.4.5.X", ""}, 0x69e399a9b, 0x4d02e093},  // TODO Check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.4.5.X", ""}, 0x605d4706c, 0x958a9ea2},  // VB6
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.5.0.X", ""}, 0x50b93d55a, 0x7ababb5a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.5.0.X", ""}, 0x72af15d4f, 0x95ca15e4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.5.0.X", ""}, 0x76a19e5a5, 0xbd41da20},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.6", ""}, 0x5d589502a, 0xca58fa0c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "1.6.1", ""}, 0x177c840f4, 0x48ffd359},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR, "1.0", ""}, 0x3404eaa9b, 0x3789c118},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR, "", ""}, 0x231271f8e, 0x986028bf},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BAMBAM, "0.1-0.4", ""}, 0x241c3b6a6, 0x81a3d66b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT, "", ""}, 0x263ed9b5a, 0x117f896a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR, "0.1", ""}, 0x1db028dca, 0x50ca53fc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT, "2.3", ""}, 0x1db028dca, 0x50ca53fc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_JDPACK, "1.01", ""}, 0x240d976a2, 0x10c77c1b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER, "1.0", ""}, 0x241c3b6a6, 0xbf363f04},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, "", ""}, 0x241c3b6a6, 0xbf363f04},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR, "1.X", ""}, 0x9c94674d4, 0x6d738d20},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.0-1.4", ""}, 0x263ed9b5a, 0x117f896a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AFFILLIATEEXE, "1.0", "TEST"}, 0xaad68a6e94, 0xe7046691},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LARP64, "1.0.3", "TEST"}, 0x1a89b5f0f, 0xf44517d8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_VPACKER, "0.02.10", ""}, 0x3404eaa9b, 0x3789c118},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XCOMP, "0.97-0.98", ""}, 0x2f6afb438, 0xea1e66e4},
    //{{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PACKER,           XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT,                    "2.40-3.XX",        ""}, 0x1eb276f62,
    // 0xdb8fbb75},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "", ""}, 0x16a45c345, 0x108edf16},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NPACK, "", ""}, 0x2d86e7bf1, 0xd0c4c278},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEPACK, "0.99", ""}, 0x341f3f6e9, 0xeaf00a09},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PEPACK, "1.0", ""}, 0x3be698dd2, 0x41708a45},  // 0.99?
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK, "1.0", ""}, 0x42f4ff4ba, 0x00d0e26d},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK, "1.11", ""}, 0x385a630a6, 0xc1e807a4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK, "1.2-1.3", ""}, 0x473022e77, 0xa9e261a2},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_XPACK, "0.97-0.98", ""}, 0x22224caef, 0x2ac44dd2},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ORIEN, "", ""}, 0x16fde75ea, 0xb4923b63},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SDPROTECTORPRO, "", ""}, 0x193d36193, 0xcde019bc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER, "", ""},
     0x193d36193,
     0xcde019bc},  // XScanEngine::RECORD_NAME_SOFTDEFENDER??XScanEngine::RECORD_NAME_SDPROTECTORPRO
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPACKER, "", ""}, 0x27a6db491, 0xcee2ac8e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS, "1.2-1.4", ""}, 0x2b72496f4, 0x6bfc6671},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_32LITE, "0.03a", ""}, 0x20953b667, 0xf053f402},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.16", ""}, 0x286d926ce, 0x4f2ced58},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.17", ""}, 0x1eb276f62, 0xdb8fbb75},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.19-1.21", ""}, 0x231271f8e, 0x986028bf},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "1.20.1", ""}, 0x286d926ce, 0x69e04866},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.1", ""}, 0xb5ec8ac1, 0x54f51579},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "1.2", ""}, 0x4eb19904, 0x48ea1201},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "2.0", ""}, 0xc6f6fec9, 0x23333b97},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_QUICKPACKNT, "0.1", ""}, 0x22224caef, 0x3778aab9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLP, "0.7.4b", ""}, 0x193d36193, 0x30c63d98},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "0.90-0.91", ""}, 0x186ad3682, 0xbea416d1},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "0.92-0.94", ""}, 0x1917b3afe, 0x93312c2e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "0.97-0.971b", ""}, 0x13e443f64, 0xe6aa8495},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "0.975-1.10b3", ""}, 0x134c8cd1e, 0x29188619},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "1.10b7-1.34", ""}, 0x212cf28ad, 0xe4c11305},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE, "", ""}, 0x778a92ee8, 0x6f2c367e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_BLADEJOINER, "1.5", ""}, 0x1a905fabfb, 0x05877992},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_CELESTYFILEBINDER, "1.0", "C++ Dynamic library"}, 0x2625a9db1f, 0x7c76448a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_CELESTYFILEBINDER, "1.0", "C++ Static library"}, 0x245138f5a4, 0x8a50a75e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESHIELD, "0.25-0.26", ""}, 0x16410b804, 0xf922f724},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_POLYCRYPTPE, "", ""}, 0x2870982b, 0x15bfcac8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PUNISHER, "1.5 demo", ""}, 0x1f9e3b7a1, 0x12e15bcc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SECURESHADE, "1.8", ""}, 0x8c9f7bdc8, 0x21ce458d},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR, "", ""}, 0x1046a0029, 0xf3f52749},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "", ""}, 0x1046a0029, 0xf3f52749},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT, "", ""}, 0x1046a0029, 0xf3f52749},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_NJOINER, "0.1", ""}, 0x76b28c3da, 0x8c42943c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HIDEANDPROTECT, "1.016", ""}, 0x26ff222837, 0xb136eb55},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPACK, "0.0.3", ""}, 0x1d07e94aa3, 0x5c0a3750},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE, "1.XX-2.XX", ""}, 0x4d37b2166, 0x556688b8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE, "2.XX", ""}, 0x4e0ec6281, 0x87857386},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_EXEJOINER, "1.0", ""}, 0x6704c9452, 0x29aaa397},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR, "1.06", "TEST"}, 0x12261bcdc, 0xa8689d85},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CEXE, "1.0", ""}, 0xcda93f5a0, 0x6ad5f3a1},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CEXE, "1.0", ""}, 0xd97446c35, 0x95065b94},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CEXE, "1.0", ""}, 0xc45e50e8a, 0x55e66552},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEARMOR, "0.7X", ""}, 0x142446410, 0xb033da06},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH, "1.0.7", ""}, 0x15a6ef8c3, 0x3434f1fd},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "0.71", ""}, 0x186ad3682, 0xbea416d1},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEDIMINISHER, "0.1", ""}, 0x142446410, 0xbac6c7d8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_EXCELSIORJET, "", ""}, 0x9f62dc5b3, 0x1c8c807a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETREACTOR, "4.2", "Native"}, 0x2e307fb348, 0x4fe9aa21},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETREACTOR, "4.2", "Native"},
     0x2e307fb348,
     0xd840af73},  // TODO Check Version!
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32, "1.02", ""}, 0x16410b804, 0x9d19c97a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR, "2.1", ""}, 0x21261d3d4, 0xddadcc96},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR, "2.2-2.4", ""}, 0x2bf67e8e3, 0xf219fb92},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CODEVEIL, "1.2", ""}, 0x16931477, 0xfcb11e9f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT, "1.0", ""}, 0x22224caef, 0xb65bfd43},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR, "1.1", ""}, 0x30309e68ce, 0x56ce963e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_QRYPT0R, "1.0", ""}, 0x0, 0xffffffff},   // no import
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DBPE, "", ""}, 0x35cf072d7, 0x28aa164},  // TODO Check Version TODO Check

    // VB cryptors
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARCRYPT, "", ""}, 0x608b5ca5f, 0x27f8d01f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AGAINNATIVITYCRYPTER, "", ""}, 0x21bae50da1, 0xab934456},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WINGSCRYPT, "1.0", "TEST"}, 0x216906261a, 0x86d73370},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTRROADS, "1.0", "TEST"}, 0x216906261a, 0x86d73370},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TSTCRYPTER, "1.0", "TEST"}, 0x216906261a, 0x86d73370},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TURKOJANCRYPTER, "1.0", "TEST"}, 0x216906261a, 0x86d73370},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WHITELLCRYPT, "", "TEST"}, 0x27e360241a, 0x69740a38},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORTALTEAMCRYPTER2, "", "TEST"}, 0x27e360241a, 0x69740a38},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PUSSYCRYPTER, "1.0", "TEST"}, 0x27e360241a, 0x69740a38},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZELDACRYPT, "1.0", ""}, 0x27e360241a, 0xffacb503},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_BIOHAZARDCRYPTER, "", "TEST"}, 0x341d510008, 0x4c51ceec},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTABLESEDUCATION, "1.0", ""}, 0x379caa9586, 0x497a33ab},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTIC, "2.1", ""}, 0x2551095bcf, 0x28ee87cc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOZ, "3", "TEST"}, 0x32a797d70b, 0x9ce9bc9d},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DIRTYCRYPTOR, "", "TEST"}, 0x2d5043f921, 0x1278f5f4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KIAMSCRYPTOR, "1.4", "TEST"}, 0x2d5043f921, 0x1278f5f4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FAKUSCRYPTOR, "1.4", "TEST"}, 0x1c5896cc05, 0x660aa806},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FASTFILECRYPT, "1.6", ""}, 0x54fe70e1c, 0x12125e9a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FILESHIELD, "1.0", "TEST"}, 0x369ad56c1b, 0x907d472a},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_GHAZZACRYPTER, "1.0", ""}, 0x2de302f688, 0x1d13438c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_H4CKY0UORGCRYPTER, "", "TEST"}, 0x68ec019f4, 0x182303e5},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HACCREWCRYPTER, "", "TEST"}, 0x3161aded4d, 0x02d8fada},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HALVCRYPTER, "", "TEST"}, 0x3c92864a7, 0x1921b4b9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KGBCRYPTER, "1.0", "TEST"}, 0x8fdee2084, 0x12e6f129},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRATOSCRYPTER, "", "TEST"}, 0xFFFFFFFFFF, 0xFFFFFFFF},  // TODO
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KUR0KX2TO, "", "TEST"}, 0x36d46acf30, 0xcf3805f3},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERPRIVATE, "1.0", "TEST"}, 0x25a8480de5, 0x208c1618},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LIGHTNINGCRYPTERSCANTIME, "1.0", ""}, 0x24bfbff151, 0xea84dab2},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LUCYPHER, "1.1", "TEST"}, 0x202da672fb, 0x3343405e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MONEYCRYPTER, "1.0", "TEST"}, 0x353acba6b3, 0x53908533},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NOXCRYPT, "1.1", ""}, 0x36d2a71d08, 0x9b536657},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RDGTEJONCRYPTER, "0.1", "TEST"}, 0xFFFFFFFFFF, 0xFFFFFFFF},  // TODO
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RDGTEJONCRYPTER, "0.8", "TEST"}, 0x2c078d7e86, 0x3c328f0c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SMOKESCREENCRYPTER, "2.0", "TEST"}, 0x87606a2bd, 0xcfe4cd48},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SNOOPCRYPT, "1.0", "TEST"}, 0x8bb735ad5, 0x22823ed8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_STASFODIDOCRYPTOR, "1.0", "TEST"}, 0x339880106, 0xe8805018},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TURKISHCYBERSIGNATURE, "1.0", "TEST"}, 0x216ef51472, 0xfaacabe5},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_UNDOCRYPTER, "1.0", "TEST"}, 0x37b90cd5a, 0xaab92c4c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WLCRYPT, "1.0", ""}, 0xeaeea9a42, 0x0f0642ae},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WOUTHRSEXECRYPTER, "1.0", ""}, 0x1d8a9e5e20, 0xc9e08d88},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ROGUEPACK, "1.1", "TEST"}, 0xbb132a76d, 0xe23394a8},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ROGUEPACK, "3.3.1", "TEST"}, 0x855d9788c, 0x96ed2351},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "0.5X", ""}, 0x38eada856, 0x37df662a},  // TODO All versions
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ELECKEY, "2.00.X", ""}, 0x3552ed494, 0xccf98822},
    // Delphi cryptors
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASSCRYPTER, "1.0", "TEST"}, 0x12d94ca858, 0x36fb88c9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AASE, "1.0", ""}, 0xc06abc0fa, 0x77035a90},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ANSKYAPOLYMORPHICPACKER, "1.3", ""}, 0x120bc5fc6c, 0x50822fc0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ANSLYMPACKER, "", "TEST"}, 0xaf2e74867b, 0x51a4c42b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CIGICIGICRYPTER, "1.0", ""}, 0x12998dbdd9, 0xf75643a6},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FEARZCRYPTER, "1.0", ""}, 0x18fc31e7a1, 0xba67afd7},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FEARZPACKER, "0.3", ""}, 0xbeb44c9f3, 0xf7a7ee23},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_GKRIPTO, "1.0", "TEST"}, 0x105df99f74, 0x2d62ed5d},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HOUNDHACKCRYPTER, "1.0.4", "TEST"}, 0xc4b2710d8, 0x6c4aee3f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ICRYPT, "1.0", ""}, 0x151f5b424a, 0xdc6b4478},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_INFCRYPTOR, "", "TEST"}, 0x14921fe579, 0x06dfef0b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_UNDERGROUNDCRYPTER, "1.0", ""}, 0x14921fe579, 0x06dfef0b},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MALPACKER, "1.2", "TEST"}, 0xd0983ca0a, 0xb82a3f7c},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MINKE, "1.01", "TEST"}, 0x161bc831e3, 0xb1440658},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_OPENSOURCECODECRYPTER, "1.0", "TEST"}, 0x1e843722ad, 0x6061e509},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORTALTEAMCRYPTER, "", "TEST"}, 0x1e843722ad, 0x6061e509},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORUKCREWCRYPTERPRIVATE, "", "TEST"}, 0x1e843722ad, 0x6061e509},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MRUNDECTETABLE, "1.0", "TEST"}, 0x149b74637d, 0x2b12c49f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NIDHOGG, "1.0", "TEST"}, 0xda5d3bb1f, 0xa52e27cc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NME, "1.1", "TEST"}, 0x84313106b, 0x8d73a5b4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_OSCCRYPTER, "", "TEST"}, 0x1e67f9aa68, 0xc45e88cf},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_P0KESCRAMBLER, "1.2", "TEST"}, 0x14017ccc57, 0x6766361e},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PANDORA, "1.0", "TEST"}, 0x1aa111e7ea, 0x5ee89fbb},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PFECX, "0.1", ""}, 0x37c8dbb1e7, 0x161cb3f4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PICRYPTOR, "3.0", ""}, 0x22d7f64fb1, 0xfcde90f0},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_POKECRYPTER, "", "TEST"}, 0x3abfae0702, 0xb99acbcc},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PUBCRYPTER, "", "TEST"}, 0xFFFFFFFFFF, 0xFFFFFFFF},  // TODO
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SEXECRYPTER, "1.1", "TEST"}, 0x144c4ac3f1, 0xb1309fe4},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SIMCRYPTER, "", "TEST"}, 0x10c6960150, 0x3070a531},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SIMPLECRYPTER, "1.2", "TEST"}, 0x23932eb2ab, 0x01e5337f},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TGRCRYPTER, "1.0", "TEST"}, 0x1a0adc8c41, 0xc26df3a5},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEZONECRYPTER, "", "TEST"}, 0x316e900676, 0x67850921},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_UNKOWNCRYPTER, "1.0", ""}, 0x19d3b4b92a, 0xeb51c252},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WINDOFCRYPT, "1.0", ""}, 0x124c114b87, 0xf7c9cbe1},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WLGROUPCRYPTER, "", ""}, 0x13bf0f6720, 0xb0f58a0d},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_DCRYPTPRIVATE,                "0.9b",             "TEST"},
    //    0xde741440ed,   0x16bbbe82},
    //    {{0, XBinary::FT_PE32,      XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR,        XScanEngine::XScanEngine::RECORD_NAME_DALKRYPT,                     "1.0",              "TEST"},
    //    0xde741440ed,   0x16bbbe82},
};
const qint32 _PE_importhash_records_size = sizeof(_PE_importhash_records);
NFD_Binary::CONST_RECORD _PE_importhash_records_armadillo[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX-2.XX", ""}, 0x2973050b33, 0x1a0c885c},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX-2.XX", ""}, 0x2f2f1df1d1, 0x8623cf54},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.XX-3.XX", ""}, 0x3010e1d59e, 0x834a7ecf},  // Check
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.XX-3.XX", ""}, 0x48c1ac32d5, 0x3f2559bb},  // MSVCRT.dll
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.50Beta3", ""}, 0x31f48f8367, 0x59d53246},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.51", ""}, 0x32bbf3aafe, 0x5a037362},  // 2.51 28Feb2002
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX-2.XX", ""}, 0x32c7a9336f, 0x6762fc6d},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.52", ""}, 0x341358d6d9, 0xb256a26f},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX-2.XX", ""}, 0x35e237026a, 0x419bf128},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.52", ""}, 0x3606885219, 0x1d8a69ae},  // 2.52 05Apr2002 (Build 1164)
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.52", ""}, 0x3606885219, 0x15114198},  // 2.52 05Apr2002
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.74-1.84", ""}, 0x3635cf517b, 0xe6ce8a9e},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX", ""}, 0x3b258f0a90, 0xe4bcc578},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.XX", ""}, 0x3b6c8abc7b, 0x604ac20f},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.90", ""}, 0x3b6e96f260, 0x927ddbdb},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "1.91c", ""}, 0x3c61329b29, 0x7177627b},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.00", ""}, 0x3c61329b29, 0x412e26ca},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.53", ""}, 0x3d32f719da, 0x9de5348d},  // 2.53 15May2002 (Build 1232)
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.XX-3.XX", ""}, 0x3d983cd830, 0xa61b1778},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.60", ""}, 0x3fa882c0da, 0xaece7e99},   // 2.60 30Jul2002 (Build 1312)
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.60c", ""}, 0x404c97c5fa, 0x4470cea0},  // 2.60c 17Aug2002 (Build 1431)
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.XX-3.XX", ""}, 0x3fb526760f, 0x72359c40},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "2.XX-3.XX", ""}, 0x3fb526760f, 0xf9f173fb},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.00-3.10", ""}, 0x40666b9f00, 0x64c37e91},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.05", ""}, 0x43d1d2c52f, 0xac05a698},  // 3.05 06Jun2003
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.30a", ""}, 0x43d1d2c52f, 0x82883188},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.40", ""}, 0x4518d21e36, 0xff5cf01b},  // 3.40 21Oct2003
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.60", ""}, 0x4518d21e36, 0x228301a9},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.61", ""}, 0x4518d21e36, 0xb79df9fe},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.70", ""}, 0x4518d21e36, 0x774538e7},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.75 Beta-1.3", ""}, 0x4580f4b95c, 0x363baa89},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.75a", ""}, 0x4610da601a, 0x5a7b25e5},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.76a", ""}, 0x4b5345e36c, 0x5f6ae2cf},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.76", ""}, 0x4c0ed4e9ea, 0x251722e7},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.78", ""}, 0x4c0ed4e9ea, 0xccda289c},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "3.78", ""}, 0x4bdf485221, 0x21ff4a57},  // 3.78 22Sep2004
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.20", ""}, 0x4fc78bc010, 0x047e53e2},  // 4.20 23May2005
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.00-4.40", ""}, 0x4fc78bc010, 0x807db698},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.42-4.54", ""}, 0x508175d00e, 0xb50f60e8},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.48", ""}, 0x508175d00e, 0xb034772c},  // 4.48 14August2006
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.66", ""}, 0x508175d00e, 0x5ca4890e},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.66", ""}, 0x508175d00e, 0x1a14aa82},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "4.66", ""}, 0x506972b7dd, 0xd09a4dc7},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.02", ""}, 0x56fa69e1fe, 0xdb61d809},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.02", ""}, 0x56e266c9cd, 0xd756b3c1},  // 5.02 11-07-2007
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.20Beta1", ""}, 0x5670adeaf6, 0x1e178fd2},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.20", ""}, 0x5670adeaf6, 0xc791b70b},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.20", ""}, 0x56698f2e57, 0x56b916d1},  // 5.20 30-10-2007
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.40", ""}, 0x56fa69e1fe, 0x7b44517b},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "5.42", ""}, 0x56fa69e1fe, 0x503225ce},  // 5.42 20-02-2008
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.00Beta1", ""}, 0x56fa69e1fe, 0xf35bbfc1},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.00", ""}, 0x57770751cb, 0xd8505c97},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.04", ""}, 0x57770751cb, 0x65f6ce6f},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.60-7.00", ""}, 0x5cee9acb73, 0xa6f43b6d},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.24", ""}, 0x600594c96e, 0xad072543},  // 6.24 02-12-2008
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.40", ""}, 0x5f7a50e70b, 0x0ecbdf27},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.40", ""}, 0x5f7a50e70b, 0xae4aa460},  // 6.40 11-02-2009
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "6.60-7.00", ""}, 0x5d069de3a4, 0x34512142},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "7.20", ""}, 0x79deb2e3e4, 0x2a3627b7},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "8.60", ""}, 0x263ed9b5a, 0x804c7692},
};
const qint32 _PE_importhash_records_armadillo_size = sizeof(_PE_importhash_records_armadillo);

NFD_Binary::CONST_RECORD _PE_importpositionhash_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.59-0.93", ""}, 0, 0xd4fdcab1},     // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "0.94-1.93", "exe"}, 0, 0x1d51299a},  // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "1.94-2.03", "exe"}, 0, 0xb3318086},  // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "1.94-2.03", "dll"}, 0, 0x3778aab9},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "2.90-3.XX", "exe"}, 0, 0xf375ee03},               // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "2.90-3.XX", "dll"}, 0, 0xf737d853},               // Fixed
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "3.91+", "dll"}, 0, 0xf737d853},                   // Fixed // TODO Check!
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "3.91+", "exe"}, 0xFFFFFFFF, 0x82a048fc},            // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "3.91+", "dll"}, 0xFFFFFFFF, 0x554a1748},            // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "", ""}, 0, 0xf375ee03},                          // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.XX-2.XX", ""}, 0, 0x1272f45b},               // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "1.XX-2.XX", ""}, 0, 0x1272f45b},           // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MKFPACK, "", ""}, 0, 0x42b3e7f9},                       // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "", ""}, 0, 0x174efb84},                        // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PACKMAN, "0.0.0.1", ""}, 0, 0x174efb84},                // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PACKMAN, "1.0", ""}, 0, 0x69076a83},                    // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "1.30-1.40", ""}, 0, 0x9b3305ed},            // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "1.40-1.84", ""}, 0, 0xcc5b2a3c},            // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT, "2.40-3.XX", ""}, 0, 0x2652ce4f},            // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EXE32PACK, "1.3X-1.4X", ""}, 0, 0x174efb84},            // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EZIP, "1.0", ""}, 0xFFFFFFFF, 0x051946f7},              // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_JDPACK, "2.00", ""}, 0, 0xc002db0e},                    // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.2", ""}, 0, 0xb2a64858},                  // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.2", ""}, 0, 0x158af2d0},                  // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.2", ""}, 0, 0x49e8aa1f},                  // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.5", ""}, 0, 0xe9ea0851},                  // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.5", ""}, 0, 0x3344b95d},                  // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "3.5", ""}, 0, 0x586088f3},                  // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMA, "1.00-3.60", ""}, 0, 0xc002db0e},            // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMA, "2.XX", ""}, 0, 0xdd92de10},                 // TODO Check version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMA, "3.70+", ""}, 0, 0xd04c7a50},                // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_CRINKLER, "", ""}, 0, 0x0b0e1fbf},                      // TODO Check!!!
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCGUARD, "5.04-5.05", ""}, 0, 0x5a169c7a},           // TODO Check version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCGUARD, "5.04-5.05", ""}, 0, 0x0b0b2965},           // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR_KERNEL32, "1.4.5.X", ""}, 0, 0x427816ab},  // Fixed
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR_USER32, "1.4.5.X", ""}, 1, 0x0c16df2d},    // Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "1.70", ""}, 0xFFFFFFFF, 0x1ff3103f},       // 1.70.4 Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "1.70", "Max protection"}, 0xFFFFFFFF, 0x0c16df2d},  // 1.70.4 Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "2.0.3-2.13", ""},
     0xFFFFFFFF,
     0x9d12b153},  // 2.0.3-2.12 Fixed 2.09-2.13 no .vmp2
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "3.0.0", ""}, 0xFFFFFFFF, 0x1e5500c1},        // 3.0.0 beta Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "3.0.9", ""}, 0xFFFFFFFF, 0xc5fb6a4b},        // 3.0.9.695 Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "3.2.0-3.5.0", ""}, 0xFFFFFFFF, 0x5caa99c7},  // 3.2.0.976 Fixed
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "3.8", ""}, 0xFFFFFFFF, 0x66e03954},          // 3.8.4
};
const qint32 _PE_importpositionhash_records_size = sizeof(_PE_importpositionhash_records);

NFD_Binary::PE_RESOURCES_RECORD _PE_resources_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_VCL, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, true, "PACKAGEINFO", 0},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_VCL, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, true, "DVCLAL", 0},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETREACTOR, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, true, "__", 0},  // TODO
                                                                                                                                                                // Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_WXWIDGETS, "", ""},
     false,
     "",
     XPE_DEF::S_RT_MENU,
     true,
     "WXWINDOWMENU",
     0},  // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_GENTEEINSTALLER, "", ""},
     false,
     "",
     XPE_DEF::S_RT_RCDATA,
     true,
     "SETUP_TEMP",
     0},                                                                                                                                                   // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_SFX, XScanEngine::XScanEngine::RECORD_NAME_WINRAR, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, true, "STARTDLG", 0},    // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_SFX, XScanEngine::XScanEngine::RECORD_NAME_WINRAR, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, true, "LICENSEDLG", 0},  // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CIGICIGICRYPTER, "", ""},
     false,
     "",
     XPE_DEF::S_RT_RCDATA,
     true,
     "AYARLAR",
     0},  // TODO Version // TODO Check
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_ALCHEMYMINDWORKS, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, false, "", 4001},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_ALCHEMYMINDWORKS, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, false, "", 5001},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP, "", ""}, false, "", XPE_DEF::S_RT_RCDATA, false, "", 11111},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_CELESTYFILEBINDER, "", ""}, true, "RBIND", 0, false, "", (quint32)-1},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_JOINER, XScanEngine::XScanEngine::RECORD_NAME_NJOINER, "", ""}, true, "NJ", 0, false, "", (quint32)-1},
};
const qint32 _PE_resources_records_size = sizeof(_PE_resources_records);

// TODO Resource version

// TODO
NFD_Binary::STRING_RECORD _PE_exportExp_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VISUALCCPP, "", ""}, "^$"},
};
const qint32 _PE_exportExp_records_size = sizeof(_PE_exportExp_records);

// TODO import

// .snaker ??? tool
// .ultra custom packer?
NFD_Binary::STRING_RECORD _PE_sectionNames_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_12311134, "", "TEST"}, "Xiao"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ABCCRYPTOR, "", ""}, ".aBc  "},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT, "", ""}, ".perplex"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR, "1.0", ""}, ".alex"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALLOY, "", ""}, ".alloy32"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALIENYZE, "", ""}, ".alien"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2, "", ""}, "ANDpakk2"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASMGUARD, "2.XX", ""}, "ASMGUARD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "1.08-2.XX", ""}, ".adata"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_ASPACK, "2.XX", ""}, ".aspack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT, "", ""}, ".adata"},  // TODO Check Version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AVERCRYPTOR, "1.0-1.02", ""}, ".avc"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_AZPROTECT, "0001", ""}, "AZPR0001"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR, "1.0", ""}, ".BCPack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BAMBAM, "", ""}, ".bedrock"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "", ""}, "bero^fr "},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER, "", ""}, "packerBY"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_CHROMIUMCRASHPAD, "", ""}, "CPADinfo"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRUNCH, "1.0", ""}, "BitArts"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTER, "", ""}, "SCRYPT"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTER, "", ""}, "FCKCrypt"},  // TODO Check
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR, "", ""}, ".ccp3p"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DALKRYPT, "1.0", ""}, ".DalKiT"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_DEPACK, "", ""}, ".depack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT, "", ""}, ".dotfix"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETREACTOR, "2.XX", ""}, ".reacto"},  // TODO Check Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETREACTOR, "4.XX", ""}, ".sdata"},   // TODO Check Version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR, "", ""}, "DAStub"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DYAMAR, "1.3.5", ""}, ".dyamarC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_DYAMAR, "1.3.5", ""}, ".dyamarD"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ELECKEY, "2.00.X", ""}, ".sstb"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE, "1.XX-2.XX", ""}, "EPE0"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE, "1.XX-2.XX", ""}, "EPE1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMAVIRTUALBOX, "", ""}, ".enigma1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ENIGMAVIRTUALBOX, "", ""}, ".enigma2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EPROT, "0.01", ""}, "!eprot"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.0", ""}, "!EPack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK, "1.4", ""}, ".!ep"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_EXCELSIORJET, "", ""}, ".jidata"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_EXCELSIORJET, "", ""}, ".jedata"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.70-2.75", ""}, "ExeS"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH, "2.76", ""}, "rsrr"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "", ""}, ".ex_cod"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR, "", ""}, ".ex_rsc"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.02-1.04", ""}, ".FISHPEP"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER, "1.02-1.03", ""}, ".PEDATA"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD, "", ""}, ".FishPE"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_GIXPROTECTOR, "", ""}, ".guruX"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_GO, "1.XX", ""}, ".symtab"},  // TODO Check
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_GENTEEINSTALLER, "", ""}, ".gentee"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR, "0.1", ""}, "hmimys"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PETOOL, XScanEngine::XScanEngine::RECORD_NAME_HOODLUM, "", ""}, ".HOODLUM"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR, "", ""}, ".inq"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_JDPACK, "", ""}, ".jdpack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, "", ""}, ".Kaos12"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER, "", ""}, ".Kaos2 "},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KBYS, "", ""}, ".shoooo"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY, "", ""}, "kkrunchy"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.4-0.5", ""}, "_!_!_!_"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.2-0.5", ""}, "krypton"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_KRYPTON, "0.2-0.5", ""}, "YADO"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LAMECRYPT, "1.0", ""}, "lamecryp"},
    {{0, XBinary::FT_PE64, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_LARP64, "1.0.3", "TEST"}, ".LARP"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MASKPE, "2.0", ""}, ".MaskPE"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW10, "", ""}, ".decode"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MEW11SE, "", ""}, "MEW"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MOLEBOXULTRA, "", ""}, ".ultra"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH, "", ""}, ".nah"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "", ""}, ".MPRESS1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MPRESS, "", ""}, ".MPRESS2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_MSLRH, "", ""}, ".mslrh"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER, "1.0", ""}, ".naked1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER, "1.0", ""}, ".naked2"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, "", ""}, "NATIVES~"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, "", ""}, "CONFIG~"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, "", ""}, "CRYPT~"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NCODE, "", ""}, ".n-coder"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NEOLITE, "1.0", ""}, ".neolit"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT, "", ""}, ".Ncryo  "},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT, "", ""}, ".De-vir "},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NOSINSTALLER, "", ""}, ".nos"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NPACK, "", ""}, ".nPack"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "", ""}, ".nsp0"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "", ""}, ".nsp1"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "", ""}, ".nsp2"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_OREANSCODEVIRTUALIZER, "", ""}, ".vlizer"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs1"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs3"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs4"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs5"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs6"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK, "", ""}, "pcs7"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEARMOR, "0.7X", ""}, ".ccg"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE, "", ""}, "pebundle"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32, "1.02", ""}, ".ficken"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEDIMINISHER, "0.1", ""}, ".teraphy"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PELOCKNT, "", ""}, "PELOCKnt"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT, "1.0", ""}, "Pingvin"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT, "2.3", ""}, "okpack"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESHIELD, "0.25-0.26", ""}, "PESHiELD"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESHIELD, "0.25-0.26", ""}, "ANAKIN2K"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "", ""}, ".petite"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PETITE, "", ""}, "petite"},  // TODO Check version
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PUNISHER, "1.5 demo", ""}, "PUNiSHER"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_QT, "", ""}, ".qtmetad"},  // TODO Version 5.x Only?
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR, "", ""}, "RCryptor"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLP, "", ""}, ".rlp"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "", ""}, ".packed"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_RLPACK, "", ""}, ".RLPack"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SAFEENGINESHIELDEN, "", ""}, ".sedata"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SCPACK, "", ""}, ".scpack"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "", ""}, ".shrink0"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "", ""}, ".shrink1"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SHRINKER, "", ""}, ".shrink2"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER, "1.X", ""}, "SDPC"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER, "1.X", ""}, "SDPD"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER, "1.X", ""}, "SDPI"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS, "", ""}, "SoftComp"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_STARFORCE, "3.XX", ""}, ".sforce3"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_STARFORCE, "4.XX-5.XX", ""}, ".ps4"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_STONESPEENCRYPTOR, "", ""}, ".Stone"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR, "1.3X-1.4X", ""}, ".svkp "},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR, "1.1X", ""}, "SVKP"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TELOCK, "", ""}, "UPX!"},  // ???
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.X", ""}, ".imports"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.X", "Themida"}, ".themida"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.X", "Winlicense"}, ".winlice"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.X", ""}, ".loadcon"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.X", ""}, ".boot"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_TPPPACK, "", ""}, ".Np"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TTPROTECT, "", ""}, ".TTP"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "", ""}, ".UPX0"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "", ""}, ".UPX1"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_UPX, "", ""}, ".UPX2"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR, "1.X", ""}, "vcasm"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VIRTUALIZEPROTECT, "", ""}, "VProtect"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, ".vmp0"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, ".vmp1"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, ".vmp2"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT, "", ""}, ".vmp3"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PETOOL, XScanEngine::XScanEngine::RECORD_NAME_VMUNPACKER, "", ""}, ".dswlab"},      // TODO Check
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_WINKRIPT, "1.0", ""}, ".wkt0"},  // TODO Check!
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_WINUPACK, "", ""}, ".Upack"},       // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_WISE, "", ""}, ".WISE"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_WIXTOOLSET, "", ""}, ".wixburn"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODE, "", ""}, ".xcpad"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR, "", ""}, "CODE    "},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR, "", ""}, ".idata  "},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR, "", ""}, "XPROT   "},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XTREAMLOK, "", ""}, ".xlok"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PETOOL, XScanEngine::XScanEngine::RECORD_NAME_XVOLKOLAK, "", ""}, ".xvlk"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER, "1.X", ""}, "yC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "1.0b", ""}, "yC"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR, "", ""}, ".yP"},
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_YZPACK, "", ""}, ".yzpack"},
};
const qint32 _PE_sectionNames_records_size = sizeof(_PE_sectionNames_records);

NFD_Binary::STRING_RECORD _PE_dot_ansistrings_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DOTFUSCATOR, "", ""}, "DotfuscatorAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::XScanEngine::RECORD_NAME_VCL, "", ".NET"}, "Borland.Vcl.Types"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_VBNET, "", ""}, "Microsoft.VisualBasic"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_JSCRIPT, "", ""}, "Microsoft.JScript.Vsa"},
    //    {{0, XBinary::FT_PE,        XScanEngine::XScanEngine::RECORD_TYPE_TOOL,              XScanEngine::XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET,  "",                 ""},
    //    "Embarcadero."},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_YANO, "1.X", ""}, "YanoAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_AGILENET, "", ""}, "ObfuscatedByAgileDotNetAttribute"},
    //    {{0, XBinary::FT_PE,        XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::XScanEngine::RECORD_NAME_SKATERNET,                    "",             ""},
    //    "Skater_NET_Obfuscator"}, {1, XBinary::FT_PE,        XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::XScanEngine::RECORD_NAME_SKATERNET,                    "", ""},
    //    "RustemSoft.Skater"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_BABELNET, "3.X", ""}, "BabelAttribute"},  // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_BABELNET, "1.X-2.X", ""}, "BabelObfuscatorAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CLISECURE, "4.X-5.X", ""}, "ObfuscatedByCliSecureAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CLISECURE, "3.X", ""}, "CliSecureRd.dll"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CLISECURE, "3.X", ""}, "CliSecureRd64.dll"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_TOOL, XScanEngine::XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET, "XE*", ""}, "Borland.Studio.Delphi"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_TOOL, XScanEngine::XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET, "8", ""}, "Borland.Vcl.Types"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET, "", ""}, "CryptoObfuscator"},  // TODO Version, die
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DEEPSEA, "4.X", ""}, "DeepSeaObfuscator"},             // TODO Version, die
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_GOLIATHNET, "", ""}, "ObfuscatedByGoliath"},           // TODO Version, die
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_MACROBJECT, "", ""},
     "Obfuscated by Macrobject Obfuscator.NET"},                                                                                                          // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SOFTWAREZATOR, "", ""}, "ObfuscatedBySoftwareZatorAttribute"},  // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_NSPACK, "2.X-3.X", ".NET"}, "nsnet"},                                  // TODO Version
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DNGUARD, "", ""}, "ZYXDNGuarder"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DNGUARD, "", ""}, "HVMRuntm.dll"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETZ, "", ""}, "NetzStarter"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_MAXTOCODE, "", ""}, "InfaceMaxtoCode"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_PHOENIXPROTECTOR, "", ""}, "?1?.?9?.resources"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_SIXXPACK, "", ""}, "Sixxpack"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "SmartAssembly.Attributes"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "SmartAssembly.Attributes.PoweredByAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CONFUSER, "1.X", ""}, "ConfusedByAttribute"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SPICESNET, "", ""}, "NineRays.Obfuscator"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_OBFUSCATORNET2009, "", ""}, "Macrobject.Obfuscator"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD, "2.X-3.X", ""},
     "Xenocode.Client.Attributes.AssemblyAttributes"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CODEVEIL, "4.X", ""}, "____KILL"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSPIDER, "0.5-1.3", ""}, "NETSpider.Attribute"},
    //    {{0, XBinary::FT_PE,        XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::XScanEngine::RECORD_NAME_EAZFUSCATOR,                  "",                 ""},
    //    "value__"},
};
const qint32 _PE_dot_ansistrings_records_size = sizeof(_PE_dot_ansistrings_records);

NFD_Binary::STRING_RECORD _PE_dot_unicodestrings_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_CODEVEIL, "3.X-4.X", ""}, "E_TamperDetected"}};
const qint32 _PE_dot_unicodestrings_records_size = sizeof(_PE_dot_unicodestrings_records);

NFD_Binary::SIGNATURE_RECORD _PE_codesection_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::XScanEngine::RECORD_NAME_GO, "1.X", ""}, "FF' Go build ID: '22"},
};
const qint32 _PE_codesection_records_size = sizeof(_PE_codesection_records);

NFD_Binary::SIGNATURE_RECORD _PE_entrypointsection_records[] = {
    {{0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_MASKPE, "2.0", ""}, "6160E8........8BC33E8B..40E8"},
};
const qint32 _PE_entrypointsection_records_size = sizeof(_PE_entrypointsection_records);

NFD_Binary::SIGNATURE_RECORD _PE_dot_codesection_records[] = {
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_OBFUSCAR, "1.0", ""}, "0691066120AA00000061D29C0617580A"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SKATER, "", ""}, "'RustemSoft.Skater'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET, "5.X", ""}, "000220....000A20FFFFFF0028........2A"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET, "5.X", ""},
     "0291203FFFFFFF5F1F18620A067E........021758911F1062600A067E"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_CODEWALL, "4.X", ""},
     "9161D281........11..175813..11..11..32..28........11..6F........13..7E........2D..73"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_EAZFUSCATOR, "", ""}, "2072FFFF0F5F20841A000061"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_PHOENIXPROTECTOR, "1.7-1.8", ""},
     "0000010B160C..........0208..........0D0906085961D21304091E630861D21305070811051E62110460D19D081758"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_SIXXPACK, "2.4", ""}, "0021......'xpack!'00................'xpack'00"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_RENETPACK, "2.0-3.X", ""}, "'Protected/Packed with ReNET-Pack by stx'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSHRINK, "2.01 Demo", "Password"},
     "20FE2B136028........13..203B28136028........13..11..11..161F4028........26"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSHRINK, "2.01 Demo", "Password"},
     "20AD65133228........13..206866133228........13..11..11..161F4028........26"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSHRINK, "2.01 Demo", ""},
     "20B9059F0728........13..2066059F0728........13..11..11..161F4028........26"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSHRINK, "2.01 Demo", ""},
     "20E6EA19BE28........13..2039EA19BE28........13..11..11..161F4028........26"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETSPIDER, "0.5-1.3", ""}, "'NETSpider.Attribute'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::XScanEngine::RECORD_NAME_DOTNETZ, "", ""}, "00'NetzStarter'00'netz'00"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_DEEPSEA, "4.X", ""}, "'DeepSeaObfuscator'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "'Powered by SmartAssembly '"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "'Powered by {smartassembly}'"},
    {{0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::XScanEngine::RECORD_NAME_FISHNET, "", ""}, "0800'FISH_NET'"},
};
const qint32 _PE_dot_codesection_records_size = sizeof(_PE_dot_codesection_records);

NFD_PE::NFD_PE(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct) : PE_Script(pPE, filePart, pOptions, pPdStruct)
{
}

// Getters - SIGNATURE_RECORD
NFD_Binary::SIGNATURE_RECORD *NFD_PE::getHeaderRecords()
{
    return _PE_header_records;
}
qint32 NFD_PE::getHeaderRecordsSize()
{
    return _PE_header_records_size;
}

NFD_Binary::SIGNATURE_RECORD *NFD_PE::getEntrypointRecords()
{
    return _PE_entrypoint_records;
}
qint32 NFD_PE::getEntrypointRecordsSize()
{
    return _PE_entrypoint_records_size;
}

NFD_Binary::SIGNATURE_RECORD *NFD_PE::getEntrypointExpRecords()
{
    return _PE_entrypointExp_records;
}
qint32 NFD_PE::getEntrypointExpRecordsSize()
{
    return _PE_entrypointExp_records_size;
}

NFD_Binary::SIGNATURE_RECORD *NFD_PE::getCodeSectionRecords()
{
    return _PE_codesection_records;
}
qint32 NFD_PE::getCodeSectionRecordsSize()
{
    return _PE_codesection_records_size;
}

NFD_Binary::SIGNATURE_RECORD *NFD_PE::getEntrypointSectionRecords()
{
    return _PE_entrypointsection_records;
}
qint32 NFD_PE::getEntrypointSectionRecordsSize()
{
    return _PE_entrypointsection_records_size;
}

NFD_Binary::SIGNATURE_RECORD *NFD_PE::getDotCodeSectionRecords()
{
    return _PE_dot_codesection_records;
}
qint32 NFD_PE::getDotCodeSectionRecordsSize()
{
    return _PE_dot_codesection_records_size;
}

// Getters - CONST_RECORD
NFD_Binary::CONST_RECORD *NFD_PE::getImportHashRecords()
{
    return _PE_importhash_records;
}
qint32 NFD_PE::getImportHashRecordsSize()
{
    return _PE_importhash_records_size;
}

NFD_Binary::CONST_RECORD *NFD_PE::getImportHashArmadilloRecords()
{
    return _PE_importhash_records_armadillo;
}
qint32 NFD_PE::getImportHashArmadilloRecordsSize()
{
    return _PE_importhash_records_armadillo_size;
}

NFD_Binary::CONST_RECORD *NFD_PE::getImportPositionHashRecords()
{
    return _PE_importpositionhash_records;
}
qint32 NFD_PE::getImportPositionHashRecordsSize()
{
    return _PE_importpositionhash_records_size;
}

// Getters - PE_RESOURCES_RECORD
NFD_Binary::PE_RESOURCES_RECORD *NFD_PE::getResourcesRecords()
{
    return _PE_resources_records;
}
qint32 NFD_PE::getResourcesRecordsSize()
{
    return _PE_resources_records_size;
}

// Getters - STRING_RECORD
NFD_Binary::STRING_RECORD *NFD_PE::getExportExpRecords()
{
    return _PE_exportExp_records;
}
qint32 NFD_PE::getExportExpRecordsSize()
{
    return _PE_exportExp_records_size;
}

NFD_Binary::STRING_RECORD *NFD_PE::getSectionNamesRecords()
{
    return _PE_sectionNames_records;
}
qint32 NFD_PE::getSectionNamesRecordsSize()
{
    return _PE_sectionNames_records_size;
}

NFD_Binary::STRING_RECORD *NFD_PE::getDotAnsiStringsRecords()
{
    return _PE_dot_ansistrings_records;
}
qint32 NFD_PE::getDotAnsiStringsRecordsSize()
{
    return _PE_dot_ansistrings_records_size;
}

NFD_Binary::STRING_RECORD *NFD_PE::getDotUnicodeStringsRecords()
{
    return _PE_dot_unicodestrings_records;
}
qint32 NFD_PE::getDotUnicodeStringsRecordsSize()
{
    return _PE_dot_unicodestrings_records_size;
}

void NFD_PE::PE_handle_import(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_PE::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)
    // Import Check

    // #ifdef QT_DEBUG
    //     for(qint32 j=0;j<pPEInfo->listImports.count();j++)
    //     {
    //         for(qint32 i=0;i<pPEInfo->listImports.at(j).listPositions.count();i++)
    //         {
    //             qDebug("(pPEInfo->listImports.at(%d).listPositions.at(%d).sName==\"%s\")&&",j,i,pPEInfo->listImports.at(j).listPositions.at(i).sName.toLatin1().data());
    //         }
    //     }
    // #endif

    QSet<QString> stDetects;

    if (pPEInfo->listImports.count() >= 1) {
        if (pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 2) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "LoadLibraryA")) {
                    stDetects.insert("kernel32_zprotect");
                }
            } else if (pPEInfo->listImports.at(0).listPositions.count() == 13) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(0).listPositions.at(3).sName == "VirtualFree") &&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName == "ExitProcess") && (pPEInfo->listImports.at(0).listPositions.at(5).sName == "CreateFileA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName == "CloseHandle") && (pPEInfo->listImports.at(0).listPositions.at(7).sName == "WriteFile") &&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName == "GetSystemDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName == "GetFileTime") && (pPEInfo->listImports.at(0).listPositions.at(10).sName == "SetFileTime") &&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName == "GetWindowsDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(12).sName == "lstrcatA")) {
                    if (pPEInfo->listImports.count() == 1) {
                        stDetects.insert("kernel32_alloy0");
                    }
                }
            } else if (pPEInfo->listImports.at(0).listPositions.count() == 15) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(0).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(0).listPositions.at(3).sName == "VirtualFree") &&
                    (pPEInfo->listImports.at(0).listPositions.at(4).sName == "ExitProcess") && (pPEInfo->listImports.at(0).listPositions.at(5).sName == "CreateFileA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(6).sName == "CloseHandle") && (pPEInfo->listImports.at(0).listPositions.at(7).sName == "WriteFile") &&
                    (pPEInfo->listImports.at(0).listPositions.at(8).sName == "GetSystemDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(9).sName == "GetFileTime") && (pPEInfo->listImports.at(0).listPositions.at(10).sName == "SetFileTime") &&
                    (pPEInfo->listImports.at(0).listPositions.at(11).sName == "GetWindowsDirectoryA") &&
                    (pPEInfo->listImports.at(0).listPositions.at(14).sName == "GetTempPathA")) {
                    stDetects.insert("kernel32_alloy2");
                }
            }
        } else if (pPEInfo->listImports.at(0).sName.toUpper() == "USER32.DLL") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).sName == "MessageBoxA")) {
                    if (pPEInfo->listImports.count() == 2) {
                        stDetects.insert("user32_pespina");
                    }

                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("user32_pespin");
                    }
                }
            }
        } else if (pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32") {
            if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(0).listPositions.at(0).nOrdinal == 1)) {
                    if (pPEInfo->listImports.count() == 1) {
                        stDetects.insert("kernel32_yzpack_b");
                    }
                }
            }
        }
    }

    if (pPEInfo->listImports.count() >= 2) {
        if (pPEInfo->listImports.at(1).sName.toUpper() == "COMCTL32.DLL") {
            if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                if ((pPEInfo->listImports.at(1).listPositions.at(0).sName == "InitCommonControls")) {
                    if (pPEInfo->listImports.count() == 2) {
                        stDetects.insert("comctl32_pespina");
                    }

                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("comctl32_pespin");
                    }
                }
            }
        }
    }

    if (pPEInfo->listImports.count() >= 3) {
        if (pPEInfo->listImports.at(2).sName.toUpper() == "KERNEL32.DLL") {
            if (pPEInfo->listImports.at(2).listPositions.count() == 2) {
                if ((pPEInfo->listImports.at(2).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName == "GetProcAddress")) {
                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("kernel32_pespinx");
                    }
                }
            } else if (pPEInfo->listImports.at(2).listPositions.count() == 4) {
                if ((pPEInfo->listImports.at(2).listPositions.at(0).sName == "LoadLibraryA") &&
                    (pPEInfo->listImports.at(2).listPositions.at(1).sName == "GetProcAddress") &&
                    (pPEInfo->listImports.at(2).listPositions.at(2).sName == "VirtualAlloc") && (pPEInfo->listImports.at(2).listPositions.at(3).sName == "VirtualFree")) {
                    if (pPEInfo->listImports.count() == 3) {
                        stDetects.insert("kernel32_pespin");
                    }
                }
            }
        }
    }

#ifdef QT_DEBUG
    qDebug() << stDetects;
#endif

    // TODO 32/64
    if (stDetects.contains("kernel32_zprotect")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, NFD_Binary::getScansStruct(0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, "", "", 0));
    }

    if (stDetects.contains("user32_pespina") && stDetects.contains("comctl32_pespina")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_PESPIN, NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESPIN, "1.0-1.2", "", 0));
    }

    if (stDetects.contains("user32_pespin") && stDetects.contains("comctl32_pespin") && stDetects.contains("kernel32_pespin")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_PESPIN, NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESPIN, "", "", 0));
    }

    if (stDetects.contains("user32_pespin") && stDetects.contains("comctl32_pespin") && stDetects.contains("kernel32_pespinx")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_PESPIN, NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_PESPIN, "1.3X", "", 0));
    }

    if (stDetects.contains("kernel32_alloy0")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_ALLOY, NFD_Binary::getScansStruct(0, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALLOY, "4.X", "", 0));
    }

    if (stDetects.contains("kernel32_alloy2")) {
        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::XScanEngine::RECORD_NAME_ALLOY, NFD_Binary::getScansStruct(2, XBinary::FT_PE32, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ALLOY, "4.X", "", 0));
    }

    //    if(stDetects.contains("kernel32_pecompact2"))
    //    {
    //        pPEInfo->basic_info.mapImportDetects.insert(XScanEngine::RECORD_NAME_PECOMPACT,NFD_Binary::getScansStruct(0,XBinary::FT_PE,XScanEngine::RECORD_TYPE_PACKER,XScanEngine::RECORD_NAME_PECOMPACT,"2.X","",0));
    //    }

    // TODO
    // Import
}

void NFD_PE::PE_handle_OperationSystem(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_PE::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(pe.getFileFormatInfo(pPdStruct));

        pPEInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssOperationSystem));
    }
}

void NFD_PE::PE_handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_PE::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // MPRESS
        if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MPRESS)) {
            _SCANS_STRUCT recordMPRESS = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MPRESS);

            qint64 nOffsetMPRESS = pe.find_ansiString(0x1f0, 16, "v", pPdStruct);

            if (nOffsetMPRESS != -1) {
                // TODO Check!
                recordMPRESS.sVersion = pe.read_ansiString(nOffsetMPRESS + 1, 0x1ff - nOffsetMPRESS);
            }

            pPEInfo->basic_info.mapResultPackers.insert(recordMPRESS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordMPRESS));
        }

        if (XPE::isImportLibraryPresent("KeRnEl32.dLl", &(pPEInfo->listImports))) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_HYPERTECHCRACKPROOF, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Spoon Studio
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Spoon Studio 2011")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SPOONSTUDIO2011, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ", ".");
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Spoon Studio")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SPOONSTUDIO, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            ss.sVersion.replace(", ", ".");
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2009")) {
            // Xenocode Virtual Application Studio 2009
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2009, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010 ISV Edition")) {
            // Xenocode Virtual Application Studio 2010 (ISV Edition)
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2010")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2010, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2012 ISV Edition")) {
            // Xenocode Virtual Application Studio 2012 (ISV Edition)
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2012ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Virtual Application Studio 2013 ISV Edition")) {
            // Xenocode Virtual Application Studio 2013 (ISV Edition)
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODEVIRTUALAPPLICATIONSTUDIO2013ISVEDITION, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Turbo Studio")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TURBOSTUDIO, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SPOONSTUDIO)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SPOONSTUDIO, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        } else if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XENOCODE)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_XENOCODE, "", "", 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("SerGreen")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_SERGREENAPPACKER, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // MoleBox Ultra
        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MOLEBOXULTRA)) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MOLEBOXULTRA)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MOLEBOXULTRA);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // NativeCryptor by DosX
        if (pPEInfo->listSectionNames.count() >= 3) {
            if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX)) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_NATIVECRYPTORBYDOSX, "", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ACTIVEMARK)) {
            _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ACTIVEMARK);
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ACTIVEMARK, ssOverlay.sVersion, ssOverlay.sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SECUROM)) {
            // TODO Version
            _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SECUROM);
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SECUROM, ssOverlay.sVersion, ssOverlay.sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ENIGMAVIRTUALBOX)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ENIGMAVIRTUALBOX);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ZLIB)) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = NFD_Binary::get_PyInstaller_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_PYINSTALLER, "", "", 0);

                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (!pPEInfo->cliInfo.bValid) {
            // TODO MPRESS import

            // UPX
            // TODO 32-64
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_UPX)) {
                VI_STRUCT viUPX = NFD_Binary::get_UPX_vi(pDevice, pOptions, pPEInfo->osHeader.nOffset, pPEInfo->osHeader.nSize, XBinary::FT_PE, pPdStruct);

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_UPX)) {
                    if ((viUPX.bIsValid)) {
                        _SCANS_STRUCT recordUPX = {};

                        recordUPX.type = XScanEngine::XScanEngine::RECORD_TYPE_PACKER;
                        recordUPX.name = XScanEngine::XScanEngine::RECORD_NAME_UPX;
                        recordUPX.sVersion = viUPX.sVersion;
                        recordUPX.sInfo = viUPX.sInfo;

                        pPEInfo->basic_info.mapResultPackers.insert(recordUPX.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordUPX));
                    } else {
                        _SCANS_STRUCT recordUPX = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_UPX);

                        recordUPX.sInfo = XBinary::appendComma(recordUPX.sInfo, "Modified");

                        pPEInfo->basic_info.mapResultPackers.insert(recordUPX.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordUPX));
                    }
                }
            }

            // EXPRESSOR
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR) || (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR_KERNEL32) &&
                                                                                                     pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR_USER32))) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXPRESSOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // ASProtect
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT)) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ASPROTECT);

                    pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }

            // PE-Quake
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEQUAKE)) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEQUAKE);

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }

            // MORPHNAH
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH)) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MORPHNAH);

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }

            // PECompact
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT)) {
                _SCANS_STRUCT recordPC = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT);

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PECOMPACT)) {
                    if (recordPC.nVariant == 1) {
                        recordPC.sVersion = "1.10b4-1.10b5";
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(recordPC.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordPC));
                } else {
                    VI_STRUCT viPECompact = SpecAbstract::PE_get_PECompact_vi(pDevice, pOptions, (SpecAbstract::PEINFO_STRUCT *)pPEInfo);

                    if (viPECompact.bIsValid) {
                        recordPC.sVersion = viPECompact.sVersion;
                        recordPC.sInfo = viPECompact.sInfo;

                        pPEInfo->basic_info.mapResultPackers.insert(recordPC.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordPC));
                    }
                }
            }

            // NSPack
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NSPACK)) {
                if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NSPACK)) {
                    _SCANS_STRUCT recordNSPack = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NSPACK);
                    pPEInfo->basic_info.mapResultPackers.insert(recordNSPack.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordNSPack));
                } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NSPACK)) {
                    _SCANS_STRUCT recordNSPack = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NSPACK);
                    pPEInfo->basic_info.mapResultPackers.insert(recordNSPack.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordNSPack));
                }
            }

            // ENIGMA
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ENIGMA)) {
                if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 nSectionOffset = pPEInfo->osImportSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osImportSection.nSize;

                    bool bDetect = false;

                    _SCANS_STRUCT recordEnigma = {};

                    recordEnigma.type = XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR;
                    recordEnigma.name = XScanEngine::XScanEngine::RECORD_NAME_ENIGMA;

                    if (!bDetect) {
                        VI_STRUCT viEngima = NFD_Binary::get_Enigma_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                        if (viEngima.bIsValid) {
                            recordEnigma.sVersion = viEngima.sVersion;
                            bDetect = true;
                        }
                    }

                    if (!bDetect) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ENIGMA)) {
                            recordEnigma.sVersion = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ENIGMA).sVersion;
                            bDetect = true;
                        }
                    }

                    if (bDetect) {
                        pPEInfo->basic_info.mapResultProtectors.insert(recordEnigma.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordEnigma));
                    }
                }
            }

            // Alienyze
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ALIENYZE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ALIENYZE);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // PESpin
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PESPIN)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PESPIN);

                // Get version
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PESPIN)) {
                    quint8 nByte = pPEInfo->sEntryPointSignature.mid(54, 2).toUInt(nullptr, 16);

                    switch (nByte) {
                        case 0x5C: ss.sVersion = "0.1"; break;
                        case 0xB7: ss.sVersion = "0.3"; break;
                        case 0x73: ss.sVersion = "0.4"; break;
                        case 0x83: ss.sVersion = "0.7"; break;
                        case 0xC8: ss.sVersion = "1.0"; break;
                        case 0x7D: ss.sVersion = "1.1"; break;
                        case 0x71: ss.sVersion = "1.3beta"; break;
                        case 0xAC: ss.sVersion = "1.3"; break;
                        case 0x88: ss.sVersion = "1.3x"; break;
                        case 0x17: ss.sVersion = "1.32"; break;
                        case 0x77: ss.sVersion = "1.33"; break;
                    }
                }

                pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // nPack
            // TODO Timestamp 'nPck'
            // TODO Check 64
            if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NPACK)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NPACK)) {
                    _SCANS_STRUCT recordNPACK = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NPACK);

                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "nPack v", pPdStruct);

                        if (nOffset_Version != -1) {
                            recordNPACK.sVersion = pe.read_ansiString(nOffset_Version + 7).section(":", 0, 0);
                        } else {
                            recordNPACK.sVersion = "1.1.200.2006";
                        }
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(recordNPACK.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordNPACK));
                }
            }

            if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ELECKEY)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ELECKEY);

                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ELECKEY)) {
                    ss.sInfo = XBinary::appendComma(ss.sInfo, "Section");
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ELECKEY)) {
                    ss.sInfo = XBinary::appendComma(ss.sInfo, "Import");
                }

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Oreans CodeVirtualizer
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_OREANSCODEVIRTUALIZER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_OREANSCODEVIRTUALIZER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->nOverlaySize) {
                qint64 nSize = pPEInfo->nOverlaySize;

                if (!pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                    nSize = qMin(pPEInfo->nOverlaySize, (qint64)0x100);
                }

                if (pe.find_signature(pPEInfo->nOverlaySize, nSize, "'asmg-protected'00", nullptr, pPdStruct) != -1) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASMGUARD, "2.XX", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASMGUARD)) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ASMGUARD, "2.XX", "", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (!pPEInfo->bIs64) {
                // MaskPE
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MASKPE)) {
                    if (pPEInfo->basic_info.mapEntryPointSectionDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MASKPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointSectionDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MASKPE);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PE-Armor
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEARMOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEARMOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEARMOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DalCrypt
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DALKRYPT))  // TODO more checks!
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DALKRYPT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // N-Code
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NCODE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NCODE);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // LameCrypt
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_LAMECRYPT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_LAMECRYPT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // SC Obfuscator
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SCOBFUSCATOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SCOBFUSCATOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PCShrink
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PCSHRINK);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DragonArmor
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DRAGONARMOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // NoodleCrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NOODLECRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PEnguinCrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PENGUINCRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXECrypt
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXECRYPT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXECRYPT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXECRYPT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXE Password Protector
                // TODO Manifest name: Microsoft.Windows.ExeProtector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXEPASSWORDPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXESTEALTH);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PE Diminisher
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEDIMINISHER)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEDIMINISHER);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // G!X Protector
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GIXPROTECTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_GIXPROTECTOR);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PC Guard
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PCGUARD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PCGUARD)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PCGUARD);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Soft Defender
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SOFTDEFENDER);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PECRYPT32
                // TODO Check!!!
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PECRYPT32);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EXECryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXECRYPTOR);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // YZPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YZPACK)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YZPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_YZPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // BCPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR))  // TODO !!!
                    {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // CRYPToCRACks PE Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CRYPTOCRACKPEPROTECTOR);
                    }

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ZProtect
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NOSTUBLINKER)) {
                        if (pPEInfo->listSectionRecords.count() >= 2) {
                            if (pe.compareSignature(&(pPEInfo->basic_info.memoryMap), "'kernel32.dll'00000000'VirtualAlloc'00000000",
                                                    pPEInfo->listSectionRecords.at(1).nOffset)) {
                                _SCANS_STRUCT recordZProtect = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, "1.3-1.4.4", "", 0);
                                pPEInfo->basic_info.mapResultProtectors.insert(recordZProtect.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordZProtect));
                            }
                        }
                    }
                } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                if (!pPEInfo->basic_info.mapResultProtectors.contains(XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NOSTUBLINKER)) {
                        if (pPEInfo->listSectionRecords.count() >= 2) {
                            if ((pPEInfo->listSectionHeaders.at(0).PointerToRawData == 0) && (pPEInfo->listSectionHeaders.at(0).SizeOfRawData == 0) &&
                                (pPEInfo->listSectionHeaders.at(0).Characteristics == 0xe00000a0)) {
                                bool bDetect1 = (pPEInfo->nEntryPointSection == 1);
                                bool bDetect2 = (pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, pPEInfo->listSectionRecords.at(2).nOffset,
                                                                    pPEInfo->listSectionRecords.at(2).nSize, pPdStruct) > 7.6);

                                if (bDetect1 || bDetect2) {
                                    _SCANS_STRUCT recordZProtect = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ZPROTECT, "1.XX", "", 0);
                                    pPEInfo->basic_info.mapResultProtectors.insert(recordZProtect.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordZProtect));
                                }
                            }
                        }
                    }
                }

                // ExeFog
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXEFOG)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXEFOG);

                    if ((pPEInfo->fileHeader.TimeDateStamp == 0) && (pPEInfo->optional_header.optionalHeader32.MajorLinkerVersion == 0) &&
                        (pPEInfo->optional_header.optionalHeader32.MinorLinkerVersion == 0) && (pPEInfo->optional_header.optionalHeader32.BaseOfData == 0x1000)) {
                        if (pPEInfo->listSectionHeaders.count()) {
                            if (pPEInfo->listSectionHeaders.at(0).Characteristics == 0xe0000020) {
                                pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // AHPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AHPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AHPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_AHPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // 12311134
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_12311134))  // TODO Check!
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_12311134);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AZProtect
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AZPROTECT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_AZPROTECT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AverCryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AVERCRYPTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AVERCRYPTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_AVERCRYPTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // WinKript
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_WINKRIPT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_WINKRIPT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // AffilliateEXE
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_AFFILLIATEEXE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_AFFILLIATEEXE);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // Advanced UPX Scrammbler
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_UPX)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ADVANCEDUPXSCRAMMBLER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ADVANCEDUPXSCRAMMBLER);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // BeRoEXEPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER);

                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER)) {
                            ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GENERIC)) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_BEROEXEPACKER);
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // Winupack
                if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_WINUPACK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_WINUPACK);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_WINUPACK)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_WINUPACK);
                    }

                    //                    recordWinupack.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(((pPEInfo->nMinorLinkerVersion)/16)*10+(pPEInfo->nMinorLinkerVersion)%16);

                    qint32 nBuildNumber = 0;

                    if ((ss.nVariant == 1) || (ss.nVariant == 2)) {
                        nBuildNumber = pPEInfo->nMinorLinkerVersion;
                    } else if ((ss.nVariant == 3) || (ss.nVariant == 4)) {
                        nBuildNumber = pPEInfo->nMinorImageVersion;
                    }
#ifdef QT_DEBUG
                    qDebug("nBuildNumber: %x", nBuildNumber);
#endif
                    switch (nBuildNumber) {
                        case 0x21: ss.sVersion = "0.21"; break;
                        case 0x22: ss.sVersion = "0.22"; break;
                        case 0x23: ss.sVersion = "0.23"; break;
                        case 0x24: ss.sVersion = "0.24"; break;
                        case 0x25: ss.sVersion = "0.25"; break;
                        case 0x26: ss.sVersion = "0.26"; break;
                        case 0x27: ss.sVersion = "0.27"; break;
                        case 0x28: ss.sVersion = "0.28"; break;
                        case 0x29: ss.sVersion = "0.29"; break;
                        case 0x30: ss.sVersion = "0.30"; break;
                        case 0x31: ss.sVersion = "0.31"; break;
                        case 0x32: ss.sVersion = "0.32"; break;
                        case 0x33: ss.sVersion = "0.33"; break;
                        case 0x34: ss.sVersion = "0.34"; break;
                        case 0x35: ss.sVersion = "0.35"; break;
                        case 0x36: ss.sVersion = "0.36 beta"; break;
                        case 0x37: ss.sVersion = "0.37 beta"; break;
                        case 0x38: ss.sVersion = "0.38 beta"; break;
                        case 0x39: ss.sVersion = "0.39 final"; break;
                        case 0x3A: ss.sVersion = "0.399"; break;
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ANDpakk2
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2) || pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2)) {
                    // TODO compare entryPoint and import sections TODO Check
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2)) {
                        _SCANS_STRUCT recordANFpakk2 = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ANDPAKK2);
                        pPEInfo->basic_info.mapResultPackers.insert(recordANFpakk2.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordANFpakk2));
                    }
                }

                // KByS
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KBYS)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KBYS)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_KBYS);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crunch
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRUNCH)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRUNCH)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CRUNCH);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // ASDPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASDPACK)) {
                    bool bDetected = false;
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ASDPACK);

                    if (pPEInfo->listSectionRecords.count() == 2) {
                        if (pPEInfo->bIsTLSPresent) {
                            bDetected = true;  // 1.00
                        }
                    }

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASDPACK)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ASDPACK);
                        bDetected = true;
                    }

                    if (bDetected) {
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // VPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_VPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_VPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_VPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // RLP
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_RLP)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_RLP)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_RLP);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crinkler
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRINKLER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRINKLER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CRINKLER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EZIP TODO CHECK
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EZIP)) {
                    if (pPEInfo->nOverlaySize) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EZIP);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // KKrunchy
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY) || pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GENERIC)) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY);

                            if (!pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KKRUNCHY)) {
                                ss.sInfo = "Patched";
                            }

                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // QuickPack NT
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_QUICKPACKNT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_QUICKPACKNT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_QUICKPACKNT);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // MKFPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MKFPACK)) {
                    qint64 mLfanew = pPEInfo->dosHeader.e_lfanew - 5;

                    if (mLfanew > 0) {
                        QString sSignature = pe.read_ansiString(mLfanew, 5);

                        if (sSignature == "llydd") {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MKFPACK);
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // 32lite
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_32LITE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_32LITE)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_32LITE);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EProt
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EPROT)) {
                    if (pPEInfo->nEntryPointSection > 0) {
                        if (pPEInfo->sEntryPointSectionName == "!eprot") {
                            quint32 nValue = pe.read_uint32(pPEInfo->osEntryPointSection.nOffset + pPEInfo->osEntryPointSection.nSize - 4);

                            if (nValue == 0x78787878) {
                                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EPROT);
                                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // RLPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_RLPACK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_RLPACK);

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_RLPACK)) {
                        ss.sInfo = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_RLPACK).sInfo;
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE)) {
                        if (pPEInfo->listSectionHeaders.count() >= 2) {
                            if (pPEInfo->listSectionHeaders.at(0).SizeOfRawData <= 0x200) {
                                ss.sInfo = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_FAKESIGNATURE).sInfo;
                                pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }

                // Packman
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PACKMAN)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PACKMAN)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PACKMAN);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Fish PE Packer
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_FISHPEPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Inquartos Obfuscator
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR) &&
                        pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GENERIC)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_INQUARTOSOBFUSCATOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Hide & Protect
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_HIDEANDPROTECT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_HIDEANDPROTECT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_HIDEANDPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // mPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // EncryptPE
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ENCRYPTPE);

                        qint64 _nOffset = pPEInfo->osHeader.nOffset;
                        qint64 _nSize = pPEInfo->osHeader.nSize;

                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "EncryptPE V", pPdStruct);

                        if (nOffset_Version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_Version + 11).section(",", 0, 0);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Yoda's Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_YODASPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Xtreme-Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_XTREMEPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // ACProtect 1.X-2.X
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT)) {
                    if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 nSectionOffset = pPEInfo->osImportSection.nOffset;
                        qint64 nSectionSize = pPEInfo->osImportSection.nSize;

                        qint64 nOffset1 = pe.find_array(nSectionOffset, nSectionSize, "MineImport_Endss", 16, pPdStruct);

                        if (nOffset1 != -1) {
                            _SCANS_STRUCT recordACProtect = {};
                            recordACProtect.type = XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR;
                            recordACProtect.name = XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT;

                            recordACProtect.sVersion = "1.XX-2.XX";

                            //                            qint64 nOffset2=pe.find_array(nSectionOffset,nSectionSize,"Randimize",9);

                            //                            if(nOffset2!=-1)
                            //                            {
                            //                                recordACProtect.sVersion="1.X";
                            //                            }

                            pPEInfo->basic_info.mapResultProtectors.insert(recordACProtect.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordACProtect));
                        }
                    }
                }

                // ACProtect
                // 2.0.X
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT))  // TODO CHECK
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ACPROTECT);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // FSG
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FSG)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FSG)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_FSG);

                        if (ss.nVariant == 0) {
                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        } else if (ss.nVariant == 1) {
                            if (pe.read_ansiString(0x154) == "KERNEL32.dll") {
                                ss.sVersion = "1.33";
                            } else {
                                ss.sVersion = "2.00";
                            }

                            pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }

                // MEW
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MEW10)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MEW10)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MEW10);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MEW11SE)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MEW11SE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MEW11SE);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Alex Protector
                // 2.0.X
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ALEXPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PEBundle
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEBUNDLE);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PE-SHiELD
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PESHIELD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PESHIELD)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PESHIELD);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PUNiSHER
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PUNISHER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PUNISHER)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PUNISHER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Shrinker
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SHRINKER)) {
                    if (pe.isImportFunctionPresentI("KERNEL32.DLL", "8", &(pPEInfo->listImports))) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SHRINKER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Secure Shade
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SECURESHADE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SECURESHADE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SECURESHADE);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PolyCrypt PE
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_POLYCRYPTPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_POLYCRYPTPE)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_POLYCRYPTPE);

                        if (pPEInfo->nImportSection == pPEInfo->nEntryPointSection) {
                            if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                                qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                                qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                                qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "PolyCrypt PE (c) 2004-2005, JLabSoftware.", pPdStruct);

                                if (nOffset_Version == -1) {
                                    recordSS.sInfo = "Modified";
                                }
                            }
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPROTECTOR);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT)) {
                    if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapHeaderDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEPACKSPROTECT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPACKER)) {
                    if (XPE::isSectionNamePresent(".hmimys", &(pPEInfo->listSectionRecords)))  // TODO Check, pdStruct
                    {
                        _SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PACKER, XScanEngine::XScanEngine::RECORD_NAME_HMIMYSPACKER, "", "", 0);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ORIEN)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ORIEN)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ORIEN);

                        QString sVersion = pPEInfo->sEntryPointSignature.mid(16, 2);

                        if (sVersion == "CE") {
                            recordSS.sVersion = "2.11";
                        } else if (sVersion == "CD") {
                            recordSS.sVersion = "2.12";
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Alloy 4.X
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ALLOY)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ALLOY)) {
                        // TODO compare entryPoint and import sections
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ALLOY);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PeX
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEX)) {
                    // TODO compare entryPoint and import sections
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEX)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEX);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // PEVProt
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_REVPROT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_REVPROT)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_REVPROT);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Software Compress
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SOFTWARECOMPRESS);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // SDProtector Pro
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SDPROTECTORPRO)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SDPROTECTORPRO)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SDPROTECTORPRO);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // Simple Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SIMPLEPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // NakedPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER) &&
                        (!pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER))) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_NAKEDPACKER);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // KaOs PE-DLL eXecutable Undetecter
                // the same as NakedPacker
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER) &&
                        pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_KAOSPEDLLEXECUTABLEUNDETECTER);
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // ASPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASPACK)) {
                    // TODO compare entryPoint and import sections
                    QString _sSignature = pPEInfo->sEntryPointSignature;
                    qint64 _nOffset = 0;
                    //                    QString _sVersion;

                    // TODO a function
                    // TODO emul !!!
                    while (XBinary::isPdStructNotCanceled(pPdStruct)) {
                        bool bContinue = false;

                        if (XBinary::compareSignatureStrings(_sSignature, "90")) {
                            bContinue = true;
                            _nOffset++;
                            _sSignature.remove(0, 2);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "7500")) {
                            bContinue = true;
                            _nOffset += 2;
                            _sSignature.remove(0, 4);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "7501")) {
                            bContinue = true;
                            _nOffset += 3;
                            _sSignature.remove(0, 6);
                        }

                        if (XBinary::compareSignatureStrings(_sSignature, "E9")) {
                            bContinue = true;
                            _nOffset++;
                            _sSignature.remove(0, 2);
                            qint32 nAddress = XBinary::hexToInt32(_sSignature);
                            _nOffset += 4;
                            // TODO image
                            qint64 nSignatureOffset = pe.addressToOffset(pPEInfo->nImageBaseAddress + pPEInfo->nEntryPointAddress + _nOffset + nAddress);

                            if (nSignatureOffset != -1) {
                                _sSignature = pe.getSignature(nSignatureOffset, 150);
                            } else {
                                break;
                            }
                        }

                        if (_nOffset) {
                            NFD_Binary::signatureScan(&(pPEInfo->basic_info.mapEntryPointDetects), _sSignature, NFD_PE::getEntrypointRecords(),
                                                      NFD_PE::getEntrypointRecordsSize(), pPEInfo->basic_info.id.fileType, XBinary::FT_PE, &(pPEInfo->basic_info),
                                                      DETECTTYPE_ENTRYPOINT, pPdStruct);
                            NFD_Binary::signatureExpScan(&pe, &(pPEInfo->basic_info.memoryMap), &(pPEInfo->basic_info.mapEntryPointDetects),
                                                         pPEInfo->nEntryPointOffset + _nOffset, NFD_PE::getEntrypointExpRecords(), NFD_PE::getEntrypointExpRecordsSize(),
                                                         pPEInfo->basic_info.id.fileType, XBinary::FT_PE, &(pPEInfo->basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
                        }

                        if (_nOffset > 20) {
                            break;
                        }

                        if (!bContinue) {
                            break;
                        }

                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASPACK)) {
                            break;
                        }
                    }

                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ASPACK)) {
                        _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ASPACK);
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }

                // No Import
                // WWPACK32
                // TODO false
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_WWPACK32)) {
                    _SCANS_STRUCT ss = {};

                    ss.type = XScanEngine::XScanEngine::RECORD_TYPE_PACKER;
                    ss.name = XScanEngine::XScanEngine::RECORD_NAME_WWPACK32;
                    ss.sVersion = XBinary::hexToString(pPEInfo->sEntryPointSignature.mid(102, 8));
                    // recordAndpakk.sInfo;

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // EXE Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EPEXEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EPROT)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EPROT);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // RCryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_RCRYPTOR);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // PE-PACK
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PEPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PEPACK);

                        if (pe.checkOffsetSize(pPEInfo->osImportSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            qint64 _nOffset = pPEInfo->osImportSection.nOffset;
                            qint64 _nSize = pPEInfo->osImportSection.nSize;

                            qint64 nOffset_PEPACK = pe.find_ansiString(_nOffset, _nSize, "PE-PACK v", pPdStruct);

                            if (nOffset_PEPACK != -1) {
                                ss.sVersion = pe.read_ansiString(nOffset_PEPACK + 9, 50);
                                ss.sVersion = ss.sVersion.section(" ", 0, 0);
                            }
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // PKLITE32
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_PKLITE32)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_PKLITE32);

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // MoleBox
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_MOLEBOX);

                    QString sComment = XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion));

                    if (sComment.contains("MoleBox ")) {
                        ss.sVersion = sComment.section("MoleBox ", 1, -1);
                    }

                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // XComp
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XCOMP)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XCOMP)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_XCOMP);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // XPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_XPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_XPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Krypton
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KRYPTON)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KRYPTON)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_KRYPTON);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // SVK Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SVKPROTECTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // TPP Pack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_TPPPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_TPPPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_TPPPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // VCasm-Protector
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR)) {
                    _SCANS_STRUCT ss = {};
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR)) {
                        ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR);
                    }

                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_VCASMPROTECTOR);

                        qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                        // TODO get max version
                        qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "vcasm_protect_", pPdStruct);

                        QString sVersionString;

                        if (nOffset_Version != -1) {
                            sVersionString = pe.read_ansiString(nOffset_Version).section("_", 2, -1);
                        }

                        if (sVersionString == "2004_11_30") {
                            ss.sVersion = "1.0";
                        }
                        if (sVersionString == "2005_3_18") {
                            ss.sVersion = "1.1-1.2";
                        }
                    }

                    if (ss.name != XScanEngine::XScanEngine::RECORD_NAME_UNKNOWN) {
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // JDPack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_JDPACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_JDPACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_JDPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Yoda's crypter
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_YODASCRYPTER);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // QrYPt0r
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_QRYPT0R)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_QRYPT0R)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_QRYPT0R);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DBPE
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DBPE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DBPE)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DBPE);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // FISH PE Shield
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_FISHPESHIELD);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // bambam
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BAMBAM)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_BAMBAM)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_BAMBAM);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // DotFix NeceProtect
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DOTFIXNICEPROTECT);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // The Best Cryptor [by FsK]
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_THEBESTCRYPTORBYFSK)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_THEBESTCRYPTORBYFSK);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // DYAMAR
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DYAMAR)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DYAMAR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DYAMAR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // CExe
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CEXE)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CEXE);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // K!Cryptor
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KCRYPTOR)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_KCRYPTOR)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_KCRYPTOR);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // Crypter
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CRYPTER)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_CRYPTER);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // Thinstall
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_THINSTALL))  // TODO Imports EP
                {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_THINSTALL);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (XPE::getResourcesVersionValue("ThinAppVersion", &(pPEInfo->resVersion)) != "") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THINSTALL, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ThinAppVersion", &(pPEInfo->resVersion)).trimmed();

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                } else if (XPE::getResourcesVersionValue("ThinstallVersion", &(pPEInfo->resVersion)) != "") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THINSTALL, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ThinstallVersion", &(pPEInfo->resVersion)).trimmed();

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }

                // ABC Cryptor
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ABCCRYPTOR)) {
                    _SCANS_STRUCT recordEP = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ABCCRYPTOR);

                    if ((pPEInfo->nEntryPointAddress - pPEInfo->listSectionHeaders.at(pPEInfo->nEntryPointSection).VirtualAddress) == 1) {
                        pPEInfo->basic_info.mapResultPackers.insert(recordEP.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordEP));
                    }
                }

                // exe 32 pack
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXE32PACK)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_EXE32PACK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_EXE32PACK);

                        qint64 _nOffset = pPEInfo->osHeader.nOffset;
                        qint64 _nSize = qMin(pPEInfo->basic_info.id.nSize, (qint64)0x2000);

                        qint64 nOffset_version = pe.find_ansiString(_nOffset, _nSize, "Packed by exe32pack", pPdStruct);

                        if (nOffset_version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_version + 20, 50);
                            ss.sVersion = ss.sVersion.section(" ", 0, 0);
                        }

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }

                // SC PACK
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SCPACK)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SCPACK)) {
                        if (pPEInfo->listSectionRecords.count() >= 3) {
                            if (pPEInfo->nEntryPointSection == 1) {
                                if (pPEInfo->listSectionHeaders.at(1).VirtualAddress == pPEInfo->nEntryPointAddress) {
                                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_SCPACK);

                                    pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                                }
                            }
                        }
                    }
                }

                // dePack
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_DEPACK)) {
                    if (pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$60")) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(XScanEngine::XScanEngine::RECORD_NAME_DEPACK);

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            } else {
                // Only 64
                // lARP64
                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_LARP64)) {
                    if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_LARP64)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_LARP64);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_VProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->nEntryPointSection > 0) {
                if (pPEInfo->sEntryPointSectionName == "VProtect")  // TODO !!!
                {
                    if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 nSectionOffset = pPEInfo->osEntryPointSection.nOffset;
                        qint64 nSectionSize = pPEInfo->osEntryPointSection.nSize;

                        qint64 nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "VProtect", pPdStruct);

                        if (nOffset_Version != -1) {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_VIRTUALIZEPROTECT, "", "", 0);

                            nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "VProtect Ultimate v", pPdStruct);

                            if (nOffset_Version != -1) {
                                ss.sVersion = pe.read_ansiString(nOffset_Version).section(" v", 1, 1);
                            }

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_TTProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImportPositionHashes.count() >= 1) {
                if (pPEInfo->listImportPositionHashes.at(0) == 0xf3f52749)  // TODO !!!
                {
                    if (pPEInfo->nEntryPointSection > 0) {
                        if (pPEInfo->sEntryPointSectionName == ".TTP")  // TODO !!!
                        {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_TTPROTECT, "", "", 0);

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_SafeengineShielden(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_SAFEENGINESHIELDEN)) {
                if (pPEInfo->nEntryPointSection > 0) {
                    if (pPEInfo->sEntryPointSectionName == ".sedata")  // TODO !!!
                    {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_SAFEENGINESHIELDEN, "2.XX", "", 0);

                        qint64 nSectionOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                        qint64 nSectionSize = pPEInfo->listSectionRecords.at(1).nSize;

                        qint64 nOffset_Version = pe.find_ansiString(nSectionOffset, nSectionSize, "Safengine Shielden v", pPdStruct);

                        if (nOffset_Version != -1) {
                            ss.sVersion = pe.read_ansiString(nOffset_Version).section(" v", 1, 1);
                        }

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_tElock(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImports.count() == 2) {
                bool bKernel32 = false;
                bool bUser32 = false;

                // TODO
                if (pPEInfo->listImports.at(0).sName == "kernel32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if (pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "GetModuleHandleA") {
                            bKernel32 = true;
                        }
                    }
                }
                if (pPEInfo->listImports.at(1).sName == "user32.dll") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "MessageBoxA")) {
                            bUser32 = true;
                        }
                    }
                }

                if (bKernel32 && bUser32) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_TELOCK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_TELOCK);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_Armadillo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bHeaderDetect = false;
            bool bImportDetect = false;

            if ((pPEInfo->nMajorLinkerVersion == 0x53) && (pPEInfo->nMinorLinkerVersion == 0x52)) {
                bHeaderDetect = true;
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            if (nNumberOfImports >= 3) {
                bImportDetect = ((pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") && (pPEInfo->listImports.at(1).sName.toUpper() == "USER32.DLL") &&
                                 (pPEInfo->listImports.at(2).sName.toUpper() == "GDI32.DLL")) ||
                                ((pPEInfo->listImports.at(0).sName.toUpper() == "KERNEL32.DLL") && (pPEInfo->listImports.at(1).sName.toUpper() == "GDI32.DLL") &&
                                 (pPEInfo->listImports.at(2).sName.toUpper() == "USER32.DLL"));
            }

            if (bImportDetect || bHeaderDetect) {
                bool bDetect = false;

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO, "", "", 0);

                if (pPEInfo->basic_info.mapImportDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO)) {
                    ss = pPEInfo->basic_info.mapImportDetects.value(XScanEngine::XScanEngine::RECORD_NAME_ARMADILLO);

                    bDetect = true;
                }

                if (bHeaderDetect) {
                    bDetect = true;
                }

                if (bDetect) {
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void NFD_PE::PE_handle_VMProtect(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_VMPROTECT);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void NFD_PE::PE_handle_Themida(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImports.count() == 1) {
                if (pPEInfo->listImports.at(0).sName == "kernel32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE);

                            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            } else if (pPEInfo->listImports.count() == 2) {
                bool bKernel32 = false;
                bool bComctl32 = false;

                // TODO
                if (pPEInfo->listImports.at(0).sName == "KERNEL32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 2) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "CreateFileA") ||
                            (pPEInfo->listImports.at(0).listPositions.at(1).sFunction == "lstrcpy")) {
                            bKernel32 = true;
                        }
                    }
                } else if (pPEInfo->listImports.at(0).sName == "kernel32.dll")  // TODO Check
                {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "lstrcpy")) {
                            bKernel32 = true;
                        }
                    }
                }

                if ((pPEInfo->listImports.at(1).sName == "COMCTL32.dll") || (pPEInfo->listImports.at(1).sName == "comctl32.dll")) {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "InitCommonControls")) {
                            bComctl32 = true;
                        }
                    }
                }

                if (bKernel32 && bComctl32) {
                    // TODO Version
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "1.XX-2.XX", "", 0);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (!pPEInfo->basic_info.mapResultProtectors.contains(XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE)) {
                // New version
                qint32 nNumbersOfImport = pPEInfo->listImports.count();

                bool bSuccess = true;

                for (qint32 i = 0; (i < nNumbersOfImport) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pPEInfo->listImports.at(i).listPositions.count() != 1) {
                        bSuccess = false;
                        break;
                    }
                }

                if (bSuccess) {
                    if (pPEInfo->listSectionNames.count() > 1) {
                        if (pPEInfo->listSectionNames.at(0) == "        ") {
                            bSuccess = false;

                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_THEMIDAWINLICENSE, "3.XX", "", 0);

                            if (XPE::isSectionNamePresent(".themida", &(pPEInfo->listSectionRecords))) {
                                ss.sInfo = "Themida";
                                bSuccess = true;
                            } else if (XPE::isSectionNamePresent(".winlice", &(pPEInfo->listSectionRecords))) {
                                ss.sInfo = "Winlicense";
                                bSuccess = true;
                            }

                            if (bSuccess) {
                                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                            }
                        }
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_Obsidium(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // TODO x64
        // KERNEL32.DLL
        // USER32.DLL
        // ADVAPI32.DLL
        // SHEL32.DLL
        if (!pPEInfo->cliInfo.bValid) {
            qint32 nNumberOfImports = pPEInfo->listImports.count();

            if ((nNumberOfImports == 2) || (nNumberOfImports == 3)) {
                bool bKernel32 = false;
                bool bUser32 = false;
                //                bool bAdvapi32=false;

                if (pPEInfo->listImports.at(0).sName == "KERNEL32.DLL") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(0).listPositions.at(0).sFunction == "ExitProcess")) {
                            bKernel32 = true;
                        }
                    }
                }

                if (pPEInfo->listImports.at(1).sName == "USER32.DLL") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        if ((pPEInfo->listImports.at(1).listPositions.at(0).sFunction == "MessageBoxA")) {
                            bUser32 = true;
                        }
                    }
                }

                if (nNumberOfImports == 3) {
                    if (pPEInfo->listImports.at(2).sName == "ADVAPI32.DLL") {
                        if (pPEInfo->listImports.at(2).listPositions.count() == 1) {
                            if ((pPEInfo->listImports.at(2).listPositions.at(0).sFunction == "RegOpenKeyExA")) {
                                //                                bAdvapi32=true;
                            }
                        }
                    }
                }

                if (bKernel32 && bUser32) {
                    if (pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$50EB$$E8") ||
                        pe.compareEntryPoint(&(pPEInfo->basic_info.memoryMap), "EB$$E8........EB$$EB")) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::XScanEngine::RECORD_NAME_OBSIDIUM, "", "", 0);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    _SCANS_STRUCT ssLinker = {};
    _SCANS_STRUCT ssCompiler = {};
    _SCANS_STRUCT ssTool = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bDetectGCC = false;
            bool bHeurGCC = false;

            if (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GENERICLINKER)) {
                switch (pPEInfo->nMajorLinkerVersion) {
                    case 2:
                        switch (pPEInfo->nMinorLinkerVersion)  // TODO Check MinGW versions
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
                            case 56: bHeurGCC = true; break;
                        }

                        break;
                }
            }

            QString sDllLib;

            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                sDllLib = pe.read_ansiString(pPEInfo->osConstDataSection.nOffset);
            }

            if (XPE::isImportLibraryPresentI("msys-1.0.dll", &(pPEInfo->listImports)) || sDllLib.contains("msys-")) {
                // Msys 1.0
                ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MSYS;
                ssTool.sVersion = "1.0";
            }

            if ((sDllLib.contains("gcc")) || (sDllLib.contains("libgcj")) || (sDllLib.contains("cyggcj")) || (sDllLib == "_set_invalid_parameter_handler") ||
                XPE::isImportLibraryPresentI("libgcc_s_dw2-1.dll", &(pPEInfo->listImports)) || pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_MINGW) ||
                pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GCC)) {
                bDetectGCC = true;
            }

            if (bDetectGCC || bHeurGCC) {
                // Mingw
                // Msys
                if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    VI_STRUCT viStruct = NFD_Binary::get_GCC_vi1(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                    ssCompiler.sVersion = viStruct.sVersion;

                    // TODO MinGW-w64
                    if (viStruct.sInfo.contains("MinGW")) {
                        ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                        ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MINGW;
                    } else if (viStruct.sInfo.contains("MSYS2")) {
                        ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                        ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MSYS2;
                    } else if (viStruct.sInfo.contains("Cygwin")) {
                        ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                        ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_CYGWIN;
                    }

                    if (ssCompiler.sVersion == "") {
                        QString _sGCCVersion;

                        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            _sGCCVersion =
                                NFD_Binary::get_GCC_vi2(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct).sVersion;

                            if (_sGCCVersion != "") {
                                ssCompiler.sVersion = _sGCCVersion;
                            }
                        }

                        if (_sGCCVersion == "") {
                            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                                _sGCCVersion =
                                    NFD_Binary::get_GCC_vi2(pDevice, pOptions, pPEInfo->osDataSection.nOffset, pPEInfo->osDataSection.nSize, pPdStruct).sVersion;

                                if (_sGCCVersion != "") {
                                    ssCompiler.sVersion = _sGCCVersion;
                                }
                            }
                        }
                    }

                    if ((ssTool.type == XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) && (pPEInfo->basic_info.mapEntryPointDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GCC))) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.value(XScanEngine::XScanEngine::RECORD_NAME_GCC).sInfo.contains("MinGW")) {
                            ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                            ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MINGW;
                        }
                    }
                }

                if (ssCompiler.sVersion != "") {
                    bDetectGCC = true;
                }

                if (!bDetectGCC) {
                    if (pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                        qint64 nGCC_MinGW =
                            pe.find_ansiString(pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, "Mingw-w64 runtime failure:", pPdStruct);

                        if (nGCC_MinGW != -1) {
                            ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                            ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MINGW;

                            bDetectGCC = true;
                        }
                    }
                }

                if (bDetectGCC) {
                    ssCompiler.type = XScanEngine::XScanEngine::RECORD_TYPE_COMPILER;
                    ssCompiler.name = XScanEngine::XScanEngine::RECORD_NAME_GCC;
                }
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                if (XBinary::isRegExpPresent("^CYGWIN", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            ssTool.sVersion = QString::number(dVersion, 'f', 2);
                        }
                    }

                    ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                    ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_CYGWIN;

                    break;
                }
            }

            if (ssCompiler.type == XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) {
                if (XPE::isSectionNamePresent(".stabstr", &(pPEInfo->listSectionRecords)))  // TODO
                {
                    XPE::SECTION_RECORD sr = XPE::getSectionRecordByName(".stabstr", &(pPEInfo->listSectionRecords));

                    if (sr.nSize) {
                        qint64 _nOffset = sr.nOffset;
                        qint64 _nSize = sr.nSize;

                        bool bSuccess = false;

                        if (!bSuccess) {
                            qint64 nGCC_MinGW = pe.find_ansiString(_nOffset, _nSize, "/gcc/mingw32/", pPdStruct);

                            if (nGCC_MinGW != -1) {
                                ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                                ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MINGW;

                                bSuccess = true;
                            }
                        }

                        if (!bSuccess) {
                            qint64 nCygwin = pe.find_ansiString(_nOffset, _nSize, "/gcc/i686-pc-cygwin/", pPdStruct);

                            if (nCygwin != -1) {
                                ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                                ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_CYGWIN;

                                bSuccess = true;
                            }
                        }
                    }
                }
            }

            if (ssCompiler.type == XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) {
                if ((ssTool.name == XScanEngine::XScanEngine::RECORD_NAME_MINGW) || (ssTool.name == XScanEngine::XScanEngine::RECORD_NAME_MSYS) || (ssTool.name == XScanEngine::XScanEngine::RECORD_NAME_MSYS2) ||
                    (ssTool.name == XScanEngine::XScanEngine::RECORD_NAME_CYGWIN)) {
                    ssCompiler.type = XScanEngine::XScanEngine::RECORD_TYPE_COMPILER;
                    ssCompiler.name = XScanEngine::XScanEngine::RECORD_NAME_GCC;
                }
            }

            if ((ssCompiler.name == XScanEngine::XScanEngine::RECORD_NAME_GCC) && (ssTool.type == XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN)) {
                ssTool.type = XScanEngine::XScanEngine::RECORD_TYPE_TOOL;
                ssTool.name = XScanEngine::XScanEngine::RECORD_NAME_MINGW;
            }

            if ((ssCompiler.name == XScanEngine::XScanEngine::RECORD_NAME_GCC) && (pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_GENERICLINKER))) {
                ssLinker.type = XScanEngine::XScanEngine::RECORD_TYPE_LINKER;
                ssLinker.name = XScanEngine::XScanEngine::RECORD_NAME_GNULINKER;
                ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            }

            if (ssTool.name == XScanEngine::XScanEngine::RECORD_NAME_MINGW) {
                if (ssTool.sVersion == "") {
                    switch (pPEInfo->nMajorLinkerVersion) {
                        case 2:
                            switch (pPEInfo->nMinorLinkerVersion) {
                                case 23: ssTool.sVersion = "4.7.0-4.8.0"; break;
                                case 24: ssTool.sVersion = "4.8.2-4.9.2"; break;
                                case 25: ssTool.sVersion = "5.3.0"; break;
                                case 29: ssTool.sVersion = "7.3.0"; break;
                                case 30: ssTool.sVersion = "7.3.0"; break;  // TODO Check
                            }
                            break;
                    }
                }
            }

            // TODO Check overlay debug

            if (ssLinker.type != XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));
            }
            if (ssCompiler.type != XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
            }
            if (ssTool.type != XScanEngine::XScanEngine::RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssTool));
            }
        }
    }
}

void NFD_PE::PE_handle_Signtools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, NFD_PE::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pe.isSignPresent()) {
            // TODO image
            XPE_DEF::IMAGE_DATA_DIRECTORY dd = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY);

            QList<XPE::CERT> listCerts = pe.getCertList(dd.VirtualAddress, dd.Size);

            if (listCerts.count()) {
                if ((listCerts.at(0).record.wRevision == 0x200) && (listCerts.at(0).record.wCertificateType == 2)) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_SIGNTOOL, XScanEngine::XScanEngine::RECORD_NAME_WINAUTH, "2.0", "PKCS #7", 0);
                    pPEInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void NFD_PE::PE_handle_Installers(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            // Inno Setup
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP) || pPEInfo->basic_info.mapHeaderDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP, "", "", 0);

                if ((pe.read_uint32(0x30) == 0x6E556E49))  // Uninstall
                {
                    ss.sInfo = "Uninstall";

                    if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                        qint64 _nSize = pPEInfo->osCodeSection.nSize;

                        qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Setup version: Inno Setup version ", pPdStruct);

                        if (nOffsetVersion != -1) {
                            QString sVersionString = pe.read_ansiString(nOffsetVersion + 34);
                            ss.sVersion = sVersionString.section(" ", 0, 0);
                            QString sEncodes = sVersionString.section(" ", 1, 1);

                            if (sEncodes == "(a)") {
                                ss.sInfo = XBinary::appendComma(ss.sInfo, "ANSI");
                            } else if (sEncodes == "(u)") {
                                ss.sInfo = XBinary::appendComma(ss.sInfo, "Unicode");
                            }
                        }
                    }
                } else if (pPEInfo->basic_info.mapOverlayDetects.value(XScanEngine::XScanEngine::RECORD_NAME_INNOSETUP).sInfo == "Uninstall") {
                    ss.sInfo = "Uninstall";
                    qint64 _nOffset = pPEInfo->nOverlayOffset;
                    qint64 _nSize = pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Inno Setup Messages (", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion + 21);
                        ss.sVersion = sVersionString.section(" ", 0, 0);
                        ss.sVersion = ss.sVersion.remove(")");
                        QString sEncodes = sVersionString.section(" ", 1, 1);

                        // TODO Check
                        if (sEncodes == "(a))") {
                            ss.sInfo = XBinary::appendComma(ss.sInfo, "ANSI");
                        } else if (sEncodes == "(u))") {
                            ss.sInfo = XBinary::appendComma(ss.sInfo, "Unicode");
                        }
                    }
                } else {
                    qint64 nLdrTableOffset = -1;

                    if (pe.read_uint32(0x30) == 0x6F6E6E49) {
                        ss.sVersion = "1.XX-5.1.X";
                        ss.sInfo = "Install";
                        nLdrTableOffset = pe.read_uint32(0x30 + 4);
                    } else  // New versions
                    {
                        XPE::RESOURCE_RECORD resHeader = XPE::getResourceRecord(XPE_DEF::S_RT_RCDATA, 11111, &(pPEInfo->listResources));

                        nLdrTableOffset = resHeader.nOffset;

                        if (nLdrTableOffset != -1) {
                            ss.sVersion = "5.1.X-X.X.X";
                            ss.sInfo = "Install";
                        }
                    }

                    if (nLdrTableOffset != -1) {
                        // TODO 1 function
                        QString sSignature = pe.getSignature(nLdrTableOffset + 0, 12);

                        if (sSignature.left(12) == "72446C507453")  // rDlPtS
                        {
                            //                    result.nLdrTableVersion=read_uint32(nLdrTableOffset+12+0);
                            //                    result.nTotalSize=read_uint32(nLdrTableOffset+12+4);
                            //                    result.nSetupE32Offset=read_uint32(nLdrTableOffset+12+8);
                            //                    result.nSetupE32UncompressedSize=read_uint32(nLdrTableOffset+12+12);
                            //                    result.nSetupE32CRC=read_uint32(nLdrTableOffset+12+16);
                            //                    result.nSetupBin0Offset=read_uint32(nLdrTableOffset+12+20);
                            //                    result.nSetupBin1Offset=read_uint32(nLdrTableOffset+12+24);
                            //                    result.nTableCRC=read_uint32(nLdrTableOffset+12+28);

                            QString sSetupDataString = pe.read_ansiString(pe.read_uint32(nLdrTableOffset + 12 + 20));

                            if (!sSetupDataString.contains("(")) {
                                sSetupDataString = pe.read_ansiString(pe.read_uint32(nLdrTableOffset + 12 + 24));
                                // TODO
                                //                                ss.sInfo=XBinary::appendComma(ss.sInfo,"OLD.TODO");
                            }

                            QString sVersion = XBinary::regExp("\\((.*?)\\)", sSetupDataString, 1);
                            QString sOptions = XBinary::regExp("\\) \\((.*?)\\)", sSetupDataString, 1);

                            if (sVersion != "") {
                                ss.sVersion = sVersion;
                            }

                            if (sOptions != "") {
                                QString sEncode = sOptions;

                                if (sEncode == "a") {
                                    ss.sInfo = XBinary::appendComma(ss.sInfo, "ANSI");
                                } else if (sEncode == "u") {
                                    ss.sInfo = XBinary::appendComma(ss.sInfo, "Unicode");
                                }
                            }
                        }
                    }
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::XScanEngine::RECORD_NAME_CAB)) {
                // Wix Tools
                if (XPE::isSectionNamePresent(".wixburn", &(pPEInfo->listSectionRecords)))  // TODO
                {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::XScanEngine::RECORD_NAME_WIXTOOLSET, "", "", 0);
                    ss.sVersion = "3.X";  // TODO check "E:\delivery\Dev\wix37\build\ship\x86\burn.pdb"
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_NOSINSTALLER)) {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::RECORD_NAME_NOSINSTALLER)) {
                    // TODO Version from resources!
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_NOSINSTALLER, "", "", 0);
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // CAB SFX
            if (pPEInfo->sResourceManifest.contains("sfxcab.exe")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_CAB, "", "", 0);

                if (pe.checkOffsetSize(pPEInfo->osResourcesSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 nSectionOffset = pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).PointerToRawData +
                                            pPEInfo->listSectionHeaders.at(pPEInfo->nResourcesSection).Misc.VirtualSize;

                    qint64 nVersionOffset = pe.find_signature(&(pPEInfo->basic_info.memoryMap), nSectionOffset - 0x600, 0x600, "BD04EFFE00000100", nullptr, pPdStruct);
                    if (nVersionOffset != -1) {
                        ss.sVersion = QString("%1.%2.%3.%4")
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 2))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 0))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 6))
                                          .arg(pe.read_uint16(nVersionOffset + 16 + 4));
                    }
                }

                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Install Anywhere
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_INSTALLANYWHERE)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)) == "InstallAnywhere") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLANYWHERE, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_GHOSTINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_GHOSTINSTALLER, "", "", 0);
                ss.sVersion = "1.0";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_QTINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_QTINSTALLER, "", "", 0);
                // ss.sVersion="";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_INSTALL4J)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALL4J, "", "", 0);
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_SMARTINSTALLMAKER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_SMARTINSTALLMAKER, "", "", 0);
                ss.sVersion = XBinary::hexToString(pPEInfo->sOverlaySignature.mid(46, 14));  // TODO make 1 function
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_TARMAINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_TARMAINSTALLER, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_CLICKTEAM)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_CLICKTEAM, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // NSIS
            if ((pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_NSIS)) || (pPEInfo->sResourceManifest.contains("Nullsoft.NSIS"))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_NSIS, "", "", 0);

                QString _sInfo = pPEInfo->basic_info.mapOverlayDetects.value(XScanEngine::RECORD_NAME_NSIS).sInfo;

                if (_sInfo != "") {
                    ss.sInfo = _sInfo;
                }

                //                QRegularExpression rxVersion("Null[sS]oft Install System v?(.*?)<");
                //                QRegularExpressionMatch matchVersion=rxVersion.match(pPEInfo->sResourceManifest);

                //                if(matchVersion.hasMatch())
                //                {
                //                    ss.sVersion=matchVersion.captured(1);
                //                }

                QString sVersion = XBinary::regExp("Null[sS]oft Install System v?(.*?)<", pPEInfo->sResourceManifest, 1);

                if (sVersion != "") {
                    ss.sVersion = sVersion;
                }

                // TODO options
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // InstallShield
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("InstallShield")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->sResourceManifest.contains("InstallShield")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", "", 0);

                if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osDataSection.nSize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "SOFTWARE\\InstallShield\\1", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion);
                        ss.sVersion = sVersionString.section("\\", 2, 2);
                    }
                }

                if (ss.sVersion == "") {
                    // TODO unicode
                    ss.sVersion = XPE::getResourcesVersionValue("ISInternalVersion", &(pPEInfo->resVersion));
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_INSTALLSHIELD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", "PackageForTheWeb", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("InstallShield")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLSHIELD, "", "", 0);

                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));

                if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("PackageForTheWeb")) {
                    ss.sInfo = "PackageForTheWeb";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("AdvancedInstallerSetup")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_ADVANCEDINSTALLER, "", "", 0);

                if ((pPEInfo->nOverlayOffset) && (pPEInfo->nOverlaySize) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->nOverlayOffset;
                    qint64 _nSize = pPEInfo->nOverlaySize;

                    qint64 nOffsetVersion = pe.find_ansiString(_nOffset, _nSize, "Advanced Installer ", pPdStruct);

                    if (nOffsetVersion != -1) {
                        QString sVersionString = pe.read_ansiString(nOffsetVersion);
                        ss.sVersion = sVersionString.section(" ", 2, 2);
                    }
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("Illustrate.Spoon.Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_SPOONINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("DeployMaster Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_DEPLOYMASTER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((pPEInfo->sResourceManifest.contains("Gentee.Installer.Install")) || (pPEInfo->sResourceManifest.contains("name=\"gentee\""))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(XScanEngine::RECORD_NAME_GENTEEINSTALLER)) {
                    if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "SETUP_TEMP", &(pPEInfo->listResources))) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            if (pPEInfo->sResourceManifest.contains("BitRock Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_BITROCKINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("GP-Install") &&
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("TASPro6-Install")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_GPINSTALL, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Total Commander Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_TOTALCOMMANDERINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Actual Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_ACTUALINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Avast Antivirus")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_AVASTANTIVIRUS, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Opera Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_OPERA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Yandex Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_YANDEX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Google Update")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_GOOGLE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Visual Studio Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_MICROSOFTVISUALSTUDIO, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Dropbox Update Setup")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_DROPBOX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("VeraCrypt")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_VERACRYPT, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft .NET Framework")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_MICROSOFTDOTNETFRAMEWORK, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("LegalTrademarks", &(pPEInfo->resVersion)).contains("Setup Factory")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_SETUPFACTORY, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion.contains(",")) {
                    ss.sVersion = ss.sVersion.remove(" ");
                    ss.sVersion = ss.sVersion.replace(",", ".");
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("This installation was built with InstallAware")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_INSTALLAWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft Office")) {
                if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Bootstrapper.exe")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_MICROSOFTOFFICE, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion)).trimmed();

                    if (ss.sVersion.contains(",")) {
                        ss.sVersion = ss.sVersion.remove(" ");
                        ss.sVersion = ss.sVersion.replace(",", ".");
                    }

                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // Squirrel Installer
            if (XPE::getResourcesVersionValue("SquirrelAwareVersion", &(pPEInfo->resVersion)) != "") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_SQUIRRELINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("SquirrelAwareVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion == "1") {
                    ss.sVersion = "1.0.0-1.9.1";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Java") &&
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Setup Launcher")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_JAVA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_VMWARE) ||
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("VMware installation")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_VMWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Windows Installer
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_MICROSOFTCOMPOUND)) {
                VI_STRUCT vi = NFD_Binary::get_WindowsInstaller_vi(pDevice, pOptions, pPEInfo->nOverlayOffset, pPEInfo->nOverlaySize, pPdStruct);

                if (vi.sVersion != "") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

                    ss.sVersion = vi.sVersion;
                    ss.sInfo = vi.sInfo;

                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // Alchemy Mindworks
            if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 4001, &(pPEInfo->listResources)) &&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 5001, &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_ALCHEMYMINDWORKS, "", "", 0);
                // TODO versions

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (!pPEInfo->basic_info.mapResultInstallers.contains(XScanEngine::RECORD_NAME_WINDOWSINSTALLER)) {
                qint32 nNumberOfResources = pPEInfo->listResources.count();

                for (qint32 i = 0; (i < nNumberOfResources) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    qint64 _nOffset = pPEInfo->listResources.at(i).nOffset;
                    qint64 _nSize = pPEInfo->listResources.at(i).nSize;
                    qint64 _nSignatureSize = qMin(_nSize, (qint64)8);

                    if (_nSignatureSize) {
                        QString sSignature = pe.getSignature(_nOffset, _nSignatureSize);

                        if (sSignature == "D0CF11E0A1B11AE1")  // DOC File TODO move to signatures
                        {
                            VI_STRUCT vi = NFD_Binary::get_WindowsInstaller_vi(pDevice, pOptions, _nOffset, _nSize, pPdStruct);

                            if (vi.sVersion != "") {
                                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

                                ss.sVersion = vi.sVersion;
                                ss.sInfo = vi.sInfo;

                                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));

                                break;
                            }
                        }
                    }
                }
            }

            // WISE Installer
            if (pPEInfo->exportHeader.sName == "STUB32.EXE") {
                if (pPEInfo->exportHeader.listPositions.count() == 2) {
                    if ((pPEInfo->exportHeader.listPositions.at(0).sFunctionName == "_MainWndProc@16") ||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName == "_StubFileWrite@12")) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                } else if (pPEInfo->exportHeader.listPositions.count() == 6) {
                    if ((pPEInfo->exportHeader.listPositions.at(0).sFunctionName == "_LanguageDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName == "_PasswordDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(2).sFunctionName == "_ProgressDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(3).sFunctionName == "_UpdateCRC@8") ||
                        (pPEInfo->exportHeader.listPositions.at(4).sFunctionName == "_t1@40") || (pPEInfo->exportHeader.listPositions.at(5).sFunctionName == "_t2@12")) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void NFD_PE::PE_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_RAR)) {
                if (XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "STARTDLG", &(pPEInfo->listResources)) &&
                    XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "LICENSEDLG", &(pPEInfo->listResources))) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if ((pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_WINRAR)) || (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_ZIP))) {
                if (pPEInfo->sResourceManifest.contains("WinRAR")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_ZIP)) {
                if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osDataSection.nSize;

                    qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "ZIP self-extractor", pPdStruct);
                    if (nOffset_Version != -1) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_ZIP, "", "", 0);
                        // TODO Version
                        pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // 7z SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("7-Zip")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_7Z, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((!pPEInfo->basic_info.mapResultSFX.contains(XScanEngine::RECORD_NAME_7Z)) && (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_7Z))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_7Z, "", "", 0);
                ss.sInfo = "Modified";
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // SQUEEZ SFX
            if (pPEInfo->basic_info.mapOverlayDetects.contains(XScanEngine::RECORD_NAME_SQUEEZSFX)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Squeez")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_INSTALLER, XScanEngine::RECORD_NAME_SQUEEZSFX, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // WinACE
            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinACE") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinAce") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("UNACE")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_WINACE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // WinZip
            if ((pPEInfo->sResourceManifest.contains("WinZipComputing.WinZip")) || (XPE::isSectionNamePresent("_winzip_", &(pPEInfo->listSectionRecords))))  // TODO
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_WINZIP, "", "", 0);

                QString _sManifest = pPEInfo->sResourceManifest.section("assemblyIdentity", 1, 1);
                ss.sVersion = XBinary::regExp("version=\"(.*?)\"", _sManifest, 1);
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Cab
            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Self-Extracting Cabinet")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_CAB, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // GkSetup SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("GkSetup Self extractor")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, XScanEngine::RECORD_TYPE_SFX, XScanEngine::RECORD_NAME_GKSETUPSFX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}