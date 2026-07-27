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
#include "nfd_dotnet.h"

using _SCANS_STRUCT = NFD_Binary::SCANS_STRUCT;

NFD_DOTNET::NFD_DOTNET(XCLIAssembly *pCliAssembly, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct)
    : DOTNET_Script(pCliAssembly, filePart, scanOptions, pPdStruct)
{
}

NFD_Binary::STRING_RECORD _DOTNET_dot_ansistrings_records[] = {
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_DOTFUSCATOR, "", ""}, "DotfuscatorAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_LIBRARY, XScanEngine::RECORD_NAME_VCL, "", ".NET"}, "Borland.Vcl.Types"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_VBNET, "", ""}, "Microsoft.VisualBasic"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_COMPILER, XScanEngine::RECORD_NAME_JSCRIPT, "", ""}, "Microsoft.JScript.Vsa"},
    //    {{0, XBinary::FT_CLI_ASSEMBLY,        XScanEngine::RECORD_TYPE_TOOL,              XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET,  "",                 ""},
    //    "Embarcadero."},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_YANO, "1.X", ""}, "YanoAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_AGILENET, "", ""}, "ObfuscatedByAgileDotNetAttribute"},
    //    {{0, XBinary::FT_CLI_ASSEMBLY,        XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::RECORD_NAME_SKATERNET,                    "",             ""},
    //    "Skater_NET_Obfuscator"}, {1, XBinary::FT_CLI_ASSEMBLY,        XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::RECORD_NAME_SKATERNET,                    "", ""},
    //    "RustemSoft.Skater"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_BABELNET, "3.X", ""}, "BabelAttribute"},  // TODO Version
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_BABELNET, "1.X-2.X", ""}, "BabelObfuscatorAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CLISECURE, "4.X-5.X", ""}, "ObfuscatedByCliSecureAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CLISECURE, "3.X", ""}, "CliSecureRd.dll"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CLISECURE, "3.X", ""}, "CliSecureRd64.dll"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET, "XE*", ""}, "Borland.Studio.Delphi"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_TOOL, XScanEngine::RECORD_NAME_EMBARCADERODELPHIDOTNET, "8", ""}, "Borland.Vcl.Types"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET, "", ""}, "CryptoObfuscator"},  // TODO Version, die
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_DEEPSEA, "4.X", ""}, "DeepSeaObfuscator"},             // TODO Version, die
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_GOLIATHNET, "", ""}, "ObfuscatedByGoliath"},           // TODO Version, die
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_MACROBJECT, "", ""},
     "Obfuscated by Macrobject Obfuscator.NET"},                                                                                                          // TODO Version
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_SOFTWAREZATOR, "", ""}, "ObfuscatedBySoftwareZatorAttribute"},  // TODO Version
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_PACKER, XScanEngine::RECORD_NAME_NSPACK, "2.X-3.X", ".NET"}, "nsnet"},                                  // TODO Version
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_DNGUARD, "", ""}, "ZYXDNGuarder"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_DNGUARD, "", ""}, "HVMRuntm.dll"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::RECORD_NAME_DOTNETZ, "", ""}, "NetzStarter"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_MAXTOCODE, "", ""}, "InfaceMaxtoCode"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_PHOENIXPROTECTOR, "", ""}, "?1?.?9?.resources"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETCOMPRESSOR, XScanEngine::RECORD_NAME_SIXXPACK, "", ""}, "Sixxpack"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "SmartAssembly.Attributes"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_SMARTASSEMBLY, "", ""}, "SmartAssembly.Attributes.PoweredByAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CONFUSER, "1.X", ""}, "ConfusedByAttribute"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_SPICESNET, "", ""}, "NineRays.Obfuscator"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_OBFUSCATORNET2009, "", ""}, "Macrobject.Obfuscator"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD, "2.X-3.X", ""},
     "Xenocode.Client.Attributes.AssemblyAttributes"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_CODEVEIL, "4.X", ""}, "____KILL"},
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_NETOBFUSCATOR, XScanEngine::RECORD_NAME_DOTNETSPIDER, "0.5-1.3", ""}, "NETSpider.Attribute"},
    //    {{0, XBinary::FT_CLI_ASSEMBLY,        XScanEngine::RECORD_TYPE_NETOBFUSCATOR,    XScanEngine::RECORD_NAME_EAZFUSCATOR,                  "",                 ""},
    //    "value__"},
};
const qint32 _DOTNET_dot_ansistrings_records_size = sizeof(_DOTNET_dot_ansistrings_records);

NFD_Binary::STRING_RECORD _DOTNET_dot_unicodestrings_records[] = {
    {{0, XBinary::FT_CLI_ASSEMBLY, XScanEngine::RECORD_TYPE_PROTECTOR, XScanEngine::RECORD_NAME_CODEVEIL, "3.X-4.X", ""}, "E_TamperDetected"}};
const qint32 _DOTNET_dot_unicodestrings_records_size = sizeof(_DOTNET_dot_unicodestrings_records);


NFD_Binary::STRING_RECORD *NFD_DOTNET::getDotAnsiStringsRecords()
{
    return _DOTNET_dot_ansistrings_records;
}

qint32 NFD_DOTNET::getDotAnsiStringsRecordsSize()
{
    return _DOTNET_dot_ansistrings_records_size;
}

NFD_Binary::STRING_RECORD *NFD_DOTNET::getDotUnicodeStringsRecords()
{
    return _DOTNET_dot_unicodestrings_records;
}

qint32 NFD_DOTNET::getDotUnicodeStringsRecordsSize()
{
    return _DOTNET_dot_unicodestrings_records_size;
}

NFD_DOTNET::DOTNETINFO_STRUCT NFD_DOTNET::getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                  XBinary::PDSTRUCT *pPdStruct)
{
    DOTNETINFO_STRUCT result = {};

    XCLIAssembly cliAssembly(pDevice, pOptions->bIsImage);

    if (cliAssembly.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&cliAssembly, parentId, pOptions, nOffset, pPdStruct);

        result.cliInfo = cliAssembly.getCliInfo(true, pPdStruct);
        result.listAnsiStrings = cliAssembly.getAnsiStrings(&(result.cliInfo), pPdStruct);
        result.listUnicodeStrings = cliAssembly.getUnicodeStrings(&(result.cliInfo), pPdStruct);

        NFD_Binary::stringScan(&result.basic_info.mapDotAnsiStringsDetects, &result.listAnsiStrings, NFD_DOTNET::getDotAnsiStringsRecords(),
                               NFD_DOTNET::getDotAnsiStringsRecordsSize(), result.basic_info.id.fileType, XBinary::FT_CLI_ASSEMBLY, &(result.basic_info),
                               DETECTTYPE_NETANSISTRING, pPdStruct);
        NFD_Binary::stringScan(&result.basic_info.mapDotUnicodeStringsDetects, &result.listUnicodeStrings, NFD_DOTNET::getDotUnicodeStringsRecords(),
                               NFD_DOTNET::getDotUnicodeStringsRecordsSize(), result.basic_info.id.fileType, XBinary::FT_CLI_ASSEMBLY, &(result.basic_info),
                               DETECTTYPE_NETUNICODESTRING, pPdStruct);

        NFD_DOTNET::handle_Protection(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    return result;
}

void NFD_DOTNET::handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, DOTNETINFO_STRUCT *pDOTNETInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    NFD_Binary::BASIC_INFO *pBI = &(pDOTNETInfo->basic_info);

    // .NET obfuscators detected by metadata ANSI strings (attributes, type names)
    const XScanEngine::RECORD_NAME arrObfuscators[] = {
        XScanEngine::RECORD_NAME_YANO,           XScanEngine::RECORD_NAME_DOTFUSCATOR,       XScanEngine::RECORD_NAME_AGILENET,
        XScanEngine::RECORD_NAME_BABELNET,       XScanEngine::RECORD_NAME_GOLIATHNET,        XScanEngine::RECORD_NAME_SPICESNET,
        XScanEngine::RECORD_NAME_OBFUSCATORNET2009, XScanEngine::RECORD_NAME_DEEPSEA,        XScanEngine::RECORD_NAME_MAXTOCODE,
        XScanEngine::RECORD_NAME_PHOENIXPROTECTOR, XScanEngine::RECORD_NAME_SMARTASSEMBLY,   XScanEngine::RECORD_NAME_CONFUSER,
        XScanEngine::RECORD_NAME_XENOCODEPOSTBUILD, XScanEngine::RECORD_NAME_CODEVEIL,       XScanEngine::RECORD_NAME_EAZFUSCATOR,
        XScanEngine::RECORD_NAME_DOTNETSPIDER,   XScanEngine::RECORD_NAME_CLISECURE,         XScanEngine::RECORD_NAME_DNGUARD,
        XScanEngine::RECORD_NAME_OBFUSCAR,       XScanEngine::RECORD_NAME_SKATER,            XScanEngine::RECORD_NAME_CRYPTOOBFUSCATORFORNET,
        XScanEngine::RECORD_NAME_SOFTWAREZATOR,  XScanEngine::RECORD_NAME_MACROBJECT,        XScanEngine::RECORD_NAME_CODEWALL,
    };

    const qint32 nNumberOfObfuscators = sizeof(arrObfuscators) / sizeof(arrObfuscators[0]);

    for (qint32 i = 0; i < nNumberOfObfuscators; i++) {
        if (pBI->mapDotAnsiStringsDetects.contains(arrObfuscators[i])) {
            _SCANS_STRUCT ss = pBI->mapDotAnsiStringsDetects.value(arrObfuscators[i]);
            pBI->mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(pBI, &ss));
        }
    }

    // CodeVeil: also detected by metadata unicode strings
    if (!pBI->mapResultNETObfuscators.contains(XScanEngine::RECORD_NAME_CODEVEIL)) {
        if (pBI->mapDotUnicodeStringsDetects.contains(XScanEngine::RECORD_NAME_CODEVEIL)) {
            _SCANS_STRUCT ss = pBI->mapDotUnicodeStringsDetects.value(XScanEngine::RECORD_NAME_CODEVEIL);
            pBI->mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(pBI, &ss));
        }
    }

    // Packers
    if (pBI->mapDotAnsiStringsDetects.contains(XScanEngine::RECORD_NAME_NSPACK)) {
        _SCANS_STRUCT ss = pBI->mapDotAnsiStringsDetects.value(XScanEngine::RECORD_NAME_NSPACK);
        pBI->mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(pBI, &ss));
    }

    // .NET compressors
    const XScanEngine::RECORD_NAME arrCompressors[] = {
        XScanEngine::RECORD_NAME_DOTNETZ,
        XScanEngine::RECORD_NAME_SIXXPACK,
        XScanEngine::RECORD_NAME_RENETPACK,
        XScanEngine::RECORD_NAME_DOTNETSHRINK,
    };

    const qint32 nNumberOfCompressors = sizeof(arrCompressors) / sizeof(arrCompressors[0]);

    for (qint32 i = 0; i < nNumberOfCompressors; i++) {
        if (pBI->mapDotAnsiStringsDetects.contains(arrCompressors[i])) {
            _SCANS_STRUCT ss = pBI->mapDotAnsiStringsDetects.value(arrCompressors[i]);
            pBI->mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(pBI, &ss));
        }
    }
}
