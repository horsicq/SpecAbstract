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
#ifndef NFD_DOTNET_H
#define NFD_DOTNET_H

#include "dotnet_script.h"
#include "nfd_binary.h"

class NFD_DOTNET : public DOTNET_Script {
    Q_OBJECT

public:
    explicit NFD_DOTNET(XCLIAssembly *pCliAssembly, XBinary::FILEPART filePart, const OPTIONS &scanOptions, XBinary::PDSTRUCT *pPdStruct);

    struct DOTNETINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;

        XCLIAssembly::CLI_INFO cliInfo;
        QList<QString> listAnsiStrings;
        QList<QString> listUnicodeStrings;
    };

    // Accessors for .NET metadata string signature records
    static NFD_Binary::STRING_RECORD *getDotAnsiStringsRecords();
    static qint32 getDotAnsiStringsRecordsSize();
    static NFD_Binary::STRING_RECORD *getDotUnicodeStringsRecords();
    static qint32 getDotUnicodeStringsRecordsSize();

    // Main .NET / CLI assembly analysis function
    static DOTNETINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                     XBinary::PDSTRUCT *pPdStruct);

    // .NET protection/obfuscation detection (moved from NFD_PE::handle_NETProtection)
    static void handle_Protection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, DOTNETINFO_STRUCT *pDOTNETInfo, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_DOTNET_H
