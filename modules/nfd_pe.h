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
#ifndef NFD_PE_H
#define NFD_PE_H

#include "pe_script.h"
#include "nfd_msdos.h"
#include "nfd_binary.h"
#include "xpe.h"
#include "xmsdos.h"

class NFD_PE : public PE_Script {
    Q_OBJECT

public:
    explicit NFD_PE(XPE *pPE, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct VCL_STRUCT {
        quint32 nValue;
        qint64 nOffset;
        bool bIs64;
    };

    struct VCL_PACKAGEINFO_MODULE {
        quint8 nFlags;
        quint8 nHashCode;
        QString sName;
    };

    struct VCL_PACKAGEINFO {
        quint32 nFlags;
        quint32 nUnknown;
        quint32 nRequiresCount;
        QList<VCL_PACKAGEINFO_MODULE> listModules;
    };

    struct PEINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        qint64 nEntryPointOffset;
        QString sEntryPointSignature;
        QString sOverlaySignature;
        qint64 nOverlayOffset;
        qint64 nOverlaySize;
        XMSDOS_DEF::IMAGE_DOS_HEADEREX dosHeader;
        XPE_DEF::IMAGE_FILE_HEADER fileHeader;
        union OPTIONAL_HEADER {
            XPE_DEF::IMAGE_OPTIONAL_HEADER32 optionalHeader32;
            XPE_DEF::IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        } optional_header;
        QList<XPE_DEF::IMAGE_SECTION_HEADER> listSectionHeaders;
        QList<XPE::SECTION_RECORD> listSectionRecords;
        QList<QString> listSectionNames;
        QList<XPE::IMPORT_HEADER> listImports;
        QList<XPE::IMPORT_RECORD> listImportRecords;
        quint64 nImportHash64;
        quint32 nImportHash32;
        QList<quint32> listImportPositionHashes;
        XPE::EXPORT_HEADER exportHeader;
        QList<QString> listExportFunctionNames;
        QList<XPE::RESOURCE_RECORD> listResources;
        QList<XMSDOS::MS_RICH_RECORD> listRichSignatures;
        QString sResourceManifest;
        XPE::RESOURCES_VERSION resVersion;
        XPE::CLI_INFO cliInfo;
        QList<QString> listAnsiStrings;
        QList<QString> listUnicodeStrings;

        qint32 nEntryPointSection;
        qint32 nResourcesSection;
        qint32 nImportSection;
        qint32 nCodeSection;
        qint32 nDataSection;
        qint32 nConstDataSection;
        qint32 nRelocsSection;
        qint32 nTLSSection;
        qint32 nIATSection;
        QString sEntryPointSectionName;
        XADDR nEntryPointAddress;
        XADDR nImageBaseAddress;
        quint8 nMinorLinkerVersion;
        quint8 nMajorLinkerVersion;
        quint16 nMinorImageVersion;
        quint16 nMajorImageVersion;
        bool bIs64;
        bool bIsNetPresent;
        bool bIsTLSPresent;

        XBinary::OFFSETSIZE osHeader;
        XBinary::OFFSETSIZE osEntryPointSection;
        XBinary::OFFSETSIZE osCodeSection;
        XBinary::OFFSETSIZE osDataSection;
        XBinary::OFFSETSIZE osConstDataSection;
        XBinary::OFFSETSIZE osImportSection;
        XBinary::OFFSETSIZE osResourcesSection;
    };

    // Accessors for PE signature tables (migrated from SpecAbstract/signatures.cpp)
    // SIGNATURE_RECORD based tables
    static NFD_Binary::SIGNATURE_RECORD *getHeaderRecords();
    static qint32 getHeaderRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getEntrypointRecords();
    static qint32 getEntrypointRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getEntrypointExpRecords();
    static qint32 getEntrypointExpRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getCodeSectionRecords();
    static qint32 getCodeSectionRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getEntrypointSectionRecords();
    static qint32 getEntrypointSectionRecordsSize();
    static NFD_Binary::SIGNATURE_RECORD *getDotCodeSectionRecords();
    static qint32 getDotCodeSectionRecordsSize();

    // CONST_RECORD based tables
    static NFD_Binary::CONST_RECORD *getImportHashRecords();
    static qint32 getImportHashRecordsSize();
    static NFD_Binary::CONST_RECORD *getImportHashArmadilloRecords();
    static qint32 getImportHashArmadilloRecordsSize();
    static NFD_Binary::CONST_RECORD *getImportPositionHashRecords();
    static qint32 getImportPositionHashRecordsSize();

    // PE_RESOURCES_RECORD based tables
    static NFD_Binary::PE_RESOURCES_RECORD *getResourcesRecords();
    static qint32 getResourcesRecordsSize();

    // STRING_RECORD based tables
    static NFD_Binary::STRING_RECORD *getExportExpRecords();
    static qint32 getExportExpRecordsSize();
    static NFD_Binary::STRING_RECORD *getSectionNamesRecords();
    static qint32 getSectionNamesRecordsSize();
    static NFD_Binary::STRING_RECORD *getDotAnsiStringsRecords();
    static qint32 getDotAnsiStringsRecordsSize();
    static NFD_Binary::STRING_RECORD *getDotUnicodeStringsRecords();
    static qint32 getDotUnicodeStringsRecordsSize();
};

#endif  // NFD_PE_H
