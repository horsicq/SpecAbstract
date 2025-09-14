/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
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
#include "specabstract.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"
#include "modules/nfd_dex.h"
#include "modules/nfd_pe.h"
#include "modules/nfd_text.h"
#include "modules/nfd_dex.h"

#include "signatures.cpp"  // Do not include in CMAKE files!

SpecAbstract::SpecAbstract(QObject *pParent) : XScanEngine(pParent)
{
}

// JARINFO delegated to NFD_JAR::getInfo

SpecAbstract::BINARYINFO_STRUCT SpecAbstract::getBinaryInfo(QIODevice *pDevice, XBinary::FT fileType, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions,
                                                            qint64 nOffset, XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    BINARYINFO_STRUCT result = {};

    XBinary binary(pDevice, pOptions->bIsImage);
    binary.setFileType(fileType);

    if (binary.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&binary, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        // Scan Header
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getBinaryRecords(),
                                  NFD_Binary::getBinaryRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getArchiveRecords(),
                                  NFD_Binary::getArchiveRecordsSize(), result.basic_info.id.fileType, XBinary::FT_ARCHIVE, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_OVERLAY) {
            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getPEOverlayRecords(),
                                      NFD_Binary::getPEOverlayRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY,
                                      pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_DEBUGDATA) {
            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_Binary::getDebugdataRecords(),
                                      NFD_Binary::getDebugdataRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info),
                                      DETECTTYPE_DEBUGDATA, pPdStruct);
        }

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            //            NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, _PE_resource_records,
            //            sizeof(_PE_resource_records),
            //                          result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);

            // TODO a function

            if (result.basic_info.mapHeaderDetects.count() == 0) {
                _SCANS_STRUCT ss = {};
                ss.fileType = result.basic_info.id.fileType;
                ss.type = RECORD_TYPE_FORMAT;

                quint32 nId = pOptions->varInfo.toUInt();

                if (nId == XPE_DEF::S_RT_DIALOG) {
                    ss.name = RECORD_NAME_RESOURCE_DIALOG;
                } else if (nId == XPE_DEF::S_RT_STRING) {
                    ss.name = RECORD_NAME_RESOURCE_STRINGTABLE;
                } else if (nId == XPE_DEF::S_RT_VERSION) {
                    ss.name = RECORD_NAME_RESOURCE_VERSIONINFO;
                } else if (nId == XPE_DEF::S_RT_ICON) {
                    ss.name = RECORD_NAME_RESOURCE_ICON;
                } else if (nId == XPE_DEF::S_RT_CURSOR) {
                    ss.name = RECORD_NAME_RESOURCE_CURSOR;
                } else if (nId == XPE_DEF::S_RT_MENU) {
                    ss.name = RECORD_NAME_RESOURCE_MENU;
                }

                if (ss.name != RECORD_NAME_UNKNOWN) {
                    result.basic_info.mapHeaderDetects.insert(ss.name, ss);
                }
            }
        }

        // TODO header data!
        result.bIsPlainText = binary.isPlainTextType();
        result.bIsUTF8 = binary.isUTF8TextType();
        result.unicodeType = binary.getUnicodeType();

        // TODO Try QTextStream functions! Check
        if (result.unicodeType != XBinary::UNICODE_TYPE_NONE) {
            result.sHeaderText = binary.read_unicodeString(2, qMin(result.basic_info.id.nSize, (qint64)0x1000), (result.unicodeType == XBinary::UNICODE_TYPE_BE));
            result.basic_info.id.fileType = XBinary::FT_UNICODE;
        } else if (result.bIsUTF8) {
            result.sHeaderText = binary.read_utf8String(3, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_UTF8;
        } else if (result.bIsPlainText) {
            result.sHeaderText = binary.read_ansiString(0, qMin(result.basic_info.id.nSize, (qint64)0x1000));
            result.basic_info.id.fileType = XBinary::FT_PLAINTEXT;
        }

        Binary_handle_Texts(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Formats(pDevice, pOptions, &result);
        Binary_handle_Databases(pDevice, pOptions, &result);
        Binary_handle_Images(pDevice, pOptions, &result);
        Binary_handle_Archives(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_Certificates(pDevice, pOptions, &result);
        Binary_handle_DebugData(pDevice, pOptions, &result, pPdStruct);
        Binary_handle_InstallerData(pDevice, pOptions, &result);
        Binary_handle_SFXData(pDevice, pOptions, &result);
        Binary_handle_ProtectorData(pDevice, pOptions, &result);
        Binary_handle_LibraryData(pDevice, pOptions, &result);

        if (result.basic_info.parentId.filePart == XBinary::FILEPART_RESOURCE) {
            Binary_handle_Resources(pDevice, pOptions, &result);
        }

        Binary_handle_FixDetects(pDevice, pOptions, &result);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::PEINFO_STRUCT SpecAbstract::getPEInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                    XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    PEINFO_STRUCT result = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&pe, parentId, pOptions, nOffset, pPdStruct);

        result.bIs64 = pe.is64();

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));

        result.nEntryPointOffset = pe.getEntryPointOffset(&(result.basic_info.memoryMap));
        result.sEntryPointSignature = pe.getSignature(result.nEntryPointOffset, 150);

        result.dosHeader = pe.getDosHeaderEx();
        result.fileHeader = pe.getFileHeader();
        result.nOverlayOffset = pe.getOverlayOffset(pPdStruct);
        result.nOverlaySize = pe.getOverlaySize(pPdStruct);

        if (result.nOverlaySize) {
            result.sOverlaySignature = pe.getSignature(result.nOverlayOffset, 150);
        }

        if (result.bIs64) {
            result.optional_header.optionalHeader64 = pe.getOptionalHeader64();
        } else {
            result.optional_header.optionalHeader32 = pe.getOptionalHeader32();
        }

        result.listSectionHeaders = pe.getSectionHeaders(pPdStruct);
        result.listSectionRecords = pe.getSectionRecords(&result.listSectionHeaders, pPdStruct);
        result.listSectionNames = XPE::getSectionNames(&(result.listSectionRecords), pPdStruct);

        result.listImports = pe.getImports(&(result.basic_info.memoryMap));
        result.listImportRecords = pe.getImportRecords(&(result.basic_info.memoryMap));
        //        for(qint32 i=0;i<result.listImports.count();i++)
        //        {
        //            qDebug(result.listImports.at(i).sName.toLatin1().data());
        //            for(qint32 j=0;j<result.listImports.at(i).listPositions.count();j++)
        //            {
        //                qDebug("%d %s",j,result.listImports.at(i).listPositions.at(j).sFunction.toLatin1().data());
        //            }
        //        }
        result.nImportHash64 = pe.getImportHash64(&(result.listImportRecords), pPdStruct);
        result.nImportHash32 = pe.getImportHash32(&(result.listImportRecords), pPdStruct);
        result.listImportPositionHashes = pe.getImportPositionHashes(&(result.listImports));

#ifdef QT_DEBUG
        QString sDebugString = QString::number(result.nImportHash64, 16) + " " + QString::number(result.nImportHash32, 16);
        qDebug("Import hash: %s", sDebugString.toLatin1().data());

        QList<XPE::IMPORT_RECORD> listImports = pe.getImportRecords(&(result.basic_info.memoryMap));

        qint32 _nNumberOfImports = listImports.count();

        for (qint32 i = 0; (i < _nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            QString sRecord = listImports.at(i).sLibrary + " " + listImports.at(i).sFunction;

            qDebug("%s", sRecord.toLatin1().data());
        }

        qDebug("=====================================================================");

        QList<quint32> listImportPositionHashesOld = pe.getImportPositionHashes(&(result.listImports), true);

        QList<XPE::IMPORT_HEADER> listImportHeaders = pe.getImports(&(result.basic_info.memoryMap));

        for (qint32 i = 0; (i < listImportHeaders.count()) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            qDebug("Import hash: %x", result.listImportPositionHashes.at(i));
            qDebug("Import hash(OLD): %x", listImportPositionHashesOld.at(i));
            for (qint32 j = 0; (j < listImportHeaders.at(i).listPositions.count()) && (XBinary::isPdStructNotCanceled(pPdStruct)); j++) {
                qDebug("%s %s", listImportHeaders.at(i).sName.toLatin1().data(), listImportHeaders.at(i).listPositions.at(j).sFunction.toLatin1().data());
            }
        }
#endif
        result.exportHeader = pe.getExport(&(result.basic_info.memoryMap), false, pPdStruct);
        result.listExportFunctionNames = pe.getExportFunctionsList(&(result.exportHeader), pPdStruct);
        result.listResources = pe.getResources(&(result.basic_info.memoryMap), 10000, pPdStruct);
        result.listRichSignatures = pe.getRichSignatureRecords(pPdStruct);
        result.cliInfo = pe.getCliInfo(true, &(result.basic_info.memoryMap), pPdStruct);
        result.listAnsiStrings = pe.getAnsiStrings(&(result.cliInfo), pPdStruct);
        result.listUnicodeStrings = pe.getUnicodeStrings(&(result.cliInfo), pPdStruct);
        result.sResourceManifest = pe.getResourceManifest(&result.listResources);
        result.resVersion = pe.getResourcesVersion(&result.listResources, pPdStruct);

        result.nEntryPointAddress =
            result.bIs64 ? result.optional_header.optionalHeader64.AddressOfEntryPoint : result.optional_header.optionalHeader32.AddressOfEntryPoint;
        result.nImageBaseAddress = result.bIs64 ? result.optional_header.optionalHeader64.ImageBase : result.optional_header.optionalHeader32.ImageBase;
        result.nMinorLinkerVersion =
            result.bIs64 ? result.optional_header.optionalHeader64.MinorLinkerVersion : result.optional_header.optionalHeader32.MinorLinkerVersion;
        result.nMajorLinkerVersion =
            result.bIs64 ? result.optional_header.optionalHeader64.MajorLinkerVersion : result.optional_header.optionalHeader32.MajorLinkerVersion;
        result.nMinorImageVersion = result.bIs64 ? result.optional_header.optionalHeader64.MinorImageVersion : result.optional_header.optionalHeader32.MinorImageVersion;
        result.nMajorImageVersion = result.bIs64 ? result.optional_header.optionalHeader64.MajorImageVersion : result.optional_header.optionalHeader32.MajorImageVersion;

        result.nEntryPointSection = pe.getEntryPointSection(&(result.basic_info.memoryMap));
        result.nResourcesSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_RESOURCE);
        result.nImportSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IMPORT);
        result.nCodeSection = pe.getNormalCodeSection(&(result.basic_info.memoryMap));
        result.nDataSection = pe.getNormalDataSection(&(result.basic_info.memoryMap));
        result.nConstDataSection = pe.getConstDataSection(&(result.basic_info.memoryMap));
        result.nRelocsSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_BASERELOC);
        result.nTLSSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_TLS);
        result.nIATSection = pe.getImageDirectoryEntrySection(&(result.basic_info.memoryMap), XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_IAT);

        result.bIsNetPresent = ((result.cliInfo.bValid) || (pe.isNETPresent() && (result.basic_info.scanOptions.bIsDeepScan)));
        result.bIsTLSPresent = (result.nTLSSection != -1);

        if (result.nEntryPointSection != -1) {
            result.sEntryPointSectionName = result.listSectionRecords.at(result.nEntryPointSection).sName;
        }

        //        result.mmCodeSectionSignatures=memoryScan(pDevice,nFirstSectionOffset,qMin((qint64)0x10000,nFirstSectionSize),_memory_records,sizeof(_memory_records),_filetype,SpecAbstract::XBinary::FT_PE);
        //        if(result.nCodeSection!=-1)
        //        {
        //            memoryScan(&result.mapCodeSectionScanDetects,pDevice,result.listSections.at(result.nCodeSection).PointerToRawData,result.listSections.at(result.nCodeSection).SizeOfRawData,_codesectionscan_records,sizeof(_codesectionscan_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
        //        }

        result.osHeader.nOffset = 0;
        result.osHeader.nSize = qMin(result.basic_info.id.nSize, (qint64)2048);

        if (result.nCodeSection != -1) {
            result.osCodeSection.nOffset = result.listSectionRecords.at(result.nCodeSection).nOffset;
            result.osCodeSection.nSize = result.listSectionRecords.at(result.nCodeSection).nSize;  // TODO limit?
        }

        if (result.nDataSection != -1) {
            result.osDataSection.nOffset = result.listSectionRecords.at(result.nDataSection).nOffset;
            result.osDataSection.nSize = result.listSectionRecords.at(result.nDataSection).nSize;
        }

        if (result.nConstDataSection != -1) {
            result.osConstDataSection.nOffset = result.listSectionRecords.at(result.nConstDataSection).nOffset;
            result.osConstDataSection.nSize = result.listSectionRecords.at(result.nConstDataSection).nSize;
        }

        if (result.nEntryPointSection != -1) {
            result.osEntryPointSection.nOffset = result.listSectionRecords.at(result.nEntryPointSection).nOffset;
            result.osEntryPointSection.nSize = result.listSectionRecords.at(result.nEntryPointSection).nSize;
        }

        if (result.nImportSection != -1) {
            result.osImportSection.nOffset = result.listSectionRecords.at(result.nImportSection).nOffset;
            result.osImportSection.nSize = result.listSectionRecords.at(result.nImportSection).nSize;
        }

        if (result.nResourcesSection != -1) {
            result.osResourcesSection.nOffset = result.listSectionRecords.at(result.nResourcesSection).nOffset;
            result.osResourcesSection.nSize = result.listSectionRecords.at(result.nResourcesSection).nSize;
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

        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_MSDOS::getHeaderLinkerRecords(),
                                  NFD_MSDOS::getHeaderLinkerRecordsSize(), result.basic_info.id.fileType, XBinary::FT_MSDOS, &(result.basic_info), DETECTTYPE_HEADER,
                                  pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapHeaderDetects, result.basic_info.sHeaderSignature, NFD_PE::getHeaderRecords(), NFD_PE::getHeaderRecordsSize(),
                                  result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_HEADER, pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapEntryPointDetects, result.sEntryPointSignature, NFD_PE::getEntrypointRecords(),
                                  NFD_PE::getEntrypointRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_ENTRYPOINT,
                                  pPdStruct);
        NFD_Binary::signatureExpScan(&pe, &(result.basic_info.memoryMap), &result.basic_info.mapEntryPointDetects, result.nEntryPointOffset,
                                     NFD_PE::getEntrypointExpRecords(), NFD_PE::getEntrypointExpRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE,
                                     &(result.basic_info), DETECTTYPE_ENTRYPOINT, pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, NFD_Binary::getBinaryRecords(), NFD_Binary::getBinaryRecordsSize(),
                                  result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, NFD_Binary::getArchiveRecords(), NFD_Binary::getArchiveRecordsSize(),
                                  result.basic_info.id.fileType, XBinary::FT_ARCHIVE, &(result.basic_info), DETECTTYPE_OVERLAY, pPdStruct);
        NFD_Binary::signatureScan(&result.basic_info.mapOverlayDetects, result.sOverlaySignature, NFD_Binary::getPEOverlayRecords(),
                                  NFD_Binary::getPEOverlayRecordsSize(), result.basic_info.id.fileType, XBinary::FT_BINARY, &(result.basic_info), DETECTTYPE_OVERLAY,
                                  pPdStruct);

        NFD_Binary::stringScan(&result.basic_info.mapSectionNamesDetects, &result.listSectionNames, NFD_PE::getSectionNamesRecords(),
                               NFD_PE::getSectionNamesRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_SECTIONNAME,
                               pPdStruct);

        // Import
        NFD_Binary::constScan(&(result.basic_info.mapImportDetects), result.nImportHash64, result.nImportHash32, NFD_PE::getImportHashRecords(),
                              NFD_PE::getImportHashRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH, pPdStruct);

        NFD_Binary::constScan(&(result.basic_info.mapImportDetects), result.nImportHash64, result.nImportHash32, NFD_PE::getImportHashArmadilloRecords(),
                              NFD_PE::getImportHashArmadilloRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH,
                              pPdStruct);

        // Export
        qint32 nNumberOfImports = result.listImportPositionHashes.count();

        for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            NFD_Binary::constScan(&(result.basic_info.mapImportDetects), i, result.listImportPositionHashes.at(i), NFD_PE::getImportPositionHashRecords(),
                                  NFD_PE::getImportPositionHashRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_IMPORTHASH,
                                  pPdStruct);
        }

        // TODO Resources scan
        NFD_Binary::PE_resourcesScan(&(result.basic_info.mapResourcesDetects), &(result.listResources), NFD_PE::getResourcesRecords(), NFD_PE::getResourcesRecordsSize(),
                                     result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_RESOURCES, pPdStruct);

        PE_x86Emul(pDevice, pOptions, &result, pPdStruct);

        // Rich
        //        qint32 nNumberOfRichSignatures=result.listRichSignatures.count();

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

        if (result.bIsNetPresent) {
            NFD_Binary::stringScan(&result.basic_info.mapDotAnsiStringsDetects, &result.listAnsiStrings, NFD_PE::getDotAnsiStringsRecords(),
                                   NFD_PE::getDotAnsiStringsRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_NETANSISTRING,
                                   pPdStruct);
            NFD_Binary::stringScan(&result.basic_info.mapDotUnicodeStringsDetects, &result.listUnicodeStrings, NFD_PE::getDotUnicodeStringsRecords(),
                                   NFD_PE::getDotUnicodeStringsRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info),
                                   DETECTTYPE_NETUNICODESTRING, pPdStruct);

            //            for(qint32 i=0;i<result.cliInfo.listUnicodeStrings.count();i++)
            //            {
            //                signatureScan(&result.mapDotUnicodestringsDetects,QBinary::stringToHex(result.cliInfo.listUnicodeStrings.at(i)),_dot_unicodestrings_records,sizeof(_dot_unicodestrings_records),result.basic_info.id.filetype,SpecAbstract::XBinary::FT_PE);
            //            }

            if (result.basic_info.scanOptions.bIsDeepScan) {
                if (pe.checkOffsetSize(result.osCodeSection)) {
                    qint64 nSectionOffset = result.osCodeSection.nOffset;
                    qint64 nSectionSize = result.osCodeSection.nSize;

                    NFD_Binary::memoryScan(&result.basic_info.mapCodeSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize, NFD_PE::getDotCodeSectionRecords(),
                                           NFD_PE::getDotCodeSectionRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info),
                                           DETECTTYPE_CODESECTION, pPdStruct);
                }
            }
        }

        if (result.basic_info.scanOptions.bIsDeepScan) {
            if (pe.checkOffsetSize(result.osCodeSection)) {
                qint64 nSectionOffset = result.osCodeSection.nOffset;
                qint64 nSectionSize = result.osCodeSection.nSize;

                NFD_Binary::memoryScan(&result.basic_info.mapCodeSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize, NFD_PE::getCodeSectionRecords(),
                                       NFD_PE::getCodeSectionRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE, &(result.basic_info), DETECTTYPE_CODESECTION,
                                       pPdStruct);
            }

            if (pe.checkOffsetSize(result.osEntryPointSection)) {
                qint64 nSectionOffset = result.osEntryPointSection.nOffset;
                qint64 nSectionSize = result.osEntryPointSection.nSize;

                NFD_Binary::memoryScan(&result.basic_info.mapEntryPointSectionDetects, pDevice, pOptions, nSectionOffset, nSectionSize,
                                       NFD_PE::getEntrypointSectionRecords(), NFD_PE::getEntrypointSectionRecordsSize(), result.basic_info.id.fileType, XBinary::FT_PE,
                                       &(result.basic_info), DETECTTYPE_ENTRYPOINTSECTION, pPdStruct);
            }
        }

        NFD_PE::PE_handle_import(pDevice, pOptions, &result, pPdStruct);

        NFD_PE::PE_handle_OperationSystem(pDevice, pOptions, &result, pPdStruct);
        NFD_PE::PE_handle_Protection(pDevice, pOptions, &result, pPdStruct);
        NFD_PE::PE_handle_SafeengineShielden(pDevice, pOptions, &result, pPdStruct);
        NFD_PE::PE_handle_VProtect(pDevice, pOptions, &result, pPdStruct);
        NFD_PE::PE_handle_TTProtect(pDevice, pOptions, &result, pPdStruct);  // TODO remove
        NFD_PE::PE_handle_VMProtect(pDevice, pOptions, &result, pPdStruct);
        PE_handle_tElock(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Armadillo(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Obsidium(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Themida(pDevice, pOptions, &result, pPdStruct);
        PE_handle_StarForce(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Petite(pDevice, pOptions, &result, pPdStruct);
        PE_handle_NETProtection(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PolyMorph(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Microsoft(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Borland(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Watcom(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Tools(pDevice, pOptions, &result, pPdStruct);
        PE_handle_wxWidgets(pDevice, pOptions, &result, pPdStruct);
        PE_handle_GCC(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Signtools(pDevice, pOptions, &result, pPdStruct);
        PE_handle_SFX(pDevice, pOptions, &result, pPdStruct);
        PE_handle_Installers(pDevice, pOptions, &result, pPdStruct);
        PE_handle_DongleProtection(pDevice, pOptions, &result, pPdStruct);
        //        PE_handle_AnslymPacker(pDevice,pOptions,&result);
        PE_handle_NeoLite(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PrivateEXEProtector(pDevice, pOptions, &result, pPdStruct);

        PE_handle_VisualBasicCryptors(pDevice, pOptions, &result, pPdStruct);
        PE_handle_DelphiCryptors(pDevice, pOptions, &result, pPdStruct);

        PE_handle_Joiners(pDevice, pOptions, &result, pPdStruct);
        PE_handle_PETools(pDevice, pOptions, &result, pPdStruct);

        PE_handle_DebugData(pDevice, pOptions, &result, pPdStruct);

        if (pOptions->bIsHeuristicScan) {
            PE_handle_UnknownProtection(pDevice, pOptions, &result, pPdStruct);
        }

        PE_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

SpecAbstract::ZIPINFO_STRUCT SpecAbstract::getZIPInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset,
                                                      XBinary::PDSTRUCT *pPdStruct)
{
    QElapsedTimer timer;
    timer.start();

    ZIPINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        result.basic_info = NFD_Binary::_initBasicInfo(&xzip, parentId, pOptions, nOffset, pPdStruct);

        //        setStatus(pOptions,XBinary::fileTypeIdToString(result.basic_info.id.fileType));
        result.listArchiveRecords = xzip.getRecords(20000, pPdStruct);

        if (pOptions->fileType == XBinary::FT_UNKNOWN) {
            QSet<XBinary::FT> stFT = XFormats::getFileTypesZIP(pDevice, &(result.listArchiveRecords), pPdStruct);

            result.bIsJAR = stFT.contains(XBinary::FT_JAR);
            result.bIsAPKS = stFT.contains(XBinary::FT_APKS);
            result.bIsIPA = stFT.contains(XBinary::FT_IPA);
        } else if (pOptions->fileType == XBinary::FT_JAR) {
            result.bIsJAR = true;
        } else if (pOptions->fileType == XBinary::FT_IPA) {
            result.bIsIPA = true;
        } else if (pOptions->fileType == XBinary::FT_APKS) {
            result.bIsAPKS = true;
        }

        result.bIsKotlin = XArchive::isArchiveRecordPresent("META-INF/androidx.core_core-ktx.version", &(result.listArchiveRecords), pPdStruct) ||
                           XArchive::isArchiveRecordPresent("kotlin/kotlin.kotlin_builtins", &(result.listArchiveRecords), pPdStruct);

        if (result.bIsIPA) {
            result.basic_info.id.fileType = XBinary::FT_IPA;
        } else if (result.bIsJAR) {
            result.basic_info.id.fileType = XBinary::FT_JAR;
        } else if (result.bIsAPKS) {
            result.basic_info.id.fileType = XBinary::FT_APKS;
        }

        Zip_handle_Metainfos(pDevice, pOptions, &(result.basic_info), &(result.listArchiveRecords), pPdStruct);
        Zip_handle_Microsoftoffice(pDevice, pOptions, &result, pPdStruct);
        Zip_handle_OpenOffice(pDevice, pOptions, &result, pPdStruct);

        if (result.bIsJAR) {
            Zip_handle_JAR(pDevice, pOptions, &result, pPdStruct);
        }

        if (result.bIsIPA) {
            Zip_handle_IPA(pDevice, pOptions, &result, pPdStruct);
        }

        Zip_handle_FixDetects(pDevice, pOptions, &result, pPdStruct);

        NFD_Binary::_handleResult(&(result.basic_info), pPdStruct);
    }

    result.basic_info.nElapsedTime = timer.elapsed();

    return result;
}

void SpecAbstract::PE_handle_tElock(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
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
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_TELOCK)) {
                        _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_TELOCK);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Armadillo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
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

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ARMADILLO, "", "", 0);

                if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ARMADILLO)) {
                    ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ARMADILLO);

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

void SpecAbstract::PE_handle_Obsidium(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
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
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_OBSIDIUM, "", "", 0);

                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Themida(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->listImports.count() == 1) {
                if (pPEInfo->listImports.at(0).sName == "kernel32.dll") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_THEMIDAWINLICENSE)) {
                            _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_THEMIDAWINLICENSE);

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
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THEMIDAWINLICENSE, "1.XX-2.XX", "", 0);

                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_THEMIDAWINLICENSE)) {
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

                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_THEMIDAWINLICENSE, "3.XX", "", 0);

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

void SpecAbstract::PE_handle_StarForce(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        bool bSF3 = XPE::isSectionNamePresent(".sforce3", &(pPEInfo->listSectionRecords));  // TODO
        bool bSF4 = XPE::isSectionNamePresent(".ps4", &(pPEInfo->listSectionRecords));      // TODO

        if (bSF3 || bSF4) {
            QString sVersion;
            QString sInfo;

            if (bSF3) {
                sVersion = "3.X";
            }

            if (bSF4) {
                sVersion = "4.X-5.X";
            }

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (pPEInfo->listImports.at(i).listPositions.count() == 1) {
                    if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "") || (pPEInfo->listImports.at(i).listPositions.at(0).sName == "1")) {
                        sInfo = pPEInfo->listImports.at(i).sName;
                    }
                }
            }

            _SCANS_STRUCT recordSS = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_STARFORCE, sVersion, sInfo, 0);
            pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
        }
    }
}

void SpecAbstract::PE_handle_Petite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (!pPEInfo->bIs64) {
                bool bKernel32 = false;
                bool bUser32 = false;
                QString sVersion;

                // TODO !!!
                // TODO Petite 2.4 Check header

                qint32 nNumberOfImports = pPEInfo->listImports.count();

                for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pPEInfo->listImports.at(i).sName.toUpper() == "USER32.DLL") {
                        if (pPEInfo->listImports.at(i).listPositions.count() == 2) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "MessageBoxA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "wsprintfA")) {
                                bUser32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 1) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "MessageBoxA")) {
                                bUser32 = true;
                            }
                        }
                    } else if (pPEInfo->listImports.at(i).sName.toUpper() == "KERNEL32.DLL") {
                        if (pPEInfo->listImports.at(i).listPositions.count() == 7) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetModuleHandleA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "VirtualAlloc") &&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName == "VirtualFree") &&
                                (pPEInfo->listImports.at(i).listPositions.at(6).sName == "LoadLibraryA")) {
                                sVersion = "2.4";
                                bKernel32 = true;
                            } else if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(1).sName == "LoadLibraryA") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(5).sName == "GlobalFree") &&
                                       (pPEInfo->listImports.at(i).listPositions.at(6).sName == "GetModuleHandleA")) {
                                sVersion = "2.3";
                                bKernel32 = true;
                            }
                        }

                        if (pPEInfo->listImports.at(i).listPositions.count() == 6) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetModuleHandleA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc") &&
                                (pPEInfo->listImports.at(i).listPositions.at(5).sName == "GlobalFree")) {
                                sVersion = "2.3";  // DLL only?? // TODO Check
                                bKernel32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 5) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "LoadLibraryA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "VirtualProtect") &&
                                (pPEInfo->listImports.at(i).listPositions.at(4).sName == "GlobalAlloc")) {
                                sVersion = "2.2";
                                bKernel32 = true;
                            }
                        } else if (pPEInfo->listImports.at(i).listPositions.count() == 4) {
                            if ((pPEInfo->listImports.at(i).listPositions.at(0).sName == "ExitProcess") &&
                                (pPEInfo->listImports.at(i).listPositions.at(1).sName == "GetProcAddress") &&
                                (pPEInfo->listImports.at(i).listPositions.at(2).sName == "LoadLibraryA") &&
                                (pPEInfo->listImports.at(i).listPositions.at(3).sName == "GlobalAlloc")) {
                                sVersion = "1.4";
                                bKernel32 = true;
                            }
                        }
                    }
                }

                // TODO Import hash
                if (bUser32 && bKernel32) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PETITE)) {
                        _SCANS_STRUCT recordPETITE = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        recordPETITE.sVersion = sVersion;
                        pPEInfo->basic_info.mapResultPackers.insert(recordPETITE.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordPETITE));
                    }
                } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_PETITE)) {
                    if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PETITE)) {
                        _SCANS_STRUCT recordPETITE = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PETITE);
                        pPEInfo->basic_info.mapResultPackers.insert(recordPETITE.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordPETITE));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_NETProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pPEInfo->bIsNetPresent) {
            // .NET
            // Enigma
            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan))  // TODO
            {
                qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                VI_STRUCT viEnigma = NFD_Binary::get_Enigma_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                if (viEnigma.bIsValid) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_ENIGMA, viEnigma.sVersion, ".NET", 0);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // .Net reactor
            if (pPEInfo->listSectionRecords.count() >= 2) {
                if (pPEInfo->basic_info.scanOptions.bIsDeepScan) {
                    qint64 _nOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize = pPEInfo->listSectionRecords.at(1).nSize;

                    qint64 nOffset_NetReactor = pe.find_signature(&(pPEInfo->basic_info.memoryMap), _nOffset, _nSize,
                                                                  "5266686E204D182276B5331112330C6D0A204D18229EA129611C76B505190158", nullptr, pPdStruct);

                    if (nOffset_NetReactor != -1) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_DOTNETREACTOR, "4.8-4.9", "", 0);
                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // TODO
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_YANO)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_YANO);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_AGILENET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_AGILENET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SKATER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SKATER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_BABELNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_BABELNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_GOLIATHNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_GOLIATHNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SPICESNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SPICESNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_OBFUSCATORNET2009)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_OBFUSCATORNET2009);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            {
                bool bDetect = false;
                _SCANS_STRUCT ss = {};

                if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DEEPSEA)) {
                    ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect = true;
                } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DEEPSEA)) {
                    ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DEEPSEA);
                    bDetect = true;
                }

                if (bDetect) {
                    qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi = NFD_Binary::get_DeepSea_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                    if (vi.bIsValid) {
                        ss.sVersion = vi.sVersion;
                        ss.sInfo = vi.sInfo;
                    }

                    pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // cliSecure
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CLISECURE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CLISECURE);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else {
                if (pPEInfo->listSectionHeaders.count() >= 2) {
                    qint64 _nOffset = pPEInfo->listSectionRecords.at(1).nOffset;
                    qint64 _nSize = pPEInfo->listSectionRecords.at(1).nSize;
                    qint32 _nCharacteristics = pPEInfo->listSectionRecords.at(1).nCharacteristics;

                    if (_nCharacteristics & (XPE_DEF::S_IMAGE_SCN_MEM_EXECUTE)) {
                        qint64 nOffset_CliSecure = pe.find_unicodeString(_nOffset, _nSize, "CliSecure", false, pPdStruct);

                        if (nOffset_CliSecure != -1) {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_CLISECURE, "4.X", "", 0);
                            pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }
                }
            }

            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_FISHNET)) || (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_FISHNET))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_FISHNET, "1.X", "", 0);  // TODO
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));       // TODO obfuscator?
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_NSPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_NSPACK);
                pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DNGUARD)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DNGUARD);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // .NETZ
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETZ)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETZ)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETZ);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_MAXTOCODE)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_MAXTOCODE);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_PHOENIXPROTECTOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            {
                bool bDetect = false;
                _SCANS_STRUCT ss = {};

                if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SMARTASSEMBLY)) {
                    ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect = true;
                } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SMARTASSEMBLY)) {
                    ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SMARTASSEMBLY);
                    bDetect = true;
                }

                if (bDetect) {
                    qint64 nSectionOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 nSectionSize = pPEInfo->osCodeSection.nSize;

                    VI_STRUCT vi = NFD_Binary::get_SmartAssembly_vi(pDevice, pOptions, nSectionOffset, nSectionSize, pPdStruct);

                    if (vi.bIsValid) {
                        ss.sVersion = vi.sVersion;
                        ss.sInfo = vi.sInfo;
                    }

                    pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CONFUSER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CONFUSER);

                if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize = pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_detect = pe.find_ansiString(_nOffset, _nSize, "Confuser v", pPdStruct);

                    if (nOffset_detect != -1) {
                        ss.sVersion = pe.read_ansiString(nOffset_detect + 10);
                    }

                    if (nOffset_detect == -1) {
                        qint64 nOffset_ConfuserEx = pe.find_ansiString(_nOffset, _nSize, "ConfuserEx v", pPdStruct);

                        if (nOffset_ConfuserEx != -1) {
                            ss.name = RECORD_NAME_CONFUSEREX;
                            ss.sVersion = pe.read_ansiString(nOffset_ConfuserEx + 12);
                        }
                    }
                }

                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Xenocode Postbuild
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_XENOCODEPOSTBUILD)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_XENOCODEPOSTBUILD);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // CodeVeil
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_CODEVEIL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapDotUnicodeStringsDetects.contains(RECORD_NAME_CODEVEIL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotUnicodeStringsDetects.value(RECORD_NAME_CODEVEIL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // CodeWall
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_CODEWALL)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_CODEWALL);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Crypto Obfuscator for .NET
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_CRYPTOOBFUSCATORFORNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_CRYPTOOBFUSCATORFORNET);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Eazfuscator
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_EAZFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_EAZFUSCATOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_EAZFUSCATOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Obfuscar
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_OBFUSCAR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_OBFUSCAR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // .NET Spider
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_DOTNETSPIDER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSPIDER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETSPIDER);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Phoenix Protector
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_PHOENIXPROTECTOR)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_PHOENIXPROTECTOR);
                pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // Sixxpack
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_SIXXPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_SIXXPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_SIXXPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // ReNET-Pack
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_RENETPACK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_RENETPACK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
            // .netshrink
            if (pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_DOTNETSHRINK)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapCodeSectionDetects.value(RECORD_NAME_DOTNETSHRINK);
                pPEInfo->basic_info.mapResultNETCompressors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Xenocode Virtual Application Studio 2009
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Postbuild 2009 for .NET")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_NETOBFUSCATOR, RECORD_NAME_XENOCODEPOSTBUILD2009FORDOTNET, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultNETObfuscators.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Xenocode Postbuild 2010 for .NET
        if (XPE::getResourcesVersionValue("Packager", &(pPEInfo->resVersion)).contains("Xenocode Postbuild 2010 for .NET")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_XENOCODEPOSTBUILD2010FORDOTNET, "", "", 0);
            ss.sVersion = XPE::getResourcesVersionValue("PackagerVersion", &(pPEInfo->resVersion)).trimmed();
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_DOTNETREACTOR)) {
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DOTNETREACTOR) &&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "__", &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DOTNETREACTOR);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
        if (!pPEInfo->basic_info.mapResultProtectors.contains(RECORD_NAME_CODEVEIL)) {
            if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CODEVEIL)) {
                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_CODEVEIL)) {
                    _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_CODEVEIL);
                    pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Microsoft(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    _SCANS_STRUCT ssLinker = {};
    _SCANS_STRUCT ssCompilerCPP = {};
    _SCANS_STRUCT ssCompilerMASM = {};
    _SCANS_STRUCT ssCompilerVB = {};
    _SCANS_STRUCT ssCompilerDot = {};
    _SCANS_STRUCT ssTool = {};
    _SCANS_STRUCT ssMFC = {};
    _SCANS_STRUCT ssNET = {};

    QMap<QString, QString> mapVersions;

    mapVersions.insert("1", "8");
    mapVersions.insert("2", "9");
    mapVersions.insert("4", "10");
    mapVersions.insert("5", "11");
    mapVersions.insert("6", "12");
    mapVersions.insert("7", "13");
    mapVersions.insert("8", "14");
    mapVersions.insert("9", "15");
    mapVersions.insert("10", "16");
    mapVersions.insert("11", "17");
    mapVersions.insert("12", "18");
    mapVersions.insert("14", "19");

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Linker
        if ((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)) && (!pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
            ssLinker.type = RECORD_TYPE_LINKER;
            ssLinker.name = RECORD_NAME_MICROSOFTLINKER;
            //        } else if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
            //            bool bMicrosoftLinker = false;

            //            if ((pPEInfo->nMajorLinkerVersion == 8) && (pPEInfo->nMinorImageVersion == 0))  // 8.0
            //            {
            //                bMicrosoftLinker = true;
            //            }

            //            if (bMicrosoftLinker) {
            //                ssLinker.type = RECORD_TYPE_LINKER;
            //                ssLinker.name = RECORD_NAME_MICROSOFTLINKER;
            //            }
        } else if ((pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) && (pPEInfo->cliInfo.bValid)) {
            ssLinker.type = RECORD_TYPE_LINKER;
            ssLinker.name = RECORD_NAME_MICROSOFTLINKER;

            ssCompilerDot.type = RECORD_TYPE_COMPILER;
            ssCompilerDot.name = RECORD_NAME_VISUALCSHARP;
        }

        // MFC
        // Static
        if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            qint64 _nOffset = pPEInfo->osDataSection.nOffset;
            qint64 _nSize = pPEInfo->osDataSection.nSize;

            qint64 nOffset_MFC = pe.find_ansiString(_nOffset, _nSize, "CMFCComObject", pPdStruct);

            if (nOffset_MFC != -1) {
                ssMFC.type = RECORD_TYPE_LIBRARY;
                ssMFC.name = RECORD_NAME_MFC;
                ssMFC.sInfo = "Static";
            }
        }

        qint32 nNumberOfImports = pPEInfo->listImports.count();

        for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            // https://en.wikipedia.org/wiki/Microsoft_Foundation_Class_Library
            // TODO eMbedded Visual C++ 4.0 		mfcce400.dll 	MFC 6.0
            if (XBinary::isRegExpPresent("^MFC", pPEInfo->listImports.at(i).sName.toUpper())) {
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

                QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                if (sVersion != "") {
                    double dVersion = sVersion.toDouble() / 10;

                    if (dVersion) {
                        ssMFC.type = RECORD_TYPE_LIBRARY;
                        ssMFC.name = RECORD_NAME_MFC;
                        ssMFC.sVersion = QString::number(dVersion, 'f', 2);

                        if (pPEInfo->listImports.at(i).sName.toUpper().contains("U.DLL")) {
                            ssMFC.sInfo = "Unicode";
                        }
                    }
                }

                break;
            }
        }

        // Rich
        // https://github.com/dishather/richprint/blob/master/comp_id.txt
        qint32 nRichSignaturesCount = pPEInfo->listRichSignatures.count();

        QList<_SCANS_STRUCT> listRichDescriptions;

        for (qint32 i = 0; (i < nRichSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
            listRichDescriptions.append(NFD_MSDOS::MSDOS_richScan(pPEInfo->listRichSignatures.at(i).nId, pPEInfo->listRichSignatures.at(i).nVersion,
                                                                  pPEInfo->listRichSignatures.at(i).nCount, NFD_MSDOS::getRichRecords(), NFD_MSDOS::getRichRecordsSize(),
                                                                  pPEInfo->basic_info.id.fileType, XBinary::FT_MSDOS,
                                                                  reinterpret_cast<NFD_Binary::BASIC_INFO *>(&(pPEInfo->basic_info)), DETECTTYPE_RICH, pPdStruct));
        }

        _fixRichSignatures(&listRichDescriptions, pPEInfo->nMajorLinkerVersion, pPEInfo->nMinorLinkerVersion, pPdStruct);

        qint32 nRichDescriptionsCount = listRichDescriptions.count();

        _SCANS_STRUCT _ssLinker = {};
        _SCANS_STRUCT _ssCompilerCPP = {};
        _SCANS_STRUCT _ssCompilerMASM = {};
        _SCANS_STRUCT _ssCompilerVB = {};

        for (qint32 i = nRichDescriptionsCount - 1; (i >= 0) && (XBinary::isPdStructNotCanceled(pPdStruct)); i--) {
            if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_LINKER) {
                if (listRichDescriptions.at(i).sVersion > _ssLinker.sVersion) {
                    _ssLinker.name = listRichDescriptions.at(i).name;
                    _ssLinker.sVersion = listRichDescriptions.at(i).sVersion;
                    _ssLinker.sInfo = listRichDescriptions.at(i).sInfo;
                    _ssLinker.type = listRichDescriptions.at(i).type;
                }
            } else if (listRichDescriptions.at(i).type == SpecAbstract::RECORD_TYPE_COMPILER) {
                if (listRichDescriptions.at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) {
                    if (listRichDescriptions.at(i).sInfo != "Basic") {
                        if (listRichDescriptions.at(i).sVersion > _ssCompilerCPP.sVersion) {
                            _ssCompilerCPP.name = RECORD_NAME_VISUALCCPP;
                            _ssCompilerCPP.sVersion = listRichDescriptions.at(i).sVersion;
                            _ssCompilerCPP.sInfo = listRichDescriptions.at(i).sInfo;
                            _ssCompilerCPP.type = listRichDescriptions.at(i).type;
                        }
                    } else {
                        if (listRichDescriptions.at(i).sVersion > _ssCompilerVB.sVersion) {
                            _ssCompilerVB.type = RECORD_TYPE_COMPILER;
                            _ssCompilerVB.name = RECORD_NAME_VISUALBASIC;
                            _ssCompilerVB.sVersion = listRichDescriptions.at(i).sVersion;

                            QString _sVersion = _ssCompilerVB.sVersion.section(".", 0, 0);
                            QString _sVersionCompiler = mapVersions.key(_sVersion, "");

                            if (_sVersionCompiler != "") {
                                _ssCompilerVB.sVersion = _sVersionCompiler + "." + _ssCompilerVB.sVersion.section(".", 1, 2);
                            }

                            _ssCompilerVB.sInfo = "Native";
                        }
                    }
                } else if (listRichDescriptions.at(i).name == RECORD_NAME_MASM) {
                    if (listRichDescriptions.at(i).sVersion > _ssCompilerMASM.sVersion) {
                        _ssCompilerMASM.name = listRichDescriptions.at(i).name;
                        _ssCompilerMASM.sVersion = listRichDescriptions.at(i).sVersion;
                        _ssCompilerMASM.sInfo = listRichDescriptions.at(i).sInfo;
                        _ssCompilerMASM.type = listRichDescriptions.at(i).type;
                    }
                } else {
                    if (listRichDescriptions.at(i).sVersion > _ssCompilerCPP.sVersion) {
                        _ssCompilerCPP.name = listRichDescriptions.at(i).name;
                        _ssCompilerCPP.sVersion = listRichDescriptions.at(i).sVersion;
                        _ssCompilerCPP.sInfo = listRichDescriptions.at(i).sInfo;
                        _ssCompilerCPP.type = listRichDescriptions.at(i).type;
                    }
                }
            }

            //            if (listRichDescriptions.at(i).name == SpecAbstract::RECORD_NAME_IMPORT) {
            //                break;
            //            }
        }

        if (_ssLinker.name != RECORD_NAME_UNKNOWN) {
            ssLinker.name = _ssLinker.name;
            ssLinker.sVersion = _ssLinker.sVersion;
            ssLinker.sInfo = _ssLinker.sInfo;
            ssLinker.type = _ssLinker.type;
        }

        if (_ssCompilerVB.name != RECORD_NAME_UNKNOWN) {
            ssCompilerVB.name = _ssCompilerVB.name;
            ssCompilerVB.sVersion = _ssCompilerVB.sVersion;
            ssCompilerVB.sInfo = _ssCompilerVB.sInfo;
            ssCompilerVB.type = _ssCompilerVB.type;
        } else if (_ssCompilerCPP.name != RECORD_NAME_UNKNOWN) {
            ssCompilerCPP.name = _ssCompilerCPP.name;
            ssCompilerCPP.sVersion = _ssCompilerCPP.sVersion;
            ssCompilerCPP.sInfo = _ssCompilerCPP.sInfo;
            ssCompilerCPP.type = _ssCompilerCPP.type;
        } else if (_ssCompilerMASM.name != RECORD_NAME_UNKNOWN) {
            ssCompilerMASM.name = _ssCompilerMASM.name;
            ssCompilerMASM.sVersion = _ssCompilerMASM.sVersion;
            ssCompilerMASM.sInfo = _ssCompilerMASM.sInfo;
            ssCompilerMASM.type = _ssCompilerMASM.type;
        }

        // TODO Check MASM for .NET

        if (!pPEInfo->cliInfo.bValid) {
            // VB
            bool bVBnew = false;

            _SCANS_STRUCT _recordCompiler = {};

            if (XPE::isImportLibraryPresentI("VB40032.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "4.0";
            } else if (XPE::isImportLibraryPresentI("MSVBVM50.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "5.0";
                bVBnew = true;
            }

            if (XPE::isImportLibraryPresentI("MSVBVM60.DLL", &(pPEInfo->listImports))) {
                _recordCompiler.type = RECORD_TYPE_COMPILER;
                _recordCompiler.name = RECORD_NAME_VISUALBASIC;
                _recordCompiler.sVersion = "6.0";
                bVBnew = true;
            }

            if (bVBnew) {
                if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                    qint64 _nSize = pPEInfo->osCodeSection.nSize;

                    qint64 nOffset_Options = pe.find_uint32(_nOffset, _nSize, 0x21354256, false, pPdStruct);

                    if (nOffset_Options == -1) {
                        nOffset_Options = pe.find_uint32(_nOffset, _nSize, 0x21364256, false, pPdStruct);
                    }

                    if (nOffset_Options != -1) {
                        quint32 nOffsetOptions2 = pe.read_uint32(_nOffset + 0x30);

                        quint32 nOffsetOptions3 = pe.addressToOffset(pe.getBaseAddress() + nOffsetOptions2);
                        quint32 nValue = pe.read_uint32(nOffsetOptions3 + 0x20);
                        _recordCompiler.sInfo = nValue ? "P-Code" : "Native";
                    }
                }
            }

            if (ssCompilerCPP.name != RECORD_NAME_VISUALBASIC) {
                if (_recordCompiler.name == RECORD_NAME_VISUALBASIC) {
                    ssCompilerVB = _recordCompiler;
                }
            }
        } else {
            ssNET.type = SpecAbstract::RECORD_TYPE_LIBRARY;
            ssNET.name = SpecAbstract::RECORD_NAME_DOTNET;
            ssNET.sVersion = pPEInfo->cliInfo.metaData.header.sVersion;

            if (pPEInfo->cliInfo.bHidden) {
                ssNET.sInfo = "Hidden";
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_VBNET)) {
                ssCompilerVB.type = RECORD_TYPE_COMPILER;
                ssCompilerVB.name = RECORD_NAME_VBNET;
            }

            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_JSCRIPT)) {
                ssCompilerVB.type = RECORD_TYPE_COMPILER;
                ssCompilerVB.name = RECORD_NAME_JSCRIPT;
            }
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssCompilerCPP.type == RECORD_TYPE_UNKNOWN)) {
            ssCompilerCPP.type = SpecAbstract::RECORD_TYPE_COMPILER;
            ssCompilerCPP.name = SpecAbstract::RECORD_NAME_VISUALCCPP;

            QString _sVersion = mapVersions.value(ssMFC.sVersion.section(".", 0, 0)) + "." + ssMFC.sVersion.section(".", 1, 1);

            if (_sVersion != "") {
                ssCompilerCPP.sVersion = _sVersion;
            }
        }

        if (ssCompilerCPP.name != RECORD_NAME_VISUALCCPP) {
            // TODO Check mb MS Linker only

            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_VISUALCCPP)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_VISUALCCPP);

                ssCompilerCPP.type = ss.type;
                ssCompilerCPP.name = ss.name;
                ssCompilerCPP.sVersion = ss.sVersion;
            }
        }

        // TODO if Export ^? RECORD_NAME_VISUALCCPP/C++

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssMFC.sVersion == "")) {
            if ((ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) && (ssLinker.sVersion != "")) {
                ssMFC.sVersion = ssLinker.sVersion.section(".", 0, 1);
            }
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssLinker.name != RECORD_NAME_MICROSOFTLINKER)) {
            ssLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name = SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if ((ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) && (ssLinker.name != RECORD_NAME_MICROSOFTLINKER)) {
            ssLinker.type = SpecAbstract::RECORD_TYPE_LINKER;
            ssLinker.name = SpecAbstract::RECORD_NAME_MICROSOFTLINKER;
        }

        if ((ssLinker.name == RECORD_NAME_MICROSOFTLINKER) && (ssLinker.sVersion == "")) {
            ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
        }

        if ((ssMFC.name == RECORD_NAME_MFC) && (ssLinker.sVersion == "") && (pPEInfo->nMinorLinkerVersion != 10)) {
            ssLinker.sVersion = ssMFC.sVersion;
            //            recordLinker.sVersion=QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
        }

        if (ssLinker.name == RECORD_NAME_MICROSOFTLINKER) {
            if (ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) {
                if (ssCompilerCPP.sVersion == "") {
                    QString sLinkerVersion = ssLinker.sVersion;
                    QString sLinkerMajorVersion = sLinkerVersion.section(".", 0, 1);

                    QString _sVersion = mapVersions.value(sLinkerMajorVersion);

                    if (_sVersion != "") {
                        ssCompilerCPP.sVersion = _sVersion;
                    }
                }
            }
        }

        if (ssCompilerCPP.name == RECORD_NAME_VISUALCCPP) {
            QString sCompilerVersion = ssCompilerCPP.sVersion;
            QString sCompilerBuildVersion = sCompilerVersion.section(".", 2, 2);

            bool bNewMSVC = false;
            if (sCompilerVersion.toInt() == 19) {
                bNewMSVC = true;
            }

            ssTool.type = SpecAbstract::RECORD_TYPE_TOOL;
            ssTool.name = SpecAbstract::RECORD_NAME_MICROSOFTVISUALSTUDIO;

            // https://docs.microsoft.com/en-us/cpp/error-messages/compiler-warnings/compiler-warnings-by-compiler-version?view=vs-2019
            // https://github.com/dishather/richprint/blob/master/comp_id.txt

            if (!bNewMSVC) {
                if (sCompilerVersion == "12.00.8168") ssTool.sVersion = "6.0";
                else if (sCompilerVersion == "12.00.8804") ssTool.sVersion = "6.0 SP5-SP6";
                else if (sCompilerVersion == "12.00.8447") ssTool.sVersion = "6.0 SP5";
                else if (sCompilerVersion == "13.00.9176") ssTool.sVersion = "Windows XP SP1 DDK";
                else if (sCompilerVersion == "13.00.9466") ssTool.sVersion = "2002(.NET) 7.0.9466";
                else if (sCompilerVersion == "13.10.3052") ssTool.sVersion = "2003";
                else if (sCompilerVersion == "13.10.3077") ssTool.sVersion = "2003(.NET) 7.0.1.3088";
                else if (sCompilerVersion == "13.10.4035") ssTool.sVersion = "Windows Server 2003 SP1 DDK";
                else if (sCompilerVersion == "13.10.6030") ssTool.sVersion = "2003(.NET) SP1 (kb918007)";
                else if (sCompilerVersion == "14.00.40310") ssTool.sVersion = "Windows Server 2003 SP1 DDK (for AMD64)";
                else if (sCompilerVersion == "14.00.40607") ssTool.sVersion = "2005 Beta 1 [8.0]";
                else if (sCompilerVersion == "14.00.50215") ssTool.sVersion = "2005 Beta 2 [8.0]";
                else if (sCompilerVersion == "14.00.50320") ssTool.sVersion = "2005 [8.0]";
                else if (sCompilerVersion == "14.00.50727") ssTool.sVersion = "2005 SP1";
                else if (sCompilerVersion == "15.00.20706") ssTool.sVersion = "2008 Beta 2 [9.0]";
                else if (sCompilerVersion == "15.00.21022") ssTool.sVersion = "2008 (9.0.21022.8 RTM)";
                else if (sCompilerVersion == "15.00.30411") ssTool.sVersion = "2008 with Feature Pack";
                else if (sCompilerVersion == "15.00.30729") ssTool.sVersion = "2008 SP1 (9.0.30729.1 SP)";
                else if (sCompilerVersion == "16.00.20506") ssTool.sVersion = "2010 Beta 1";
                else if (sCompilerVersion == "16.00.21003") ssTool.sVersion = "2010 Beta 2";
                else if (sCompilerVersion == "16.00.30319") ssTool.sVersion = "2010 (10.0.30319.1 RTMRel)";
                else if (sCompilerVersion == "16.00.40219") ssTool.sVersion = "2010 SP1 kb 983509 (10.0.40219.1 SP1Rel)";
                else if (sCompilerVersion == "17.00.50727") ssTool.sVersion = "2012 Premium (11.0.50727.1 RTMREL)";
                else if (sCompilerVersion == "17.00.51025") ssTool.sVersion = "2012 November CTP [11.0]";
                else if (sCompilerVersion == "17.00.51106") ssTool.sVersion = "2012 Update 1 (17.00.51106.1 Update 1)";
                else if (sCompilerVersion == "17.00.60315") ssTool.sVersion = "2012 Update 2 (17.00.60315.1 Update 2)";
                else if (sCompilerVersion == "17.00.60610") ssTool.sVersion = "2012 Update 3 (17.00.60610.1 Update 3)";
                else if (sCompilerVersion == "17.00.61030") ssTool.sVersion = "2012 Premium Update 4 (11.0.61030.00 Update 4)";
                else if (sCompilerVersion == "18.00.20617") ssTool.sVersion = "2013 Preview [12.0]";
                else if (sCompilerVersion == "18.00.20827") ssTool.sVersion = "2013 RC [12.0]";
                else if (sCompilerVersion == "18.00.21005") ssTool.sVersion = "2013 RTM";
                else if (sCompilerVersion == "18.00.21114") ssTool.sVersion = "2013 Nobemver CTP [12.0";
                else if (sCompilerVersion == "18.00.30324") ssTool.sVersion = "2013 Update2 RC [12.0]";
                else if (sCompilerVersion == "18.00.30501") ssTool.sVersion = "2013 12.0.30501.00 Update 2";
                else if (sCompilerVersion == "18.00.30723") ssTool.sVersion = "2013 12.0.30723.00 Update 3";
                else if (sCompilerVersion == "18.00.31101") ssTool.sVersion = "2013 12.0.31101.00 Update 4";
                else if (sCompilerVersion == "18.00.40629") ssTool.sVersion = "2013 12.0.40629.00 Update 5";
            } else {
                if (sCompilerBuildVersion == "22215") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23007") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23013") ssTool.sVersion = "2015";
                else if (sCompilerBuildVersion == "23026") ssTool.sVersion = "Community 2015 [14.0]";
                else if (sCompilerBuildVersion == "23506") ssTool.sVersion = "Community 2015 14.0.24728.2 (UPD 1)";
                else if (sCompilerBuildVersion == "23918") ssTool.sVersion = "Community 2015 UPD2 (14.0.25123.0)";
                else if (sCompilerBuildVersion == "24103") ssTool.sVersion = "2015 SP1";  // ???
                else if (sCompilerBuildVersion == "24118") ssTool.sVersion = "2015 SP1";  // ???
                else if (sCompilerBuildVersion == "24123") ssTool.sVersion = "Community 2015 UPD3";
                else if (sCompilerBuildVersion == "24210") ssTool.sVersion = "2015 Update 3 [14.0]";
                else if (sCompilerBuildVersion == "24212") ssTool.sVersion = "2015 Update 3";
                else if (sCompilerBuildVersion == "24213") ssTool.sVersion = "Community 2015 UPD3.1";
                else if (sCompilerBuildVersion == "24215") ssTool.sVersion = "2015 Update 3.1";
                else if (sCompilerBuildVersion == "24218") ssTool.sVersion = "2015 Update 3.1";
                else if (sCompilerBuildVersion == "24723") ssTool.sVersion = "2015";                    // Update 4? 2017?
                else if (sCompilerBuildVersion == "25017") ssTool.sVersion = "2017 version 15.0-15.2";  // 14.10
                else if (sCompilerBuildVersion == "25019") ssTool.sVersion = "2017";                    // 15.2?
                else if (sCompilerBuildVersion == "25506") ssTool.sVersion = "2017 version 15.3.0";     // 14.11
                else if (sCompilerBuildVersion == "25507") ssTool.sVersion = "2017 version 15.3.3";
                else if (sCompilerBuildVersion == "25542") ssTool.sVersion = "2017 version 15.4.4";
                else if (sCompilerBuildVersion == "25547") ssTool.sVersion = "2017 version 15.4.5";
                else if (sCompilerBuildVersion == "25830") ssTool.sVersion = "2017 version 15.5.0";  // 14.12
                else if (sCompilerBuildVersion == "25831") ssTool.sVersion = "2017 version 15.5.2";
                else if (sCompilerBuildVersion == "25834") ssTool.sVersion = "2017 version 15.5.3-15.5.4";
                else if (sCompilerBuildVersion == "25835") ssTool.sVersion = "2017 version 15.5.6-15.5.7";
                else if (sCompilerBuildVersion == "26128") ssTool.sVersion = "2017 version 15.6.0-15.6.2";  // 14.13
                else if (sCompilerBuildVersion == "26129") ssTool.sVersion = "2017 version 15.6.3-15.6.4";
                else if (sCompilerBuildVersion == "26131") ssTool.sVersion = "2017 version 15.6.6";
                else if (sCompilerBuildVersion == "26132") ssTool.sVersion = "2017 version 15.6.7";
                else if (sCompilerBuildVersion == "26428") ssTool.sVersion = "2017 version 15.7.1";  // 14.14
                else if (sCompilerBuildVersion == "26429") ssTool.sVersion = "2017 version 15.7.2";
                else if (sCompilerBuildVersion == "26430") ssTool.sVersion = "2017 version 15.7.3";
                else if (sCompilerBuildVersion == "26431") ssTool.sVersion = "2017 version 15.7.4";
                else if (sCompilerBuildVersion == "26433") ssTool.sVersion = "2017 version 15.7.5";
                else if (sCompilerBuildVersion == "26726") ssTool.sVersion = "2017 version 15.8.0";  // 14.15
                else if (sCompilerBuildVersion == "26729") ssTool.sVersion = "2017 version 15.8.4";
                else if (sCompilerBuildVersion == "26730") ssTool.sVersion = "2017 version 15.8.9";
                else if (sCompilerBuildVersion == "26732") ssTool.sVersion = "2017 version 15.8.5";
                else if (sCompilerBuildVersion == "26926") ssTool.sVersion = "2017 version 15.9.0";  // 14.16
                else if (sCompilerBuildVersion == "27023") ssTool.sVersion = "2017 version 15.9.1";
                else if (sCompilerBuildVersion == "27025") ssTool.sVersion = "2017 version 15.9.4";
                else if (sCompilerBuildVersion == "27026") ssTool.sVersion = "2017 version 15.9.5";
                else if (sCompilerBuildVersion == "27027") ssTool.sVersion = "2017 version 15.9.7";
                else if (sCompilerBuildVersion == "27030") ssTool.sVersion = "2017 version 15.9.11";
                else if (sCompilerBuildVersion == "27508") ssTool.sVersion = "2019 version 16.0.0";  // 14.20
                else if (sCompilerBuildVersion == "27702") ssTool.sVersion = "2019 version 16.1.2";  // 14.21
                else if (sCompilerBuildVersion == "27905") ssTool.sVersion = "2019 version 16.2.3";  // 14.22
                else if (sCompilerBuildVersion == "28105") ssTool.sVersion = "2019 version 16.3.2";  // 14.23
                else if (sCompilerBuildVersion == "28314") ssTool.sVersion = "2019 version 16.4.0";  // 14.24
                else if (sCompilerBuildVersion == "28315") ssTool.sVersion = "2019 version 16.4.3";
                else if (sCompilerBuildVersion == "28316") ssTool.sVersion = "2019 version 16.4.4";
                else if (sCompilerBuildVersion == "28319") ssTool.sVersion = "2019 version 16.4.6";
                else if (sCompilerBuildVersion == "28610") ssTool.sVersion = "2019 version 16.5.0";  // 14.25
                else if (sCompilerBuildVersion == "28611") ssTool.sVersion = "2019 version 16.5.1";
                else if (sCompilerBuildVersion == "28612") ssTool.sVersion = "2019 version 16.5.2";
                else if (sCompilerBuildVersion == "28614") ssTool.sVersion = "2019 version 16.5.4";
                else if (sCompilerBuildVersion == "28805") ssTool.sVersion = "2019 version 16.6.0";  // 14.26
                else if (sCompilerBuildVersion == "28806") ssTool.sVersion = "2019 version 16.6.2-16.6.5";
                else if (sCompilerBuildVersion == "29110") ssTool.sVersion = "2019 version 16.7.0";  // 14.27
                else if (sCompilerBuildVersion == "29111") ssTool.sVersion = "2019 version 16.7.1-16.7.4";
                else if (sCompilerBuildVersion == "29112") ssTool.sVersion = "2019 version 16.7.5";
                else if (sCompilerBuildVersion == "29333") ssTool.sVersion = "2019 version 16.8.0";  // 14.28
                else if (sCompilerBuildVersion == "29334") ssTool.sVersion = "2019 version 16.8.2";
                else if (sCompilerBuildVersion == "29335") ssTool.sVersion = "2019 version 16.8.3";
                else if (sCompilerBuildVersion == "29336") ssTool.sVersion = "2019 version 16.8.4";
                else if (sCompilerBuildVersion == "29337") ssTool.sVersion = "2019 version 16.8.5";
                else if (sCompilerBuildVersion == "29910") ssTool.sVersion = "2019 version 16.9.0";
                else if (sCompilerBuildVersion == "29913") ssTool.sVersion = "2019 version 16.9.2";
                else if (sCompilerBuildVersion == "29914") ssTool.sVersion = "2019 version 16.9.4";
                else if (sCompilerBuildVersion == "29915") ssTool.sVersion = "2019 version 16.9.5";
                else if (sCompilerBuildVersion == "30037") ssTool.sVersion = "2019 version 16.10.0";
                else if (sCompilerBuildVersion == "30038") ssTool.sVersion = "2019 version 16.10.3";
                else if (sCompilerBuildVersion == "30040") ssTool.sVersion = "2019 version 16.10.4";
                else if (sCompilerBuildVersion == "30133") ssTool.sVersion = "2019 version 16.11.1";  // 14.29
                else if (sCompilerBuildVersion == "30136") ssTool.sVersion = "2019 version 16.11.5";
                else if (sCompilerBuildVersion == "30137") ssTool.sVersion = "2019 version 16.11.6";
                else if (sCompilerBuildVersion == "30138") ssTool.sVersion = "2019 version 16.11.8";
                else if (sCompilerBuildVersion == "30139") ssTool.sVersion = "2019 version 16.11.9";
                else if (sCompilerBuildVersion == "30140") ssTool.sVersion = "2019 version 16.11.10";
                else if (sCompilerBuildVersion == "30141") ssTool.sVersion = "2019 version 16.11.11";
                else if (sCompilerBuildVersion == "30142") ssTool.sVersion = "2019 version 16.11.12";
                else if (sCompilerBuildVersion == "30143") ssTool.sVersion = "2019 version 16.11.13";
                else if (sCompilerBuildVersion == "30144") ssTool.sVersion = "2019 version 16.11.14";
                else if (sCompilerBuildVersion == "30145") ssTool.sVersion = "2019 version 16.11.15";
                else if (sCompilerBuildVersion == "30146") ssTool.sVersion = "2019 version 16.11.17";
                else if (sCompilerBuildVersion == "30147") ssTool.sVersion = "2019 version 16.11.21";
                else if (sCompilerBuildVersion == "30148") ssTool.sVersion = "2019 version 16.11.24-16.11.26";
                else if (sCompilerBuildVersion == "30151") ssTool.sVersion = "2019 version 16.11.27";

                if (ssTool.sVersion == "") {
                    if (sCompilerBuildVersion == "30401") ssTool.sVersion = "2022 version 17.0.0 preview2";  // 14.30
                    else if (sCompilerBuildVersion == "30423") ssTool.sVersion = "2022 version 17.0.0 pre 3.1";
                    else if (sCompilerBuildVersion == "30528") ssTool.sVersion = "2022 version 17.0.0 pre 4.0";
                    else if (sCompilerBuildVersion == "30704") ssTool.sVersion = "2022 version 17.0.0 pre 5.0";
                    else if (sCompilerBuildVersion == "30705") ssTool.sVersion = "2022 version 17.0.0 pre 7.0";
                    else if (sCompilerBuildVersion == "30818") ssTool.sVersion = "2022 version 17.1.0 pre 1.0";  // 14.31
                    else if (sCompilerBuildVersion == "30919") ssTool.sVersion = "2022 version 17.1.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31103") ssTool.sVersion = "2022 version 17.1.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31104") ssTool.sVersion = "2022 version 17.1.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31114") ssTool.sVersion = "2022 version 17.2.0 pre 1.0";  // 14.32
                    else if (sCompilerBuildVersion == "31302") ssTool.sVersion = "2022 version 17.2.0 pre 2.1";
                    else if (sCompilerBuildVersion == "31326") ssTool.sVersion = "2022 version 17.2.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31328") ssTool.sVersion = "2022 version 17.2.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31329") ssTool.sVersion = "2022 version 17.2.1-17.2.4";
                    else if (sCompilerBuildVersion == "31332") ssTool.sVersion = "2022 version 17.2.5";
                    else if (sCompilerBuildVersion == "31424") ssTool.sVersion = "2022 version 17.3.0 pre 1.0";  // 14.33
                    else if (sCompilerBuildVersion == "31517") ssTool.sVersion = "2022 version 17.3.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31627") ssTool.sVersion = "2022 version 17.3.0 pre 3.0";
                    else if (sCompilerBuildVersion == "31628") ssTool.sVersion = "2022 version 17.3.0 pre 4.0";
                    else if (sCompilerBuildVersion == "31629") ssTool.sVersion = "2022 version 17.3.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31630") ssTool.sVersion = "2022 version 17.3.4";
                    else if (sCompilerBuildVersion == "31721") ssTool.sVersion = "2022 version 17.4.0 pre 1.0";  // 14.34
                    else if (sCompilerBuildVersion == "31823") ssTool.sVersion = "2022 version 17.4.0 pre 2.0";
                    else if (sCompilerBuildVersion == "31921") ssTool.sVersion = "2022 version 17.4.0 pre 4.0";
                    else if (sCompilerBuildVersion == "31932") ssTool.sVersion = "2022 version 17.4.0 pre 5.0";
                    else if (sCompilerBuildVersion == "31933") ssTool.sVersion = "2022 version 17.4.0 pre 6.0";
                    else if (sCompilerBuildVersion == "31935") ssTool.sVersion = "2022 version 17.4.2";
                    else if (sCompilerBuildVersion == "31937") ssTool.sVersion = "2022 version 17.4.3";
                    else if (sCompilerBuildVersion == "31942") ssTool.sVersion = "2022 version 17.4.5";
                    else if (sCompilerBuildVersion == "32019") ssTool.sVersion = "2022 version 17.5.0 pre 1.0";  // 14.35
                    else if (sCompilerBuildVersion == "32124") ssTool.sVersion = "2022 version 17.5.0 pre 2.0";
                    else if (sCompilerBuildVersion == "32213") ssTool.sVersion = "2022 version 17.5.0 pre 4.0";
                    else if (sCompilerBuildVersion == "32215") ssTool.sVersion = "2022 version 17.5.0-17.5.2";
                    else if (sCompilerBuildVersion == "32216") ssTool.sVersion = "2022 version 17.5.3";
                    else if (sCompilerBuildVersion == "32217") ssTool.sVersion = "2022 version 17.5.4-17.5.5";
                    else if (sCompilerBuildVersion == "32323") ssTool.sVersion = "2022 version 17.6.0 pre 1.0";  // 14.36
                    else if (sCompilerBuildVersion == "32502") ssTool.sVersion = "2022 version 17.6.0 pre 2.0";
                    else if (sCompilerBuildVersion == "32522") ssTool.sVersion = "2022 version 17.6.0 pre 3.0-4.0";
                    else if (sCompilerBuildVersion == "32530") ssTool.sVersion = "2022 version 17.6.0 pre 5.0-7.0";
                    else if (sCompilerBuildVersion == "32532") ssTool.sVersion = "2022 version 17.6.0-17.6.2";
                    else if (sCompilerBuildVersion == "32534") ssTool.sVersion = "2022 version 17.6.3";
                    else if (sCompilerBuildVersion == "32535") ssTool.sVersion = "2022 version 17.6.4";
                    else if (sCompilerBuildVersion == "32705") ssTool.sVersion = "2022 version 17.7.0 pre 1.0-2.0";  // 14.37
                }
            }

            if (ssTool.sVersion == "") {
                QString sLinkerMajorVersion = ssLinker.sVersion.section(".", 0, 1);

                if (sLinkerMajorVersion != "") {
                    if (sLinkerMajorVersion == "4.00") ssTool.sVersion = "4.00";
                    else if (sLinkerMajorVersion == "4.20") ssTool.sVersion = "4.20";
                    else if (sLinkerMajorVersion == "5.00") ssTool.sVersion = "5.0";
                    else if (sLinkerMajorVersion == "6.00") ssTool.sVersion = "6.0";
                    else if (sLinkerMajorVersion == "7.00") ssTool.sVersion = "2002";
                    else if (sLinkerMajorVersion == "7.10") ssTool.sVersion = "2003";
                    else if (sLinkerMajorVersion == "8.00") ssTool.sVersion = "2005";
                    else if (sLinkerMajorVersion == "9.00") ssTool.sVersion = "2008";
                    else if (sLinkerMajorVersion == "10.00") ssTool.sVersion = "2010";
                    else if (sLinkerMajorVersion == "11.00") ssTool.sVersion = "2012";
                    else if (sLinkerMajorVersion == "12.00") ssTool.sVersion = "2013";
                    else if (sLinkerMajorVersion == "14.00") ssTool.sVersion = "2015";
                    else if (sLinkerMajorVersion == "14.10") ssTool.sVersion = "2017 version 15.0-15.2";
                    else if (sLinkerMajorVersion == "14.11") ssTool.sVersion = "2017 version 15.3";
                    else if (sLinkerMajorVersion == "14.12") ssTool.sVersion = "2017 version 15.5";
                    else if (sLinkerMajorVersion == "14.13") ssTool.sVersion = "2017 version 15.6";
                    else if (sLinkerMajorVersion == "14.14") ssTool.sVersion = "2017 version 15.7";
                    else if (sLinkerMajorVersion == "14.15") ssTool.sVersion = "2017 version 15.8";
                    else if (sLinkerMajorVersion == "14.16") ssTool.sVersion = "2017 version 15.9";
                    else if (sLinkerMajorVersion == "14.20") ssTool.sVersion = "2019 version 16.0";
                    else if (sLinkerMajorVersion == "14.21") ssTool.sVersion = "2019 version 16.1";
                    else if (sLinkerMajorVersion == "14.22") ssTool.sVersion = "2019 version 16.2";
                    else if (sLinkerMajorVersion == "14.23") ssTool.sVersion = "2019 version 16.3";
                    else if (sLinkerMajorVersion == "14.24") ssTool.sVersion = "2019 version 16.4";
                    else if (sLinkerMajorVersion == "14.25") ssTool.sVersion = "2019 version 16.5";
                    else if (sLinkerMajorVersion == "14.26") ssTool.sVersion = "2019 version 16.6";
                    else if (sLinkerMajorVersion == "14.27") ssTool.sVersion = "2019 version 16.7-16.8";
                    else if (sLinkerMajorVersion == "14.28") ssTool.sVersion = "2019 version 16.9-16.10";
                    else if (sLinkerMajorVersion == "14.29") ssTool.sVersion = "2019 version 16.11";
                    else if (sLinkerMajorVersion == "14.30") ssTool.sVersion = "2022 version 17.0";
                    else if (sLinkerMajorVersion == "14.31") ssTool.sVersion = "2022 version 17.1";
                    else if (sLinkerMajorVersion == "14.32") ssTool.sVersion = "2022 version 17.2";
                    else if (sLinkerMajorVersion == "14.33") ssTool.sVersion = "2022 version 17.3";
                    else if (sLinkerMajorVersion == "14.34") ssTool.sVersion = "2022 version 17.4";
                    else if (sLinkerMajorVersion == "14.35") ssTool.sVersion = "2022 version 17.5";
                    else if (sLinkerMajorVersion == "14.36") ssTool.sVersion = "2022 version 17.6";
                    else if (sLinkerMajorVersion == "14.37") ssTool.sVersion = "2022 version 17.7";
                }
            }

            if (ssTool.sVersion == "") {
                // TODO
            }
        } else if (ssCompilerMASM.name == SpecAbstract::RECORD_NAME_MASM) {
            QString sCompilerVersion = ssCompilerMASM.sVersion;
            QString sLinkerVersion = ssLinker.sVersion;

            if ((sLinkerVersion == "5.12.8078") && (sCompilerVersion == "6.14.8444")) {
                ssTool.type = SpecAbstract::RECORD_TYPE_TOOL;
                ssTool.name = SpecAbstract::RECORD_NAME_MASM32;
                ssTool.sVersion = "8-11";
            }
        }

        if (pe.isImportLibraryPresentI("MSVCRT.dll", &(pPEInfo->listImports))) {
            // TODO
        }

        if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));
        }

        if (ssCompilerCPP.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerCPP.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompilerCPP));
        }

        if (ssCompilerMASM.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerMASM.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompilerMASM));
        }

        if (ssCompilerVB.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerVB.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompilerVB));
        }

        if (ssCompilerDot.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompilerDot.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompilerDot));
        }

        if (ssTool.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssTool));
        }

        if (ssMFC.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(ssMFC.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssMFC));
        }

        if (ssNET.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(ssNET.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssNET));
        }
    }
}

void SpecAbstract::PE_handle_Borland(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    // TODO Turbo Linker
    // https://delphi.fandom.com/wiki/Determine_Delphi_Application
    // TODO if Delphi Linker -> 2.25
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT recordLinker = {};
        _SCANS_STRUCT recordCompiler = {};
        _SCANS_STRUCT recordTool = {};
        _SCANS_STRUCT recordVCL = {};

        if (pPEInfo->basic_info.mapHeaderDetects.contains(SpecAbstract::RECORD_NAME_TURBOLINKER)) {
            _SCANS_STRUCT recordTurboLinker = pPEInfo->basic_info.mapHeaderDetects.value(SpecAbstract::RECORD_NAME_TURBOLINKER);

            VI_STRUCT vi = NFD_Binary::get_TurboLinker_vi(pDevice, pOptions);

            if (vi.bIsValid) {
                recordTurboLinker.sVersion = vi.sVersion;
            } else {
                recordTurboLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
            }

            recordLinker = recordTurboLinker;
        }

        if (!pPEInfo->cliInfo.bValid) {
            qint64 nOffset_string = -1;
            qint64 nOffset_Boolean = -1;
            qint64 nOffset_String = -1;
            qint64 nOffset_TObject = -1;
            //        qint64 nOffset_AnsiString=-1;
            //        qint64 nOffset_WideString=-1;

            qint64 nOffset_BorlandCPP = -1;
            qint64 nOffset_CodegearCPP = -1;
            qint64 nOffset_EmbarcaderoCPP_old = -1;
            qint64 nOffset_EmbarcaderoCPP_new = -1;

            QList<VCL_STRUCT> listVCL;

            bool bCppExport = (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames), "__CPPdebugHook")) ||
                              (XBinary::isStringInListPresent(&(pPEInfo->listExportFunctionNames), "___CPPdebugHook"));

            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                qint64 _nSize = pPEInfo->osCodeSection.nSize;

                nOffset_TObject = pe.find_array(_nOffset, _nSize, "\x07\x54\x4f\x62\x6a\x65\x63\x74", 8, pPdStruct);  // TObject

                if (nOffset_TObject != -1) {
                    nOffset_Boolean = pe.find_array(_nOffset, _nSize, "\x07\x42\x6f\x6f\x6c\x65\x61\x6e", 8, pPdStruct);  // Boolean
                    nOffset_string = pe.find_array(_nOffset, _nSize, "\x06\x73\x74\x72\x69\x6e\x67", 7, pPdStruct);       // string

                    if ((nOffset_Boolean != -1) || (nOffset_string != -1)) {
                        if (nOffset_string == -1) {
                            nOffset_String = pe.find_array(_nOffset, _nSize, "\x06\x53\x74\x72\x69\x6e\x67", 7, pPdStruct);  // String
                        }

                        listVCL = PE_getVCLstruct(pDevice, pOptions, _nOffset, _nSize, pPEInfo->bIs64, pPdStruct);
                    }
                }
                //            nOffset_AnsiString=pe.find_array(_nOffset,_nSize,"\x0a\x41\x6e\x73\x69\x53\x74\x72\x69\x6e\x67",11); // AnsiString
                //            nOffset_WideString=pe.find_array(_nOffset,_nSize,"\x0a\x57\x69\x64\x65\x53\x74\x72\x69\x6e\x67",11); // WideString
            }

            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;

                nOffset_BorlandCPP = pe.find_ansiString(_nOffset, _nSize, "Borland C++ - Copyright ", pPdStruct);  // Borland C++ - Copyright 1994 Borland Intl.

                if (nOffset_BorlandCPP == -1) {
                    nOffset_CodegearCPP =
                        pe.find_ansiString(_nOffset, _nSize, "CodeGear C++ - Copyright ", pPdStruct);  // CodeGear C++ - Copyright 2008 Embarcadero TechnologiessData

                    if (nOffset_CodegearCPP == -1) {
                        nOffset_EmbarcaderoCPP_old =
                            pe.find_ansiString(_nOffset, _nSize, "Embarcadero RAD Studio - Copyright ", pPdStruct);  // Embarcadero RAD Studio - Copyright 2009
                                                                                                                     // Embarcadero Technologies, Inc.

                        if (nOffset_EmbarcaderoCPP_old == -1) {
                            nOffset_EmbarcaderoCPP_new =
                                pe.find_ansiString(_nOffset, _nSize, "Embarcadero RAD Studio 27.0 - Copyright 2020 Embarcadero Technologies, Inc.", pPdStruct);
                        }
                    }
                }
            }

            bool bPackageinfo = XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "PACKAGEINFO", &(pPEInfo->listResources));
            bool bDvcal = XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "DVCLAL", &(pPEInfo->listResources));

            if (bPackageinfo || bDvcal || pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP) || (nOffset_TObject != -1) ||
                (nOffset_BorlandCPP != -1) || (nOffset_CodegearCPP != -1) || (nOffset_EmbarcaderoCPP_old != -1) || (nOffset_EmbarcaderoCPP_new != -1) || bCppExport) {
                bool bCpp = false;
                bool bVCL = bPackageinfo;
                QString sVCLVersion;
                QString sDelphiVersion;
                QString sBuilderVersion;
                QString sObjectPascalCompilerVersion;
                QString sCppCompilerVersion;
                bool bNewVersion = false;

                enum COMPANY {
                    COMPANY_BORLAND = 0,
                    COMPANY_CODEGEAR,
                    COMPANY_EMBARCADERO
                };

                COMPANY company = COMPANY_BORLAND;

                if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BORLANDCPP) || (nOffset_BorlandCPP != -1) || (nOffset_CodegearCPP != -1) ||
                    (nOffset_EmbarcaderoCPP_old != -1) || (nOffset_EmbarcaderoCPP_new != -1) || bCppExport) {
                    bCpp = true;

                    if (nOffset_BorlandCPP != -1) {
                        company = COMPANY_BORLAND;
                    } else if (nOffset_CodegearCPP != -1) {
                        company = COMPANY_CODEGEAR;
                    } else if (nOffset_EmbarcaderoCPP_old != -1) {
                        company = COMPANY_EMBARCADERO;
                    } else if (nOffset_EmbarcaderoCPP_new != -1) {
                        company = COMPANY_EMBARCADERO;
                    } else if (bCppExport) {
                        company = COMPANY_EMBARCADERO;
                    }
                }

                if (nOffset_TObject != -1) {
                    if (nOffset_string != -1) {
                        if (bDvcal || bPackageinfo) {
                            // TODO Borland Version
                            sDelphiVersion = "2005+";
                            bNewVersion = true;
                        } else {
                            sDelphiVersion = "2";
                            sObjectPascalCompilerVersion = "9.0";
                        }
                    } else if (nOffset_String != -1) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "3-7";
                    }
                }

                if (bPackageinfo) {
                    VCL_PACKAGEINFO pi = PE_getVCLPackageInfo(pDevice, pOptions, &pPEInfo->listResources, pPdStruct);

                    if (pi.listModules.count()) {
                        quint32 nProducer = (pi.nFlags >> 26) & 0x3;

                        if (nProducer == 2)  // C++
                        {
                            bCpp = true;
                        } else if (nProducer == 3)  // Pascal
                        {
                            bCpp = false;
                        }

                        //                    for(qint32 i=0;i<pi.listModules.count();i++)
                        //                    {
                        //                        qDebug(pi.listModules.at(i).sName.toLatin1().data());
                        //                    }
                    }
                }

                if (nOffset_BorlandCPP != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_BorlandCPP + 24, 4);
                }

                if (nOffset_CodegearCPP != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_CodegearCPP + 25, 4);
                }

                if (nOffset_EmbarcaderoCPP_old != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_EmbarcaderoCPP_old + 35, 4);
                }

                if (nOffset_EmbarcaderoCPP_new != -1) {
                    sCppCompilerVersion = pe.read_ansiString(nOffset_EmbarcaderoCPP_new + 40, 4);
                }

                if (sCppCompilerVersion == "2009") {
                    sBuilderVersion = "2009";
                } else if (sCppCompilerVersion == "2015") {
                    sBuilderVersion = "2015";
                } else if (sCppCompilerVersion == "2020") {
                    sBuilderVersion = "10.4";
                }

                if (listVCL.count()) {
                    bVCL = true;
                    qint32 nVCLOffset = listVCL.at(0).nOffset;
                    qint32 nVCLValue = listVCL.at(0).nValue;

                    //                    qDebug("nVCLOffset: %d",nVCLOffset);
                    //                    qDebug("nVCLValue: %d",nVCLValue);
                    //                bVCL=true;

                    if ((nVCLOffset == 24) && (nVCLValue == 168)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2";
                        sObjectPascalCompilerVersion = "9.0";
                        //                    sVCLVersion="20";
                    } else if ((nVCLOffset == 28) && (nVCLValue == 180)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "3";
                        sObjectPascalCompilerVersion = "10.0";
                        //                    sVCLVersion="30";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 276)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "4";
                        sObjectPascalCompilerVersion = "12.0";
                        //                    sVCLVersion="40";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 288)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "5";
                        sObjectPascalCompilerVersion = "13.0";
                        //                    sVCLVersion="50";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 296)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "6 CLX";
                        sObjectPascalCompilerVersion = "14.0";
                        //                    sVCLVersion="60";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 300)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "7 CLX";
                        sObjectPascalCompilerVersion = "15.0";
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
                    else if ((nVCLOffset == 40) && (nVCLValue == 348)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "6-7";
                        sObjectPascalCompilerVersion = "14.0-15.0";
                        //                    sVCLVersion="140-150";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 356)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2005";
                        sObjectPascalCompilerVersion = "17.0";
                        //                    sVCLVersion="170";
                    } else if ((nVCLOffset == 40) && (nVCLValue == 400)) {
                        company = COMPANY_BORLAND;
                        sDelphiVersion = "2006";
                        sObjectPascalCompilerVersion = "18.0";
                        //                    sVCLVersion="180";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 420)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "2009";
                        sObjectPascalCompilerVersion = "20.0";
                        //                    sVCLVersion="200";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 428)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "2010-XE";
                        sObjectPascalCompilerVersion = "21.0-22.0";
                        //                    sVCLVersion="210-220";
                    } else if ((nVCLOffset == 52) && (nVCLValue == 436)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2-XE4";
                        sObjectPascalCompilerVersion = "23.0-25.0";
                        //                    sVCLVersion="230-250";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 52) && (nVCLValue == 444)) {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2-XE8";
                        sObjectPascalCompilerVersion = "23.0-29.0";
                        //                    sVCLVersion="230-290";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 104) && (nVCLValue == 760))  // 64
                    {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE2";
                        sObjectPascalCompilerVersion = "23.0";

                        bNewVersion = true;
                    } else if ((nVCLOffset == 128) && (nVCLValue == 776))  // 64
                    {
                        company = COMPANY_EMBARCADERO;
                        sDelphiVersion = "XE8-10 Seattle";
                        sObjectPascalCompilerVersion = "30.0";

                        bNewVersion = true;
                    }
                    // TODO more x64
                }

                // TODO Console !!!

                if (bNewVersion) {
                    if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                        qint64 _nOffset = pPEInfo->osConstDataSection.nOffset;
                        qint64 _nSize = pPEInfo->osConstDataSection.nSize;

                        qint64 nOffset_Version = 0;

                        if (pPEInfo->bIs64) {
                            nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "Embarcadero Delphi for Win64 compiler version ", pPdStruct);
                        } else {
                            nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "Embarcadero Delphi for Win32 compiler version ", pPdStruct);
                        }

                        if (nOffset_Version != -1) {
                            company = COMPANY_EMBARCADERO;

                            sObjectPascalCompilerVersion = pe.read_ansiString(nOffset_Version + 46);

                            sDelphiVersion = NFD_Binary::_get_DelphiVersionFromCompiler(sObjectPascalCompilerVersion).sVersion;
                        }
                    }
                }

                recordCompiler.type = RECORD_TYPE_COMPILER;
                recordTool.type = RECORD_TYPE_TOOL;

                if (!bCpp) {
                    if (company == COMPANY_BORLAND) {
                        recordCompiler.name = RECORD_NAME_BORLANDOBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_BORLANDDELPHI;
                    } else if (company == COMPANY_CODEGEAR) {
                        recordCompiler.name = RECORD_NAME_CODEGEAROBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_CODEGEARDELPHI;
                    } else if (company == COMPANY_EMBARCADERO) {
                        recordCompiler.name = RECORD_NAME_EMBARCADEROOBJECTPASCALDELPHI;
                        recordTool.name = RECORD_NAME_EMBARCADERODELPHI;
                    }

                    recordCompiler.sVersion = sObjectPascalCompilerVersion;
                    recordTool.sVersion = sDelphiVersion;
                } else {
                    if (company == COMPANY_BORLAND) {
                        recordCompiler.name = RECORD_NAME_BORLANDCPP;
                        recordTool.name = RECORD_NAME_BORLANDCPPBUILDER;
                    } else if (company == COMPANY_CODEGEAR) {
                        recordCompiler.name = RECORD_NAME_CODEGEARCPP;
                        recordTool.name = RECORD_NAME_CODEGEARCPPBUILDER;
                    } else if (company == COMPANY_EMBARCADERO) {
                        recordCompiler.name = RECORD_NAME_EMBARCADEROCPP;
                        recordTool.name = RECORD_NAME_EMBARCADEROCPPBUILDER;
                    }

                    recordCompiler.sVersion = sCppCompilerVersion;
                    recordTool.sVersion = sBuilderVersion;
                }

                if (bVCL) {
                    recordVCL.type = RECORD_TYPE_LIBRARY;
                    recordVCL.name = RECORD_NAME_VCL;
                    recordVCL.sVersion = sVCLVersion;
                }

                if (recordLinker.type == RECORD_TYPE_UNKNOWN) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_TURBOLINKER, "", "", 0);
                    recordLinker = ss;
                }
            }
        } else {
            // .NET TODO: Check!!!!
            if (pPEInfo->basic_info.mapDotAnsiStringsDetects.contains(RECORD_NAME_EMBARCADERODELPHIDOTNET)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapDotAnsiStringsDetects.value(RECORD_NAME_EMBARCADERODELPHIDOTNET);
                recordTool = ss;
            }
        }

        if (recordLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(recordLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordLinker));
        }

        if (recordCompiler.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(recordCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordCompiler));
        }

        if (recordVCL.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLibraries.insert(recordVCL.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordVCL));
        }

        if (recordTool.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultTools.insert(recordTool.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordTool));
        }
    }
}

void SpecAbstract::PE_handle_Watcom(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        _SCANS_STRUCT ssLinker = {};
        _SCANS_STRUCT ssCompiler = {};

        // Watcom linker
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WATCOMLINKER)) {
            ssLinker = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WATCOMLINKER);
            ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion, 2, 10, QChar('0'));
        }

        // Watcom CPP
        if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_WATCOMCCPP)) {
            // TODO Version???
            ssCompiler = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_WATCOMCCPP);
        }

        SpecAbstract::VI_STRUCT vi = NFD_Binary::get_Watcom_vi(pDevice, pOptions, pPEInfo->nEntryPointOffset, 0x100, pPdStruct);

        if (vi.bIsValid) {
            ssCompiler.fileType = XBinary::FT_PE;
            ssCompiler.type = RECORD_TYPE_COMPILER;
            ssCompiler.name = (RECORD_NAME)vi.vValue.toUInt();
            ssCompiler.sVersion = vi.sVersion;
            ssCompiler.sInfo = vi.sInfo;
        }

        if ((ssLinker.type != RECORD_TYPE_UNKNOWN) && (ssCompiler.type == RECORD_TYPE_UNKNOWN)) {
            ssCompiler = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_WATCOMCCPP, "", "", 0);
        }

        if ((ssLinker.type == RECORD_TYPE_UNKNOWN) && (ssCompiler.type != RECORD_TYPE_UNKNOWN)) {
            ssLinker = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_WATCOMLINKER, "", "", 0);
        }

        if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));
        }

        if (ssCompiler.type != RECORD_TYPE_UNKNOWN) {
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }
    }
}

void SpecAbstract::PE_handle_Tools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if ((pPEInfo->bIsTLSPresent) && (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_RUST))) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = NFD_Binary::get_Rust_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ssCompiler = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_RUST);

                    ssCompiler.sVersion = viStruct.sVersion;
                    ssCompiler.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
                }
            }
        }

        if (pe.isResourcePresent(XPE_DEF::S_RT_RCDATA, "SCRIPT", &(pPEInfo->listResources))) {
            _SCANS_STRUCT ssLibrary = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_AUTOIT, "3.XX", "", 0);
            // TODO Version
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLibrary));
        } else if (pe.getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)) == "Compiled AutoIt Script") {
            _SCANS_STRUCT ssLibrary = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_AUTOIT, "2.XX", "", 0);

            ssLibrary.sVersion = pe.getFileVersionMS(&(pPEInfo->resVersion));
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLibrary));
        }

        if (XPE::isImportLibraryPresentI("msvcrt.dll", &(pPEInfo->listImports)) && (pPEInfo->nMajorLinkerVersion == 6) && (pPEInfo->nMinorLinkerVersion == 0)) {
            bool bDetected = false;
            bool bDebug = false;

            if (pPEInfo->bIs64) {
                if ((pPEInfo->fileHeader.NumberOfSections == 3) || (pPEInfo->fileHeader.NumberOfSections == 5)) {
                    if ((pPEInfo->listSectionNames.at(0) == ".text") && (pPEInfo->listSectionNames.at(1) == ".data") && (pPEInfo->listSectionNames.at(2) == ".pdata")) {
                        if (pPEInfo->fileHeader.NumberOfSections == 3) {
                            bDetected = true;
                        } else if (pPEInfo->fileHeader.NumberOfSections == 5) {
                            if ((pPEInfo->listSectionNames.at(3) == ".stab") && (pPEInfo->listSectionNames.at(4) == ".stabstr")) {
                                bDebug = true;
                                bDetected = true;
                            }
                        }
                    }
                }
            } else {
                if ((pPEInfo->fileHeader.NumberOfSections == 2) || (pPEInfo->fileHeader.NumberOfSections == 4)) {
                    if ((pPEInfo->listSectionNames.at(0) == ".text") && (pPEInfo->listSectionNames.at(1) == ".data")) {
                        if (pPEInfo->fileHeader.NumberOfSections == 2) {
                            bDetected = true;
                        } else if (pPEInfo->fileHeader.NumberOfSections == 4) {
                            if ((pPEInfo->listSectionNames.at(2) == ".stab") && (pPEInfo->listSectionNames.at(3) == ".stabstr")) {
                                bDebug = true;
                                bDetected = true;
                            }
                        }
                    }
                }
            }

            if (bDetected) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_TINYC, "", "", 0);

                if (bDebug) {
                    ss.sInfo = "debug";
                }

                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_CHROMIUMCRASHPAD)) {
            XPE::SECTION_RECORD sr = XPE::getSectionRecordByName("CPADinfo", &(pPEInfo->listSectionRecords));

            if (sr.nSize) {
                quint32 nSignature = pe.read_uint32(sr.nOffset);

                if (nSignature == 0x43506164) {
                    quint32 nVersion = pe.read_uint32(sr.nOffset + 8);

                    _SCANS_STRUCT ssLibrary = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_CHROMIUMCRASHPAD, "", "", 0);
                    ssLibrary.sVersion = QString("%1.0").arg(nVersion);
                    pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLibrary));
                }
            }
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_EXCELSIORJET)) {
            // TODO Version
            _SCANS_STRUCT ssLibrary = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_JAVA, "", "Native", 0);
            pPEInfo->basic_info.mapResultLibraries.insert(ssLibrary.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLibrary));

            // TODO Version
            _SCANS_STRUCT ssCompiler = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_EXCELSIORJET, "", "", 0);  // mb Tool
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_GO) || pPEInfo->basic_info.mapCodeSectionDetects.contains(RECORD_NAME_GO)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_GO, "1.X", "", 0);

            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = NFD_Binary::get_Go_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;
                }
            }

            pPEInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Visual Objects
        if (pe.compareSignature(&(pPEInfo->basic_info.memoryMap), "'This Visual Objects application cannot be run in DOS mode'", 0x312)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_VISUALOBJECTS, "2.XX", "", 0);
            ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // FASM
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASM)) {
            // TODO correct Version
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FASM, "", "", 0);
            ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Zig
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER) &&
            (pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GENERICLINKER).nVariant == 1)) {
            if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                VI_STRUCT viStruct = NFD_Binary::get_Zig_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_ZIG, "", "", 0);

                    ss.sVersion = viStruct.sVersion;
                    ss.sInfo = viStruct.sInfo;

                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }

        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            VI_STRUCT viNim = NFD_Binary::get_Nim_vi(pDevice, pOptions, pPEInfo->osConstDataSection.nOffset, pPEInfo->osConstDataSection.nSize, pPdStruct);

            if (viNim.bIsValid) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_NIM, "", "", 0);
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Valve
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VALVE)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_STUB, RECORD_NAME_VALVE, "", "", 0);
            pPEInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // UniLink
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_UNILINK)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_UNILINK, "", "", 0);
            pPEInfo->basic_info.mapResultLinkers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // DMD32 D
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DMD32)) {
            // TODO correct Version
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_DMD32, "", "", 0);
            pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GoLink, GoAsm
        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GOLINK)) {
            _SCANS_STRUCT ssLinker = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LINKER, RECORD_NAME_GOLINK, "", "", 0);
            ssLinker.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
            pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));

            _SCANS_STRUCT ssCompiler = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_GOASM, "", "", 0);
            pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
        }

        if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LAYHEYFORTRAN90)) {
            QString sLFString = pe.read_ansiString(0x200);

            if (sLFString == "This program must be run under Windows 95, NT, or Win32s\r\nPress any key to exit.$") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_LAYHEYFORTRAN90, "", "", 0);
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // Flex
        if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
            qint64 _nOffset = pPEInfo->osDataSection.nOffset;
            qint64 _nSize = pPEInfo->osDataSection.nSize;
            // TODO FPC Version in Major and Minor linker

            qint64 nOffset_FlexLM = pe.find_ansiString(_nOffset, _nSize, "@(#) FLEXlm ", pPdStruct);

            if (nOffset_FlexLM != -1) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_FLEXLM, "", "", 0);

                ss.sVersion = pe.read_ansiString(nOffset_FlexLM + 12, 50);
                ss.sVersion = ss.sVersion.section(" ", 0, 0);

                if (ss.sVersion.left(1) == "v") {
                    ss.sVersion.remove(0, 1);
                }

                // TODO Version
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            qint64 nOffset_FlexNet = -1;

            if (nOffset_FlexLM == -1) {
                nOffset_FlexNet = pe.find_ansiString(_nOffset, _nSize, "@(#) FLEXnet Licensing v", pPdStruct);
            }

            if (nOffset_FlexNet == -1) {
                nOffset_FlexNet = pe.find_ansiString(_nOffset, _nSize, "@(#) FlexNet Licensing v", pPdStruct);
            }

            if (nOffset_FlexNet != -1) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_FLEXNET, "", "", 0);

                ss.sVersion = pe.read_ansiString(nOffset_FlexNet + 24, 50);

                if (ss.sVersion.contains("build")) {
                    ss.sVersion = ss.sVersion.section(" ", 0, 2);
                } else {
                    ss.sVersion = ss.sVersion.section(" ", 0, 0);
                }

                // TODO Version
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        if (!pPEInfo->cliInfo.bValid) {
            // Qt
            // TODO Find Strings QObject
            if (XPE::isImportLibraryPresentI("QtCore4.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "4.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("QtCored4.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "4.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt5Core.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "5.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt5Cored.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "5.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt6Core.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::isImportLibraryPresentI("Qt6Cored.dll", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_QT, "6.X", "Debug", 0);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_QT)) {
                // TODO Version!
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_QT);
                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;
                // TODO FPC Version in Major and Minor linker

                qint64 nOffset_FPC = pe.find_ansiString(_nOffset, _nSize, "FPC ", pPdStruct);

                if (nOffset_FPC != -1) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FPC, "", "", 0);
                    QString sFPCVersion = pe.read_ansiString(nOffset_FPC);
                    ss.sVersion = sFPCVersion.section(" ", 1, -1).section(" - ", 0, 0);

                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));

                    // Lazarus
                    qint64 nOffset_Lazarus = pe.find_ansiString(_nOffset, _nSize, "Lazarus LCL: ", pPdStruct);

                    if (nOffset_Lazarus == -1) {
                        if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                            _nOffset = pPEInfo->osConstDataSection.nOffset;
                            _nSize = pPEInfo->osConstDataSection.nSize;

                            nOffset_Lazarus = pe.find_ansiString(_nOffset, _nSize, "Lazarus LCL: ", pPdStruct);
                        }
                    }

                    QString sLazarusVersion;

                    if (nOffset_Lazarus != -1) {
                        sLazarusVersion = pe.read_ansiString(nOffset_Lazarus + 13);
                        sLazarusVersion = sLazarusVersion.section(" ", 0, 0);
                    }

                    if (nOffset_Lazarus != -1) {
                        _SCANS_STRUCT ssLazarus = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_TOOL, RECORD_NAME_LAZARUS, "", "", 0);

                        ssLazarus.sVersion = sLazarusVersion;

                        pPEInfo->basic_info.mapResultTools.insert(ssLazarus.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLazarus));
                    }
                } else {
                    //                    qint64 nOffset_TObject=pe.find_array(_nOffset,_nSize,"\x07\x54\x4f\x62\x6a\x65\x63\x74",8); // TObject

                    //                    if(nOffset_TObject!=-1)
                    //                    {

                    //                        SCANS_STRUCT ss=NFD_Binary::getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_COMPILER,RECORD_NAME_FPC,"","",0);

                    //                        // TODO Version
                    //                        pPEInfo->basic_info.mapResultCompilers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
                    //                    }
                    qint64 nOffset_RunTimeError = pe.find_array(_nOffset, _nSize, "\x0e\x52\x75\x6e\x74\x69\x6d\x65\x20\x65\x72\x72\x6f\x72\x20", 15,
                                                                pPdStruct);  // Runtime Error TODO: use findAnsiString

                    if (nOffset_RunTimeError != -1) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_FPC, "", "", 0);

                        // TODO Version
                        pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // Python
            // TODO Create function
            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^PYTHON", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);

                            ss.sVersion = QString::number(dVersion / 10, 'f', 1);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                } else if (XBinary::isRegExpPresent("^LIBPYTHON", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d.\\d)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);

                            ss.sVersion = QString::number(dVersion);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                }
            }

            // Perl
            // TODO Create function
            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^PERL", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sVersion != "") {
                        double dVersion = sVersion.toDouble();

                        if (dVersion) {
                            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_PERL, "", "", 0);

                            ss.sVersion = QString::number(dVersion / 100, 'f', 2);
                            pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                        }
                    }

                    break;
                }
            }

            // Virtual Pascal
            if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                qint64 _nSize = pPEInfo->osDataSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_VP =
                    pe.find_ansiString(_nOffset, _nSize, "Virtual Pascal - Copyright (C) ", pPdStruct);  // "Virtual Pascal - Copyright (C) 1996-2000 vpascal.com"

                if (nOffset_VP != -1) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_VIRTUALPASCAL, "", "", 0);

                    // TODO Version???
                    ss.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // PowerBASIC
            if (pe.checkOffsetSize(pPEInfo->osCodeSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                qint64 _nOffset = pPEInfo->osCodeSection.nOffset;
                qint64 _nSize = pPEInfo->osCodeSection.nSize;
                // TODO VP Version in Major and Minor linker

                qint64 nOffset_PB = pe.find_ansiString(_nOffset, _nSize, "PowerBASIC", pPdStruct);

                if (nOffset_PB != -1) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_COMPILER, RECORD_NAME_POWERBASIC, "", "", 0);

                    // TODO Version???
                    pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // PureBasic
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_PUREBASIC)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_PUREBASIC);

                // TODO Version???
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // lcc-win
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_LCCWIN)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_LCCWIN);

                // TODO Version???
                pPEInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));

                if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
                    _SCANS_STRUCT ssLinker = {};
                    ssLinker.name = RECORD_NAME_LCCLNK;
                    ssLinker.type = RECORD_TYPE_LINKER;
                    ssLinker.sVersion = QString("%1.%2").arg(QString::number(pPEInfo->nMajorLinkerVersion), QString::number(pPEInfo->nMinorLinkerVersion));
                    pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PETools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_VMUNPACKER)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_VMUNPACKER);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_XVOLKOLAK)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_XVOLKOLAK);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_HOODLUM)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapSectionNamesDetects.value(RECORD_NAME_HOODLUM);

            pPEInfo->basic_info.mapResultPETools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::PE_handle_wxWidgets(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bDynamic = false;
            bool bStatic = false;
            QString sVersion;
            QString sInfo;

            qint32 nNumberOfImports = pPEInfo->listImports.count();

            for (qint32 i = 0; (i < nNumberOfImports) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (XBinary::isRegExpPresent("^WX", pPEInfo->listImports.at(i).sName.toUpper())) {
                    QString sDllVersion = XBinary::regExp("(\\d+)", pPEInfo->listImports.at(i).sName.toUpper(), 0);

                    if (sDllVersion != "") {
                        double dVersion = sDllVersion.toDouble();

                        if (dVersion) {
                            // TODO a function
                            if (dVersion < 100) {
                                sVersion = QString::number(dVersion / 10, 'f', 1);
                            } else if (dVersion < 1000) {
                                sVersion = QString::number(dVersion / 100, 'f', 2);
                            }

                            bDynamic = true;
                        }
                    }

                    break;
                }
            }

            if (!bDynamic) {
                if (XPE::isResourcePresent(XPE_DEF::S_RT_MENU, "WXWINDOWMENU", &(pPEInfo->listResources))) {
                    bStatic = true;
                }
            }

            if (bDynamic || bStatic) {
                if (pe.checkOffsetSize(pPEInfo->osConstDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osConstDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osConstDataSection.nSize;
                    // TODO VP Version in Major and Minor linker

                    qint64 nOffset_Version = -1;

                    if (nOffset_Version == -1) {
                        nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "3.1.1 (wchar_t,Visual C++ 1900,wx containers)", pPdStruct);

                        if (nOffset_Version != -1) {
                            sVersion = "3.1.1";
                            sInfo = "Visual C++ 1900";
                        }
                    }

                    if (nOffset_Version == -1) {
                        nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "3.1.2 (wchar_t,Visual C++ 1900,wx containers,compatible with 3.0)", pPdStruct);

                        if (nOffset_Version != -1) {
                            sVersion = "3.1.2";
                            sInfo = "Visual C++ 1900";
                        }
                    }
                }
            }

            if (bDynamic || bStatic) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_LIBRARY, RECORD_NAME_WXWIDGETS, "", "", 0);

                if (bDynamic) {
                    ss.sInfo = "";
                } else if (bStatic) {
                    ss.sInfo = "Static";
                }

                ss.sVersion = sVersion;
                ss.sInfo = XBinary::appendComma(ss.sInfo, sInfo);

                pPEInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_GCC(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    _SCANS_STRUCT ssLinker = {};
    _SCANS_STRUCT ssCompiler = {};
    _SCANS_STRUCT ssTool = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bDetectGCC = false;
            bool bHeurGCC = false;

            if (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER)) {
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
                ssTool.type = RECORD_TYPE_TOOL;
                ssTool.name = RECORD_NAME_MSYS;
                ssTool.sVersion = "1.0";
            }

            if ((sDllLib.contains("gcc")) || (sDllLib.contains("libgcj")) || (sDllLib.contains("cyggcj")) || (sDllLib == "_set_invalid_parameter_handler") ||
                XPE::isImportLibraryPresentI("libgcc_s_dw2-1.dll", &(pPEInfo->listImports)) || pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_MINGW) ||
                pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_GCC)) {
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
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_MINGW;
                    } else if (viStruct.sInfo.contains("MSYS2")) {
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_MSYS2;
                    } else if (viStruct.sInfo.contains("Cygwin")) {
                        ssTool.type = RECORD_TYPE_TOOL;
                        ssTool.name = RECORD_NAME_CYGWIN;
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

                    if ((ssTool.type == RECORD_TYPE_UNKNOWN) && (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_GCC))) {
                        if (pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_GCC).sInfo.contains("MinGW")) {
                            ssTool.type = RECORD_TYPE_TOOL;
                            ssTool.name = RECORD_NAME_MINGW;
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
                            ssTool.type = RECORD_TYPE_TOOL;
                            ssTool.name = RECORD_NAME_MINGW;

                            bDetectGCC = true;
                        }
                    }
                }

                if (bDetectGCC) {
                    ssCompiler.type = RECORD_TYPE_COMPILER;
                    ssCompiler.name = RECORD_NAME_GCC;
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

                    ssTool.type = RECORD_TYPE_TOOL;
                    ssTool.name = RECORD_NAME_CYGWIN;

                    break;
                }
            }

            if (ssCompiler.type == RECORD_TYPE_UNKNOWN) {
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
                                ssTool.type = RECORD_TYPE_TOOL;
                                ssTool.name = RECORD_NAME_MINGW;

                                bSuccess = true;
                            }
                        }

                        if (!bSuccess) {
                            qint64 nCygwin = pe.find_ansiString(_nOffset, _nSize, "/gcc/i686-pc-cygwin/", pPdStruct);

                            if (nCygwin != -1) {
                                ssTool.type = RECORD_TYPE_TOOL;
                                ssTool.name = RECORD_NAME_CYGWIN;

                                bSuccess = true;
                            }
                        }
                    }
                }
            }

            if (ssCompiler.type == RECORD_TYPE_UNKNOWN) {
                if ((ssTool.name == RECORD_NAME_MINGW) || (ssTool.name == RECORD_NAME_MSYS) || (ssTool.name == RECORD_NAME_MSYS2) ||
                    (ssTool.name == RECORD_NAME_CYGWIN)) {
                    ssCompiler.type = RECORD_TYPE_COMPILER;
                    ssCompiler.name = RECORD_NAME_GCC;
                }
            }

            if ((ssCompiler.name == RECORD_NAME_GCC) && (ssTool.type == RECORD_TYPE_UNKNOWN)) {
                ssTool.type = RECORD_TYPE_TOOL;
                ssTool.name = RECORD_NAME_MINGW;
            }

            if ((ssCompiler.name == RECORD_NAME_GCC) && (pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))) {
                ssLinker.type = RECORD_TYPE_LINKER;
                ssLinker.name = RECORD_NAME_GNULINKER;
                ssLinker.sVersion = QString("%1.%2").arg(pPEInfo->nMajorLinkerVersion).arg(pPEInfo->nMinorLinkerVersion);
            }

            if (ssTool.name == RECORD_NAME_MINGW) {
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

            if (ssLinker.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultLinkers.insert(ssLinker.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssLinker));
            }
            if (ssCompiler.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultCompilers.insert(ssCompiler.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssCompiler));
            }
            if (ssTool.type != RECORD_TYPE_UNKNOWN) {
                pPEInfo->basic_info.mapResultTools.insert(ssTool.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssTool));
            }
        }
    }
}

void SpecAbstract::PE_handle_Signtools(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (pe.isSignPresent()) {
            // TODO image
            XPE_DEF::IMAGE_DATA_DIRECTORY dd = pe.getOptionalHeader_DataDirectory(XPE_DEF::S_IMAGE_DIRECTORY_ENTRY_SECURITY);

            QList<XPE::CERT> listCerts = pe.getCertList(dd.VirtualAddress, dd.Size);

            if (listCerts.count()) {
                if ((listCerts.at(0).record.wRevision == 0x200) && (listCerts.at(0).record.wCertificateType == 2)) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SIGNTOOL, RECORD_NAME_WINAUTH, "2.0", "PKCS #7", 0);
                    pPEInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_Installers(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            // Inno Setup
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INNOSETUP) || pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INNOSETUP, "", "", 0);

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
                } else if (pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_INNOSETUP).sInfo == "Uninstall") {
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

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_CAB)) {
                // Wix Tools
                if (XPE::isSectionNamePresent(".wixburn", &(pPEInfo->listSectionRecords)))  // TODO
                {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WIXTOOLSET, "", "", 0);
                    ss.sVersion = "3.X";  // TODO check "E:\delivery\Dev\wix37\build\ship\x86\burn.pdb"
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_NOSINSTALLER)) {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_NOSINSTALLER)) {
                    // TODO Version from resources!
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_NOSINSTALLER, "", "", 0);
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // CAB SFX
            if (pPEInfo->sResourceManifest.contains("sfxcab.exe")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_CAB, "", "", 0);

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
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALLANYWHERE)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)) == "InstallAnywhere") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLANYWHERE, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_GHOSTINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GHOSTINSTALLER, "", "", 0);
                ss.sVersion = "1.0";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_QTINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_QTINSTALLER, "", "", 0);
                // ss.sVersion="";
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALL4J)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALL4J, "", "", 0);
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SMARTINSTALLMAKER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SMARTINSTALLMAKER, "", "", 0);
                ss.sVersion = XBinary::hexToString(pPEInfo->sOverlaySignature.mid(46, 14));  // TODO make 1 function
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_TARMAINSTALLER)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_TARMAINSTALLER, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_CLICKTEAM)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_CLICKTEAM, "", "", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // NSIS
            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_NSIS)) || (pPEInfo->sResourceManifest.contains("Nullsoft.NSIS"))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_NSIS, "", "", 0);

                QString _sInfo = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_NSIS).sInfo;

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
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (pPEInfo->sResourceManifest.contains("InstallShield")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);

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
            } else if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_INSTALLSHIELD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "PackageForTheWeb", 0);
                // TODO version
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("InstallShield")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLSHIELD, "", "", 0);

                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));

                if (XPE::getResourcesVersionValue("CompanyName", &(pPEInfo->resVersion)).contains("PackageForTheWeb")) {
                    ss.sInfo = "PackageForTheWeb";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("AdvancedInstallerSetup")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ADVANCEDINSTALLER, "", "", 0);

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
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SPOONINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->sResourceManifest.contains("DeployMaster Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_DEPLOYMASTER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((pPEInfo->sResourceManifest.contains("Gentee.Installer.Install")) || (pPEInfo->sResourceManifest.contains("name=\"gentee\""))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            } else {
                if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_GENTEEINSTALLER)) {
                    if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "SETUP_TEMP", &(pPEInfo->listResources))) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GENTEEINSTALLER, "", "", 0);

                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            if (pPEInfo->sResourceManifest.contains("BitRock Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_BITROCKINSTALLER, "", "", 0);

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("GP-Install") &&
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("TASPro6-Install")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GPINSTALL, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                ss.sVersion.replace(", ", ".");
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Total Commander Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_TOTALCOMMANDERINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Actual Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ACTUALINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("Avast Antivirus")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_AVASTANTIVIRUS, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Opera Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_OPERA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Yandex Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_YANDEX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Google Update")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_GOOGLE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Visual Studio Installer")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTVISUALSTUDIO, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Dropbox Update Setup")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_DROPBOX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("VeraCrypt")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_VERACRYPT, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft .NET Framework")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTDOTNETFRAMEWORK, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("LegalTrademarks", &(pPEInfo->resVersion)).contains("Setup Factory")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SETUPFACTORY, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion.contains(",")) {
                    ss.sVersion = ss.sVersion.remove(" ");
                    ss.sVersion = ss.sVersion.replace(",", ".");
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("Comments", &(pPEInfo->resVersion)).contains("This installation was built with InstallAware")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_INSTALLAWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Microsoft Office")) {
                if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Bootstrapper.exe")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_MICROSOFTOFFICE, "", "", 0);
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
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SQUIRRELINSTALLER, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("SquirrelAwareVersion", &(pPEInfo->resVersion)).trimmed();

                if (ss.sVersion == "1") {
                    ss.sVersion = "1.0.0-1.9.1";
                }

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Java") &&
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("Setup Launcher")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_JAVA, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_VMWARE) ||
                XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("VMware installation")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_VMWARE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Windows Installer
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND)) {
                VI_STRUCT vi = NFD_Binary::get_WindowsInstaller_vi(pDevice, pOptions, pPEInfo->nOverlayOffset, pPEInfo->nOverlaySize, pPdStruct);

                if (vi.sVersion != "") {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

                    ss.sVersion = vi.sVersion;
                    ss.sInfo = vi.sInfo;

                    pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // Alchemy Mindworks
            if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 4001, &(pPEInfo->listResources)) &&
                XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, 5001, &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_ALCHEMYMINDWORKS, "", "", 0);
                // TODO versions

                pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (!pPEInfo->basic_info.mapResultInstallers.contains(RECORD_NAME_WINDOWSINSTALLER)) {
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
                                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WINDOWSINSTALLER, "", "", 0);

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
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                } else if (pPEInfo->exportHeader.listPositions.count() == 6) {
                    if ((pPEInfo->exportHeader.listPositions.at(0).sFunctionName == "_LanguageDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(1).sFunctionName == "_PasswordDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(2).sFunctionName == "_ProgressDlg@16") ||
                        (pPEInfo->exportHeader.listPositions.at(3).sFunctionName == "_UpdateCRC@8") ||
                        (pPEInfo->exportHeader.listPositions.at(4).sFunctionName == "_t1@40") || (pPEInfo->exportHeader.listPositions.at(5).sFunctionName == "_t2@12")) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_WISE, "", "", 0);

                        // Check version
                        pPEInfo->basic_info.mapResultInstallers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_SFX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_RAR)) {
                if (XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "STARTDLG", &(pPEInfo->listResources)) &&
                    XPE::isResourcePresent(XPE_DEF::S_RT_DIALOG, "LICENSEDLG", &(pPEInfo->listResources))) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if ((pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_WINRAR)) || (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ZIP))) {
                if (pPEInfo->sResourceManifest.contains("WinRAR")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINRAR, "", "", 0);
                    // TODO Version
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_ZIP)) {
                if (pe.checkOffsetSize(pPEInfo->osDataSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osDataSection.nOffset;
                    qint64 _nSize = pPEInfo->osDataSection.nSize;

                    qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "ZIP self-extractor", pPdStruct);
                    if (nOffset_Version != -1) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_ZIP, "", "", 0);
                        // TODO Version
                        pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }

            // 7z SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("7-Zip")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_7Z, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if ((!pPEInfo->basic_info.mapResultSFX.contains(RECORD_NAME_7Z)) && (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_7Z))) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_7Z, "", "", 0);
                ss.sInfo = "Modified";
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // SQUEEZ SFX
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_SQUEEZSFX)) {
                if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("Squeez")) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_INSTALLER, RECORD_NAME_SQUEEZSFX, "", "", 0);
                    ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion)).trimmed();
                    pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                }
            }

            // WinACE
            if (XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinACE") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("WinAce") ||
                XPE::getResourcesVersionValue("InternalName", &(pPEInfo->resVersion)).contains("UNACE")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINACE, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // WinZip
            if ((pPEInfo->sResourceManifest.contains("WinZipComputing.WinZip")) || (XPE::isSectionNamePresent("_winzip_", &(pPEInfo->listSectionRecords))))  // TODO
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_WINZIP, "", "", 0);

                QString _sManifest = pPEInfo->sResourceManifest.section("assemblyIdentity", 1, 1);
                ss.sVersion = XBinary::regExp("version=\"(.*?)\"", _sManifest, 1);
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // Cab
            if (XPE::getResourcesVersionValue("FileDescription", &(pPEInfo->resVersion)).contains("Self-Extracting Cabinet")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_CAB, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("FileVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            // GkSetup SFX
            if (XPE::getResourcesVersionValue("ProductName", &(pPEInfo->resVersion)).contains("GkSetup Self extractor")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_SFX, RECORD_NAME_GKSETUPSFX, "", "", 0);
                ss.sVersion = XPE::getResourcesVersionValue("ProductVersion", &(pPEInfo->resVersion));
                pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_PolyMorph(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPEInfo)
    Q_UNUSED(pPdStruct)
    // ExeSax
}

void SpecAbstract::PE_handle_DongleProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pPEInfo->listImports.count() == 1) {
        if (XBinary::isRegExpPresent("^NOVEX", pPEInfo->listImports.at(0).sName.toUpper())) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DONGLEPROTECTION, RECORD_NAME_GUARDIANSTEALTH, "", "", 0);
            pPEInfo->basic_info.mapResultSFX.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

// void SpecAbstract::PE_handle_AnslymPacker(QIODevice *pDevice,XScanEngine::SCAN_OPTIONS *pOptions,SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//     XPE pe(pDevice,pOptions->bIsImage);

//    if(pe.isValid(pPdStruct))
//    {
//        if(!pPEInfo->cliInfo.bInit)
//        {
//            if((pPEInfo->nImportHash64==0xaf2e74867b)&&(pPEInfo->nImportHash32==0x51a4c42b))
//            {
//                _SCANS_STRUCT ss=NFD_Binary::getScansStruct(0,XBinary::FT_PE,RECORD_TYPE_PACKER,RECORD_NAME_ANSLYMPACKER,"","",0);
//                pPEInfo->basic_info.mapResultPackers.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
//            }
//        }
//    }
//}

void SpecAbstract::PE_handle_NeoLite(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            if (pPEInfo->nEntryPointSection != 0) {
                if (pe.checkOffsetSize(pPEInfo->osEntryPointSection) && (pPEInfo->basic_info.scanOptions.bIsDeepScan)) {
                    qint64 _nOffset = pPEInfo->osEntryPointSection.nOffset;
                    qint64 _nSize = pPEInfo->osEntryPointSection.nSize;

                    qint64 nOffset_Version = pe.find_ansiString(_nOffset, _nSize, "NeoLite Executable File Compressor", pPdStruct);

                    if (nOffset_Version != -1) {
                        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PACKER, RECORD_NAME_NEOLITE, "1.0", "", 0);
                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_PrivateEXEProtector(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                 XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        if (!pPEInfo->cliInfo.bValid) {
            bool bKernel32ExitProcess = false;
            bool bKernel32 = false;
            bool bUser32 = false;
            bool bCharacteristics = false;
            bool bPEPLinker = false;
            bool bTurboLinker = false;

            if (pPEInfo->listImports.count() >= 1) {
                if (pPEInfo->listImports.at(0).sName == "KERNEL32.DLL") {
                    if (pPEInfo->listImports.at(0).listPositions.count() == 1) {
                        bKernel32 = true;

                        if (pPEInfo->listImports.at(0).listPositions.at(0).sName == "ExitProcess") {
                            bKernel32ExitProcess = true;
                        }
                    }
                }
            }

            if (pPEInfo->listImports.count() == 2) {
                if (pPEInfo->listImports.at(1).sName == "USER32.DLL") {
                    if (pPEInfo->listImports.at(1).listPositions.count() == 1) {
                        bUser32 = true;
                    }
                }
            }

            qint32 nNumberOfSections = pPEInfo->listSectionHeaders.count();

            for (qint32 i = 0; (i < nNumberOfSections) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if ((pPEInfo->listSectionHeaders.at(i).Characteristics & 0xFFFF) == 0) {
                    bCharacteristics = true;
                    break;
                }
            }

            bPEPLinker = pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PRIVATEEXEPROTECTOR);
            bTurboLinker = pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TURBOLINKER);

            if (bKernel32ExitProcess && bCharacteristics && bPEPLinker) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PRIVATEEXEPROTECTOR);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (bKernel32 && bCharacteristics && bTurboLinker) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PRIVATEEXEPROTECTOR, "2.25", "", 0);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }

            if (bKernel32 && bUser32 && bCharacteristics && bTurboLinker) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_PRIVATEEXEPROTECTOR, "2.30-2.70", "", 0);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::PE_handle_VisualBasicCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                                 XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // 1337 Exe Crypter
        if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_1337EXECRYPTER)) {
            if (XPE::isImportLibraryPresentI("MSVBVM60.DLL", &(pPEInfo->listImports))) {
                _SCANS_STRUCT ssOverlay = pPEInfo->basic_info.mapOverlayDetects.value(RECORD_NAME_1337EXECRYPTER);
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_PROTECTOR, RECORD_NAME_1337EXECRYPTER, ssOverlay.sVersion, ssOverlay.sInfo, 0);
                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // AGAINNATIVITYCRYPTER
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) {
            if (pPEInfo->basic_info.mapOverlayDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // AR Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ARCRYPT)) {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ARCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // WingsCrypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WINGSCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WINGSCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Crypt R.Roads
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTRROADS))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTRROADS);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Whitell Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WHITELLCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WHITELLCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // ZeldaCrypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ZELDACRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ZELDACRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Biohazard Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BIOHAZARDCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_BIOHAZARDCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cryptable seducation
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTABLESEDUCATION))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTABLESEDUCATION);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cryptic
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTIC))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTIC);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // CRyptOZ
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CRYPTOZ))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CRYPTOZ);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Dirty Cryptor
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DIRTYCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DIRTYCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Fakus Cryptor
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FAKUSCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FAKUSCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Fast file Crypt
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FASTFILECRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FASTFILECRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // FileShield
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FILESHIELD))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FILESHIELD);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GhaZza CryPter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_GHAZZACRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_GHAZZACRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_H4CKY0UORGCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_H4CKY0UORGCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HACCREWCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HACCREWCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HALVCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HALVCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KGBCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KGBCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KIAMSCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KIAMSCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KRATOSCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KRATOSCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_KUR0KX2TO))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_KUR0KX2TO);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERPRIVATE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_LUCYPHER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_LUCYPHER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MONEYCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MONEYCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER2))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER2);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NOXCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NOXCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PUSSYCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PUSSYCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_RDGTEJONCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_RDGTEJONCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SMOKESCREENCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SMOKESCREENCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SNOOPCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SNOOPCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_STASFODIDOCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_STASFODIDOCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TSTCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TSTCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TURKISHCYBERSIGNATURE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TURKISHCYBERSIGNATURE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TURKOJANCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TURKOJANCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNDOCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNDOCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WLCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WLCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ROGUEPACK))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ROGUEPACK);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::PE_handle_DelphiCryptors(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Ass Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ASSCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ASSCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Aase
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_AASE))  // TODO more checks!
        {
            //                    if(pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_AASE))
            //                    {
            //                        _SCANS_STRUCT ss=pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_AASE);
            //                        pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
            //                    }

            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_AASE);
            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Anskya Polymorphic Packer
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ANSKYAPOLYMORPHICPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ANSKYAPOLYMORPHICPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // AnslymPacker
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ANSLYMPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ANSLYMPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // Cigicigi Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CIGICIGICRYPTER))  // TODO more checks!
        {
            if (XPE::isResourcePresent(XPE_DEF::S_RT_RCDATA, "AYARLAR", &(pPEInfo->listResources))) {
                _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CIGICIGICRYPTER);

                pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
            }
        }

        // fEaRz Crypter
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FEARZCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FEARZCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // fEaRz Packer
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_FEARZPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_FEARZPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        // GKripto
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_GKRIPTO))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_GKRIPTO);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_HOUNDHACKCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_HOUNDHACKCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_ICRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_ICRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_INFCRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_INFCRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MALPACKER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MALPACKER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MINKE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MINKE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORTALTEAMCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORTALTEAMCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MORUKCREWCRYPTERPRIVATE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MORUKCREWCRYPTERPRIVATE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_MRUNDECTETABLE))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_MRUNDECTETABLE);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NIDHOGG))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NIDHOGG);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NME))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NME);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_OPENSOURCECODECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_OPENSOURCECODECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_OSCCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_OSCCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_P0KESCRAMBLER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_P0KESCRAMBLER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PANDORA))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PANDORA);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PFECX))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PFECX);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PICRYPTOR))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PICRYPTOR);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_POKECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_POKECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_PUBCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_PUBCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SIMCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SIMCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SEXECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SEXECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_SIMPLECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_SIMPLECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_TGRCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_TGRCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_THEZONECRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_THEZONECRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNDERGROUNDCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNDERGROUNDCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UNKOWNCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UNKOWNCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WINDOFCRYPT))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WINDOFCRYPT);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_WLGROUPCRYPTER))  // TODO more checks!
        {
            _SCANS_STRUCT ss = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_WLGROUPCRYPTER);

            pPEInfo->basic_info.mapResultProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        //        if(pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DCRYPTPRIVATE)) // TODO more checks!
        //        {
        //            _SCANS_STRUCT ss=pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DCRYPTPRIVATE);

        //            pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //        }

        //        if(pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_DALKRYPT)) // TODO more checks!
        //        {
        //            _SCANS_STRUCT ss=pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_DALKRYPT);

        //            pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //        }
    }
}

void SpecAbstract::PE_handle_Joiners(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // Blade Joiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_BLADEJOINER)) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_BLADEJOINER)) {
                if (pPEInfo->nOverlaySize) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_BLADEJOINER);
                    pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }
        }

        // ExeJoiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_EXEJOINER)) {
            if (pPEInfo->basic_info.mapEntryPointDetects.contains(RECORD_NAME_EXEJOINER)) {
                if (pPEInfo->nOverlaySize) {
                    _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapEntryPointDetects.value(RECORD_NAME_EXEJOINER);
                    pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                }
            }
        }

        // Celesty File Binder
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_CELESTYFILEBINDER)) {
            if (pe.isResourcePresent("RBIND", -1, &(pPEInfo->listResources))) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_CELESTYFILEBINDER);
                pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        // N-Joiner
        if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_NJOINER)) {
            if (pe.isResourcePresent("NJ", -1, &(pPEInfo->listResources)) || pe.isResourcePresent("NJOY", -1, &(pPEInfo->listResources))) {
                _SCANS_STRUCT recordSS = pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_NJOINER);
                pPEInfo->basic_info.mapResultJoiners.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }
    }
}

void SpecAbstract::PE_handle_DebugData(QIODevice *pDevice, SCAN_OPTIONS *pOptions, PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        // if (pELFInfo->nSymTabOffset > 0) {
        //     qint32 nNumberOfSymbols = XELF::getNumberOfSymbols(pELFInfo->nSymTabOffset);

        //     if (nNumberOfSymbols) {
        //         _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ELF, RECORD_TYPE_DEBUGDATA, RECORD_NAME_SYMBOLTABLE, "", "", 0);

        //         ss.sInfo = pELFInfo->listSectionRecords.at(pELFInfo->nSymTabSection).sName;
        //         ss.sInfo = XBinary::appendComma(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));

        //         pELFInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pELFInfo->basic_info), &ss));
        //     }
        // }

        if (XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".stab", pPdStruct) &&
            XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".stabstr", pPdStruct)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DEBUGDATA, RECORD_NAME_STABSDEBUGINFO, "", "", 0);
            pPEInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
        }

        if (XBinary::isStringInListPresent(&(pPEInfo->listSectionNames), ".debug_info", pPdStruct)) {
            XPE::SECTION_RECORD sr = pe.getSectionRecordByName(".debug_info", &(pPEInfo->listSectionRecords));

            if (sr.nOffset && sr.nSize) {
                VI_STRUCT viStruct = NFD_Binary::get_DWRAF_vi(pDevice, pOptions, sr.nOffset, sr.nSize, pPdStruct);

                if (viStruct.bIsValid) {
                    _SCANS_STRUCT ssDebugInfo = NFD_Binary::getScansStruct(0, XBinary::FT_PE, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                    ssDebugInfo.sVersion = viStruct.sVersion;

                    pPEInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ssDebugInfo));
                }
            }
        }
    }
}

bool SpecAbstract::PE_isProtectionPresent(SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    return (pPEInfo->basic_info.mapResultPackers.count() || pPEInfo->basic_info.mapResultProtectors.count() || pPEInfo->basic_info.mapResultSFX.count() ||
            pPEInfo->basic_info.mapResultInstallers.count() || pPEInfo->basic_info.mapResultNETObfuscators.count() ||
            pPEInfo->basic_info.mapResultDongleProtection.count());
}

void SpecAbstract::PE_handle_UnknownProtection(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo,
                                               XBinary::PDSTRUCT *pPdStruct)
{
    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
#ifdef QT_DEBUG
        //        qint32 i=pPEInfo->listImportPositionHashes.count()-1;

        //        if(i>0)
        //        {
        //            if(pPEInfo->listImports.at(i).listPositions.count()>1)
        //            {
        //                _SCANS_STRUCT ss={};

        //                ss.type=RECORD_TYPE_PROTECTOR;
        //                ss.name=(SpecAbstract::RECORD_NAME)(RECORD_NAME_UNKNOWN0+i);
        //                ss.sVersion=QString("%1").arg(pPEInfo->listImportPositionHashes.at(i),0,16);
        //                ss.bIsHeuristic=true;

        //                pPEInfo->basic_info.mapResultProtectors.insert(ss.name,scansToScan(&(pPEInfo->basic_info),&ss));
        //            }
        //        }

#endif

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            if (pPEInfo->listSectionRecords.count()) {
                if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                    if (pPEInfo->basic_info.mapImportDetects.contains(RECORD_NAME_UPX) && (pPEInfo->basic_info.mapImportDetects.value(RECORD_NAME_UPX).nVariant == 0)) {
                        _SCANS_STRUCT ss = {};

                        ss.type = RECORD_TYPE_PACKER;
                        ss.name = RECORD_NAME_UNK_UPXLIKE;
                        ss.bIsHeuristic = true;

                        pPEInfo->basic_info.mapResultPackers.insert(ss.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &ss));
                    }
                }
            }
        }

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            QMapIterator<RECORD_NAME, _SCANS_STRUCT> i(pPEInfo->basic_info.mapEntryPointDetects);

            while (i.hasNext() && (XBinary::isPdStructNotCanceled(pPdStruct))) {
                i.next();

                _SCANS_STRUCT recordSS = i.value();

                if (recordSS.name != RECORD_NAME_GENERIC) {
                    recordSS.bIsHeuristic = true;

                    if (recordSS.type == RECORD_TYPE_PACKER) {
                        pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    } else if (recordSS.type == RECORD_TYPE_PROTECTOR) {
                        pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
                    }
                }
            }
        }

        if ((!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_UPX)) && (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_UNK_UPXLIKE))) {
            VI_STRUCT viUPX = NFD_Binary::get_UPX_vi(pDevice, pOptions, pPEInfo->osHeader.nOffset, pPEInfo->osHeader.nSize, XBinary::FT_PE, pPdStruct);

            if ((viUPX.bIsValid)) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_UPX;
                recordSS.sVersion = viUPX.sVersion;
                recordSS.sInfo = viUPX.sInfo;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_ASPACK)) {
            if (XPE::isSectionNamePresent(".aspack", &(pPEInfo->listSectionRecords)) && XPE::isSectionNamePresent(".adata", &(pPEInfo->listSectionRecords))) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_ASPACK;
                recordSS.sVersion = "2.12-2.XX";
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_PECOMPACT)) {
            VI_STRUCT viPECompact = PE_get_PECompact_vi(pDevice, pOptions, pPEInfo);

            if (viPECompact.bIsValid) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_PECOMPACT;
                recordSS.sVersion = viPECompact.sVersion;
                recordSS.sInfo = viPECompact.sInfo;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_KKRUNCHY)) {
            if (pPEInfo->basic_info.mapSectionNamesDetects.contains(RECORD_NAME_KKRUNCHY) &&
                (pPEInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_KKRUNCHY).nVariant == 0)) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PACKER;
                recordSS.name = RECORD_NAME_KKRUNCHY;
                recordSS.bIsHeuristic = true;

                pPEInfo->basic_info.mapResultPackers.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (!PE_isProtectionPresent(pPEInfo, pPdStruct)) {
            bool bLastSectionEntryPoint = false;
            bool bEmptyFirstSection = false;
            bool bHighEntropyFirstSection = false;
            bool bHighEntropy = false;

            qint32 nNumberOfSections = pPEInfo->listSectionRecords.count();

            if (nNumberOfSections >= 2) {
                if (pPEInfo->nEntryPointSection == nNumberOfSections - 1) {
                    bLastSectionEntryPoint = true;
                }
            }

            if (nNumberOfSections > 0) {
                if (pPEInfo->listSectionRecords.at(0).nSize == 0) {
                    bEmptyFirstSection = 0;
                }
            }

            if (pe.isPacked(pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, 0, -1, pPdStruct))) {
                bHighEntropy = true;
            } else if (nNumberOfSections > 0) {
                double dEntropy =
                    pe.getBinaryStatus(XBinary::BSTATUS_ENTROPY, pPEInfo->listSectionRecords.at(0).nOffset, pPEInfo->listSectionRecords.at(0).nSize, pPdStruct);

                if (pe.isPacked(dEntropy)) {
                    bHighEntropyFirstSection = true;
                }
            }

            if (bLastSectionEntryPoint || bEmptyFirstSection || bHighEntropyFirstSection || bHighEntropy) {
                _SCANS_STRUCT recordSS = {};

                recordSS.type = RECORD_TYPE_PROTECTOR;
                recordSS.name = RECORD_NAME_GENERIC;
                recordSS.bIsHeuristic = true;

                if (bLastSectionEntryPoint) {
                    recordSS.sInfo = XBinary::appendComma(recordSS.sInfo, "Last section entry point");  // mb TODO translate
                }

                if (bEmptyFirstSection) {
                    recordSS.sInfo = XBinary::appendComma(recordSS.sInfo, "Empty first section");  // mb TODO translate
                }

                if (bHighEntropy) {
                    recordSS.sInfo = XBinary::appendComma(recordSS.sInfo, "High entropy");  // mb TODO translate
                } else if (bHighEntropyFirstSection) {
                    recordSS.sInfo = XBinary::appendComma(recordSS.sInfo, "High entropy first section");  // mb TODO translate
                }

                pPEInfo->basic_info.mapResultProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));
            }
        }

        if (pPEInfo->basic_info.scanOptions.bIsTest && pPEInfo->basic_info.scanOptions.bIsVerbose) {
            // TODO names of note sections

            qint32 nIndex = 1;

            {
                qint32 nNumberOfRecords = pPEInfo->listImportRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_LIBRARY;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN9 + nIndex);
                    recordSS.sVersion = QString("LIBRARY_") + pPEInfo->listImportRecords.at(i).sLibrary;

                    pPEInfo->basic_info.mapResultLibraries.insert(recordSS.name, NFD_Binary::scansToScan(&(pPEInfo->basic_info), &recordSS));

                    nIndex++;
                }
            }
        }
    }
}

void SpecAbstract::PE_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_RLPACK) || pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_BACKDOORPECOMPRESSPROTECTOR)) {
        pPEInfo->basic_info.mapResultLinkers.remove(RECORD_NAME_MICROSOFTLINKER);
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_MASM);
        pPEInfo->basic_info.mapResultTools.remove(RECORD_NAME_MASM32);
    }

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_AHPACKER) || pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_EPEXEPACK)) {
        pPEInfo->basic_info.mapResultPackers.remove(RECORD_NAME_AHPACKER);
    }

    // Check SafeEngine
    if (pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_VISUALCCPP) &&
        pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_BORLANDOBJECTPASCALDELPHI)) {
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_BORLANDOBJECTPASCALDELPHI);
    }

    if (pPEInfo->basic_info.mapResultLinkers.contains(RECORD_NAME_MICROSOFTLINKER) && pPEInfo->basic_info.mapResultLinkers.contains(RECORD_NAME_TURBOLINKER)) {
        pPEInfo->basic_info.mapResultLinkers.remove(RECORD_NAME_TURBOLINKER);
    }

    if (pPEInfo->basic_info.mapResultTools.contains(RECORD_NAME_MICROSOFTVISUALSTUDIO) && pPEInfo->basic_info.mapResultTools.contains(RECORD_NAME_BORLANDDELPHI)) {
        pPEInfo->basic_info.mapResultTools.remove(RECORD_NAME_BORLANDDELPHI);
    }

    if (pPEInfo->basic_info.mapResultPackers.contains(RECORD_NAME_SIMPLEPACK) && pPEInfo->basic_info.mapResultCompilers.contains(RECORD_NAME_FASM)) {
        pPEInfo->basic_info.mapResultCompilers.remove(RECORD_NAME_FASM);
    }
}

void SpecAbstract::Binary_handle_Texts(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                       XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->bIsPlainText) || (pBinaryInfo->unicodeType != XBinary::UNICODE_TYPE_NONE) || (pBinaryInfo->bIsUTF8)) {
        qint32 nSignaturesCount = NFD_TEXT::getTextExpRecordsSize() / sizeof(NFD_Binary::STRING_RECORD);

        for (qint32 i = 0; (i < nSignaturesCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++)  // TODO move to an own function !!!
        {
            if (XBinary::isRegExpPresent(NFD_TEXT::getTextExpRecords()[i].pszString, pBinaryInfo->sHeaderText)) {
                _SCANS_STRUCT record = {};
                record.nVariant = NFD_TEXT::getTextExpRecords()[i].basicInfo.nVariant;
                record.fileType = NFD_TEXT::getTextExpRecords()[i].basicInfo.fileType;
                record.type = NFD_TEXT::getTextExpRecords()[i].basicInfo.type;
                record.name = NFD_TEXT::getTextExpRecords()[i].basicInfo.name;
                record.sVersion = NFD_TEXT::getTextExpRecords()[i].basicInfo.pszVersion;
                record.sInfo = NFD_TEXT::getTextExpRecords()[i].basicInfo.pszInfo;
                record.nOffset = 0;

                pBinaryInfo->basic_info.mapTextHeaderDetects.insert(record.name, record);
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_CCPP)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_CCPP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PYTHON)) {
            if ((pBinaryInfo->sHeaderText.contains("class")) && (pBinaryInfo->sHeaderText.contains("self"))) {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PYTHON);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_HTML)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_HTML);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_XML)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_XML);
            ss.sVersion = XBinary::regExp("version=['\"](.*?)['\"]", pBinaryInfo->sHeaderText, 1);

            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PHP)) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PHP);
            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }

        //        if(pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_PERL))
        //        {
        //            _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapTextHeaderDetects.value(RECORD_NAME_PERL);
        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        if (pBinaryInfo->basic_info.mapTextHeaderDetects.contains(RECORD_NAME_SHELL)) {
            QString sInterpreter;

            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/local\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);  // #!/usr/local/bin/ruby
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/env (\\w+)", pBinaryInfo->sHeaderText, 1);      // #!/usr/bin/env perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/usr\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);          // #!/usr/bin/perl
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!\\/bin\\/(\\w+)", pBinaryInfo->sHeaderText, 1);                // #!/bin/sh
            if (sInterpreter == "") sInterpreter = XBinary::regExp("#!(\\w+)", pBinaryInfo->sHeaderText, 1);                         // #!perl

            if (sInterpreter == "perl") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_PERL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "sh") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_SHELL, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "ruby") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_RUBY, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else if (sInterpreter == "python") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_PYTHON, "", "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            } else {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_TEXT, RECORD_TYPE_SOURCECODE, RECORD_NAME_SHELL, sInterpreter, "", 0);
                pBinaryInfo->basic_info.mapResultTexts.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }

        //        if(pBinaryInfo->basic_info.mapResultTexts.count()==0)
        //        {
        //            _SCANS_STRUCT ss=NFD_Binary::getScansStruct(0,XBinary::FT_TEXT,RECORD_TYPE_FORMAT,RECORD_NAME_PLAIN,"","",0);

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

        //            pBinaryInfo->basic_info.mapResultTexts.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }
    }
}

void SpecAbstract::Binary_handle_Archives(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                          XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // 7-Zip
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        //        // TODO more options
        //        _SCANS_STRUCT ss=pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        //        if(ss.type==RECORD_TYPE_ARCHIVE)
        //        {
        //            ss.sVersion=QString("%1.%2").arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(6*2,2))).arg(XBinary::hexToUint8(pBinaryInfo->basic_info.sHeaderSignature.mid(7*2,2)));
        //            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name,scansToScan(&(pBinaryInfo->basic_info),&ss));
        //        }

        XSevenZip xsevenzip(pDevice);

        if (xsevenzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

            ss.sVersion = xsevenzip.getVersion();
#ifdef QT_DEBUG
            qint32 nNumberOfRecords = xsevenzip.getNumberOfRecords(pPdStruct);
            Q_UNUSED(nNumberOfRecords)
#endif
            //            ss.sInfo=QString("%1 records").arg(xsevenzip.getNumberOfRecords());

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // ZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZIP)) && (pBinaryInfo->basic_info.id.nSize >= 64))  // TODO min size
    {
        XZip xzip(pDevice);

        if (xzip.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZIP);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, "Encrypted");
            }

            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // GZIP
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GZIP)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GZIP);

        // TODO options
        // TODO type gzip
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // xar
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XAR)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XAR);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LZFSE
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LZFSE)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LZFSE);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // CAB
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CAB)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XCab xcab(pDevice);

        if (xcab.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CAB);

            ss.sVersion = xcab.getVersion();
            ss.sInfo = QString("%1 records").arg(xcab.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // MAch-O FAT
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MACHOFAT)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        XMACHOFat xmachofat(pDevice);

        if (xmachofat.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MACHOFAT);

            ss.sVersion = xmachofat.getVersion();
            ss.sInfo = QString("%1 records").arg(xmachofat.getNumberOfRecords(pPdStruct));

            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // RAR
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RAR)) && (pBinaryInfo->basic_info.id.nSize >= 64)) {
        XRar xrar(pDevice);

        if (xrar.isValid(pPdStruct)) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RAR);

            ss.sVersion = xrar.getVersion();
            ss.sInfo = QString("%1 records").arg(xrar.getNumberOfRecords(pPdStruct));
            // TODO options

            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // zlib
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZLIB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZLIB);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // XZ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XZ)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XZ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // ARJ
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARJ)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARJ);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // LHA
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LHA)) && (pBinaryInfo->basic_info.id.nSize >= 4)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LHA);

        bool bDetected = false;

        switch (binary.read_uint8(0x5)) {
            case 0x30: bDetected = 1; break;
            case 0x31: bDetected = 1; break;
            case 0x32: bDetected = 1; break;
            case 0x33: bDetected = 1; break;
            case 0x34: bDetected = 1; break;
            case 0x35: bDetected = 1; break;
            case 0x36: bDetected = 1; break;
            case 0x64: bDetected = 1; break;
            case 0x73: bDetected = 1; break;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO options
            // TODO files
            pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    // BZIP2
    else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BZIP2)) && (pBinaryInfo->basic_info.id.nSize >= 9)) {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BZIP2);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
    // TAR
    else if ((pBinaryInfo->basic_info.id.nSize >= 500) && (binary.getSignature(0x100, 6) == "007573746172"))  // "00'ustar'"
    {
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;

        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_TAR, "", "", 0);

        // TODO options
        // TODO files
        pBinaryInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Certificates(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Windows Authenticode Portable Executable Signature Format
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINAUTH)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        quint32 nLength = XBinary::hexToUint32(pBinaryInfo->basic_info.sHeaderSignature.mid(0, 8));

        if (nLength >= pBinaryInfo->basic_info.id.nSize) {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINAUTH);
            pBinaryInfo->basic_info.mapResultCertificates.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_DebugData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo,
                                           XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pPdStruct)

    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MINGW)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MinGW debug data
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MINGW);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDBFILELINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PDB File Link
        // TODO more infos
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDBFILELINK);
        pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BORLANDDEBUGINFO)) && (pBinaryInfo->basic_info.id.nSize >= 16)) {
        quint16 nSignature = binary.read_uint16(0);

        if (nSignature == 0x52FB) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_BORLANDDEBUGINFO, "", "", 0);

            quint8 nMajor = binary.read_uint8(3);
            quint8 nMinor = binary.read_uint8(2);
            quint16 nNumberOfSymbols = binary.read_uint16(0xE);
            double dVersion = nMajor + (double)nMinor / 100.0;

            ss.type = RECORD_TYPE_DEBUGDATA;
            ss.name = RECORD_NAME_BORLANDDEBUGINFO;
            ss.sVersion = QString::number(dVersion, 'f', 2);
            ss.sInfo = "TDS";

            if (nNumberOfSymbols) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, QString("%1 symbols").arg(nNumberOfSymbols));
            }

            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        } else {
            _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BORLANDDEBUGINFO);
            pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
    if (binary.getSize() > 16) {
        // unsigned_16     signature;      /* == 0x8386                    */
        // unsigned_8      exe_major_ver;  /* == 2 or 3                    */
        // unsigned_8      exe_minor_ver;  /* == 0                         */
        // unsigned_8      obj_major_ver;  /* == 1                         */
        // unsigned_8      obj_minor_ver;  /* == 1                         */
        // unsigned_16     lang_size;
        // unsigned_16     segment_size;
        // unsigned_32     debug_size;
        // TODO more
        if (binary.read_uint16(binary.getSize() - 14) == 0x8386) {
            qint64 nHeaderOffset = binary.getSize() - 14;
            quint8 exe_major_ver = binary.read_uint16(nHeaderOffset + 2);
            quint8 exe_minor_ver = binary.read_uint16(nHeaderOffset + 3);
            // quint8 obj_major_ver = binary.read_uint16(nHeaderOffset + 4);
            // quint8 obj_minor_ver = binary.read_uint16(nHeaderOffset + 5);
            // quint16 nLangSize = binary.read_uint16(nHeaderOffset + 6);
            // quint16 nSegmentSize = binary.read_uint16(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 10);

            qint64 nDebugOffset = binary.getSize() - nDebugSize;

            if (nDebugOffset >= 0) {
                // TODO Language
                // https://github.com/open-watcom/open-watcom-v2/blob/e7d0bef544987dd0429f547a2119e0c9d9472770/bld/exedump/c/wdwarf.c#L132
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_WATCOMDEBUGINFO, "", "", 0);
                ss.sVersion = QString("%1.%2").arg(QString::number(exe_major_ver), QString::number(exe_minor_ver));
                ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint16(binary.getSize() - 8) == 0x424E) {
            QString sSignature = binary.read_ansiString(binary.getSize() - 8, 4);

            if ((sSignature == "NB05") || (sSignature == "NB07") || (sSignature == "NB08") || (sSignature == "NB09") || (sSignature == "NB10") ||
                (sSignature == "NB11")) {
                qint64 nHeaderOffset = binary.getSize() - 8;
                quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 4);

                qint64 nDebugOffset = binary.getSize() - nDebugSize;

                if (nDebugOffset >= 0) {
                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_CODEVIEWDEBUGINFO, "", "", 0);
                    ss.sVersion = "4.0";
                    ss.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));

                    pBinaryInfo->basic_info.mapResultDebugData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
                }
            }
        }
    }

    if (binary.getSize() > 16) {
        if (binary.read_uint32(binary.getSize() - 16) == 0x534954) {
            // typedef struct {
            //     unsigned_32 signature;
            //     unsigned_32 vendor;
            //     unsigned_32 type;
            //     unsigned_32 size;
            // } TISTrailer;

            qint64 nHeaderOffset = binary.getSize() - 16;

            quint32 nVendor = binary.read_uint32(nHeaderOffset + 4);
            quint32 nType = binary.read_uint32(nHeaderOffset + 8);
            quint32 nDebugSize = binary.read_uint32(nHeaderOffset + 12);

            if ((nVendor == 0) && (nType == 0)) {
                qint64 nDebugOffset = nHeaderOffset - nDebugSize;

                if (nDebugOffset >= 0) {
                    VI_STRUCT viStruct = NFD_Binary::get_DWRAF_vi(pDevice, pOptions, nDebugOffset, binary.getSize() - nDebugOffset, pPdStruct);

                    if (viStruct.bIsValid) {
                        _SCANS_STRUCT ssDebugInfo = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_DEBUGDATA, RECORD_NAME_DWARFDEBUGINFO, "", "", 0);
                        ssDebugInfo.sVersion = viStruct.sVersion;
                        ssDebugInfo.sInfo = QString("0x%1 bytes").arg(XBinary::valueToHexEx(nDebugSize));
                        ssDebugInfo.sInfo = XBinary::appendComma(ssDebugInfo.sInfo, "Watcom");

                        pBinaryInfo->basic_info.mapResultDebugData.insert(ssDebugInfo.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ssDebugInfo));
                    }
                }
            }
        }
    }
}

void SpecAbstract::Binary_handle_Formats(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if (pBinaryInfo->basic_info.id.nSize == 0) {
        _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_EMPTYFILE, "", "", 0);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TODO move to own type
        // PDF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDF);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(5 * 2, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPOUND)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compound
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPOUND);

        quint16 nSub1 = binary.read_uint16(0x200);
        quint16 nSub2 = binary.read_uint16(0x1000);

        // TODO More
        if ((nSub1 == 0) && (nSub2 == 0xFFFD)) {
            ss.type = RECORD_TYPE_INSTALLER;  // TODO mapResultInstallers
            ss.name = RECORD_NAME_MICROSOFTINSTALLER;
            ss.sVersion = "";
            ss.sInfo = "";
        } else if (nSub1 == 0xA5EC) {
            ss.type = RECORD_TYPE_FORMAT;
            ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
            ss.sVersion = "97-2003";
            ss.sInfo = "";
        }

        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft Compiled HTML Help
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTCOMPILEDHTMLHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AUTOIT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AutoIt Compiled Script
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AUTOIT);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // RTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RTF);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LUACOMPILED)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Lua
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LUACOMPILED);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JAVACOMPILEDCLASS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // java
        quint16 nMinor = binary.read_uint16(4, true);
        quint16 nMajor = binary.read_uint16(6, true);

        if (nMajor) {
            QString sVersion = XJavaClass::_getJDKVersion(nMajor, nMinor);

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JAVACOMPILEDCLASS);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_COFF)) && (pBinaryInfo->basic_info.id.nSize >= 76)) {
        // COFF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_COFF);

        bool bDetected = false;

        qint64 nOffset = binary.read_uint32(72, true) + 58;

        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....4C01", nOffset)) {
            ss.sInfo = "I386";
            bDetected = true;
        }
        if (binary.compareSignature(&(pBinaryInfo->basic_info.memoryMap), "600A0000FFFF....6486", nOffset)) {
            ss.sInfo = "AMD64";
            bDetected = true;
        }

        if (bDetected) {
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEX)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // dex
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEX);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(8, 6));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SWF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // SWF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SWF);
        ss.sVersion = QString("%1").arg(binary.read_uint8(3));
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTWINHELP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Microsoft WinHelp
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTWINHELP);
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP3)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP3
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP3);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MP4)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // MP4
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MP4);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSMEDIA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Windows Media
        // TODO WMV/WMA
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSMEDIA);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FLASHVIDEO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Flash Video
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FLASHVIDEO);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WAV)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // VAW
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WAV);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AU
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AU);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DEB)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DEB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DEB);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVI)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVI);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WEBP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WEBP);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TTF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TTF
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TTF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDARSC)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDARSC);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ANDROIDXML)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ANDROIDXML);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AR)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // AR
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AR);
        // TODO Version
        pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }

    if (pBinaryInfo->basic_info.id.nSize >= 0x8010) {
        if (binary.compareSignature("01'CD001'01", 0x8000)) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_ISO9660, "", "", 0);
            // TODO Version
            pBinaryInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Databases(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PDB)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // PDB
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PDB);
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKERDATABASE)) && (pBinaryInfo->basic_info.id.nSize >= 32)) {
        // Microsoft Linker Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTLINKERDATABASE);
        //        ss.sVersion=QString("%1.%2").arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(32*2,4))).arg(QBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(34*2,4)));
        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTACCESS)) && (pBinaryInfo->basic_info.id.nSize >= 128)) {
        // Microsoft Access Database
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MICROSOFTACCESS);

        quint32 nVersion = binary.read_int32(0x14);

        switch (nVersion) {
            case 0x0000: ss.sVersion = "JET3"; break;  // TODO
            case 0x0001: ss.sVersion = "JET4"; break;  // TODO
            case 0x0002: ss.sVersion = "2007"; break;
            case 0x0103: ss.sVersion = "2010"; break;
        }

        pBinaryInfo->basic_info.mapResultDatabases.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_Images(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_JPEG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // JPEG
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_JPEG);
        quint32 nMajor = pBinaryInfo->basic_info.sHeaderSignature.mid(11 * 2, 2).toUInt(nullptr, 16);
        quint32 nMinor = pBinaryInfo->basic_info.sHeaderSignature.mid(12 * 2, 2).toUInt(nullptr, 16);
        ss.sVersion = QString("%1.%2").arg(nMajor).arg(nMinor, 2, 10, QChar('0'));
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GIF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // GIF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GIF);
        // TODO Version
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TIFF)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // TIFF
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TIFF);
        // More information
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSICON)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Icon
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSICON);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSCURSOR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        // Windows Cursor
        // TODO more information
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSCURSOR);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINDOWSBITMAP)) && (pBinaryInfo->basic_info.id.nSize >= 40)) {
        // Windows Bitmap
        // TODO more information
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        quint32 _nSize = qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(2 * 2, 8).toUInt(nullptr, 16));
        if (pBinaryInfo->basic_info.id.nSize >= _nSize) {
            QString sVersion;

            switch (qFromBigEndian(pBinaryInfo->basic_info.sHeaderSignature.mid(14 * 2, 8).toUInt(nullptr, 16))) {
                case 40: sVersion = "3"; break;
                case 108: sVersion = "4"; break;
                case 124: sVersion = "5"; break;
            }

            if (sVersion != "") {
                _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINDOWSBITMAP);
                ss.sVersion = sVersion;
                pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
            }
        }
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_PNG)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // PNG
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_PNG);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(16, true)).arg(binary.read_uint32(20, true));

        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DJVU)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // DJVU
        // TODO options
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_IMAGE;
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DJVU);
        pBinaryInfo->basic_info.mapResultImages.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_InstallerData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    // Inno Setup
    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INNOSETUP)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INNOSETUP);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLANYWHERE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLANYWHERE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GHOSTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GHOSTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NSIS)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NSIS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SIXXPACK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SIXXPACK);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_THINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_THINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SMARTINSTALLMAKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SMARTINSTALLMAKER);
        ss.sVersion = XBinary::hexToString(pBinaryInfo->basic_info.sHeaderSignature.mid(46, 14));
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_TARMAINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_TARMAINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_CLICKTEAM)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_CLICKTEAM);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_QTINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_QTINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ADVANCEDINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ADVANCEDINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_OPERA)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_OPERA);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GPINSTALL)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_GPINSTALL);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AVASTANTIVIRUS)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AVASTANTIVIRUS);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALLSHIELD)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALLSHIELD);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SETUPFACTORY)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SETUPFACTORY);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTUALINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTUALINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_INSTALL4J)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_INSTALL4J);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_VMWARE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_VMWARE);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOSINSTALLER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOSINSTALLER);
        pBinaryInfo->basic_info.mapResultInstallerData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_SFXData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WINRAR)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WINRAR);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SQUEEZSFX)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SQUEEZSFX);
        pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_7Z)) && (pBinaryInfo->basic_info.id.nSize >= 20)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_7Z);

        if (ss.type == RECORD_TYPE_SFXDATA) {
            pBinaryInfo->basic_info.mapResultSFXData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_ProtectorData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FISHNET)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Inno Setup
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FISHNET);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_XENOCODE)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        // Xenocode
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_XENOCODE);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MOLEBOXULTRA)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_MOLEBOXULTRA);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_1337EXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_1337EXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ACTIVEMARK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ACTIVEMARK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_AGAINNATIVITYCRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_AGAINNATIVITYCRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ARCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ARCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_NOXCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_NOXCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_FASTFILECRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_FASTFILECRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_LIGHTNINGCRYPTERSCANTIME);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_ZELDACRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_ZELDACRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WOUTHRSEXECRYPTER)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WOUTHRSEXECRYPTER);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_WLCRYPT)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_WLCRYPT);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_DOTNETSHRINK)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_DOTNETSHRINK);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SPOONSTUDIO)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SPOONSTUDIO);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SECUROM)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SECUROM);
        ss.sVersion = binary.read_ansiString(8);
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SERGREENAPPACKER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_SERGREENAPPACKER);
        // TODO Version
        pBinaryInfo->basic_info.mapResultProtectorData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Binary_handle_LibraryData(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_SHELL)) && (pBinaryInfo->basic_info.id.nSize >= 8)) {
        QString sString = binary.read_ansiString(0);

        if (sString.contains("python")) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_LIBRARY, RECORD_NAME_PYTHON, "", "", 0);
            pBinaryInfo->basic_info.mapResultLibraryData.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::Binary_handle_Resources(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BINARYINFO_STRUCT *pBinaryInfo)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_VERSIONINFO)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_VERSIONINFO);
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if ((pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_BITMAPINFOHEADER)) && (pBinaryInfo->basic_info.id.nSize >= 30)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_BITMAPINFOHEADER);

        ss.sInfo = QString("%1x%2").arg(binary.read_uint32(4)).arg(binary.read_uint32(8));
        // TODO
        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_STRINGTABLE)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_STRINGTABLE);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_DIALOG)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_DIALOG);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_ICON)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_ICON);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_CURSOR)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_CURSOR);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    } else if (pBinaryInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_RESOURCE_MENU)) {
        _SCANS_STRUCT ss = pBinaryInfo->basic_info.mapHeaderDetects.value(RECORD_NAME_RESOURCE_MENU);

        pBinaryInfo->basic_info.mapResultResources.insert(ss.name, NFD_Binary::scansToScan(&(pBinaryInfo->basic_info), &ss));
    }
}

void SpecAbstract::Zip_handle_Microsoftoffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("docProps/app.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                QString sData = xzip.decompress(&record, pPdStruct).data();
                QString sApplication = XBinary::regExp("<Application>(.*?)</Application>", sData, 1);

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_MICROSOFTOFFICE, "", "", 0);

                if (sApplication == "Microsoft Office Word") {
                    ss.name = RECORD_NAME_MICROSOFTOFFICEWORD;
                } else if (sApplication == "Microsoft Excel") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                } else if (sApplication == "Microsoft Visio") {
                    ss.name = RECORD_NAME_MICROSOFTVISIO;
                } else if (sApplication == "SheetJS") {
                    ss.name = RECORD_NAME_MICROSOFTEXCEL;
                    ss.sInfo = "SheetJS";
                }

                ss.sVersion = XBinary::regExp("<AppVersion>(.*?)</AppVersion>", sData, 1);
                pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_OpenOffice(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        XArchive::RECORD record = XArchive::getArchiveRecord("meta.xml", &(pZipInfo->listArchiveRecords));

        if (!record.spInfo.sRecordName.isEmpty()) {
            if ((record.spInfo.nUncompressedSize) && (record.spInfo.nUncompressedSize <= 0x4000)) {
                QString sData = xzip.decompress(&record, pPdStruct).data();

                // TODO
                if (sData.contains(":opendocument:")) {
                    pZipInfo->basic_info.id.fileType = XBinary::FT_DOCUMENT;

                    _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_BINARY, RECORD_TYPE_FORMAT, RECORD_NAME_OPENDOCUMENT, "", "", 0);

                    pZipInfo->basic_info.mapResultFormats.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
                }
            }
        }
    }
}

void SpecAbstract::Zip_handle_Metainfos(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, BASIC_INFO *pBasicInfo, QList<XArchive::RECORD> *pListArchiveRecords,
                                        XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pListArchiveRecords, pPdStruct)) {
        QString sDataManifest = xjar.decompress(pListArchiveRecords, "META-INF/MANIFEST.MF", pPdStruct).data();

        if (sDataManifest != "") {
            QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sAntVersion = XBinary::regExp("Ant-Version: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");
            QString sBuiltJdk = XBinary::regExp("Build-Jdk: (.*?)\n", sDataManifest, 1).remove("\r");

            if (sCreatedBy.contains("Android Gradle")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDGRADLE, "", "", 0);
                ss.sVersion = XBinary::regExp("Android Gradle (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("MOTODEV Studio for Android") || sCreatedBy.contains("MOTODEV Studio for ANDROID")) {
                // TODO Check "MOTODEV Studio for ANDROID" version
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_MOTODEVSTUDIOFORANDROID, "", "", 0);
                ss.sVersion = XBinary::regExp("MOTODEV Studio for Android v(.*?).release", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("Android Maven") || sCreatedBy.contains("Apache Maven Bundle Plugin")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDMAVENPLUGIN, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Radialix")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_RADIALIX, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Radialix", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("AntiLVL")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_ANTILVL, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkEditor")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_APKEDITOR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("d2j-apk-sign")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_D2JAPKSIGN, "", "", 0);
                ss.sVersion = XBinary::regExp("d2j-apk-sign (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("singlejar")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_SINGLEJAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("PseudoApkSigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_PSEUDOAPKSIGNER, "", "", 0);
                ss.sVersion = XBinary::regExp("PseudoApkSigner (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkSigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNER, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("www.HiAPK.com")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_HIAPKCOM, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("com.haibison.apksigner") || sCreatedBy.contains("com.haibison.apksigner")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APK_SIGNER, "", "", 0);

                if (sBuiltBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sBuiltBy, 1);
                } else if (sCreatedBy.contains("com.haibison.apksigner")) {
                    ss.sVersion = XBinary::regExp("com.haibison.apksigner (.*?)$", sCreatedBy, 1);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sBuiltBy.contains("BundleTool") || sCreatedBy.contains("BundleTool")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_BUNDLETOOL, "", "", 0);

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(COMEX SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_COMEXSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (COMEX SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(NetEase ApkSigner)"))  // TODO Check " " !!!
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_NETEASEAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (NetEase ApkSigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signatory)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNATORY, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signatory)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(signupdate)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_SIGNUPDATE, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (signupdate)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(KT Android SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (KT Android SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(abc SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (abc SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(dotools sign apk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_DOTOOLSSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (dotools sign apk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Android apksigner)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_ANDROIDAPKSIGNER, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Android apksigner)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(ApkModifier SignApk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKMODIFIERSIGNAPK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (ApkModifier SignApk)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Baidu Signature platform)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_BAIDUSIGNATUREPLATFORM, "", "", 0);
                ss.sVersion = sCreatedBy.section(" (Baidu Signature platform)", 0, 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("tiny-sign")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_TINYSIGN, "", "", 0);
                ss.sVersion = sCreatedBy.section("tiny-sign-", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("DexGuard, version")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);
                ss.sVersion = XBinary::regExp("DexGuard, version (.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("ApkProtector")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_APKPROTECTOR, "", "", 0);

                if (sCreatedBy.section(" ", 0, 0) == "ApkProtector") {
                    ss.sVersion = sCreatedBy.section(" ", 1, 1).remove(")").remove("(");
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Sun Microsystems Inc.)") || sCreatedBy.contains("(BEA Systems, Inc.)") || sCreatedBy.contains("(The FreeBSD Foundation)") ||
                       sCreatedBy.contains("(d2j-null)") || sCreatedBy.contains("(d2j-2.1-SNAPSHOT)") || sCreatedBy.contains("(Oracle Corporation)") ||
                       sCreatedBy.contains("(Apple Inc.)") || sCreatedBy.contains("(Google Inc.)") || sCreatedBy.contains("(Jeroen Frijters)") ||
                       sCreatedBy.contains("(IBM Corporation)") || sCreatedBy.contains("(JetBrains s.r.o)") || sCreatedBy.contains("(Alibaba)") ||
                       sCreatedBy.contains("(AdoptOpenJdk)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy.section(" ", 0, 0);

                if (sCreatedBy.contains("(Apple Inc.)")) {
                    ss.name = RECORD_NAME_APPLEJDK;
                } else if (sCreatedBy.contains("(IBM Corporation)")) {
                    ss.name = RECORD_NAME_IBMJDK;
                } else if (sCreatedBy.contains("(AdoptOpenJdk)")) {
                    ss.name = RECORD_NAME_OPENJDK;
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy == "1.6.0_21") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sCreatedBy;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(JetBrains s.r.o)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JETBRAINS, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-null)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(d2j-2.1-SNAPSHOT)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_APKTOOL, RECORD_NAME_DEX2JAR, "2.1", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(Jeroen Frijters)")) {
                // Check OpenJDK
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_IKVMDOTNET, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("(BEA Systems, Inc.)")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_BEAWEBLOGIC, "", "", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            } else if (sCreatedBy.contains("dx ")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_COMPILER, RECORD_NAME_DX, "", "", 0);
                ss.sVersion = sCreatedBy.section("dx ", 1, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sAntVersion.contains("Apache Ant")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_APACHEANT, "", "", 0);
                ss.sVersion = XBinary::regExp("Apache Ant (.*?)$", sAntVersion, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltBy.contains("Generated-by-ADT")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ECLIPSE, "", "ADT", 0);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sBuiltJdk != "") {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_JAR, RECORD_TYPE_TOOL, RECORD_NAME_JDK, "", "", 0);
                ss.sVersion = sBuiltJdk;
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sProtectedBy.contains("DexProtector")) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXPROTECTOR, "", "", 0);

                if (sProtectedBy.section(" ", 0, 0) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 1, 1).remove(")").remove("(");
                } else if (sProtectedBy.section(" ", 1, 1) == "DexProtector") {
                    ss.sVersion = sProtectedBy.section(" ", 0, 0);
                }

                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (XBinary::regExp("^\\d+(\\.\\d+)*$", sCreatedBy, 0) != "")  // 0.0.0
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            if (sCreatedBy.contains("(d8)") || sCreatedBy.contains("(dx)"))  // Dexguard
            {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_GENERIC, RECORD_NAME_GENERIC, "", "", 0);

                ss.sVersion = XBinary::regExp("(.*?)$", sCreatedBy, 1);
                pBasicInfo->mapMetainfosDetects.insert(ss.name, ss);
            }

            // TODO heur if String contains add to heur
        }
    }
}

void SpecAbstract::Zip_handle_JAR(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XJAR xjar(pDevice);

    if (xjar.isValid(pPdStruct) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xjar.getFileFormatInfo(pPdStruct));

        pZipInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ssOperationSystem));

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APPLEJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APPLEJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IBMJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IBMJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_OPENJDK)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_OPENJDK);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_JETBRAINS)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_JETBRAINS);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_IKVMDOTNET)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_IKVMDOTNET);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BEAWEBLOGIC)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BEAWEBLOGIC);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APACHEANT)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APACHEANT);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }

        if (pZipInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SINGLEJAR)) {
            _SCANS_STRUCT ss = pZipInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SINGLEJAR);
            pZipInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(&(pApkInfo->listArchiveRecords), pPdStruct)) {
        _SCANS_STRUCT ssOperationSystem = NFD_Binary::getOperationSystemScansStruct(xapk.getFileFormatInfo(pPdStruct));

        pApkInfo->basic_info.mapResultOperationSystems.insert(ssOperationSystem.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssOperationSystem));

        // 0x7109871a APK_SIGNATURE_SCHEME_V2_BLOCK_ID
        // TODO Check 0x7109871f
        // https://github.com/18598925736/ApkChannelPackageJavaCore/blob/9342d57a1fc5f9271d569612df6028758f6ee42d/src/channel/data/Constants.java#L38
        // 0xf05368c0 APK_SIGNATURE_SCHEME_V3_BLOCK_ID
        // 0x42726577 padding
        // 0x504b4453 DEPENDENCY_INFO_BLOCK_ID;
        // https://github.com/jomof/CppBuildCacheWorkInProgress/blob/148b94d712d14b6f2a13ab37a526c7795e2215b3/agp-7.1.0-alpha01/tools/base/signflinger/src/com/android/signflinger/SignedApk.java#L56
        // 0x71777777 Walle
        // https://github.com/Meituan-Dianping/walle/blob/f78edcf1117a0aa858a3d04bb24d86bf9ad51bb2/payload_reader/src/main/java/com/meituan/android/walle/ApkUtil.java#L40
        // 0x6dff800d SOURCE_STAMP_BLOCK_ID
        // 0x2146444e Google Play

        QList<XAPK::APK_SIG_BLOCK_RECORD> listApkSignaturesBlockRecords = xapk.getAPKSignaturesBlockRecordsList();

        _SCANS_STRUCT ssSignTool = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_APKSIGNATURESCHEME, "", "", 0);

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x7109871a)) {
            ssSignTool.sVersion = "v2";
        } else if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0xf05368c0)) {
            ssSignTool.sVersion = "v3";
        }

        // TODO V4

        if (ssSignTool.sVersion != "") {
            pApkInfo->basic_info.mapResultSigntools.insert(ssSignTool.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssSignTool));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x71777777)) {
            _SCANS_STRUCT ssWalle = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_WALLE, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssWalle.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssWalle));
        }

        if (XAPK::isAPKSignatureBlockRecordPresent(&listApkSignaturesBlockRecords, 0x2146444e)) {
            _SCANS_STRUCT ssGooglePlay = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_GOOGLEPLAY, "", "", 0);
            pApkInfo->basic_info.mapResultTools.insert(ssGooglePlay.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssGooglePlay));
        }

        if (pApkInfo->bIsKotlin) {
            _SCANS_STRUCT ssKotlin = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_KOTLIN, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssKotlin.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssKotlin));
        } else {
            _SCANS_STRUCT ssJava = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LANGUAGE, RECORD_NAME_JAVA, "", "", 0);
            pApkInfo->basic_info.mapResultLanguages.insert(ssJava.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssJava));
        }

        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_SIGNTOOL, RECORD_NAME_UNKNOWN, "", "", 0);

            qint32 nNumberOfRecords = listApkSignaturesBlockRecords.count();

            for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                if (listApkSignaturesBlockRecords.at(i).nID > 0xFFFF) {
                    if ((listApkSignaturesBlockRecords.at(i).nID != 0x7109871a) && (listApkSignaturesBlockRecords.at(i).nID != 0xf05368c0) &&
                        (listApkSignaturesBlockRecords.at(i).nID != 0x42726577)) {
                        ss.name = (RECORD_NAME)((int)RECORD_NAME_UNKNOWN0 + i);
                        ss.sVersion = XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nID);
                        // ss.sInfo=XBinary::valueToHex(listApkSignaturesBlockRecords.at(i).nDataSize);
                        pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
                    }
                }
            }
        }

        QByteArray baAndroidManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "AndroidManifest.xml", pPdStruct);

        if (baAndroidManifest.size() > 0) {
            QString sAndroidManifest = XAndroidBinary::getDecoded(&baAndroidManifest, pPdStruct);

            QString sCompileSdkVersion = XBinary::regExp("android:compileSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sCompileSdkVersionCodename = XBinary::regExp("android:compileSdkVersionCodename=\"(.*?)\"", sAndroidManifest, 1);
            QString sTargetSdkVersion = XBinary::regExp("android:targetSdkVersion=\"(.*?)\"", sAndroidManifest, 1);
            QString sMinSdkVersion = XBinary::regExp("android:minSdkVersion=\"(.*?)\"", sAndroidManifest, 1);

            // Check
            if (!XBinary::checkStringNumber(sCompileSdkVersion, 1, 40)) sCompileSdkVersion = "";
            if (!XBinary::checkStringNumber(sTargetSdkVersion, 1, 40)) sTargetSdkVersion = "";
            if (!XBinary::checkStringNumber(sMinSdkVersion, 1, 40)) sMinSdkVersion = "";

            if (!XBinary::checkStringNumber(sCompileSdkVersionCodename.section(".", 0, 0), 1, 15)) sCompileSdkVersionCodename = "";

            if ((sCompileSdkVersion != "") || (sCompileSdkVersionCodename != "") || (sTargetSdkVersion != "") || (sMinSdkVersion != "")) {
                _SCANS_STRUCT ssAndroidSDK = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_TOOL, RECORD_NAME_ANDROIDSDK, "", "", 0);

                QString _sVersion;
                QString _sAndroidVersion;

                _sVersion = sCompileSdkVersion;
                _sAndroidVersion = sCompileSdkVersionCodename;

                if (_sVersion == "") _sVersion = sMinSdkVersion;
                if (_sVersion == "") _sVersion = sTargetSdkVersion;

                if (_sVersion != "") {
                    ssAndroidSDK.sVersion = QString("API %1").arg(_sVersion);

                    pApkInfo->basic_info.mapResultTools.insert(ssAndroidSDK.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ssAndroidSDK));
                }
            }

            QString sJetpack = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/androidx.core_core.version").data();
            if (sJetpack != "") {
                QString sJetpackVersion = XBinary::regExp("(.*?)\n", sJetpack, 1).remove("\r");

                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_LIBRARY, RECORD_NAME_ANDROIDJETPACK, "", "", 0);
                ss.sVersion = sJetpackVersion;
                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDGRADLE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDGRADLE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDMAVENPLUGIN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDMAVENPLUGIN);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_RADIALIX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_RADIALIX);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_MOTODEVSTUDIOFORANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_MOTODEVSTUDIOFORANDROID);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANTILVL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANTILVL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKEDITOR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKEDITOR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BUNDLETOOL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BUNDLETOOL);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEX2JAR)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEX2JAR);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_D2JAPKSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_D2JAPKSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_PSEUDOAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_PSEUDOAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APK_SIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APK_SIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_NETEASEAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_NETEASEAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DOTOOLSSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DOTOOLSSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNATORY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNATORY);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_SIGNUPDATE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_SIGNUPDATE);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ANDROIDAPKSIGNER)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ANDROIDAPKSIGNER);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKMODIFIERSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKMODIFIERSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_BAIDUSIGNATUREPLATFORM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_BAIDUSIGNATUREPLATFORM);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_TINYSIGN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_TINYSIGN);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_COMEXSIGNAPK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_COMEXSIGNAPK);
                pApkInfo->basic_info.mapResultSigntools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_ECLIPSE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_ECLIPSE);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_HIAPKCOM)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_HIAPKCOM);
                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DX)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DX);
                pApkInfo->basic_info.mapResultCompilers.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECSHELL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECSHELL);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_JIAGU)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_JIAGU);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IJIAMI)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IJIAMI);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTPROTECTION);
                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU) ||
                pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_TENCENTLEGU)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_TENCENTLEGU);
                } else if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MOBILETENCENTPROTECT)) {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MOBILETENCENTPROTECT);
                }

                qint32 nNumberOfRecords = pApkInfo->listArchiveRecords.count();

                for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/arm64-v8a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/arm64-v8a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi-v7a/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi-v7a/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/armeabi/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/armeabi/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    } else if (pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName.contains("lib/x86/libshella-")) {
                        ss.sVersion = XBinary::regExp("lib/x86/libshella-(.*?).so", pApkInfo->listArchiveRecords.at(i).spInfo.sRecordName, 1);

                        break;
                    }
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppGuard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Kiro
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_KIRO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_KIRO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DxShield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DXSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DXSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // qdbh
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QDBH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QDBH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Bangcle Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BANGCLEPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BANGCLEPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Qihoo 360 Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QIHOO360PROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QIHOO360PROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Alibaba Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_ALIBABAPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_ALIBABAPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Baidu Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BAIDUPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BAIDUPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // NQ Shield
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NQSHIELD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NQSHIELD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Nagapt Protection
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_NAGAPTPROTECTION)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_NAGAPTPROTECTION);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SecNeo
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SECNEO)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SECNEO);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // LIAPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_LIAPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_LIAPP);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // yidun
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_YIDUN)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_YIDUN);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // PangXie
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PANGXIE)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PANGXIE);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Hdus-Wjus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_HDUS_WJUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_HDUS_WJUS);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Medusah
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_MEDUSAH)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_MEDUSAH);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // AppSolid
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APPSOLID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APPSOLID);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Proguard
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_PROGUARD)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_PROGUARD);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // VDog
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_VDOG)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_VDOG);

                QString sVersion = xapk.decompress(&(pApkInfo->listArchiveRecords), "assets/version").data();

                if (sVersion != "") {
                    // V4.1.0_VDOG-1.8.5.3_AOP-7.23
                    ss.sVersion = sVersion.section("VDOG-", 1, 1).section("_", 0, 0);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // APKProtect
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECT)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECT);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ollvm-tll
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_OLLVMTLL)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_OLLVMTLL);

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // DexGuard
            if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD) ||
                pApkInfo->dexInfoClasses.basic_info.mapResultProtectors.contains(RECORD_NAME_DEXGUARD)) {
                _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_APK, RECORD_TYPE_PROTECTOR, RECORD_NAME_DEXGUARD, "", "", 0);

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXGUARD)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXGUARD).sVersion;
                } else if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_GENERIC)) {
                    ss.sVersion = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_GENERIC).sVersion;
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_DEXPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_DEXPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_DEXPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_DEXPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKPROTECTOR) ||
                pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                _SCANS_STRUCT ss = {};

                if (pApkInfo->basic_info.mapMetainfosDetects.contains(RECORD_NAME_APKPROTECTOR)) {
                    ss = pApkInfo->basic_info.mapMetainfosDetects.value(RECORD_NAME_APKPROTECTOR);
                } else {
                    ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKPROTECTOR);
                }

                pApkInfo->basic_info.mapResultAPKProtectors.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // SandHook
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_SANDHOOK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_SANDHOOK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unicom SDK
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNICOMSDK)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNICOMSDK);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Unity
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_UNITY)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_UNITY);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // IL2CPP
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_IL2CPP)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_IL2CPP);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // Basic4Android
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_BASIC4ANDROID)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_BASIC4ANDROID);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // ApkToolPlus
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_APKTOOLPLUS)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_APKTOOLPLUS);

                pApkInfo->basic_info.mapResultTools.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }

            // QML
            if (pApkInfo->basic_info.mapArchiveDetects.contains(RECORD_NAME_QML)) {
                _SCANS_STRUCT ss = pApkInfo->basic_info.mapArchiveDetects.value(RECORD_NAME_QML);

                pApkInfo->basic_info.mapResultLibraries.insert(ss.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &ss));
            }
        }
    }
}

void SpecAbstract::Zip_handle_IPA(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)
    Q_UNUSED(pOptions)
    Q_UNUSED(pPdStruct)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->bIsIPA) {
            _SCANS_STRUCT ssFormat = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_IPA, "", "", 0);

            ssFormat.sVersion = xzip.getVersion();
            ssFormat.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.listDetects.append(NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ssFormat));
        }
    }
}

void SpecAbstract::Zip_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::ZIPINFO_STRUCT *pZipInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        if (pZipInfo->basic_info.id.fileType == XBinary::FT_ZIP) {
            pZipInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
            // TODO deep scan
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            if (xzip.isEncrypted()) {
                ss.sInfo = XBinary::appendComma(ss.sInfo, "Encrypted");
            }

            // TODO files
            pZipInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        } else if (pZipInfo->basic_info.id.fileType == XBinary::FT_APKS) {
            _SCANS_STRUCT ss = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, RECORD_TYPE_FORMAT, RECORD_NAME_ZIP, "", "", 0);

            ss.sVersion = xzip.getVersion();
            ss.sInfo = QString("%1 records").arg(xzip.getNumberOfRecords(pPdStruct));

            pZipInfo->basic_info.mapResultArchives.insert(ss.name, NFD_Binary::scansToScan(&(pZipInfo->basic_info), &ss));
        }
    }
}

void SpecAbstract::APK_handle_FixDetects(QIODevice *pDevice, SCAN_OPTIONS *pOptions, APKINFO_STRUCT *pApkInfo, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pOptions)

    XAPK xapk(pDevice);

    if (xapk.isValid(pPdStruct)) {
        if (pApkInfo->basic_info.scanOptions.bIsVerbose) {
            if (pApkInfo->basic_info.mapMetainfosDetects.count() == 0) {
                QString sDataManifest = xapk.decompress(&(pApkInfo->listArchiveRecords), "META-INF/MANIFEST.MF").data();

                QString sProtectedBy = XBinary::regExp("Protected-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sCreatedBy = XBinary::regExp("Created-By: (.*?)\n", sDataManifest, 1).remove("\r");
                QString sBuiltBy = XBinary::regExp("Built-By: (.*?)\n", sDataManifest, 1).remove("\r");

                if (sProtectedBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                    recordSS.sVersion = "Protected: " + sProtectedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sCreatedBy != "") && (sCreatedBy != "1.0 (Android)")) {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN1);
                    recordSS.sVersion = "Created: " + sCreatedBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if (sBuiltBy != "") {
                    _SCANS_STRUCT recordSS = {};

                    recordSS.type = RECORD_TYPE_PROTECTOR;
                    recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN2);
                    recordSS.sVersion = "Built: " + sBuiltBy;

                    pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                }

                if ((sProtectedBy != "") && (sCreatedBy != "") && (sBuiltBy != "")) {
                    if (sDataManifest.contains("-By")) {
                        _SCANS_STRUCT recordSS = {};

                        recordSS.type = RECORD_TYPE_PROTECTOR;
                        recordSS.name = (RECORD_NAME)(RECORD_NAME_UNKNOWN0);
                        recordSS.sVersion = "CHECK";

                        pApkInfo->basic_info.mapResultAPKProtectors.insert(recordSS.name, NFD_Binary::scansToScan(&(pApkInfo->basic_info), &recordSS));
                    }
                }
            }
        }
    }
}

SpecAbstract::DEXINFO_STRUCT SpecAbstract::APK_scan_DEX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::APKINFO_STRUCT *pApkInfo,
                                                        XBinary::PDSTRUCT *pPdStruct, const QString &sFileName)
{
    Q_UNUSED(pOptions)

    DEXINFO_STRUCT result = {};

    XZip xzip(pDevice);

    if (xzip.isValid(pPdStruct)) {
        QByteArray baRecordData = xzip.decompress(&(pApkInfo->listArchiveRecords), sFileName, pPdStruct);

        QBuffer buffer(&baRecordData);

        if (buffer.open(QIODevice::ReadOnly)) {
            result = NFD_DEX::getDEXInfo(&buffer, pApkInfo->basic_info.id, pOptions, 0, pPdStruct);

            buffer.close();
        }
    }

    return result;
}

void SpecAbstract::Binary_handle_FixDetects(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::BINARYINFO_STRUCT *pBinaryInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    if (pBinaryInfo->basic_info.mapResultFormats.contains(RECORD_NAME_PDF)) {
        pBinaryInfo->basic_info.mapResultTexts.clear();

        pBinaryInfo->basic_info.mapResultFormats[RECORD_NAME_PDF].id.fileType = XBinary::FT_BINARY;
        pBinaryInfo->basic_info.id.fileType = XBinary::FT_BINARY;
    }
}

// LX Microsoft-specific handling moved to NFD_LX::getInfo


// void SpecAbstract::fixDetects(SpecAbstract::PEINFO_STRUCT *pPEInfo)
//{
//     if(pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_MICROSOFTLINKER)&&pPEInfo->basic_info.mapHeaderDetects.contains(RECORD_NAME_GENERICLINKER))
//     {
//         pPEInfo->basic_info.mapHeaderDetects.remove(RECORD_NAME_MICROSOFTLINKER);
//     }

//    if(pPEInfo->_mapImportDetects.contains(RECORD_NAME_C)&&pPEInfo->_mapImportDetects.contains(RECORD_NAME_VISUALCPP))
//    {
//        pPEInfo->_mapImportDetects.remove(RECORD_NAME_VISUALCPP);
//    }

//    if(pPEInfo->basic_info.mapSpecialDetects.contains(RECORD_NAME_ENIGMA))
//    {
//        pPEInfo->basic_info.mapEntryPointDetects.remove(RECORD_NAME_BORLANDCPP);
//    }
//}

// moved: get_GCC_vi1 -> NFD_Binary
// moved: get_GCC_vi2 -> NFD_Binary
// moved: get_Nim_vi -> NFD_Binary
// moved: get_Zig_vi -> NFD_Binary

bool SpecAbstract::PE_isValid_UPX(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    bool bResult = false;

    if (pPEInfo->listSectionHeaders.count() >= 3) {
        // pPEInfo->listSections.at(0).SizeOfRawData!=0 dump file
        if ((pPEInfo->listSectionHeaders.at(0).SizeOfRawData == 0) && ((pPEInfo->nResourcesSection == -1) || (pPEInfo->nResourcesSection == 2))) {
            bResult = true;
        }
    }

    return bResult;
}

void SpecAbstract::PE_x86Emul(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo, XBinary::PDSTRUCT *pPdStruct)
{
    XBinary binary(pDevice, pOptions->bIsImage);

    XADDR nAddress = pPEInfo->nImageBaseAddress + pPEInfo->nEntryPointAddress;

    QString sSignature;

    bool bSuccess = true;
    bool bVMProtect = true;

    qint32 nCount = 10;

    for (qint32 i = 0; (i < nCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        qint64 nOffset = XBinary::addressToOffset(&(pPEInfo->basic_info.memoryMap), nAddress);

        if (nOffset == -1) {
            bSuccess = false;
            break;
        }

        quint8 nByte = binary.read_uint8(nOffset);
        nAddress++;
        nOffset++;

        if (nByte == 0x9c)  // pushf
        {
            sSignature += "9C";
        } else if (nByte == 0x60)  // pusha
        {
            sSignature += "60";
        } else if (nByte == 0xe9)  // jmp ..
        {
            sSignature += "E9$$$$$$$$";
            nAddress += (4 + binary.read_int32(nOffset));
        } else if (nByte == 0xe8)  // call ..
        {
            sSignature += "E8$$$$$$$$";
            nAddress += (4 + binary.read_int32(nOffset));
        } else if (nByte == 0x68)  // push ..
        {
            sSignature += "68........";
            nAddress += 4;
        } else if (nByte == 0x53)  // push ebx
        {
            sSignature += "53";
        } else if (nByte == 0xC7)  // mov DWORD PTR [reg+],imm
        {
            sSignature += "C7";
            quint8 nMODRM = binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if ((nMODRM == 0x04) || (nMODRM == 0x44)) {
                sSignature += XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB = binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if (nSIB == 0x24)  // ESP+
                {
                    sSignature += "24";

                    if (nMODRM == 0x44) {
                        //                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature += "..";

                        nAddress++;
                        nOffset++;
                    }

                    sSignature += "........";

                    nAddress += 4;
                    nOffset += 4;
                } else {
                    bVMProtect = false;
                }
            } else {
                bVMProtect = false;
            }
        } else if (nByte == 0x8D)  // lea esp,dword ptr[esp+]
        {
            sSignature += "8D";
            quint8 nMODRM = binary.read_uint8(nOffset);

            nAddress++;
            nOffset++;

            if (nMODRM == 0x64) {
                sSignature += XBinary::valueToHex(nMODRM).toUpper();
                quint8 nSIB = binary.read_uint8(nOffset);

                nAddress++;
                nOffset++;

                if (nSIB == 0x24)  // ESP+
                {
                    sSignature += "24";

                    if (nMODRM == 0x64) {
                        //                        quint8 nDISP=binary.read_uint8(nOffset);

                        sSignature += "..";

                        nAddress++;
                        nOffset++;
                    }
                } else {
                    bVMProtect = false;
                }
            } else {
                bVMProtect = false;
            }
        } else {
            bVMProtect = false;
        }

        if (!bVMProtect) {
            break;
        }
    }

    if (!bSuccess) {
        bVMProtect = false;
    }
}

SpecAbstract::VI_STRUCT SpecAbstract::PE_get_PECompact_vi(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, SpecAbstract::PEINFO_STRUCT *pPEInfo)
{
    Q_UNUSED(pDevice)
    Q_UNUSED(pOptions)

    VI_STRUCT result = {};

    if (pPEInfo->listSectionHeaders.count() >= 2) {
        if (pPEInfo->listSectionHeaders.at(0).PointerToRelocations == 0x32434550) {
            result.bIsValid = true;

            quint32 nBuildNumber = pPEInfo->listSectionHeaders.at(0).PointerToLinenumbers;

            // TODO !!! more build versions
            switch (nBuildNumber) {
                case 20206: result.sVersion = "2.70"; break;
                case 20240: result.sVersion = "2.78a"; break;
                case 20243: result.sVersion = "2.79b1"; break;
                case 20245: result.sVersion = "2.79bB"; break;
                case 20247: result.sVersion = "2.79bD"; break;
                case 20252: result.sVersion = "2.80b1"; break;
                case 20256: result.sVersion = "2.80b5"; break;
                case 20261: result.sVersion = "2.82"; break;
                case 20285: result.sVersion = "2.92.0"; break;
                case 20288: result.sVersion = "2.93b3"; break;
                case 20294: result.sVersion = "2.96.2"; break;
                case 20295: result.sVersion = "2.97b1"; break;
                case 20296: result.sVersion = "2.98"; break;
                case 20300: result.sVersion = "2.98.04"; break;
                case 20301: result.sVersion = "2.98.05"; break;
                case 20302: result.sVersion = "2.98.06"; break;
                case 20303: result.sVersion = "2.99b"; break;
                case 20308: result.sVersion = "3.00.2"; break;
                case 20312: result.sVersion = "3.01.3"; break;
                case 20317: result.sVersion = "3.02.1"; break;
                case 20318: result.sVersion = "3.02.2"; break;
                case 20323: result.sVersion = "3.03.5b"; break;
                case 20327: result.sVersion = "3.03.9b"; break;
                case 20329: result.sVersion = "3.03.10b"; break;
                case 20334: result.sVersion = "3.03.12b"; break;
                case 20342: result.sVersion = "3.03.18b"; break;
                case 20343: result.sVersion = "3.03.19b"; break;
                case 20344: result.sVersion = "3.03.20b"; break;
                case 20345: result.sVersion = "3.03.21b"; break;
                case 20348: result.sVersion = "3.03.23b"; break;
                default: {
                    if (nBuildNumber > 20308) {
                        result.sVersion = QString("3.X(build %1)").arg(nBuildNumber);
                    } else if (nBuildNumber == 0) {
                        result.sVersion = "2.20-2.68";
                    } else {
                        result.sVersion = QString("2.X(build %1)").arg(nBuildNumber);
                    }
                }
            }

            //                            qDebug("nVersion: %d",nVersion);
        }
    }

    return result;
}

QList<XScanEngine::SCANSTRUCT> SpecAbstract::convert(QList<SCAN_STRUCT> *pListScanStructs)
{
    QList<XScanEngine::SCANSTRUCT> listResult;

    qint32 nNumberOfRecords = pListScanStructs->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::SCANSTRUCT record = {};

        record.bIsHeuristic = pListScanStructs->at(i).bIsHeuristic;
        record.bIsUnknown = pListScanStructs->at(i).bIsUnknown;
        record.id = pListScanStructs->at(i).id;
        record.parentId = pListScanStructs->at(i).parentId;
        record.nType = pListScanStructs->at(i).type;
        record.nName = pListScanStructs->at(i).name;
        record.sType = recordTypeIdToString(pListScanStructs->at(i).type);
        record.sName = recordNameIdToString(pListScanStructs->at(i).name);
        record.sVersion = pListScanStructs->at(i).sVersion;
        record.sInfo = pListScanStructs->at(i).sInfo;

        record.globalColorRecord = typeToGlobalColorRecord(record.sType);
        record.nPrio = typeToPrio(record.sType);
        record.bIsProtection = isProtection(record.sType);
        record.sType = translateType(record.sType);

        listResult.append(record);
    }

    // XFormats::sortRecords(&listResult); // TODO Check

    return listResult;
}

QList<XScanEngine::DEBUG_RECORD> SpecAbstract::convertHeur(QList<DETECT_RECORD> *pListDetectRecords)
{
    QList<XScanEngine::DEBUG_RECORD> listResult;

    qint32 nNumberOfRecords = pListDetectRecords->count();

    for (qint32 i = 0; i < nNumberOfRecords; i++) {
        XScanEngine::DEBUG_RECORD record = {};

        record.sType = XScanEngine::heurTypeIdToString(pListDetectRecords->at(i).detectType);
        record.sName = QString("%1(%2)[%3]")
                           .arg(SpecAbstract::recordNameIdToString(pListDetectRecords->at(i).name), pListDetectRecords->at(i).sVersion, pListDetectRecords->at(i).sInfo);
        record.sValue = pListDetectRecords->at(i).sValue;

        listResult.append(record);
    }

    return listResult;
}

// MSDOS_compareRichRecord moved to NFD_MSDOS

void SpecAbstract::filterResult(QList<SpecAbstract::SCAN_STRUCT> *pListRecords, const QSet<SpecAbstract::RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct)
{
    QList<SpecAbstract::SCAN_STRUCT> listRecords;
    qint32 nNumberOfRecords = pListRecords->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        if (stRecordTypes.contains((RECORD_TYPE)pListRecords->at(i).type)) {
            listRecords.append(pListRecords->at(i));
        }
    }

    *pListRecords = listRecords;
}

void SpecAbstract::_fixRichSignatures(QList<_SCANS_STRUCT> *pListRichSignatures, qint32 nMajorLinkerVersion, qint32 nMinorLinkerVersion, XBinary::PDSTRUCT *pPdStruct)
{
    Q_UNUSED(nMajorLinkerVersion)

    qint32 nNumberOfRecords = pListRichSignatures->count();

    for (qint32 i = 0; (i < nNumberOfRecords) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
        QString sMajor = pListRichSignatures->at(i).sVersion.section(".", 0, 0);
        QString sBuild = pListRichSignatures->at(i).sVersion.section(".", 2, 2);

        qint32 nBuild = sBuild.toInt();
        qint32 nMinorVersion = 0;

        bool bFix = false;

        if (nBuild > 25000) {
            if ((pListRichSignatures->at(i).name == RECORD_NAME_UNIVERSALTUPLECOMPILER) && (sMajor.toInt() >= 19)) {
                bFix = true;  // C++
            } else if (sMajor.toInt() >= 14) {
                if (pListRichSignatures->at(i).name == RECORD_NAME_MICROSOFTLINKER) {
                    if ((nMinorLinkerVersion >= 10) && (nMinorLinkerVersion <= 40)) {
                        nMinorVersion = nMinorLinkerVersion;
                    }
                }

                bFix = true;  // Linker, MASM ...
            }
        }

        if (bFix) {
            if (nMinorVersion == 0) {
                if (nBuild < 25506) nMinorVersion = 10;
                else if (nBuild < 25830) nMinorVersion = 11;
                else if (nBuild < 26128) nMinorVersion = 12;
                else if (nBuild < 26428) nMinorVersion = 13;
                else if (nBuild < 26726) nMinorVersion = 14;
                else if (nBuild < 26926) nMinorVersion = 15;
                else if (nBuild < 27508) nMinorVersion = 16;
                else if (nBuild < 27702) nMinorVersion = 20;
                else if (nBuild < 27905) nMinorVersion = 21;
                else if (nBuild < 28105) nMinorVersion = 22;
                else if (nBuild < 28314) nMinorVersion = 23;
                else if (nBuild < 28610) nMinorVersion = 24;
                else if (nBuild < 28805) nMinorVersion = 25;
                else if (nBuild < 29110) nMinorVersion = 26;
                else if (nBuild < 29333) nMinorVersion = 27;
                else if (nBuild < 30133) nMinorVersion = 28;
                else if (nBuild < 30401) nMinorVersion = 29;
                else if (nBuild < 30818) nMinorVersion = 30;
                else if (nBuild < 31114) nMinorVersion = 31;
                else if (nBuild < 31424) nMinorVersion = 32;
                else if (nBuild < 31721) nMinorVersion = 33;
                else if (nBuild < 32019) nMinorVersion = 34;
                else if (nBuild < 32323) nMinorVersion = 35;
                else if (nBuild >= 32323) nMinorVersion = 36;
            }

            (*pListRichSignatures)[i].sVersion = QString("%1.%2.%3").arg(sMajor, QString::number(nMinorVersion), sBuild);
        }
    }
}

void SpecAbstract::_processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                  XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct)
{
    BASIC_INFO basic_info = {};

    if ((fileType == XBinary::FT_PE32) || (fileType == XBinary::FT_PE64)) {
        SpecAbstract::PEINFO_STRUCT pe_info = SpecAbstract::getPEInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pe_info.basic_info;
    } else if ((fileType == XBinary::FT_ELF32) || (fileType == XBinary::FT_ELF64)) {
        SpecAbstract::ELFINFO_STRUCT elf_info = NFD_ELF::getELFInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = elf_info.basic_info;
    } else if ((fileType == XBinary::FT_MACHO32) || (fileType == XBinary::FT_MACHO64)) {
        SpecAbstract::MACHOINFO_STRUCT mach_info = NFD_MACH::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = mach_info.basic_info;
    } else if (fileType == XBinary::FT_LE) {
        SpecAbstract::LEINFO_STRUCT le_info = NFD_LE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = le_info.basic_info;
    } else if (fileType == XBinary::FT_LX) {
        SpecAbstract::LXINFO_STRUCT lx_info = NFD_LX::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = lx_info.basic_info;
    } else if (fileType == XBinary::FT_NE) {
        SpecAbstract::NEINFO_STRUCT ne_info = NFD_NE::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = ne_info.basic_info;
    } else if (fileType == XBinary::FT_MSDOS) {
        SpecAbstract::MSDOSINFO_STRUCT msdos_info = NFD_MSDOS::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = msdos_info.basic_info;
    } else if (fileType == XBinary::FT_JAR) {
        SpecAbstract::JARINFO_STRUCT jar_info = NFD_JAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jar_info.basic_info;
    } else if (fileType == XBinary::FT_APK) {
        SpecAbstract::APKINFO_STRUCT apk_info = NFD_APK::getAPKInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = apk_info.basic_info;
    } else if ((fileType == XBinary::FT_ZIP) || (fileType == XBinary::FT_IPA)) {
        // mb TODO split detects
        SpecAbstract::ZIPINFO_STRUCT zip_info = SpecAbstract::getZIPInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = zip_info.basic_info;
    } else if (fileType == XBinary::FT_RAR) {
        SpecAbstract::RARINFO_STRUCT rar_info = NFD_RAR::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = rar_info.basic_info;
    } else if (fileType == XBinary::FT_JAVACLASS) {
        SpecAbstract::JAVACLASSINFO_STRUCT javaclass_info = NFD_JavaClass::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = javaclass_info.basic_info;
    } else if (fileType == XBinary::FT_DEX) {
        SpecAbstract::DEXINFO_STRUCT dex_info = NFD_DEX::getDEXInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = dex_info.basic_info;
    } else if (fileType == XBinary::FT_AMIGAHUNK) {
        SpecAbstract::AMIGAHUNKINFO_STRUCT amigaHunk_info = NFD_Amiga::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = amigaHunk_info.basic_info;
    } else if (fileType == XBinary::FT_PDF) {
        SpecAbstract::PDFINFO_STRUCT pdf_info = NFD_PDF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = pdf_info.basic_info;
    } else if (fileType == XBinary::FT_JPEG) {
        SpecAbstract::JPEGINFO_STRUCT jpeg_info = NFD_JPEG::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = jpeg_info.basic_info;
    } else if (fileType == XBinary::FT_CFBF) {
        SpecAbstract::CFBFINFO_STRUCT cfbf_info = NFD_CFBF::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = cfbf_info.basic_info;
    } else if (fileType == XBinary::FT_COM) {
        SpecAbstract::COMINFO_STRUCT com_info = NFD_COM::getInfo(pDevice, parentId, pScanOptions, 0, pPdStruct);
        basic_info = com_info.basic_info;
    } else {
        SpecAbstract::BINARYINFO_STRUCT binary_info = SpecAbstract::getBinaryInfo(pDevice, fileType, parentId, pScanOptions, 0, pPdStruct);
        basic_info = binary_info.basic_info;
    }

    if (bAddUnknown) {
        if (!basic_info.listDetects.count()) {
            _SCANS_STRUCT ssUnknown = {};

            ssUnknown.type = SpecAbstract::RECORD_TYPE_UNKNOWN;
            ssUnknown.name = SpecAbstract::RECORD_NAME_UNKNOWN;
            ssUnknown.bIsUnknown = true;

            basic_info.listDetects.append(NFD_Binary::scansToScan(&basic_info, &ssUnknown));
        }
    }

    QList<XScanEngine::SCANSTRUCT> listScanStructs = convert(&(basic_info.listDetects));

    if (pScanOptions->bIsSort) {
        sortRecords(&listScanStructs);
    }

    pScanResult->listRecords.append(listScanStructs);
    pScanResult->listDebugRecords.append(convertHeur(&(basic_info.listHeurs)));

    if (pScanID) {
        *pScanID = basic_info.id;
    }
}

QList<SpecAbstract::VCL_STRUCT> SpecAbstract::PE_getVCLstruct(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, qint64 nSize, bool bIs64,
                                                              XBinary::PDSTRUCT *pPdStruct)
{
    QList<VCL_STRUCT> listResult;

    XPE pe(pDevice, pOptions->bIsImage);

    qint64 _nOffset = nOffset;
    qint64 _nSize = nSize;

    qint32 nAddressSize = bIs64 ? 8 : 4;

    while ((_nSize > 0) && (XBinary::isPdStructNotCanceled(pPdStruct))) {
        qint64 nClassOffset = pe.find_array(_nOffset, _nSize, "\x07\x08\x54\x43\x6f\x6e\x74\x72\x6f\x6c", 10, pPdStruct);  // 0708'TControl'

        if (nClassOffset == -1) {
            break;
        }

        quint32 nDword = pe.read_uint32(nClassOffset + 10);
        qint64 nClassOffset2 = pe.addressToOffset(nDword);

        if (nClassOffset2 != -1) {
            for (qint32 i = 0; (i < 20) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
                quint32 nValue = pe.read_uint32(nClassOffset2 - nAddressSize * (i + 1));

                if (nValue <= 0xFFFF) {
                    VCL_STRUCT record = {};

                    record.nValue = nValue;
                    record.nOffset = nAddressSize * (i + 1);
                    record.bIs64 = bIs64;

                    listResult.append(record);

                    break;
                }
            }
        }

        qint64 nDelta = (nClassOffset - _nOffset) + 1;

        _nOffset += nDelta;
        _nSize -= nDelta;
    }

    return listResult;
}

SpecAbstract::VCL_PACKAGEINFO SpecAbstract::PE_getVCLPackageInfo(QIODevice *pDevice, XScanEngine::SCAN_OPTIONS *pOptions, QList<XPE::RESOURCE_RECORD> *pListResources,
                                                                 XBinary::PDSTRUCT *pPdStruct)
{
    VCL_PACKAGEINFO result = {};

    XPE pe(pDevice, pOptions->bIsImage);

    if (pe.isValid(pPdStruct)) {
        XPE::RESOURCE_RECORD rh = pe.getResourceRecord(10, "PACKAGEINFO", pListResources);

        if ((rh.nOffset != -1) && (rh.nSize)) {
            qint64 nOffset = rh.nOffset;
            quint32 nFlags = pe.read_uint32(nOffset);

            quint32 _nFlags = nFlags & 0xFF00;

            if (_nFlags == 0) {
                result.nFlags = nFlags;
                nOffset += 4;
                result.nUnknown = pe.read_uint32(nOffset);

                if (result.nUnknown == 0) {
                    nOffset += 4;
                    result.nRequiresCount = pe.read_uint32(nOffset);
                    nOffset += 4;
                } else {
                    nOffset += 3;
                }

                qint32 nCount = result.nRequiresCount ? result.nRequiresCount : 1000;

                for (qint32 i = 0; (i < nCount) && (XBinary::isPdStructNotCanceled(pPdStruct)); i++) {
                    if (nOffset - rh.nOffset > rh.nSize) {
                        break;
                    }

                    VCL_PACKAGEINFO_MODULE vpm = VCL_PACKAGEINFO_MODULE();
                    vpm.nFlags = pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.nHashCode = pe.read_uint8(nOffset);
                    nOffset++;
                    vpm.sName = pe.read_ansiString(nOffset);
                    nOffset += vpm.sName.length() + 1;

                    result.listModules.append(vpm);
                }
            }
        }
    }

    return result;
}
