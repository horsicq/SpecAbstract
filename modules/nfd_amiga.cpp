#include "nfd_amiga.h"

NFD_Amiga::NFD_Amiga(XAmigaHunk *pAmiga, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : Amiga_Script(pAmiga, filePart, pOptions, pPdStruct) {}

NFD_Binary::SCANS_STRUCT NFD_Amiga::detectOperationSystem(XBinary::PDSTRUCT *pPdStruct)
{
    // // Use the underlying Amiga object to get file format info and map to OS record
    // XAmigaHunk *pAmiga = getAmiga();
    // XBinary::FILEFORMATINFO ffi = pAmiga->getFileFormatInfo(pPdStruct);
    // // Build via SpecAbstract helper, then copy fields into NFD structure (layout is identical)
    // SpecAbstract::_SCANS_STRUCT ss = SpecAbstract::getOperationSystemScansStruct(ffi);
    // NFD_Binary::SCANS_STRUCT result = {};
    // result.nOffset = ss.nOffset;
    // result.nVariant = ss.nVariant;
    // result.fileType = ss.fileType;
    // result.type = ss.type;
    // result.name = ss.name;
    // result.sVersion = ss.sVersion;
    // result.sInfo = ss.sInfo;
    // result.bIsHeuristic = ss.bIsHeuristic;
    // result.bIsUnknown = ss.bIsUnknown;
    // result.varExtra = ss.varExtra;
    // return result;

    NFD_Binary::SCANS_STRUCT result = {};
    return result;
}
