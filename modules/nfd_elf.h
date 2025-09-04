#ifndef NFD_ELF_H
#define NFD_ELF_H

#include "elf_script.h"
#include "nfd_binary.h"

class QIODevice;

class NFD_ELF : public ELF_Script {
    Q_OBJECT

public:
    explicit NFD_ELF(XELF *pELF, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);

    struct ELFINFO_STRUCT {
        NFD_Binary::BASIC_INFO basic_info;
        QString sEntryPointSignature;
        bool bIs64;
        bool bIsBigEndian;

        QList<XELF::TAG_STRUCT> listTags;
        QList<QString> listLibraries;
        QList<QString> listComments;
        QList<XELF_DEF::Elf_Shdr> listSectionHeaders;
        QList<XELF_DEF::Elf_Phdr> listProgramHeaders;
        QList<XELF::SECTION_RECORD> listSectionRecords;
        QList<XELF::NOTE> listNotes;

        qint32 nSymTabSection;
        qint64 nSymTabOffset;
        qint32 nDebugSection;
        qint64 nDWARFDebugOffset;
        qint64 nDWARFDebugSize;

        qint32 nCommentSection;
        qint32 nStringTableSection;
        QByteArray baStringTable;
        QString sRunPath;

        XBinary::OFFSETSIZE osCommentSection;
    };

    static ELFINFO_STRUCT getInfo(QIODevice *pDevice, XScanEngine::SCANID parentId, XScanEngine::SCAN_OPTIONS *pOptions, qint64 nOffset, XBinary::PDSTRUCT *pPdStruct);

    // SIGNATURE_RECORD based tables (migrated from SpecAbstract/signatures.cpp)
    static NFD_Binary::SIGNATURE_RECORD *getEntrypointRecords();
    static qint32 getEntrypointRecordsSize();
};

#endif  // NFD_ELF_H
