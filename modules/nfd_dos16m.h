#ifndef NFD_DOS16M_H
#define NFD_DOS16M_H

#include "dos16m_script.h"

class NFD_DOS16M : public DOS16M_Script {
    Q_OBJECT

public:
    explicit NFD_DOS16M(XDOS16 *pXdos16, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_DOS16M_H
