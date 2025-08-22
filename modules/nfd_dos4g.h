#ifndef NFD_DOS4G_H
#define NFD_DOS4G_H

#include "dos4g_script.h"

class NFD_DOS4G : public DOS4G_Script {
    Q_OBJECT

public:
    explicit NFD_DOS4G(XDOS16 *pXdos16, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_DOS4G_H
