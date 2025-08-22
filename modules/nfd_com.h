#ifndef NFD_COM_H
#define NFD_COM_H

#include "com_script.h"

class NFD_COM : public COM_Script {
    Q_OBJECT

public:
    explicit NFD_COM(XCOM *pCOM, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_COM_H
