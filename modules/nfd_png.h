#ifndef NFD_PNG_H
#define NFD_PNG_H

#include "png_script.h"

class NFD_PNG : public PNG_Script {
    Q_OBJECT
public:
    explicit NFD_PNG(XPNG *pPNG, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_PNG_H
