#ifndef NFD_IMAGE_H
#define NFD_IMAGE_H

#include "image_script.h"

class NFD_IMAGE : public Image_Script {
    Q_OBJECT
public:
    explicit NFD_IMAGE(XBinary *pImage, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_IMAGE_H
