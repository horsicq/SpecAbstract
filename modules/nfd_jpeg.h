#ifndef NFD_JPEG_H
#define NFD_JPEG_H

#include "jpeg_script.h"

class NFD_JPEG : public Jpeg_Script {
    Q_OBJECT
public:
    explicit NFD_JPEG(XJpeg *pJpeg, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JPEG_H
