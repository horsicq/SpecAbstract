#ifndef NFD_JAVACLASS_H
#define NFD_JAVACLASS_H

#include "javaclass_script.h"

class NFD_JavaClass : public JavaClass_Script {
    Q_OBJECT

public:
    explicit NFD_JavaClass(XJavaClass *pJavaClass, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // NFD_JAVACLASS_H
