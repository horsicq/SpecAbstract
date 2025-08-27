#include "nfd_javaclass.h"

NFD_JavaClass::NFD_JavaClass(XJavaClass *pJavaClass, XBinary::FILEPART filePart, OPTIONS *pOptions, XBinary::PDSTRUCT *pPdStruct)
    : JavaClass_Script(pJavaClass, filePart, pOptions, pPdStruct)
{
}
