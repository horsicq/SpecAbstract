#include "nfd_text.h"

// Text header regex-based detections (migrated from SpecAbstract/signatures.cpp)
static NFD_Binary::STRING_RECORD g_TEXT_Exp_records[] =
{
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_CCPP,                         "",                 ""},                    "#include [\"<].*?[>\"]"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_CCPP,                         "",                 "header"},              "#ifndef (\\w+).*\\s+#define \\1"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_HTML,                         "",                 ""},                    "^<(!DOCTYPE )?[Hh][Tt][Mm][Ll]"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_PHP,                          "",                 ""},                    "^<\\?php"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_PYTHON,                       "",                 ""},                    "import"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_XML,                          "",                 ""},                    "^<\\?xml"},
    {{0, XBinary::FT_TEXT,      XScanEngine::RECORD_TYPE_SOURCECODE,       XScanEngine::RECORD_NAME_SHELL,                        "",                 ""},                    "#!"},
};

NFD_Binary::STRING_RECORD *NFD_TEXT::getTextExpRecords()
{
    return g_TEXT_Exp_records;
}

qint32 NFD_TEXT::getTextExpRecordsSize()
{
    return sizeof(g_TEXT_Exp_records);
}
