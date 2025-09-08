/* Copyright (c) 2019-2025 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "nfd_text.h"

// Text header regex-based detections (migrated from SpecAbstract/signatures.cpp)
static NFD_Binary::STRING_RECORD g_TEXT_Exp_records[] = {
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_CCPP, "", ""}, "#include [\"<].*?[>\"]"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_CCPP, "", "header"}, "#ifndef (\\w+).*\\s+#define \\1"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_HTML, "", ""}, "^<(!DOCTYPE )?[Hh][Tt][Mm][Ll]"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_PHP, "", ""}, "^<\\?php"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_PYTHON, "", ""}, "import"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_XML, "", ""}, "^<\\?xml"},
    {{0, XBinary::FT_TEXT, XScanEngine::RECORD_TYPE_SOURCECODE, XScanEngine::RECORD_NAME_SHELL, "", ""}, "#!"},
};

NFD_Binary::STRING_RECORD *NFD_TEXT::getTextExpRecords()
{
    return g_TEXT_Exp_records;
}

qint32 NFD_TEXT::getTextExpRecordsSize()
{
    return sizeof(g_TEXT_Exp_records);
}
