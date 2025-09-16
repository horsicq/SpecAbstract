/* Copyright (c) 2017-2025 hors<horsicq@gmail.com>
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
#ifndef SPECABSTRACT_H
#define SPECABSTRACT_H

#ifndef USE_ARCHIVE
#define USE_ARCHIVE
#endif
#ifndef USE_DEX
#define USE_DEX
#endif
#ifndef USE_PDF
#define USE_PDF
#endif

#include "xscanengine.h"
#include "modules/nfd_binary.h"
#include "modules/nfd_amiga.h"
#include "modules/nfd_jpeg.h"
#include "modules/nfd_cfbf.h"
#include "modules/nfd_pdf.h"
#include "modules/nfd_elf.h"
#include "modules/nfd_com.h"
#include "modules/nfd_msdos.h"
// Newly delegated NFD modules
#include "modules/nfd_javaclass.h"
#include "modules/nfd_rar.h"
#include "modules/nfd_le.h"
#include "modules/nfd_lx.h"
#include "modules/nfd_ne.h"
#include "modules/nfd_dex.h"
#include "modules/nfd_zip.h"
#include "modules/nfd_jar.h"
#include "modules/nfd_apk.h"
#include "modules/nfd_machofat.h"
#include "modules/nfd_mach.h"
#include "modules/nfd_pe.h"

class SpecAbstract : public XScanEngine {
    Q_OBJECT

public:
    explicit SpecAbstract(QObject *pParent = nullptr);

private:
    // MSDOS_compareRichRecord moved into NFD_MSDOS
    static void filterResult(QList<NFD_Binary::SCAN_STRUCT> *pListRecords, const QSet<RECORD_TYPE> &stRecordTypes, XBinary::PDSTRUCT *pPdStruct);

protected:
    virtual void _processDetect(XScanEngine::SCANID *pScanID, XScanEngine::SCAN_RESULT *pScanResult, QIODevice *pDevice, const XScanEngine::SCANID &parentId,
                                XBinary::FT fileType, XScanEngine::SCAN_OPTIONS *pScanOptions, bool bAddUnknown, XBinary::PDSTRUCT *pPdStruct);
};

#endif  // SPECABSTRACT_H
