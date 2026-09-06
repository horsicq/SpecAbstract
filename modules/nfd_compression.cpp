/* SPDX-License-Identifier: MIT */
#include "nfd_compression.h"

#include "xancientdecoder.h"
#include "xlzmadecoder.h"

#include <QBuffer>
#include <QtEndian>

namespace {
const qint64 MAX_PACKED = 4 * 1024 * 1024;
const qint64 MAX_OUTPUT = 16 * 1024 * 1024;
const qint64 MAX_DECODER_MEMORY = 32 * 1024 * 1024;

class DiscardDevice : public QIODevice {
protected:
    qint64 readData(char *, qint64) override { return -1; }
    qint64 writeData(const char *, qint64 size) override
    {
        if (size < 0 || size > MAX_OUTPUT - m_count) return -1;
        m_count += size;
        return size;
    }
private:
    qint64 m_count = 0;
};

bool add(NFD_Binary::BINARYINFO_STRUCT *info, XScanEngine::RECORD_NAME name, const QString &customName, const QString &detail)
{
    info->basic_info.id.fileType = XBinary::FT_ARCHIVE;
    NFD_Binary::SCANS_STRUCT record = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, name, QString(), detail, 0);
    record.sName = customName;
    info->basic_info.mapResultArchives.insert(name, NFD_Binary::scansToScan(&info->basic_info, &record));
    return true;
}

// Reads the PowerPacker stream backwards, advancing the shared cursor/bit pair.
struct BitReader {
    BitReader(const QByteArray &data, int &cursor, int &bit) : data(data), cursor(cursor), bit(bit) {}
    bool operator()(quint32 count, quint32 &value)
    {
        value = 0;
        for (quint32 i = 0; i < count; ++i) {
            if (cursor < 8) return false;
            value = (value << 1) | ((static_cast<quint8>(data.at(cursor)) >> bit) & 1U);
            if (++bit == 8) { bit = 0; --cursor; }
        }
        return true;
    }
    const QByteArray &data;
    int &cursor;
    int &bit;
};

bool powerPacker(const QByteArray &data, NFD_Binary::BINARYINFO_STRUCT *info, XBinary::PDSTRUCT *pd)
{
    if (data.size() < 13 || !data.startsWith("PP20")) return false;
    const quint32 mode = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + 4));
    if (mode != 0x09090909 && mode != 0x090a0a0a && mode != 0x090a0b0b && mode != 0x090a0c0c && mode != 0x090a0c0d) return false;
    const quint32 trailer = qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + data.size() - 4));
    const quint32 outputSize = trailer >> 8;
    if (!outputSize || outputSize > static_cast<quint64>(MAX_OUTPUT) || (trailer & 0xff) > 31) return false;
    int cursor = data.size() - 5;
    int bit = 0;
    BitReader readBits(data, cursor, bit);
    quint32 value = 0;
    if (!readBits(trailer & 0xff, value)) return false;
    quint32 produced = 0;
    // Validate the backward bitstream without reconstructing its bytes. A
    // reference is legal only when its source has already been produced.
    while (produced < outputSize) {
        if (!XBinary::isPdStructNotCanceled(pd) || !readBits(1, value)) return false;
        if (!value) {
            quint32 count = 1;
            do {
                if (!readBits(2, value) || value > outputSize - produced - count) return false;
                count += value;
            } while (value == 3);
            for (quint32 i = 0; i < count; ++i) if (!readBits(8, value)) return false;
            produced += count;
            if (produced == outputSize) break;
        }
        quint32 modeIndex = 0, distance = 0, count = 0;
        if (!readBits(2, modeIndex)) return false;
        quint32 width = static_cast<quint8>(data.at(4 + static_cast<int>(modeIndex)));
        if (modeIndex == 3) {
            if (!readBits(1, value)) return false;
            if (!value) width = 7;
            if (!readBits(width, distance)) return false;
            count = 5;
            if (count > outputSize - produced) return false;
            do {
                if (!readBits(3, value) || value > outputSize - produced - count) return false;
                count += value;
            } while (value == 7);
        } else {
            count = modeIndex + 2;
            if (!readBits(width, distance) || count > outputSize - produced) return false;
        }
        if (distance >= produced) return false;
        produced += count;
    }
    // Only alignment bits may precede the consumed stream.
    if ((cursor - 7) * 8 - bit > 31 || !XBinary::isPdStructNotCanceled(pd)) return false;
    return add(info, XScanEngine::RECORD_NAME_UNKNOWN, "PowerPacker (PP20)",
               QString("bitstream structure verified, %1 bytes unpacked").arg(outputSize));
}

bool ancient(const QByteArray &data, NFD_Binary::BINARYINFO_STRUCT *info, XBinary::PDSTRUCT *pd)
{
    const XAncientDecoder::TYPE type = XAncientDecoder::identify(data);
    const bool rnc = type == XAncientDecoder::TYPE_RNC;
    if (!rnc && type != XAncientDecoder::TYPE_TPWM && type != XAncientDecoder::TYPE_UNIX_PACK && type != XAncientDecoder::TYPE_FREEZE) return false;
    XAncientDecoder::INFO description;
    if (!XAncientDecoder::describe(data, type, &description) || (rnc && description.packedSize != data.size()) ||
        description.rawSize <= 0 || description.rawSize > MAX_OUTPUT || description.imageSize > MAX_OUTPUT || !XBinary::isPdStructNotCanceled(pd)) return false;
    QByteArray raw;
    if (!XAncientDecoder::decode(data, type, &raw, &description, nullptr, true) || raw.size() != description.rawSize ||
        !XBinary::isPdStructNotCanceled(pd)) return false;
    if (description.packedSize <= 0 || description.packedSize > data.size()) return false;
    const qint64 trailingSize = data.size() - description.packedSize;
    if (type == XAncientDecoder::TYPE_TPWM && trailingSize) return false;
    // The pack backend permits encoder padding after its consumed stream.
    // Keep that allowance small and report it rather than validating the tail.
    if (type == XAncientDecoder::TYPE_UNIX_PACK && trailingSize > 16) return false;
    const QString name = rnc ? "RNC" : type == XAncientDecoder::TYPE_TPWM ? "TPWM" : type == XAncientDecoder::TYPE_UNIX_PACK ? "pack" : "Freeze";
    QString detail = description.method + QString(", decoded stream verified, %1 bytes unpacked").arg(raw.size());
    if (trailingSize) detail += QString(", %1 trailing bytes permitted as pack padding").arg(trailingSize);
    return add(info, XScanEngine::RECORD_NAME_UNKNOWN, name, detail);
}

bool lzma(const QByteArray &data, NFD_Binary::BINARYINFO_STRUCT *info, XBinary::PDSTRUCT *pd)
{
    if (data.size() < 18 || static_cast<quint8>(data.at(0)) >= 225 || data.at(13) != 0) return false;
    const quint32 dictionary = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + 1));
    // LZMA-alone has no magic. Use plausible encoder dictionaries only as a
    // prefilter; a complete stream decode below is required for recognition.
    if (dictionary < 4096 || dictionary > static_cast<quint64>(MAX_OUTPUT) ||
        ((dictionary & (dictionary - 1)) && (dictionary < 3 * 1024 * 1024 || (dictionary & 0xfffff)))) return false;
    const quint64 declared = qFromLittleEndian<quint64>(reinterpret_cast<const uchar *>(data.constData() + 5));
    const bool unknownSize = declared == Q_UINT64_C(0xffffffffffffffff);
    if (!unknownSize && declared > static_cast<quint64>(MAX_OUTPUT)) return false;
    const QByteArray properties = data.left(5);
    qint64 memory = 0;
    if (!XLZMADecoder::getMemoryRequirement(properties, &memory, pd) || memory > MAX_DECODER_MEMORY || !XBinary::isPdStructNotCanceled(pd)) return false;

    QBuffer input;
    input.setData(data.mid(13));
    DiscardDevice output;
    if (!input.open(QIODevice::ReadOnly) || !output.open(QIODevice::WriteOnly)) return false;
    XBinary::DATAPROCESS_STATE state = {};
    state.pDeviceInput = &input;
    state.pDeviceOutput = &output;
    state.nInputLimit = input.size();
    state.nProcessedLimit = -1;
    // This existing policy also bounds the decoder's transient reservations.
    state.mapUnpackProperties.insert(XBinary::UNPACK_PROP_MAX_OUTPUT_SIZE, MAX_DECODER_MEMORY);
    if (!unknownSize) state.mapProperties.insert(XBinary::FPART_PROP_UNCOMPRESSEDSIZE, static_cast<qint64>(declared));
    if (!XLZMADecoder::decompress(&state, properties, pd) || state.nCountInput != input.size() ||
        state.nCountOutput < 0 || state.nCountOutput > MAX_OUTPUT || !XBinary::isPdStructNotCanceled(pd)) return false;
    return add(info, XScanEngine::RECORD_NAME_LZMA, "LZMA",
               QString("LZMA-alone stream verified, %1 bytes unpacked, %2-byte dictionary").arg(state.nCountOutput).arg(dictionary));
}
}  // namespace

bool NFDCompression::detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pInfo || !pDevice->isOpen() || !pDevice->isReadable() || pDevice->isSequential() || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    XBinary binary(pDevice);
    const qint64 size = binary.getSize();
    if (size < 12 || size > MAX_PACKED) return false;
    const qint64 saved = pDevice->pos();
    const QByteArray header = binary.read_array(0, qMin(size, static_cast<qint64>(14)));
    bool found = false;
    if (header.size() >= 12) {
        const XAncientDecoder::TYPE type = XAncientDecoder::identify(header);
        const bool knownMagic = header.startsWith("PP20") || type == XAncientDecoder::TYPE_RNC || type == XAncientDecoder::TYPE_TPWM ||
                                type == XAncientDecoder::TYPE_UNIX_PACK || type == XAncientDecoder::TYPE_FREEZE;
        const quint32 dictionary = qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(header.constData() + 1));
        const bool possibleLzma = header.size() >= 14 && static_cast<quint8>(header.at(0)) < 225 && header.at(13) == 0 && dictionary >= 4096 &&
                                  dictionary <= static_cast<quint64>(MAX_OUTPUT) &&
                                  (!(dictionary & (dictionary - 1)) || (dictionary >= 3 * 1024 * 1024 && !(dictionary & 0xfffff)));
        if (knownMagic || possibleLzma) {
            const QByteArray data = binary.read_array(0, size);
            if (data.size() == size && XBinary::isPdStructNotCanceled(pPdStruct)) {
                found = header.startsWith("PP20") ? powerPacker(data, pInfo, pPdStruct) :
                        knownMagic ? ancient(data, pInfo, pPdStruct) : lzma(data, pInfo, pPdStruct);
            }
        }
    }
    if (saved >= 0) pDevice->seek(saved);
    return found;
}
