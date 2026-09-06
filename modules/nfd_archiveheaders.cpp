/* SPDX-License-Identifier: MIT */
#include "nfd_archiveheaders.h"

#include <QtEndian>

namespace {

quint8 byte(const QByteArray &data, int offset)
{
    return static_cast<quint8>(data.at(offset));
}

quint16 le16(const QByteArray &data, int offset)
{
    return qFromLittleEndian<quint16>(reinterpret_cast<const uchar *>(data.constData() + offset));
}

quint32 le32(const QByteArray &data, int offset)
{
    return qFromLittleEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + offset));
}

quint64 le64(const QByteArray &data, int offset)
{
    return qFromLittleEndian<quint64>(reinterpret_cast<const uchar *>(data.constData() + offset));
}

quint16 be16(const QByteArray &data, int offset)
{
    return qFromBigEndian<quint16>(reinterpret_cast<const uchar *>(data.constData() + offset));
}

quint32 be32(const QByteArray &data, int offset)
{
    return qFromBigEndian<quint32>(reinterpret_cast<const uchar *>(data.constData() + offset));
}

quint32 crc32(const QByteArray &data)
{
    return XBinary::_getCRC32(data, 0xffffffffU, XBinary::_getCRC32Table_EDB88320()) ^ 0xffffffffU;
}

bool add(NFD_Binary::BINARYINFO_STRUCT *info, XScanEngine::RECORD_NAME name, const QString &version, const QString &detail,
         const QString &customName = QString())
{
    info->basic_info.id.fileType = XBinary::FT_ARCHIVE;
    NFD_Binary::SCANS_STRUCT record = NFD_Binary::getScansStruct(0, XBinary::FT_ARCHIVE, XScanEngine::RECORD_TYPE_FORMAT, name, version, detail, 0);
    record.sName = customName;
    info->basic_info.mapResultArchives.insert(name, NFD_Binary::scansToScan(&info->basic_info, &record));
    return true;
}

bool vint(const QByteArray &data, int &offset, quint64 &value)
{
    value = 0;
    for (int i = 0; i < 10 && offset < data.size(); ++i) {
        const quint8 ch = byte(data, offset++);
        if (i == 9 && ch > 1) return false;
        value |= static_cast<quint64>(ch & 0x7f) << (7 * i);
        if (!(ch & 0x80)) return true;
    }
    return false;
}

bool lha(XBinary &binary, const QByteArray &header, NFD_Binary::BINARYINFO_STRUCT *info)
{
    if (header.size() < 24) return false;
    const QByteArray method = header.mid(2, 5);
    const bool pma = method == "-pm0-" || method == "-pm1-" || method == "-pm2-";
    const bool lh = method.size() == 5 && method.startsWith("-lh") && method.endsWith('-') && QByteArray("0123456789abcdex").contains(method.at(3));
    const bool lz = method == "-lzs-" || method == "-lz4-" || method == "-lz5-";
    if (!pma && !lh && !lz) return false;
    const quint8 level = byte(header, 20);
    if (level > 3 || (pma && level != 0)) return false;
    quint64 headerSize = level < 2 ? byte(header, 0) + 2U : le16(header, 0);
    if (level == 3) {
        if (header.size() < 32 || le16(header, 0) != 4) return false;
        headerSize = le32(header, 24);
    }
    // LHA for OS-9/68k records the size excluding its first two bytes.
    // The OS field is the discriminator used by lhasa for this legacy variant.
    if (level == 2 && byte(header, 23) == 'K') headerSize += 2;
    const quint64 minimum = level == 0 ? 24 : level == 1 ? 27 : level == 2 ? 26 : 32;
    if (headerSize < minimum || headerSize > 1024 * 1024 || headerSize > static_cast<quint64>(binary.getSize()) ||
        le32(header, 7) > static_cast<quint64>(binary.getSize()) - headerSize) return false;
    const QByteArray full = binary.read_array(0, static_cast<qint64>(headerSize));
    if (static_cast<quint64>(full.size()) != headerSize) return false;
    if (level < 2) {
        quint32 sum = 0;
        for (int i = 2; i < full.size(); ++i) sum += byte(full, i);
        if ((sum & 0xff) != byte(full, 1) || byte(full, 21) > headerSize - minimum) return false;
    } else {
        // Extended header lengths include their own size fields. Require the
        // terminator inside the declared header; do not walk packed file data.
        int pos = level == 2 ? 24 : 28;
        const int width = level == 2 ? 2 : 4;
        while (true) {
            if (pos > full.size() - width) return false;
            const quint32 length = width == 2 ? le16(full, pos) : le32(full, pos);
            if (!length) break;
            if (length < static_cast<quint32>(width + 1) || length > static_cast<quint32>(full.size() - pos)) return false;
            pos += static_cast<int>(length);
        }
    }
    return add(info, pma ? XScanEngine::RECORD_NAME_UNKNOWN : XScanEngine::RECORD_NAME_LHA, QString(),
               QString("header level %1, method %2").arg(level).arg(QString::fromLatin1(method)), pma ? QString("PMA") : QString());
}

bool sevenZip(XBinary &binary, const QByteArray &header, NFD_Binary::BINARYINFO_STRUCT *info)
{
    if (header.size() < 32 || header.left(6) != QByteArray::fromHex("377abcaf271c") || crc32(header.mid(12, 20)) != le32(header, 8)) return false;
    const quint64 nextOffset = le64(header, 12);
    const quint64 nextSize = le64(header, 20);
    const quint64 available = static_cast<quint64>(binary.getSize()) - 32;
    QString detail;
    if (nextOffset > available || nextSize > available - nextOffset) {
        // A split first volume and a truncated file cannot be distinguished
        // from this header alone. Preserve that uncertainty in the result.
        detail = "start header CRC verified; next header outside this file";
    } else if (nextSize <= 1024 * 1024) {
        const QByteArray next = binary.read_array(static_cast<qint64>(32 + nextOffset), static_cast<qint64>(nextSize));
        if (static_cast<quint64>(next.size()) != nextSize || crc32(next) != le32(header, 28)) return false;
        detail = nextSize ? "header CRC verified" : "empty archive";
    } else {
        detail = "start header CRC verified";
    }
    return add(info, XScanEngine::RECORD_NAME_7Z, QString("%1.%2").arg(byte(header, 6)).arg(byte(header, 7)), detail);
}

bool rar(XBinary &binary, const QByteArray &header, NFD_Binary::BINARYINFO_STRUCT *info)
{
    if (header.size() >= 20 && header.left(7) == QByteArray::fromHex("526172211a0700")) {
        const quint16 flags = le16(header, 10);
        const quint16 size = le16(header, 12);
        if (byte(header, 9) != 0x73 || size < 13 || size > binary.getSize() - 7) return false;
        // RAR <=2.9 embeds comments in HEAD_SIZE but excludes those bytes
        // from the main header CRC, as documented in UnRAR arcread.cpp.
        const int checkedSize = flags & 2 ? 13 : size;
        const QByteArray main = binary.read_array(9, checkedSize - 2);
        if (main.size() != checkedSize - 2 || (crc32(main) & 0xffff) != le16(header, 7)) return false;
        QString detail = "archive header CRC verified";
        if (flags & 1) detail += ", volume";
        if (flags & 0x80) detail += ", encrypted headers";
        return add(info, XScanEngine::RECORD_NAME_RAR, "1.5-4.x", detail);
    }
    if (header.size() >= 15 && header.left(8) == QByteArray::fromHex("526172211a070100")) {
        int pos = 12;
        quint64 size = 0;
        if (!vint(header, pos, size) || size < 3 || size > 1024 * 1024 || size > static_cast<quint64>(binary.getSize() - pos)) return false;
        const QByteArray block = binary.read_array(12, pos - 12 + static_cast<qint64>(size));
        if (block.size() != pos - 12 + static_cast<qint64>(size) || crc32(block) != le32(header, 8)) return false;
        int cursor = pos - 12;
        quint64 type = 0, flags = 0, extraSize = 0, dataSize = 0;
        if (!vint(block, cursor, type) || (type != 1 && type != 4) || !vint(block, cursor, flags)) return false;
        if ((flags & 1) && !vint(block, cursor, extraSize)) return false;
        if ((flags & 2) && !vint(block, cursor, dataSize)) return false;
        if (extraSize > static_cast<quint64>(block.size() - cursor)) return false;
        const QByteArray body = block.left(block.size() - static_cast<int>(extraSize));
        quint64 value = 0;
        if (!vint(body, cursor, value)) return false;
        if (type == 1) {
            // Archive flags can require a following volume number.
            if ((value & 2) && !vint(body, cursor, value)) return false;
        } else {
            // Encryption version 0: flags, KDF count, 16-byte salt, and
            // optionally eight password-check bytes plus their four-byte CRC.
            if (value != 0 || !vint(body, cursor, value)) return false;
            const int required = 17 + ((value & 1) ? 12 : 0);
            if (body.size() - cursor < required) return false;
        }
        if (dataSize > static_cast<quint64>(binary.getSize()) - 12 - static_cast<quint64>(block.size())) return false;
        return add(info, XScanEngine::RECORD_NAME_RAR, "5.0", type == 4 ? "RAR5 format; encrypted archive header CRC verified" : "RAR5 format; archive header CRC verified");
    }
    return false;
}

bool tar(const QByteArray &header, NFD_Binary::BINARYINFO_STRUCT *info)
{
    if (header.size() < 512 || !byte(header, 0)) return false;
    bool ok = false;
    QByteArray field = header.mid(148, 8);
    field.replace('\0', ' ');
    const quint32 expected = field.trimmed().toUInt(&ok, 8);
    if (!ok) return false;
    quint32 sum = 0;
    qint32 signedSum = 0;
    for (int i = 0; i < 512; ++i) {
        const quint8 ch = i >= 148 && i < 156 ? 32 : byte(header, i);
        sum += ch;
        signedSum += ch < 128 ? ch : static_cast<qint32>(ch) - 256;
    }
    if (expected != sum && (signedSum < 0 || expected != static_cast<quint32>(signedSum))) return false;
    QString detail = "V7 header";
    if (header.mid(257, 6) == QByteArray("ustar\0", 6)) detail = byte(header, 156) == 'x' || byte(header, 156) == 'g' ? "POSIX pax header" : "POSIX ustar header";
    else if (header.mid(257, 6) == "ustar ") detail = "GNU header";
    else if (header.mid(257, 6) != QByteArray(6, '\0')) return false;
    return add(info, XScanEngine::RECORD_NAME_TAR, QString(), detail);
}

QString versionText(quint16 number)
{
    QString text = QString::number(number >> 12) + "." + QString::number((number >> 4) & 0xff, 16).rightJustified(2, '0');
    if (number & 15) text += "." + QString::number(number & 15);
    return text;
}

bool compression(XBinary &binary, const QByteArray &header, NFD_Binary::BINARYINFO_STRUCT *info)
{
    if (header.size() >= 6 && header.left(2) == QByteArray::fromHex("1f9d")) {
        const quint8 flags = byte(header, 2);
        const int bits = flags & 0x1f;
        if (!(flags & 0x60) && bits >= 9 && bits <= 16 && !(byte(header, 4) & 1)) {
            return add(info, XScanEngine::RECORD_NAME_UNKNOWN, QString(), QString("LZW, %1-bit maximum%2").arg(bits).arg(flags & 0x80 ? ", block mode" : ""), "compress (Z)");
        }
    }
    if (header.size() >= 36 && header.left(4) == "LZIP" && byte(header, 4) == 1) {
        const int bits = byte(header, 5) & 31;
        if (bits < 12 || bits > 29 || byte(header, 6) != 0) return false;
        const QByteArray trailer = binary.read_array(binary.getSize() - 20, 20);
        if (trailer.size() != 20) return false;
        const quint64 memberSize = le64(trailer, 12);
        if (memberSize < 36 || memberSize > static_cast<quint64>(binary.getSize())) return false;
        const QByteArray lastHeader = binary.read_array(binary.getSize() - static_cast<qint64>(memberSize), 6);
        if (lastHeader.size() != 6 || lastHeader.left(4) != "LZIP" || byte(lastHeader, 4) != 1) return false;
        return add(info, XScanEngine::RECORD_NAME_LZIP, "1", "member header and trailer", "LZIP");
    }
    if (header.size() >= 31 && header.left(9) == QByteArray::fromHex("894c5a4f000d0a1a0a")) {
        const quint16 version = be16(header, 9);
        if (version < 0x900) return false;
        int pos = version >= 0x940 ? 15 : 13;
        if (version >= 0x940 && be16(header, 13) < 0x900) return false;
        const quint8 method = byte(header, pos++);
        if (method < 1 || method > 3) return false;
        if (version >= 0x940 && byte(header, pos++) > 9) return false;
        if (pos > header.size() - 4) return false;
        const quint32 flags = be32(header, pos);
        pos += 4;
        if (flags & 0x800) pos += 4;
        pos += version >= 0x940 ? 12 : 8;
        if (pos >= header.size()) return false;
        const int end = pos + 1 + byte(header, pos);
        const QByteArray full = binary.read_array(9, end + 4 - 9);
        if (full.size() != end + 4 - 9) return false;
        const QByteArray checked = full.left(full.size() - 4);
        quint32 checksum = 0;
        if (flags & 0x1000) checksum = crc32(checked);
        else {
            quint32 a = 1, b = 0;
            for (char ch : checked) { a = (a + static_cast<quint8>(ch)) % 65521; b = (b + a) % 65521; }
            checksum = (b << 16) | a;
        }
        if (checksum != be32(full, full.size() - 4)) return false;
        QString detail = QString("header checksum verified, method %1, writer %2, LZO library %3").arg(method).arg(versionText(version)).arg(versionText(be16(header, 11)));
        if (version >= 0x940) detail += ", minimum reader " + versionText(be16(header, 13));
        return add(info, XScanEngine::RECORD_NAME_UNKNOWN, QString(), detail, "lzop");
    }
    return false;
}

}  // namespace

bool NFDArchiveHeaders::detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pInfo || !XBinary::isPdStructNotCanceled(pPdStruct)) return false;
    XBinary binary(pDevice);
    if (pDevice->isSequential() || binary.getSize() <= 0) return false;
    const qint64 saved = pDevice->pos();
    const QByteArray header = binary.read_array(0, qMin(binary.getSize(), static_cast<qint64>(512)));
    const bool found = sevenZip(binary, header, pInfo) || rar(binary, header, pInfo) || lha(binary, header, pInfo) || tar(header, pInfo) ||
                       compression(binary, header, pInfo);
    if (saved >= 0) pDevice->seek(saved);
    return found;
}
