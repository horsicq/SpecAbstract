/* Copyright (c) 2026 hors<horsicq@gmail.com>
 * MIT License
 */
#include "nfd_legacy.h"

#include <QPointer>
#include <QSet>
#include <QtEndian>
#include <algorithm>
#include <cstring>

namespace {
// Recognition has an independent I/O and record budget. Member data is skipped,
// except for the ASCII syntax of uuencode; compressed data is never decoded.
const qint64 MAX_READ = 16 * 1024 * 1024;
const int MAX_RECORDS = 16384;

bool within(qint64 total, qint64 offset, qint64 length)
{
    return offset >= 0 && length >= 0 && offset <= total && length <= total - offset;
}

class Reader {
public:
    Reader(QIODevice *device, XBinary::PDSTRUCT *pd) : device(device), pd(pd), saved(device->pos()), size(device->size()), budget(MAX_READ) {}
    ~Reader() { if (device && saved >= 0) device->seek(saved); }
    bool active() { return XBinary::isPdStructNotCanceled(pd) && !device.isNull(); }
    QByteArray read(qint64 offset, qint64 length)
    {
        if (!within(size, offset, length) || length > budget || !active() || !device->seek(offset)) return QByteArray();
        budget -= length;
        QByteArray data = device->read(length);
        if (!device || data.size() != length || !active()) return QByteArray();
        return data;
    }
    QPointer<QIODevice> device;
    XBinary::PDSTRUCT *pd;
    qint64 saved, size, budget;
};

quint8 u8(const QByteArray &b, int n) { return static_cast<quint8>(b.at(n)); }
quint16 be16(const QByteArray &b, int n) { return qFromBigEndian<quint16>(b.constData() + n); }
quint32 be32(const QByteArray &b, int n) { return qFromBigEndian<quint32>(b.constData() + n); }
quint16 le16(const QByteArray &b, int n) { return qFromLittleEndian<quint16>(b.constData() + n); }
quint32 le32(const QByteArray &b, int n) { return qFromLittleEndian<quint32>(b.constData() + n); }

quint16 crc16(const QByteArray &b, int start, int length, bool ccitt)
{
    quint32 crc = 0;
    for (int i = start; i < start + length; ++i) {
        if (ccitt) {
            crc ^= quint32(u8(b, i)) << 8;
            for (int j = 0; j < 8; ++j) crc = ((crc << 1) ^ ((crc & 0x8000U) ? 0x1021U : 0)) & 0xffffU;
        } else {
            crc ^= u8(b, i);
            for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ ((crc & 1U) ? 0xa001U : 0);
        }
    }
    return static_cast<quint16>(crc);
}

quint32 crc32(const QByteArray &b)
{
    quint32 crc = 0xffffffffU;
    for (char c : b) {
        crc ^= static_cast<quint8>(c);
        for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ ((crc & 1U) ? 0xedb88320U : 0);
    }
    return crc ^ 0xffffffffU;
}

qint64 padded(qint64 n) { return (n + 127) & ~qint64(127); }

struct Result {
    QString name, version, info;
    XScanEngine::RECORD_NAME record = XScanEngine::RECORD_NAME_UNKNOWN;
    bool wrapper = false;
};

bool macBinary(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 128 || u8(h, 0) || u8(h, 74) || u8(h, 82) || u8(h, 1) < 1 || u8(h, 1) > 63) return false;
    const int version = u8(h, 122), minimum = u8(h, 123);
    if (version == 0) {
        // MacBinary I has no magic or CRC. Require its reserved/name padding and
        // exact fork framing to avoid accepting arbitrary binary zero fields.
        if (minimum || be16(h, 124)) return false;
        for (int i = 2 + u8(h, 1); i < 65; ++i) if (h.at(i)) return false;
        for (int i = 101; i < 128; ++i) if (h.at(i)) return false;
    } else if (version == 129) {
        if (minimum != 129 || be16(h, 124) != crc16(h, 0, 124, true)) return false;
    } else if (version == 130) {
        if (h.mid(102, 4) != "mBIN" || (minimum != 0 && minimum != 129 && minimum != 130) || be16(h, 124) != crc16(h, 0, 124, true)) return false;
    } else return false;
    const qint64 data = be32(h, 83), resource = be32(h, 87), comment = be16(h, 99), secondary = be16(h, 120);
    if (!data && !resource && !comment) return false;
    const qint64 end = 128 + padded(secondary) + padded(data) + padded(resource) + padded(comment);
    if (end != r.size) return false;
    out.name = QStringLiteral("MacBinary"); out.version = (version == 0) ? QStringLiteral("I") : (version == 129) ? QStringLiteral("II") : QStringLiteral("III");
    out.wrapper = true;
    return true;
}

bool appleSingle(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 26 || (be32(h, 0) != 0x00051600U && be32(h, 0) != 0x00051607U)) return false;
    const quint32 version = be32(h, 4);
    const int count = be16(h, 24);
    if ((version != 0x00010000U && version != 0x00020000U) || count < 1 || count > 4096) return false;
    const int floor = 26 + count * 12;
    const QByteArray directory = r.read(26, count * 12);
    if (directory.size() != count * 12) return false;
    QSet<quint32> ids;
    QList<QPair<qint64, qint64>> ranges;
    qint64 end = floor;
    for (int i = 0; i < count; ++i) {
        const quint32 id = be32(directory, i * 12);
        const qint64 offset = be32(directory, i * 12 + 4), length = be32(directory, i * 12 + 8);
        if (!id || ids.contains(id) || offset < floor || !within(r.size, offset, length)) return false;
        ids.insert(id);
        if (length) ranges.append(qMakePair(offset, offset + length));
        end = qMax(end, offset + length);
    }
    std::sort(ranges.begin(), ranges.end());
    for (int i = 1; i < ranges.size(); ++i) if (ranges.at(i).first < ranges.at(i - 1).second) return false;
    if (end != r.size || !r.active()) return false;
    out.name = (be32(h, 0) == 0x00051600U) ? QStringLiteral("AppleSingle") : QStringLiteral("AppleDouble");
    out.version = (version == 0x00010000U) ? QStringLiteral("1") : QStringLiteral("2"); out.wrapper = true;
    return true;
}

bool binHex(Reader &r, const QByteArray &prefix, Result &out)
{
    static const QByteArray banner("(This file must be converted with BinHex 4.0)");
    static const QByteArray alphabet("!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr");
    if (!prefix.startsWith(banner)) return false;
    int pos = banner.size();
    while (pos < prefix.size() && (prefix.at(pos) == '\r' || prefix.at(pos) == '\n' || prefix.at(pos) == ' ' || prefix.at(pos) == '\t')) ++pos;
    if (pos == prefix.size() || prefix.at(pos++) != ':') return false;
    QByteArray header;
    quint32 bits = 0;
    int available = 0, wanted = 1;
    bool escaped = false;
    while (pos < prefix.size() && header.size() < wanted) {
        const char c = prefix.at(pos++);
        if (c == '\r' || c == '\n') continue;
        const int digit = alphabet.indexOf(c);
        if (digit < 0) return false;
        bits = (bits << 6) | quint32(digit); available += 6;
        if (available < 8) continue;
        available -= 8;
        const quint8 value = static_cast<quint8>((bits >> available) & 0xffU);
        if (escaped) {
            escaped = false;
            if (!value) header.append(char(0x90));
            else {
                if (value == 1 || header.isEmpty()) return false;
                // Decode only the at most 85-byte transport header, even when
                // an RLE run continues into the data fork.
                const char previous = header.at(header.size() - 1);
                const int copies = qMin(int(value) - 1, wanted - header.size());
                header.append(QByteArray(copies, previous));
            }
        } else if (value == 0x90) escaped = true;
        else header.append(char(value));
        if (wanted == 1 && !header.isEmpty()) {
            const int nameLength = u8(header, 0);
            if (nameLength < 1 || nameLength > 63) return false;
            wanted = nameLength + 22;
        }
    }
    if (header.size() != wanted || u8(header, u8(header, 0) + 1) != 0 || be16(header, wanted - 2) != crc16(header, 0, wanted - 2, true)) return false;
    const QByteArray tail = r.read(qMax(qint64(0), r.size - 128), qMin(qint64(128), r.size)).trimmed();
    if (!tail.endsWith(':')) return false;
    out.name = QStringLiteral("BinHex"); out.version = QStringLiteral("4.0"); out.info = QStringLiteral("Header CRC verified"); out.wrapper = true;
    return true;
}

QByteArray nextLine(const QByteArray &b, int &pos)
{
    const int start = pos;
    while (pos < b.size() && b.at(pos) != '\r' && b.at(pos) != '\n' && pos - start <= 1024) ++pos;
    QByteArray value = b.mid(start, pos - start);
    if (pos < b.size() && b.at(pos) == '\r') ++pos;
    if (pos < b.size() && b.at(pos) == '\n') ++pos;
    return value;
}

bool uuencode(Reader &r, const QByteArray &prefix, Result &out)
{
    // Mail/test transports may have a short explanatory preamble. Accept only
    // printable text before a begin line, and still validate the entire body.
    int start = 0;
    for (;;) {
        start = prefix.indexOf("begin ", start);
        if (start < 0 || start > 4096) return false;
        if (!start || prefix.at(start - 1) == '\n' || prefix.at(start - 1) == '\r') break;
        ++start;
    }
    for (int i = 0; i < start; ++i) {
        const quint8 c = u8(prefix, i);
        if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c > 0x7e) return false;
    }
    if (r.size > MAX_READ - 8192) return false;
    const QByteArray b = r.read(0, r.size);
    if (b.size() != r.size) return false;
    int pos = start;
    const QByteArray begin = nextLine(b, pos);
    if (begin.size() < 11 || begin.size() > 1024) return false;
    int name = 6;
    while (name < begin.size() && begin.at(name) >= '0' && begin.at(name) <= '7') ++name;
    if ((name != 9 && name != 10) || name + 1 >= begin.size() || begin.at(name) != ' ') return false;
    for (int i = name + 1; i < begin.size(); ++i) if (u8(begin, i) < 0x20 || u8(begin, i) == 0x7f) return false;
    bool data = false;
    for (int records = 0; records < 262144 && pos < b.size(); ++records) {
        if ((records & 255) == 0 && !r.active()) return false;
        const QByteArray row = nextLine(b, pos);
        if (row.isEmpty()) return false;
        const int count = (u8(row, 0) - 0x20) & 63;
        if (u8(row, 0) < 0x20 || u8(row, 0) > 0x60 || count > 45) return false;
        if (!count) {
            if (row.size() != 1 || !data || nextLine(b, pos) != "end" || !b.mid(pos).trimmed().isEmpty()) return false;
            out.name = QStringLiteral("UUE"); out.info = QStringLiteral("uuencode"); out.wrapper = true; return true;
        }
        if (row.size() != 1 + 4 * ((count + 2) / 3)) return false;
        for (int i = 1; i < row.size(); ++i) if (u8(row, i) < 0x20 || u8(row, i) > 0x60) return false;
        data = true;
    }
    return false;
}

bool skipBytes(int n, int end, int &pos)
{
    if (n < 0 || n > end - pos) return false;
    pos += n;
    return true;
}

bool microsoftCompress(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 12) return false;
    if (h.startsWith(QByteArray::fromHex("535a444488f02733"))) {
        if (h.size() < 14 || h.at(8) != 'A' || (le32(h, 10) && r.size == 14)) return false;
        out.name = QStringLiteral("SZDD"); out.info = QStringLiteral("LZSS"); return true;
    }
    if (h.startsWith(QByteArray::fromHex("535a2088f02733d1"))) {
        if (le32(h, 8) && r.size == 12) return false;
        out.name = QStringLiteral("SZDD"); out.info = QStringLiteral("QBasic variant"); return true;
    }
    if (!h.startsWith(QByteArray::fromHex("4b57414a88f027d1")) || h.size() < 14) return false;
    const int method = le16(h, 8), end = le16(h, 10), flags = le16(h, 12);
    if (method > 4 || end < 14 || end > r.size || (flags & ~63)) return false;
    const QByteArray header = r.read(0, end);
    if (header.size() != end) return false;
    int pos = 14;
    quint32 unpacked = 0;
    if (flags & 1) { if (!skipBytes(4, end, pos)) return false; unpacked = le32(header, pos - 4); }
    if ((flags & 2) && !skipBytes(2, end, pos)) return false;
    if (flags & 4) { if (!skipBytes(2, end, pos)) return false; if (!skipBytes(le16(header, pos - 2), end, pos)) return false; }
    for (int flag : {8, 16}) if (flags & flag) {
        const int limit = qMin(end, pos + (flag == 8 ? 9 : 4));
        while (pos < limit && header.at(pos)) ++pos;
        if (pos == limit) return false;
        ++pos;
    }
    if (flags & 32) { if (!skipBytes(2, end, pos)) return false; if (!skipBytes(le16(header, pos - 2), end, pos)) return false; }
    if ((flags & 1) && ((unpacked && end == r.size) || (method <= 1 && qint64(unpacked) != r.size - end))) return false;
    static const char *methods[] = {"Stored", "XOR", "LZSS", "LZH", "MSZIP"};
    out.name = QStringLiteral("KWAJ"); out.info = QString::fromLatin1(methods[method]); return true;
}

bool arc(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 25 || u8(h, 0) != 0x1a) return false;
    qint64 pos = 0;
    for (int count = 0; count < MAX_RECORDS; ++count) {
        QByteArray entry = r.read(pos, 2);
        if (entry.size() != 2 || u8(entry, 0) != 0x1a) return false;
        const int method = u8(entry, 1);
        if (!method) {
            if (!count) return false;
            out.name = QStringLiteral("ARC"); return true;
        }
        if ((method < 1 || method > 10) && method != 0x7f) return false;
        const int headerSize = (method == 1) ? 25 : 29;
        entry = r.read(pos, headerSize);
        if (entry.size() != headerSize) return false;
        const QByteArray filename = entry.mid(2, 13);
        const int end = filename.indexOf('\0');
        if (end < 1) return false;
        for (int i = 0; i < end; ++i) if (u8(filename, i) < 0x20 || u8(filename, i) > 0x7e) return false;
        const qint64 packed = le32(entry, 15);
        if (!within(r.size, pos + headerSize, packed) || (method == 2 && packed != le32(entry, 25))) return false;
        pos += headerSize + packed;
    }
    return false;
}

bool arj(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 4 || le16(h, 0) != 0xea60) return false;
    const int length = le16(h, 2);
    if (length < 30 || length > 2600) return false;
    const QByteArray header = r.read(4, length + 4);
    if (header.size() != length + 4 || u8(header, 0) < 30 || u8(header, 0) > length - 2 || u8(header, 6) != 2 ||
        crc32(header.left(length)) != le32(header, length)) return false;
    const int nameEnd = header.indexOf('\0', u8(header, 0));
    if (nameEnd < 0 || nameEnd >= length || header.indexOf('\0', nameEnd + 1) >= length || header.indexOf('\0', nameEnd + 1) < 0) return false;
    qint64 pos = 8 + length;
    bool terminated = false;
    for (int count = 0; count < 256; ++count) {
        const QByteArray size = r.read(pos, 2);
        if (size.size() != 2) return false;
        const int extraLength = le16(size, 0); pos += 2;
        if (!extraLength) { terminated = true; break; }
        const QByteArray extra = r.read(pos, extraLength + 4);
        if (extra.size() != extraLength + 4 || crc32(extra.left(extraLength)) != le32(extra, extraLength)) return false;
        pos += extraLength + 4;
    }
    const QByteArray next = r.read(pos, 4);
    if (!terminated || next.size() != 4 || le16(next, 0) != 0xea60 || !within(r.size, pos + 4, le16(next, 2))) return false;
    out.name = QStringLiteral("ARJ"); out.record = XScanEngine::RECORD_NAME_ARJ;
    out.info = QStringLiteral("Header revision %1; minimum extractor revision %2").arg(u8(header, 1)).arg(u8(header, 2)); return true;
}

bool zoo(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 34 || !h.startsWith("ZOO ") || le32(h, 20) != 0xfdc4a7dcU || quint32(le32(h, 24) + le32(h, 28)) != 0) return false;
    qint64 pos = le32(h, 24);
    if (pos < 34) return false;
    for (int count = 0; count < MAX_RECORDS; ++count) {
        const QByteArray e = r.read(pos, 51);
        if (e.size() != 51 || le32(e, 0) != 0xfdc4a7dcU || u8(e, 4) > 2) return false;
        const qint64 next = le32(e, 6);
        if (!next) {
            if (!count) return false;
            out.name = QStringLiteral("ZOO");
            out.info = QStringLiteral("Minimum extractor version %1.%2").arg(u8(h, 32)).arg(u8(h, 33)); return true;
        }
        if (next <= pos || u8(e, 5) > 2 || !within(r.size, le32(e, 10), le32(e, 24)) ||
            (u8(e, 5) == 0 && le32(e, 20) != le32(e, 24))) return false;
        pos = next;
    }
    return false;
}

bool lzx(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 10 || !h.startsWith("LZX")) return false;
    qint64 pos = 10;
    qint64 groupSize = 0;
    int count = 0;
    for (; pos < r.size && count < MAX_RECORDS; ++count) {
        QByteArray e = r.read(pos, 31);
        if (e.size() != 31 || !u8(e, 30) || (u8(e, 11) != 0 && u8(e, 11) != 2)) return false;
        const int length = 31 + u8(e, 30) + u8(e, 14);
        const qint64 packed = le32(e, 6);
        groupSize += le32(e, 2);  // At most MAX_RECORDS * UINT32_MAX.
        if (packed && ((u8(e, 11) == 0 && packed != groupSize) || (u8(e, 11) == 2 && (packed & 1)))) return false;
        e = r.read(pos, length);
        if (e.size() != length || !within(r.size, pos + length, packed)) return false;
        const quint32 stored = le32(e, 26);
        for (int i = 26; i < 30; ++i) e[i] = 0;
        if (crc32(e) != stored) return false;
        if (packed) groupSize = 0;
        pos += length + packed;
    }
    if (!count || pos != r.size || groupSize) return false;
    out.name = QStringLiteral("LZX"); out.info = QStringLiteral("Amiga archive; header CRCs verified"); return true;
}

bool dms(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 56 || !h.startsWith("DMS!") || be16(h, 50) > 6 || crc16(h, 4, 50, false) != be16(h, 54)) return false;
    const QByteArray track = r.read(56, 20);
    if (track.size() != 20 || !track.startsWith("TR") || u8(track, 13) > 6 || crc16(track, 0, 18, false) != be16(track, 18) ||
        !within(r.size, 76, be16(track, 6))) return false;
    out.name = QStringLiteral("DMS"); out.info = QStringLiteral("Disk Masher System; header CRCs verified"); return true;
}

bool diskDoubler(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 62) return false;
    const quint32 magic = be32(h, 0);
    if (magic == 0xabcd0054U) {
        if (h.size() < 84) return false;
        const quint16 stored = be16(h, 82);
        if (stored && crc16(h, 0, 82, true) != stored) return false;
        const qint64 packed = qint64(be32(h, 8)) + be32(h, 16), end = 84 + packed;
        if (!within(r.size, 84, packed) || (u8(h, 20) & 0x7f) > 10 || (u8(h, 21) & 0x7f) > 10) return false;
        if (((u8(h, 20) & 0x7f) == 0 && be32(h, 4) != be32(h, 8)) || ((u8(h, 21) & 0x7f) == 0 && be32(h, 12) != be32(h, 16))) return false;
        if (end != r.size && (r.size - end != 84 || r.read(end, 84) != h.left(84))) return false;
        out.name = QStringLiteral("Disk Doubler"); return true;
    }
    if (magic == 0x44444152U) {
        if (h.size() < 78 || crc16(h, 0, 76, true) != be16(h, 76) || be32(h, 8) != r.size) return false;
        const QByteArray entry = r.read(78, 124);
        if (entry.size() != 124 || !entry.startsWith("DDAR") || u8(entry, 8) > 63) return false;
        out.name = QStringLiteral("DDAR"); out.info = QStringLiteral("Disk Doubler archive; header CRC verified"); return true;
    }
    if (magic == 0x44444132U) {
        if (be16(h, 4) != 62 || crc16(h, 0, 60, true) != be16(h, 60)) return false;
        qint64 pos = 62;
        for (int count = 0; count < MAX_RECORDS; ++count) {
            QByteArray e = r.read(pos, 6);
            if (e.size() != 6 || !e.startsWith("DDA2")) return false;
            if (be16(e, 4) == 0xbbbb) {
                if (!count || r.size - pos - 6 > 4096) return false;
                out.name = QStringLiteral("DDA2"); out.info = QStringLiteral("Disk Doubler archive; header CRC verified"); return true;
            }
            e = r.read(pos, 46);
            if (e.size() != 46 || u8(e, 6) > 31 || be32(e, 42) < 46 || !within(r.size, pos, be32(e, 42))) return false;
            pos += be32(e, 42);
        }
    }
    return false;
}

bool stuffIt(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() >= 22 && h.startsWith("SIT!") && h.mid(10, 4) == "rLau") {
        if (be32(h, 6) != r.size || !be16(h, 4)) return false;
        const QByteArray entry = r.read(22, 112);
        if (entry.size() != 112 || u8(entry, 2) > 63 || crc16(entry, 0, 110, false) != be16(entry, 110)) return false;
        out.name = QStringLiteral("StuffIt"); out.version = QString::number(u8(h, 14)); out.info = QStringLiteral("Archive header revision"); return true;
    }
    const QByteArray suffix(" Aladdin Systems, Inc., http://www.aladdinsys.com/StuffIt/\r\n");
    if (h.size() >= 100 && h.startsWith("StuffIt (c)1997-") && h.mid(20, suffix.size()) == suffix) {
        if (u8(h, 82) != 5 || be32(h, 84) != r.size || !be16(h, 92)) return false;
        const qint64 pos = be32(h, 94);
        QByteArray entry = r.read(pos, 34);
        if (pos < 100 || entry.size() != 34 || be32(entry, 0) != 0xa5a5a5a5U || be16(entry, 6) < 48) return false;
        const int length = be16(entry, 6);
        entry = r.read(pos, length);
        if (entry.size() != length) return false;
        const quint16 stored = be16(entry, 32);
        entry[32] = 0; entry[33] = 0;
        if (crc16(entry, 0, length, false) != stored) return false;
        out.name = QStringLiteral("StuffIt"); out.version = QStringLiteral("5"); out.info = QStringLiteral("Archive format; header CRC verified"); return true;
    }
    return false;
}

int nextBit(const QByteArray &h, int &pos)
{
    if (pos >= h.size() * 8) return -1;
    const int value = (u8(h, pos / 8) >> (pos % 8)) & 1;
    ++pos;
    return value;
}

bool nextInteger(const QByteArray &h, int &pos, quint64 &value)
{
    int ones = 1;
    for (;;) { const int b = nextBit(h, pos); if (b < 0 || ones >= 64) return false; if (!b) break; ++ones; }
    quint64 encoded = 0;
    for (int i = 0; i < 64 && ones; ++i) {
        const int b = nextBit(h, pos); if (b < 0) return false;
        if (b) { --ones; encoded |= Q_UINT64_C(1) << i; }
    }
    if (ones || !encoded) return false;
    value = encoded - 1; return true;
}

// StuffIt X uses a bit-coded first element. Validate both bounded key/value
// lists, rather than treating the eight-byte signature alone as sufficient.
bool stuffItX(const QByteArray &h, Result &out)
{
    if (!h.startsWith("StuffIt!") || h.size() < 10) return false;
    int pos = 64;
    quint64 type = 0;
    if (nextBit(h, pos) < 0 || !nextInteger(h, pos, type) || type == 0 || type > 15) return false;
    for (int list = 0; list < 2; ++list) {
        QSet<quint64> keys;
        bool terminated = false;
        for (int i = 0; i < 32; ++i) {
            quint64 key = 0, value = 0;
            if (!nextInteger(h, pos, key)) return false;
            if (!key) { terminated = true; break; }
            if (key > quint64(list ? 6 : 10) || keys.contains(key) || !nextInteger(h, pos, value)) return false;
            keys.insert(key);
            if (list && key == 4 && !nextInteger(h, pos, value)) return false;
        }
        if (!terminated) return false;
    }
    out.name = QStringLiteral("StuffIt X"); return true;
}
}  // namespace

bool NFDLegacy::detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pInfo, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pInfo || !pDevice->isOpen() || !pDevice->isReadable() || pDevice->isSequential()) return false;
    Reader r(pDevice, pPdStruct);
    if (r.size < 2 || !r.active()) return false;
    const QByteArray h = r.read(0, qMin(qint64(8192), r.size));
    if (h.isEmpty()) return false;
    Result result;
    const bool found = appleSingle(r, h, result) || macBinary(r, h, result) || binHex(r, h, result) || uuencode(r, h, result) ||
                       microsoftCompress(r, h, result) || arc(r, h, result) || arj(r, h, result) || zoo(r, h, result) || lzx(r, h, result) ||
                       dms(r, h, result) || diskDoubler(r, h, result) || stuffIt(r, h, result) || stuffItX(h, result);
    if (!found || !r.active()) return false;
    NFD_Binary::SCAN_STRUCT scan = {};
    if (!result.wrapper) pInfo->basic_info.id.fileType = XBinary::FT_ARCHIVE;
    scan.id = pInfo->basic_info.id;
    scan.parentId = pInfo->basic_info.parentId;
    scan.type = XScanEngine::RECORD_TYPE_FORMAT;
    scan.name = result.record;
    scan.sName = result.name;
    scan.sVersion = result.version;
    scan.sInfo = result.info;
    if (result.wrapper) pInfo->basic_info.mapResultFormats.insert(scan.name, scan);
    else pInfo->basic_info.mapResultArchives.insert(scan.name, scan);
    return true;
}
