#include "nfd_containers.h"

#include <QXmlStreamReader>
#include <cstring>
#include "../../XArchive/Algos/include/zlib.h"

namespace {

// Recognition budgets, independent of declared payload size. No payload is
// extracted, mounted or executed. Large/unsupported structures remain unclaimed.
const quint64 kReadBudget = 2 * 1024 * 1024;
const quint64 kMaxRead = 256 * 1024;
const quint32 kMaxRecords = 4096;

class Reader {
public:
    Reader(QIODevice *device, XBinary::PDSTRUCT *pd) : d(device), p(pd), saved(device->pos()), size(quint64(device->size())) {}
    ~Reader() { if (saved >= 0) d->seek(saved); }
    bool active() const { return XBinary::isPdStructNotCanceled(p); }
    bool range(quint64 off, quint64 len) const { return off <= size && len <= size - off; }
    QByteArray read(quint64 off, quint64 len)
    {
        if (!active() || !range(off, len) || len > kMaxRead || len > kReadBudget - used || ++reads > 16384) return {};
        used += len;
        if (!d->seek(qint64(off))) return {};
        QByteArray b = d->read(qint64(len));
        return quint64(b.size()) == len ? b : QByteArray();
    }
    bool zeroes(quint64 off, quint64 len)
    {
        while (len) {
            quint64 n = qMin(len, quint64(4096));
            QByteArray b = read(off, n);
            if (quint64(b.size()) != n) return false;
            for (char c : b) if (c) return false;
            off += n; len -= n;
        }
        return true;
    }
    QIODevice *d;
    XBinary::PDSTRUCT *p;
    qint64 saved;
    quint64 size, used = 0, stringWork = kReadBudget;
    quint32 reads = 0;
};

quint64 number(const QByteArray &b, int off, int bytes, bool big = false)
{
    quint64 n = 0;
    for (int i = 0; i < bytes; ++i) n = (n << 8) | quint8(b.at(off + (big ? i : bytes - 1 - i)));
    return n;
}
quint32 u32(const QByteArray &b, int o, bool be = false) { return quint32(number(b, o, 4, be)); }
quint16 u16(const QByteArray &b, int o, bool be = false) { return quint16(number(b, o, 2, be)); }
quint64 u64(const QByteArray &b, int o, bool be = false) { return number(b, o, 8, be); }
bool power2(quint64 n) { return n && !(n & (n - 1)); }
bool span(quint64 off, quint64 len, quint64 end) { return off <= end && len <= end - off; }
bool sectors(Reader &r, quint64 off, quint64 len) { return off <= r.size / 512 && len <= r.size / 512 - off; }

bool asciiNumber(const QByteArray &b, int off, int len, int base, quint64 *out, bool padded = false)
{
    QByteArray s = b.mid(off, len);
    if (s.size() != len) return false;
    if (padded) s = s.trimmed();
    if (s.isEmpty()) return false;
    quint64 n = 0;
    for (char c : s) {
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
        if (v < 0 || v >= base || n > (~quint64(0) - quint64(v)) / quint64(base)) return false;
        n = n * quint64(base) + quint64(v);
    }
    *out = n;
    return true;
}

bool sumValid(const QByteArray &b, int checksum)
{
    quint32 sum = 0;
    for (int i = 0; i < b.size(); ++i) if (i < checksum || i >= checksum + 4) sum += quint8(b.at(i));
    return ~sum == u32(b, checksum, true);
}
bool crc32cValid(const QByteArray &b)
{
    quint32 crc = ~quint32(0);
    for (int i = 0; i < b.size(); ++i) {
        crc ^= (i >= 4 && i < 8) ? 0 : quint8(b.at(i));
        for (int j = 0; j < 8; ++j) crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78U : 0);
    }
    return ~crc == u32(b, 4);
}

// Kept a C++11 aggregate (no default member initialisers) so the `out = {...}`
// sites below stay valid: the trailing members they omit are value-initialised,
// which is RECORD_NAME_UNKNOWN (0) and false.
struct Result {
    QString name, version, info;
    XScanEngine::RECORD_NAME key;
    bool database;
};

bool dmg(Reader &r, Result &out)
{
    if (r.size < 512) return false;
    const quint64 end = r.size - 512;
    QByteArray h = r.read(end, 512);
    if (h.size() != 512 || !h.startsWith("koly") || u32(h, 4, true) != 4 || u32(h, 8, true) != 512) return false;
    if (u32(h, 56, true) != 1 || u32(h, 60, true) != 1 || !u64(h, 492, true)) return false;
    const quint64 data = u64(h, 24, true), dataSize = u64(h, 32, true);
    const quint64 xml = u64(h, 216, true), xmlSize = u64(h, 224, true);
    if (!span(data, dataSize, end) || !dataSize || !xmlSize || xml < data + dataSize || !span(xml, xmlSize, end)) return false;
    if (!span(u64(h, 40, true), u64(h, 48, true), end)) return false;
    // UDIF checksums describe data/resource contents; validate their declared
    // shape here. Computing whole-image checksums is outside this recognizer.
    for (int pos : {80, 352}) {
        const quint32 type = u32(h, pos, true), bits = u32(h, pos + 4, true);
        if (bits > 1024 || (type == 2 && bits != 32)) return false;
    }
    QByteArray x = r.read(xml, xmlSize);
    if (quint64(x.size()) != xmlSize) return false;
    QXmlStreamReader parser(x);
    bool plist = false, blkx = false;
    int depth = 0;
    while (!parser.atEnd() && r.active()) {
        parser.readNext();
        if (parser.isStartElement()) {
            if (++depth > 64) return false;
            if (depth == 1) plist = parser.name() == QStringLiteral("plist");
            if (parser.name() == QStringLiteral("key")) {
                if (parser.readElementText() == QStringLiteral("blkx")) blkx = true;
                --depth;
            }
        } else if (parser.isEndElement()) --depth;
    }
    if (!r.active() || parser.hasError() || !plist || !blkx) return false;
    out = {QStringLiteral("Apple Disk Image (UDIF)"), QStringLiteral("4"), QStringLiteral("XML metadata; format revision")};
    return true;
}

bool vhd(Reader &r, Result &out)
{
    if (r.size < 1024 || r.size % 512) return false;
    QByteArray h = r.read(r.size - 512, 512);
    if (h.size() != 512 || !h.startsWith("conectix") || u32(h, 12, true) != 0x10000 || !sumValid(h, 64)) return false;
    quint32 type = u32(h, 60, true);
    quint64 diskSize = u64(h, 48, true), next = u64(h, 16, true);
    if (!diskSize || diskSize % 512 || !(u32(h, 8, true) & 2)) return false;
    QString kind;
    if (type == 2) {
        if (next != ~quint64(0) || diskSize != r.size - 512) return false;
        kind = QStringLiteral("fixed");
    } else if (type == 3 || type == 4) {
        if (next % 512 || !span(next, 1024, r.size - 512)) return false;
        QByteArray d = r.read(next, 1024);
        if (d.size() != 1024 || !d.startsWith("cxsparse") || u64(d, 8, true) != ~quint64(0) || u32(d, 24, true) != 0x10000 || !sumValid(d, 36)) return false;
        quint64 count = u32(d, 28, true), block = u32(d, 32, true), bat = u64(d, 16, true);
        if (!power2(block) || block < 512 || !count || count < (diskSize - 1) / block + 1 || bat % 512 || !span(bat, count * 4, r.size - 512)) return false;
        kind = type == 3 ? QStringLiteral("dynamic") : QStringLiteral("differencing");
    } else return false;
    out = {QStringLiteral("VHD"), QStringLiteral("1.0"), kind + QStringLiteral("; checksummed format header")};
    return true;
}

bool vhdxMetadata(Reader &r, const QByteArray &t, Result &out)
{
    quint32 count = u32(t, 8);
    if (!count || count > 2047 || u32(t, 12)) return false;
    const QByteArray batGuid = QByteArray::fromHex("6677c22d23f600429d64115e9bfd4a08");
    const QByteArray metaGuid = QByteArray::fromHex("06a27c8b90479a4bb8fe575f050f886e");
    quint64 meta = 0, metaSize = 0;
    bool bat = false;
    QList<QPair<quint64, quint64>> spans;
    for (quint32 i = 0; i < count; ++i) {
        int p = 16 + int(i) * 32;
        quint64 off = u64(t, p + 16), len = u32(t, p + 24);
        if (off < 1048576 || off % 1048576 || !len || len % 1048576 || !r.range(off, len) || u32(t, p + 28) > 1) return false;
        for (const QPair<quint64, quint64> &s : spans) if (off < s.first + s.second && s.first < off + len) return false;
        spans.append(qMakePair(off, len));
        QByteArray id = t.mid(p, 16);
        if (id == batGuid) { if (bat) return false; bat = true; }
        if (id == metaGuid) { if (meta) return false; meta = off; metaSize = len; }
    }
    if (!bat || !meta) return false;
    QByteArray m = r.read(meta, 65536);
    if (m.size() != 65536 || !m.startsWith("metadata") || u16(m, 8)) return false;
    quint16 entries = u16(m, 10);
    if (!entries || entries > 2047) return false;
    const QByteArray sizeGuid = QByteArray::fromHex("2442a52f1bcd7648b2115dbed83bf4b8");
    const QByteArray paramGuid = QByteArray::fromHex("3767a1ca36fa434db3b633f0aa44e76b");
    const QByteArray sectorGuid = QByteArray::fromHex("1dbf41816fa90947ba47f233a8faab5f");
    quint64 disk = 0;
    quint32 flags = 0, sector = 0;
    bool parameters = false;
    for (quint16 i = 0; i < entries; ++i) {
        int p = 32 + int(i) * 32;
        quint64 off = u32(m, p + 16), len = u32(m, p + 20);
        if ((len && off < 65536) || (!len && off) || !span(off, len, metaSize) || len > 1048576) return false;
        QByteArray id = m.mid(p, 16);
        if (id != sizeGuid && id != paramGuid && id != sectorGuid) continue;
        if (len != (id == sectorGuid ? 4 : 8)) return false;
        QByteArray v = r.read(meta + off, len);
        if (quint64(v.size()) != len) return false;
        if (id == sizeGuid) { if (disk) return false; disk = u64(v, 0); }
        if (id == paramGuid) {
            if (parameters || !power2(u32(v, 0)) || u32(v, 0) < 1048576 || u32(v, 0) > 256 * 1048576) return false;
            parameters = true; flags = u32(v, 4);
        }
        if (id == sectorGuid) { if (sector) return false; sector = u32(v, 0); }
    }
    if (!disk || !parameters || (sector != 512 && sector != 4096) || disk % sector) return false;
    out = {QStringLiteral("VHDX"), QStringLiteral("1"), (flags & 2) ? QStringLiteral("differencing") : (flags & 1) ? QStringLiteral("fixed") : QStringLiteral("dynamic")};
    return true;
}

bool vhdx(Reader &r, const QByteArray &h, Result &out)
{
    if (!h.startsWith("vhdxfile") || r.size < 1048576) return false;
    QByteArray a = r.read(65536, 4096), b = r.read(131072, 4096);
    bool va = a.size() == 4096 && a.startsWith("head") && crc32cValid(a);
    bool vb = b.size() == 4096 && b.startsWith("head") && crc32cValid(b);
    if ((!va && !vb) || (va && vb && u64(a, 8) == u64(b, 8))) return false;
    const QByteArray &current = va && (!vb || u64(a, 8) > u64(b, 8)) ? a : b;
    quint64 log = u64(current, 72), length = u32(current, 68);
    if (u16(current, 64) != 0 || u16(current, 66) != 1 || length < 1048576 || length % 1048576 || log < 1048576 || log % 1048576 || !r.range(log, length)) return false;
    for (quint64 off : {quint64(196608), quint64(262144)}) {
        QByteArray t = r.read(off, 65536);
        if (t.size() == 65536 && t.startsWith("regi") && crc32cValid(t) && vhdxMetadata(r, t, out)) return true;
    }
    return false;
}

bool qcow(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 104 || h.left(4) != QByteArray::fromHex("514649fb")) return false;
    quint32 version = u32(h, 4, true), bits = u32(h, 20, true);
    if ((version != 2 && version != 3) || bits < 9 || bits > 21 || !u64(h, 24, true) || u32(h, 32, true) > 2) return false;
    quint64 cluster = quint64(1) << bits, l1 = u64(h, 40, true), refs = u64(h, 48, true);
    quint64 entries = u32(h, 36, true), refClusters = u32(h, 56, true), backing = u64(h, 8, true);
    quint32 backingLen = u32(h, 16, true);
    if (!entries || !refClusters || l1 < cluster || refs < cluster || l1 % cluster || refs % cluster || !r.range(l1, entries * 8) || !r.range(refs, refClusters * cluster)) return false;
    if (backing && (backingLen > 1023 || !backingLen || !span(backing, backingLen, cluster) || !r.range(backing, backingLen))) return false;
    quint64 features = version == 3 ? u64(h, 72, true) : 0;
    quint32 headerSize = version == 3 ? u32(h, 100, true) : 72;
    if (version == 3 && (headerSize < 104 || headerSize % 8 || headerSize > cluster || !r.range(0, headerSize) || u32(h, 96, true) > 6)) return false;
    if (backing && backing < headerSize) return false;
    quint64 coverage = cluster * (cluster / ((features & 16) ? 16 : 8));
    if ((features & 16) && bits < 14) return false;
    if (entries < (u64(h, 24, true) - 1) / coverage + 1) return false;
    if (u32(h, 60, true) && (!u64(h, 64, true) || u64(h, 64, true) % 8 || !r.range(u64(h, 64, true), 40))) return false;
    QString compression;
    if (features & 8) {
        if (headerSize < 112 || h.size() < 112 || quint8(h.at(104)) != 1) return false;
        compression = QStringLiteral("Zstandard compressed clusters");
    }
    out = {QStringLiteral("QCOW2"), QString::number(version), compression};
    return true;
}

bool vdi(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 456 || u32(h, 64) != 0xbeda107f || u32(h, 68) != 0x10001) return false;
    quint64 header = u32(h, 72), map = u32(h, 340), data = u32(h, 344);
    quint32 type = u32(h, 76), sector = u32(h, 360), block = u32(h, 376), extra = u32(h, 380);
    quint64 size = u64(h, 368), blocks = u32(h, 384), allocated = u32(h, 388);
    if (header < 384 || !r.range(72, header) || type < 1 || type > 4 || sector != 512 || !size || size % sector || !power2(block) || block < sector) return false;
    if (!blocks || allocated > blocks || blocks != (size - 1) / block + 1 || map < 72 + header || data < map || !span(map, blocks * 4, data)) return false;
    // The product can exceed 64 bits even though both counts are 32-bit.
    if (data > r.size || allocated > (r.size - data) / (quint64(block) + extra)) return false;
    if (type == 2 && allocated != blocks) return false;
    out = {QStringLiteral("VirtualBox Disk Image (VDI)"), QStringLiteral("1.1"), type == 1 ? QStringLiteral("dynamic") : type == 2 ? QStringLiteral("fixed") : QStringLiteral("differencing")};
    return true;
}

bool vmdk(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 512) return false;
    if (u64(h, 0) == 0xcafebabeULL) {
        // SESparse uses virtual grains_size; only allocated data need exist.
        if (u64(h, 8) != 0x200000001ULL || !u64(h, 16) || u64(h, 24) != 8 || u64(h, 32) != 64 || u64(h, 40)) return false;
        for (int p = 48; p < 80; p += 8) if (u64(h, p)) return false;
        for (int p = 80; p < 192; p += 16) if (!u64(h, p + 8) || !sectors(r, u64(h, p), u64(h, p + 8))) return false;
        if (u64(h, 88) != 1 || !sectors(r, u64(h, 192), 0) || u64(h, 200) < u64(h, 16)) return false;
        QByteArray v = r.read(u64(h, 80) * 512, 512);
        if (v.size() != 512 || u64(v, 0) != 0xcafecafeULL) return false;
        out = {QStringLiteral("VMDK"), QStringLiteral("0x0000000200000001"), QStringLiteral("SESparse; extent format revision")};
        return true;
    }
    if (!h.startsWith("KDMV")) return false;
    quint32 version = u32(h, 4), flags = u32(h, 8), entries = u32(h, 44);
    quint64 capacity = u64(h, 12), grain = u64(h, 20), descriptor = u64(h, 28), descriptorSize = u64(h, 36), directory = u64(h, 56), overhead = u64(h, 64);
    if (version < 1 || version > 3 || !capacity || !power2(grain) || grain < 8 || !power2(entries) || entries > 65536 || !overhead || !sectors(r, 0, overhead)) return false;
    if (descriptorSize && (!descriptor || !sectors(r, descriptor, descriptorSize))) return false;
    if ((flags & 1) && h.mid(73, 4) != QByteArray::fromHex("0a200d0a")) return false;
    if (u16(h, 77) > 1) return false;
    quint64 tables = (capacity - 1) / grain / entries + 1;
    if (directory == ~quint64(0)) {
        if (!(flags & 0x20000) || r.size < 1536) return false;
        QByteArray footer = r.read(r.size - 1024, 512);
        if (footer.size() != 512 || !footer.startsWith("KDMV") || u32(footer, 4) != version || u64(footer, 12) != capacity) return false;
        directory = u64(footer, 56);
    }
    if (!directory || !sectors(r, directory, (tables * 4 + 511) / 512)) return false;
    out = {QStringLiteral("VMDK"), QString::number(version), (flags & 0x10000) ? QStringLiteral("compressed sparse extent") : QStringLiteral("sparse extent")};
    return true;
}

bool cpio(Reader &r, const QByteArray &head, Result &out)
{
    QByteArray magic = head.left(6);
    bool newc = magic == "070701" || magic == "070702", crc = magic == "070702", odc = magic == "070707";
    bool be = head.left(2) == QByteArray::fromHex("71c7"), binary = be || head.left(2) == QByteArray::fromHex("c771");
    if (!newc && !odc && !binary) return false;
    quint64 off = 0;
    for (quint32 record = 0; record < kMaxRecords && r.active(); ++record) {
        const quint64 headerSize = newc ? 110 : odc ? 76 : 26;
        QByteArray h = r.read(off, headerSize);
        if (quint64(h.size()) != headerSize) return false;
        quint64 nameSize = 0, fileSize = 0, checksum = 0, mode = 0, links = 0;
        if (newc) {
            if (h.left(6) != magic) return false;
            quint64 fields[13] = {};
            for (int i = 0; i < 13; ++i) if (!asciiNumber(h, 6 + i * 8, 8, 16, &fields[i])) return false;
            mode = fields[1]; links = fields[4]; fileSize = fields[6]; nameSize = fields[11]; checksum = fields[12];
            if (!crc && checksum) return false;
        } else if (odc) {
            if (h.left(6) != magic) return false;
            quint64 dummy;
            for (int i = 0; i < 7; ++i) if (!asciiNumber(h, 6 + i * 6, 6, 8, &dummy)) return false;
            if (!asciiNumber(h, 48, 11, 8, &dummy) || !asciiNumber(h, 59, 6, 8, &nameSize) || !asciiNumber(h, 65, 11, 8, &fileSize) ||
                !asciiNumber(h, 18, 6, 8, &mode) || !asciiNumber(h, 36, 6, 8, &links)) return false;
        } else {
            if (u16(h, 0, be) != 070707) return false;
            mode = u16(h, 6, be); links = u16(h, 12, be); nameSize = u16(h, 20, be);
            fileSize = (quint64(u16(h, 22, be)) << 16) | u16(h, 24, be);
        }
        if (!nameSize || nameSize > 4096 || !r.range(off + headerSize, nameSize)) return false;
        QByteArray name = r.read(off + headerSize, nameSize);
        if (quint64(name.size()) != nameSize || name.at(name.size() - 1) || name.indexOf('\0') != name.size() - 1) return false;
        quint64 data = off + headerSize + nameSize;
        quint64 alignment = newc ? 4 : binary ? 2 : 1;
        data = (data + alignment - 1) & ~(alignment - 1);
        if (!r.range(data, fileSize)) return false;
        if (name == QByteArray("TRAILER!!!\0", 11)) {
            if (fileSize) return false;
            out = {QStringLiteral("CPIO"), newc ? QString::fromLatin1(magic) : odc ? QStringLiteral("070707") : QStringLiteral("binary 070707"),
                   newc ? (crc ? QStringLiteral("new ASCII; additive checksum") : QStringLiteral("new ASCII")) : odc ? QStringLiteral("old ASCII") : be ? QStringLiteral("big-endian") : QStringLiteral("little-endian")};
            return true;
        }
        quint64 kind = mode & 0170000;
        if (!links || (kind != 0100000 && kind != 0040000 && kind != 0120000 && kind != 0060000 && kind != 0020000 && kind != 0010000 && kind != 0140000)) return false;
        if (crc) {
            quint32 sum = 0;
            for (quint64 done = 0; done < fileSize;) {
                quint64 n = qMin(fileSize - done, quint64(16384));
                QByteArray d = r.read(data + done, n);
                if (quint64(d.size()) != n) return false;
                for (char c : d) sum += quint8(c);
                done += n;
            }
            if (sum != checksum) return false;
        }
        off = (data + fileSize + alignment - 1) & ~(alignment - 1);
        if (off > r.size) return false;
    }
    return false;
}

bool ar(Reader &r, const QByteArray &h, Result &out)
{
    if (!h.startsWith("!<arch>\n")) return false;
    quint64 off = 8;
    bool deb = false, control = false, data = false;
    quint32 count = 0;
    while (off < r.size && count < kMaxRecords && r.active()) {
        QByteArray a = r.read(off, 60);
        if (a.size() != 60 || a.mid(58, 2) != "`\n") return false;
        quint64 length = 0, dummy = 0;
        if (!asciiNumber(a, 48, 10, 10, &length, true) || !r.range(off + 60, length)) return false;
        // GNU symbol/string tables may leave ownership fields blank.
        for (const QPair<int, int> &f : {qMakePair(16, 12), qMakePair(28, 6), qMakePair(34, 6), qMakePair(40, 8)}) {
            if (!a.mid(f.first, f.second).trimmed().isEmpty() && !asciiNumber(a, f.first, f.second, f.first == 40 ? 8 : 10, &dummy, true)) return false;
        }
        QByteArray name = a.left(16).trimmed();
        if (name.isEmpty()) return false;
        if (name.startsWith("#1/")) {
            quint64 longLen;
            if (!asciiNumber(name, 3, name.size() - 3, 10, &longLen) || !longLen || longLen > length || longLen > 4096) return false;
        }
        if (name.endsWith('/') && name.size() > 1) name.chop(1);
        if (count == 0 && name == "debian-binary" && length == 4) deb = r.read(off + 60, 4) == "2.0\n";
        if (name == "control.tar" || name.startsWith("control.tar.")) control = true;
        if (name == "data.tar" || name.startsWith("data.tar.")) data = true;
        off += 60 + length;
        if (length & 1) {
            if (r.read(off, 1) != "\n") return false;
            ++off;
        }
        ++count;
    }
    if (!count || off != r.size) return false;
    if (deb && control && data) out = {QStringLiteral("Debian package"), QStringLiteral("2.0"), QStringLiteral("ar container"), XScanEngine::RECORD_NAME_DEB};
    else out = {QStringLiteral("ar"), QString(), QStringLiteral("Unix archive"), XScanEngine::RECORD_NAME_AR};
    return true;
}

bool rpmHeader(Reader &r, quint64 off, quint64 *end)
{
    QByteArray h = r.read(off, 16);
    if (h.size() != 16 || h.left(8) != QByteArray::fromHex("8eade80100000000")) return false;
    quint64 count = u32(h, 8, true), bytes = u32(h, 12, true);
    if (!count || count > 4096 || bytes > kMaxRead || !r.range(off + 16, count * 16 + bytes)) return false;
    QByteArray index = r.read(off + 16, count * 16), store = r.read(off + 16 + count * 16, bytes);
    if (quint64(index.size()) != count * 16 || quint64(store.size()) != bytes) return false;
    for (quint64 i = 0; i < count; ++i) {
        int p = int(i) * 16;
        quint32 type = u32(index, p + 4, true), start = u32(index, p + 8, true), n = u32(index, p + 12, true);
        if (type > 9 || start > bytes || n > kReadBudget) return false;
        quint64 width = type == 3 ? 2 : type == 4 ? 4 : type == 5 ? 8 : 1;
        if (type <= 5 || type == 7) {
            if (!span(start, quint64(n) * width, bytes) || start % width) return false;
        } else {
            if ((type == 6 && n != 1) || !n || n > bytes - start) return false;
            int pos = int(start);
            for (quint32 j = 0; j < n; ++j) {
                if (!r.active() || !r.stringWork) return false;
                const quint64 limit = qMin(quint64(store.size() - pos), r.stringWork);
                const char *startString = store.constData() + pos;
                const char *endString = static_cast<const char *>(std::memchr(startString, 0, size_t(limit)));
                const quint64 scanned = endString ? quint64(endString - startString) + 1 : limit;
                r.stringWork -= scanned;
                if (!endString) return false;
                pos += int(scanned);  // bounded by the 256-KiB store
            }
        }
    }
    *end = off + 16 + count * 16 + bytes;
    return true;
}

bool rpm(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 96 || h.left(4) != QByteArray::fromHex("edabeedb") || quint8(h.at(4)) != 3 || h.at(5) || u16(h, 6, true) > 1 || u16(h, 78, true) != 5 || !h.mid(10, 66).contains('\0')) return false;
    quint64 sig = 0, main = 0;
    if (!rpmHeader(r, 96, &sig)) return false;
    quint64 aligned = (sig + 7) & ~quint64(7);
    if (!r.zeroes(sig, aligned - sig) || !rpmHeader(r, aligned, &main) || main >= r.size) return false;
    out = {QStringLiteral("RPM"), QStringLiteral("lead 3.0; header 1"), QStringLiteral("package container; signatures not verified")};
    return true;
}

bool git(Reader &r, const QByteArray &h, Result &out)
{
    if (r.size < 8 || r.size > 65536 || h.size() < 2) return false;
    quint16 z = u16(h, 0, true);
    if ((quint8(h.at(0)) & 15) != 8 || (quint8(h.at(0)) >> 4) > 7 || z % 31 || (quint8(h.at(1)) & 32)) return false;
    QByteArray compressed = r.read(0, r.size), decoded(65536, '\0');
    if (quint64(compressed.size()) != r.size || !r.active()) return false;
    z_stream stream = {};
    stream.next_in = reinterpret_cast<Bytef *>(compressed.data()); stream.avail_in = uInt(compressed.size());
    stream.next_out = reinterpret_cast<Bytef *>(decoded.data()); stream.avail_out = uInt(decoded.size());
    if (inflateInit(&stream) != Z_OK) return false;
    int status = inflate(&stream, Z_FINISH);
    bool complete = status == Z_STREAM_END && stream.total_in == r.size && stream.total_out <= 65536;
    int size = int(stream.total_out);
    inflateEnd(&stream);
    if (!complete || !r.active()) return false;
    decoded.resize(size);
    int zero = decoded.indexOf('\0'), space = decoded.indexOf(' ');
    if (space <= 0 || zero <= space + 1 || zero > 64) return false;
    QByteArray kind = decoded.left(space);
    if (kind != "blob" && kind != "tree" && kind != "commit" && kind != "tag") return false;
    quint64 length = 0;
    if (!asciiNumber(decoded, space + 1, zero - space - 1, 10, &length) || length != quint64(size - zero - 1) || (zero > space + 2 && decoded.at(space + 1) == '0')) return false;
    out = {QStringLiteral("Git loose object"), QString(), QString::fromLatin1(kind) + QStringLiteral("; %1 payload bytes").arg(length)};
    return true;
}

bool sqlite(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 108 || h.left(16) != QByteArray("SQLite format 3\0", 16)) return false;
    quint32 page = u16(h, 16, true); if (page == 1) page = 65536;
    if (!power2(page) || page < 512 || page > 65536 || r.size % page || r.size < page || quint8(h.at(20)) > page - 480 || h.mid(21, 3) != QByteArray::fromHex("402020")) return false;
    quint8 write = quint8(h.at(18)), read = quint8(h.at(19));
    quint32 schema = u32(h, 44, true), encoding = u32(h, 56, true);
    if (write < 1 || write > 2 || read < 1 || read > 2 || schema > 4 || encoding > 3 || (schema && !encoding)) return false;
    for (int i = 72; i < 92; ++i) if (h.at(i)) return false;
    quint32 declared = u32(h, 28, true);
    if (declared && u32(h, 24, true) == u32(h, 92, true) && quint64(declared) > r.size / page) return false;
    quint8 type = quint8(h.at(100));
    if (type != 5 && type != 13) return false;
    quint32 cells = u16(h, 103, true), content = u16(h, 105, true); if (!content) content = 65536;
    quint32 header = type == 5 ? 112 : 108;
    if (header + cells * 2 > page || content < header + cells * 2 || content > page - quint8(h.at(20)) || quint8(h.at(107)) > 60) return false;
    if (!schema && (type != 13 || cells)) return false;  // empty sqlite_schema
    out = {QStringLiteral("SQLite 3"), QStringLiteral("schema %1; read %2, write %3").arg(schema).arg(read).arg(write), QStringLiteral("%1-byte pages").arg(page),
           XScanEngine::RECORD_NAME_UNKNOWN, true};
    return true;
}

bool wim(Reader &r, const QByteArray &h, Result &out)
{
    if (h.size() < 208 || h.left(8) != QByteArray("MSWIM\0\0\0", 8) || u32(h, 8) != 208) return false;
    quint32 version = u32(h, 12), chunk = u32(h, 20), flags = u32(h, 16);
    if ((version != 0x10d00 && version != 0xe00) || !u16(h, 40) || u16(h, 40) > u16(h, 42) || u32(h, 120) > u32(h, 44)) return false;
    if ((flags & 2) ? (!power2(chunk) || chunk < 4096 || chunk > 67108864) : chunk != 0) return false;
    for (int p : {48, 72, 96, 124}) {
        quint64 size = u64(h, p) & 0x00ffffffffffffffULL, off = u64(h, p + 8);
        if ((!size && off) || (size && off < 208) || !r.range(off, size)) return false;
    }
    if (!(u64(h, 72) & 0x00ffffffffffffffULL)) return false;
    out = {QStringLiteral("WIM"), QStringLiteral("0x%1").arg(version, 8, 16, QLatin1Char('0')), QStringLiteral("%1 image(s); part %2/%3").arg(u32(h, 44)).arg(u16(h, 40)).arg(u16(h, 42))};
    return true;
}

}  // namespace

bool NFDContainers::detect(QIODevice *pDevice, NFD_Binary::BINARYINFO_STRUCT *pBinaryInfo, XBinary::PDSTRUCT *pPdStruct)
{
    if (!pDevice || !pBinaryInfo || !pDevice->isOpen() || !pDevice->isReadable() || pDevice->isSequential() || pDevice->size() < 8) return false;
    Reader reader(pDevice, pPdStruct);
    QByteArray h = reader.read(0, qMin(reader.size, quint64(512)));
    if (h.isEmpty()) return false;
    Result result = {};
    // Footer recognition precedes short compression signatures, especially a
    // UDIF data fork that happens to start with a zlib stream.
    bool found = dmg(reader, result) || vhd(reader, result) || vhdx(reader, h, result) || qcow(reader, h, result) || vdi(reader, h, result) ||
                 vmdk(reader, h, result) || cpio(reader, h, result) || ar(reader, h, result) || rpm(reader, h, result) ||
                 sqlite(reader, h, result) || wim(reader, h, result) || git(reader, h, result);
    if (!found || !reader.active()) return false;
    NFD_Binary::BASIC_INFO &basic = pBinaryInfo->basic_info;
    basic.id.fileType = result.database ? XBinary::FT_BINARY : XBinary::FT_ARCHIVE;
    NFD_Binary::SCAN_STRUCT record = {};
    record.id = basic.id; record.parentId = basic.parentId;
    record.type = result.database ? XScanEngine::RECORD_TYPE_DATABASE : XScanEngine::RECORD_TYPE_FORMAT; record.name = result.key;
    record.sName = result.name; record.sVersion = result.version; record.sInfo = result.info;
    if (result.database) basic.mapResultDatabases.insert(result.key, record);
    else basic.mapResultArchives.insert(result.key, record);
    return true;
}
