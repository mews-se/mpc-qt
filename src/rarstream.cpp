#include <algorithm>
#include <QFile>
#include <QFileInfo>
#include <QList>
#include <QRegularExpression>
#include <QtEndian>
#include <mpv/stream_cb.h>
#include "logger.h"
#include "rarstream.h"

static constexpr char logModule[] = "rarstream";
static constexpr char protocol[] = "rar";
static constexpr char urlPrefix[] = "rar://";

static const QByteArray rar4Signature("Rar!\x1a\x07\x00", 7);
static const QByteArray rar5Signature("Rar!\x1a\x07\x01\x00", 8);

namespace {

struct Entry {
    QString name;
    qint64 dataOffset = 0;
    qint64 dataSize = 0;
    qint64 unpackedSize = -1;
    bool stored = false;
    bool encrypted = false;
    bool directory = false;
    bool continuesBefore = false;
    bool continuesAfter = false;
};

struct Segment {
    QString path;
    qint64 offset;
    qint64 length;
    qint64 start;
};

quint16 le16(const QByteArray &b, int pos)
{
    return qFromLittleEndian<quint16>(b.constData() + pos);
}

quint32 le32(const QByteArray &b, int pos)
{
    return qFromLittleEndian<quint32>(b.constData() + pos);
}

bool readVint(const QByteArray &b, int &pos, quint64 &value)
{
    value = 0;
    for (int shift = 0; shift < 64 && pos < b.size(); shift += 7) {
        quint8 byte = b[pos++];
        value |= quint64(byte & 0x7f) << shift;
        if (!(byte & 0x80))
            return true;
    }
    return false;
}

bool scanRar4(QFile &file, QList<Entry> &entries)
{
    enum { MainHeader = 0x73, FileHeader = 0x74, ServiceHeader = 0x7a, EndHeader = 0x7b };
    qint64 pos = rar4Signature.size();
    while (pos + 7 <= file.size()) {
        if (!file.seek(pos))
            return false;
        QByteArray head = file.read(7);
        if (head.size() < 7)
            return false;
        quint8 type = head[2];
        quint16 flags = le16(head, 3);
        quint16 headSize = le16(head, 5);
        if (headSize < 7)
            return false;
        head += file.read(headSize - 7);
        if (head.size() < headSize)
            return false;

        quint64 addSize = 0;
        if (flags & 0x8000) {
            if (headSize < 11)
                return false;
            addSize = le32(head, 7);
        }
        if (type == MainHeader && (flags & 0x0080))
            return false; // headers are encrypted
        if (type == EndHeader)
            return true;
        if (type == FileHeader || type == ServiceHeader) {
            if (headSize < 32)
                return false;
            quint64 unpackedSize = le32(head, 11);
            int nameOffset = 32;
            if (flags & 0x0100) {
                if (headSize < 40)
                    return false;
                addSize |= quint64(le32(head, 32)) << 32;
                unpackedSize |= quint64(le32(head, 36)) << 32;
                nameOffset = 40;
            }
            int nameSize = le16(head, 26);
            if (nameOffset + nameSize > headSize)
                return false;
            if (type == FileHeader) {
                // Unicode names come after the plain name and a zero byte.
                QByteArray name = head.mid(nameOffset, nameSize);
                if (int zero = name.indexOf('\0'); zero >= 0)
                    name.truncate(zero);
                Entry e;
                e.name = QString::fromUtf8(name);
                e.dataOffset = pos + headSize;
                e.dataSize = addSize;
                e.unpackedSize = unpackedSize;
                e.stored = quint8(head[25]) == 0x30;
                e.encrypted = flags & 0x0004;
                e.directory = (flags & 0x00e0) == 0x00e0;
                e.continuesBefore = flags & 0x0001;
                e.continuesAfter = flags & 0x0002;
                entries.append(e);
            }
        }
        pos += headSize + addSize;
    }
    return true;
}

bool hasEncryptionRecord(const QByteArray &head, int pos, int end)
{
    while (pos < end) {
        quint64 size, type;
        if (!readVint(head, pos, size) || size > quint64(end - pos))
            return false;
        int next = pos + int(size);
        if (!readVint(head, pos, type))
            return false;
        if (type == 0x01)
            return true;
        pos = next;
    }
    return false;
}

bool scanRar5(QFile &file, QList<Entry> &entries)
{
    enum { FileHeader = 2, EncryptionHeader = 4, EndHeader = 5 };
    qint64 pos = rar5Signature.size();
    while (pos + 7 <= file.size()) {
        if (!file.seek(pos))
            return false;
        // CRC32, then the header size as a vint of at most three bytes
        QByteArray start = file.read(7);
        int sizeEnd = 4;
        quint64 headSize;
        if (!readVint(start, sizeEnd, headSize) || headSize == 0 || headSize > 0x200000)
            return false;
        if (!file.seek(pos + sizeEnd))
            return false;
        QByteArray head = file.read(headSize);
        if (head.size() < qsizetype(headSize))
            return false;

        int p = 0;
        quint64 type, flags, extraSize = 0, dataSize = 0;
        if (!readVint(head, p, type) || !readVint(head, p, flags))
            return false;
        if ((flags & 0x0001) && !readVint(head, p, extraSize))
            return false;
        if ((flags & 0x0002) && !readVint(head, p, dataSize))
            return false;
        if (extraSize > headSize)
            return false;
        if (type == EncryptionHeader)
            return false;
        if (type == EndHeader)
            return true;

        qint64 dataOffset = pos + sizeEnd + headSize;
        if (type == FileHeader) {
            quint64 fileFlags, unpackedSize, attributes, compression, hostOs, nameSize;
            if (!readVint(head, p, fileFlags) || !readVint(head, p, unpackedSize)
                    || !readVint(head, p, attributes))
                return false;
            if (fileFlags & 0x0002)
                p += 4; // modification time
            if (fileFlags & 0x0004)
                p += 4; // data CRC32
            if (!readVint(head, p, compression) || !readVint(head, p, hostOs)
                    || !readVint(head, p, nameSize))
                return false;
            if (p + nameSize > headSize)
                return false;
            Entry e;
            e.name = QString::fromUtf8(head.mid(p, nameSize));
            e.dataOffset = dataOffset;
            e.dataSize = dataSize;
            e.unpackedSize = (fileFlags & 0x0008) ? -1 : qint64(unpackedSize);
            e.stored = ((compression >> 7) & 0x07) == 0;
            e.encrypted = hasEncryptionRecord(head, headSize - extraSize, headSize);
            e.directory = fileFlags & 0x0001;
            e.continuesBefore = flags & 0x0008;
            e.continuesAfter = flags & 0x0010;
            entries.append(e);
        }
        pos = dataOffset + dataSize;
    }
    return true;
}

bool scanVolume(const QString &path, QList<Entry> &entries)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return false;
    QByteArray signature = file.read(rar5Signature.size());
    if (signature.startsWith(rar5Signature))
        return scanRar5(file, entries);
    if (signature.startsWith(rar4Signature))
        return scanRar4(file, entries);
    return false;
}

// The biggest file that starts in the first volume is the one to play.
int pickEntry(const QList<Entry> &entries)
{
    int best = -1;
    for (int i = 0; i < entries.size(); i++) {
        if (entries[i].directory || entries[i].continuesBefore)
            continue;
        if (best < 0 || entries[i].unpackedSize > entries[best].unpackedSize)
            best = i;
    }
    return best;
}

const QRegularExpression newStyleName(R"(^(.*\.part)(\d+)(\.rar)$)",
                                      QRegularExpression::CaseInsensitiveOption);

// Volume names are either name.part1.rar, name.part2.rar, ... or the older
// name.rar, name.r00 ... name.r99, name.s00 and so on.
QString volumeName(const QString &first, int index)
{
    if (auto m = newStyleName.match(first); m.hasMatch()) {
        int width = m.captured(2).size();
        int number = m.captured(2).toInt() + index;
        return m.captured(1) + QString::number(number).rightJustified(width, '0')
                + m.captured(3);
    }
    if (index == 0)
        return first;
    QString base = first.chopped(3);
    QChar letter(char16_t((first.right(3)[0].isUpper() ? 'R' : 'r') + (index - 1) / 100));
    return base + letter + QString::number((index - 1) % 100).rightJustified(2, '0');
}

QString firstVolume(const QString &fileName)
{
    auto m = newStyleName.match(fileName);
    if (!m.hasMatch() || m.captured(2).toInt() <= 1)
        return fileName;
    QString first = m.captured(1) + QString("1").rightJustified(m.captured(2).size(), '0')
            + m.captured(3);
    return QFileInfo::exists(first) ? first : fileName;
}

class RarReader {
public:
    bool open(const QString &fileName);
    int64_t read(char *buf, uint64_t nbytes);
    int64_t seek(int64_t offset);
    int64_t size() const { return totalSize; }

private:
    QList<Segment> segments;
    qint64 totalSize = 0;
    qint64 position = 0;
    QFile file;
};

bool RarReader::open(const QString &fileName)
{
    QList<Entry> entries;
    if (!scanVolume(fileName, entries))
        return false;
    int index = pickEntry(entries);
    if (index < 0 || !entries[index].stored || entries[index].encrypted)
        return false;

    Entry entry = entries[index];
    QString path = fileName;
    for (int volume = 1;; volume++) {
        if (entry.dataSize > 0)
            segments.append({ path, entry.dataOffset, entry.dataSize, totalSize });
        totalSize += entry.dataSize;
        if (!entry.continuesAfter)
            break;

        path = volumeName(fileName, volume);
        entries.clear();
        if (!scanVolume(path, entries)) {
            Logger::log(logModule, QString("missing or unreadable volume %1").arg(path));
            return false;
        }
        auto next = std::find_if(entries.cbegin(), entries.cend(), [&](const Entry &e) {
            return e.continuesBefore && e.name == entry.name;
        });
        if (next == entries.cend()) {
            Logger::log(logModule, QString("%1 does not continue %2").arg(path, entry.name));
            return false;
        }
        entry = *next;
    }
    if (entry.unpackedSize >= 0 && entry.unpackedSize != totalSize) {
        Logger::log(logModule, QString("%1: volumes hold %2 of %3 bytes")
                    .arg(entry.name).arg(totalSize).arg(entry.unpackedSize));
        return false;
    }
    Logger::log(logModule, QString("streaming %1 from %2 volume(s)")
                .arg(entry.name).arg(segments.size()));
    return true;
}

int64_t RarReader::read(char *buf, uint64_t nbytes)
{
    if (position >= totalSize)
        return 0;
    auto s = std::upper_bound(segments.cbegin(), segments.cend(), position,
                              [](qint64 pos, const Segment &seg) { return pos < seg.start; }) - 1;
    if (file.fileName() != s->path) {
        file.close();
        file.setFileName(s->path);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Unbuffered))
            return -1;
    }
    qint64 within = position - s->start;
    qint64 wanted = std::min<qint64>(nbytes, s->length - within);
    if (!file.seek(s->offset + within))
        return -1;
    qint64 got = file.read(buf, wanted);
    if (got <= 0)
        return -1;
    position += got;
    return got;
}

int64_t RarReader::seek(int64_t offset)
{
    if (offset < 0 || offset > totalSize)
        return MPV_ERROR_GENERIC;
    position = offset;
    return position;
}

int64_t readFn(void *cookie, char *buf, uint64_t nbytes)
{
    return static_cast<RarReader*>(cookie)->read(buf, nbytes);
}

int64_t seekFn(void *cookie, int64_t offset)
{
    return static_cast<RarReader*>(cookie)->seek(offset);
}

int64_t sizeFn(void *cookie)
{
    return static_cast<RarReader*>(cookie)->size();
}

void closeFn(void *cookie)
{
    delete static_cast<RarReader*>(cookie);
}

int openFn(void *userData, char *uri, mpv_stream_cb_info *info)
{
    Q_UNUSED(userData)
    QString fileName = QString::fromUtf8(uri).mid(qstrlen(urlPrefix));
    auto reader = new RarReader;
    if (!reader->open(fileName)) {
        delete reader;
        return MPV_ERROR_LOADING_FAILED;
    }
    info->cookie = reader;
    info->read_fn = readFn;
    info->seek_fn = seekFn;
    info->size_fn = sizeFn;
    info->close_fn = closeFn;
    return 0;
}

}

void RarStream::registerProtocol(mpv_handle *mpv)
{
    if (mpv_stream_cb_add_ro(mpv, protocol, nullptr, openFn) < 0)
        Logger::log(logModule, "could not register the rar protocol");
}

bool RarStream::canStream(const QString &fileName)
{
    if (!fileName.endsWith(".rar", Qt::CaseInsensitive))
        return false;
    QList<Entry> entries;
    if (!scanVolume(firstVolume(fileName), entries))
        return false;
    int index = pickEntry(entries);
    return index >= 0 && entries[index].stored && !entries[index].encrypted;
}

QString RarStream::streamUrl(const QString &fileName)
{
    return urlPrefix + firstVolume(fileName);
}
