#ifndef RARSTREAM_H
#define RARSTREAM_H

#include <QString>
#include <mpv/client.h>

// Plays a file stored uncompressed in a (multi-volume) RAR archive by mapping
// reads straight onto the volume files, so seeking works like a plain file.
// Compressed or encrypted archives are left to mpv's libarchive support.
namespace RarStream {
    void registerProtocol(mpv_handle *mpv);
    bool canStream(const QString &fileName);
    QString streamUrl(const QString &fileName);
}

#endif // RARSTREAM_H
