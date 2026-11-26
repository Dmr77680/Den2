// SPDX-FileCopyrightText: Copyright 2026 citron Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <zlib.h>

// [Nextendo] Minimal, defensive ZIP reader for the BCAT packages served by
// https://nextendo.network/api/bcat/<titleId>. Only what that package needs is supported:
// stored (0) and deflate (8) entries, no encryption, no ZIP64, no multi-disk archives. Every
// size and offset is bounds-checked against the buffer, and the CRC-32 of each entry is verified.
// Header-only and free of any emulator dependency so it can be tested on its own.
namespace Service::BCAT::NextendoZip {

struct Entry {
    std::string name;
    std::vector<std::uint8_t> data;
};

struct Limits {
    std::size_t max_entries = 512;
    std::size_t max_entry_bytes = 32u * 1024u * 1024u;
    std::size_t max_total_bytes = 32u * 1024u * 1024u;
};

namespace detail {

inline std::uint32_t Le16(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8);
}

inline std::uint32_t Le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

} // namespace detail

// Parses `zip` into `out` (directory entries are skipped). Returns false and fills `error` when
// the archive is malformed, uses an unsupported feature, or exceeds `limits`.
inline bool Parse(std::span<const std::uint8_t> zip, std::vector<Entry>& out, std::string& error,
                  const Limits& limits = {}) {
    using detail::Le16;
    using detail::Le32;

    out.clear();
    const std::uint8_t* const base = zip.data();
    const std::uint64_t size = zip.size();

    constexpr std::uint64_t kEocdSize = 22;
    if (size < kEocdSize) {
        error = "archive too small";
        return false;
    }

    // Locate the end-of-central-directory record (the comment is at most 65535 bytes long).
    std::uint64_t eocd = 0;
    bool found = false;
    const std::uint64_t lowest = size > kEocdSize + 0xFFFF ? size - kEocdSize - 0xFFFF : 0;
    for (std::uint64_t pos = size - kEocdSize;; --pos) {
        if (Le32(base + pos) == 0x06054B50u) {
            eocd = pos;
            found = true;
            break;
        }
        if (pos == lowest) {
            break;
        }
    }
    if (!found) {
        error = "end of central directory not found";
        return false;
    }

    const std::uint32_t disk_no = Le16(base + eocd + 4);
    const std::uint32_t cd_disk = Le16(base + eocd + 6);
    const std::uint32_t entries_on_disk = Le16(base + eocd + 8);
    const std::uint32_t entries_total = Le16(base + eocd + 10);
    const std::uint64_t cd_size = Le32(base + eocd + 12);
    const std::uint64_t cd_offset = Le32(base + eocd + 16);

    if (disk_no != 0 || cd_disk != 0 || entries_on_disk != entries_total) {
        error = "multi-disk archives are not supported";
        return false;
    }
    if (entries_total == 0xFFFFu || cd_size == 0xFFFFFFFFu || cd_offset == 0xFFFFFFFFu) {
        error = "ZIP64 archives are not supported";
        return false;
    }
    if (entries_total > limits.max_entries) {
        error = "too many entries";
        return false;
    }
    if (cd_offset + cd_size > eocd) {
        error = "central directory out of bounds";
        return false;
    }

    const std::uint64_t cd_end = cd_offset + cd_size;
    std::uint64_t pos = cd_offset;
    std::uint64_t total_bytes = 0;

    for (std::uint32_t i = 0; i < entries_total; ++i) {
        if (pos + 46 > cd_end || Le32(base + pos) != 0x02014B50u) {
            error = "bad central directory entry";
            return false;
        }
        const std::uint8_t* const cd = base + pos;
        const std::uint32_t made_by = Le16(cd + 4);
        const std::uint32_t flags = Le16(cd + 8);
        const std::uint32_t method = Le16(cd + 10);
        const std::uint32_t crc_expected = Le32(cd + 16);
        const std::uint64_t comp_size = Le32(cd + 20);
        const std::uint64_t uncomp_size = Le32(cd + 24);
        const std::uint32_t name_len = Le16(cd + 28);
        const std::uint32_t extra_len = Le16(cd + 30);
        const std::uint32_t comment_len = Le16(cd + 32);
        const std::uint32_t external_attrs = Le32(cd + 38);
        const std::uint64_t local_offset = Le32(cd + 42);

        const std::uint64_t header_len = 46ull + name_len + extra_len + comment_len;
        if (pos + header_len > cd_end) {
            error = "central directory entry out of bounds";
            return false;
        }
        std::string name(reinterpret_cast<const char*>(cd + 46), name_len);
        pos += header_len;

        // Directory entries carry no data.
        if (!name.empty() && name.back() == '/' && uncomp_size == 0) {
            continue;
        }
        if ((flags & 1u) != 0) {
            error = "encrypted entries are not supported";
            return false;
        }
        if (method != 0 && method != 8) {
            error = "unsupported compression method";
            return false;
        }
        if (comp_size == 0xFFFFFFFFu || uncomp_size == 0xFFFFFFFFu || local_offset == 0xFFFFFFFFu) {
            error = "ZIP64 entries are not supported";
            return false;
        }
        // Reject symbolic links (made on Unix, S_IFLNK in the high half of the attributes).
        if ((made_by >> 8) == 3 && ((external_attrs >> 16) & 0xF000u) == 0xA000u) {
            error = "symbolic links are not allowed";
            return false;
        }
        if (uncomp_size > limits.max_entry_bytes) {
            error = "entry too large";
            return false;
        }
        total_bytes += uncomp_size;
        if (total_bytes > limits.max_total_bytes) {
            error = "package too large";
            return false;
        }
        if (method == 0 && comp_size != uncomp_size) {
            error = "stored entry size mismatch";
            return false;
        }

        if (local_offset + 30 > size || Le32(base + local_offset) != 0x04034B50u) {
            error = "bad local header";
            return false;
        }
        const std::uint8_t* const lh = base + local_offset;
        const std::uint64_t data_offset = local_offset + 30ull + Le16(lh + 26) + Le16(lh + 28);
        if (data_offset + comp_size > size) {
            error = "entry data out of bounds";
            return false;
        }

        Entry entry;
        entry.name = std::move(name);
        entry.data.resize(static_cast<std::size_t>(uncomp_size));

        if (uncomp_size > 0) {
            if (method == 0) {
                std::memcpy(entry.data.data(), base + data_offset,
                            static_cast<std::size_t>(uncomp_size));
            } else {
                z_stream stream{};
                if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) {
                    error = "inflate init failed";
                    return false;
                }
                stream.next_in = const_cast<Bytef*>(base + data_offset);
                stream.avail_in = static_cast<uInt>(comp_size);
                stream.next_out = entry.data.data();
                stream.avail_out = static_cast<uInt>(uncomp_size);
                const int rc = inflate(&stream, Z_FINISH);
                const bool ok = rc == Z_STREAM_END && stream.total_out == uncomp_size;
                inflateEnd(&stream);
                if (!ok) {
                    error = "inflate failed";
                    return false;
                }
            }
        }

        const std::uint32_t crc_actual =
            entry.data.empty()
                ? 0u
                : static_cast<std::uint32_t>(crc32(0L, entry.data.data(),
                                                    static_cast<uInt>(entry.data.size())));
        if (crc_actual != crc_expected) {
            error = "CRC mismatch";
            return false;
        }

        out.push_back(std::move(entry));
    }

    return true;
}

// A package path must be exactly "<directory>/<file>", each part 1..31 characters taken from
// A-Z a-z 0-9 _ - . (they have to fit a 32-byte DirectoryName / FileName), never "." or "..".
inline bool SplitPackagePath(const std::string& path, std::string& dir, std::string& file) {
    const auto slash = path.find('/');
    if (slash == std::string::npos || slash == 0 || path.find('/', slash + 1) != std::string::npos) {
        return false;
    }
    dir = path.substr(0, slash);
    file = path.substr(slash + 1);

    const auto valid_part = [](const std::string& part) {
        if (part.empty() || part.size() > 31 || part == "." || part == "..") {
            return false;
        }
        for (const char c : part) {
            const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
            if (!ok) {
                return false;
            }
        }
        return true;
    };
    return valid_part(dir) && valid_part(file);
}

} // namespace Service::BCAT::NextendoZip
