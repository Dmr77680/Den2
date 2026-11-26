// SPDX-FileCopyrightText: Copyright 2026 citron Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/format.h>

#include "common/logging.h"
#include "common/settings.h"
#include "core/file_sys/vfs/vfs.h"
#include "core/hle/service/bcat/nextendo_bcat.h"
#include "core/hle/service/bcat/nextendo_zip.h"
#include "web_service/nextendo_api.h"

namespace Service::BCAT::NextendoBcat {

namespace {

// Titles for which Nextendo publishes a BCAT package and that DEN installs it for.
constexpr std::array<u64, 1> kTitles{{
    0x0100C2500FC20000, // Splatoon 3
}};

// Hash of the last installed package, stored next to the directories. It is a file, not a
// directory, so the delivery cache services never list it.
constexpr const char* kHashFileName = ".nextendo_bcat_hash";

constexpr std::chrono::seconds kRecheckInterval{60};

bool WantsPackage(u64 title_id) {
    for (const u64 id : kTitles) {
        if (id == title_id) {
            return true;
        }
    }
    return false;
}

std::string ReadStoredHash(const FileSys::VirtualDir& root) {
    const auto file = root->GetFile(kHashFileName);
    if (file == nullptr) {
        return {};
    }
    const auto bytes = file->ReadAllBytes();
    return std::string(bytes.begin(), bytes.end());
}

void WriteStoredHash(const FileSys::VirtualDir& root, const std::string& hash) {
    auto file = root->GetFile(kHashFileName);
    if (file == nullptr) {
        file = root->CreateFile(kHashFileName);
    }
    if (file == nullptr || !file->Resize(hash.size())) {
        LOG_WARNING(Service_BCAT, "[Nextendo] could not store the BCAT package hash");
        return;
    }
    file->WriteBytes(std::vector<u8>(hash.begin(), hash.end()));
}

} // namespace

void EnsureInstalled(const FileSys::VirtualDir& root, u64 title_id) {
    if (root == nullptr || !WantsPackage(title_id)) {
        return;
    }
    if (!Settings::values.enable_nextendo.GetValue()) {
        return;
    }

    static std::mutex mutex;
    static std::unordered_map<u64, std::chrono::steady_clock::time_point> last_check;

    // One install at a time; a second caller waits for the first and then finds it up to date.
    std::scoped_lock lock{mutex};

    const auto now = std::chrono::steady_clock::now();
    if (const auto it = last_check.find(title_id);
        it != last_check.end() && now - it->second < kRecheckInterval) {
        return;
    }
    last_check[title_id] = now;

    const std::string title_hex = fmt::format("{:016x}", title_id);
    const std::vector<u8> zip = WebService::NextendoApi::DownloadBcatSeed(title_hex);
    if (zip.empty()) {
        LOG_INFO(Service_BCAT,
                 "[Nextendo] no BCAT package received for {} (offline or none published): "
                 "keeping the local cache",
                 title_hex);
        return;
    }

    const std::string new_hash = WebService::NextendoApi::HashBcatSeedHex(zip);
    if (ReadStoredHash(root) == new_hash && !root->GetSubdirectories().empty()) {
        LOG_INFO(Service_BCAT, "[Nextendo] BCAT package for {} is already installed", title_hex);
        return;
    }

    std::vector<NextendoZip::Entry> entries;
    std::string error;
    if (!NextendoZip::Parse(zip, entries, error)) {
        LOG_ERROR(Service_BCAT, "[Nextendo] BCAT package for {} rejected: {}", title_hex, error);
        return;
    }

    struct PendingFile {
        std::string name;
        const std::vector<u8>* data;
    };
    std::map<std::string, std::vector<PendingFile>> directories;
    std::set<std::string> seen_paths;
    for (const auto& entry : entries) {
        std::string dir_name;
        std::string file_name;
        if (!NextendoZip::SplitPackagePath(entry.name, dir_name, file_name)) {
            LOG_ERROR(Service_BCAT, "[Nextendo] BCAT package for {} rejected: bad path \"{}\"",
                      title_hex, entry.name);
            return;
        }
        if (!seen_paths.insert(entry.name).second) {
            LOG_ERROR(Service_BCAT, "[Nextendo] BCAT package for {} rejected: duplicate \"{}\"",
                      title_hex, entry.name);
            return;
        }
        directories[dir_name].push_back({file_name, &entry.data});
    }
    if (directories.empty()) {
        LOG_WARNING(Service_BCAT, "[Nextendo] BCAT package for {} is empty: keeping the cache",
                    title_hex);
        return;
    }

    // The package is the whole delivery cache of the title: drop what it no longer contains.
    for (const auto& sub : root->GetSubdirectories()) {
        const std::string name = sub->GetName();
        if (directories.find(name) == directories.end()) {
            root->DeleteSubdirectoryRecursive(name);
        }
    }

    size_t file_count = 0;
    size_t byte_count = 0;
    for (const auto& [dir_name, files] : directories) {
        root->DeleteSubdirectoryRecursive(dir_name);
        const auto dir = root->CreateSubdirectory(dir_name);
        if (dir == nullptr) {
            LOG_ERROR(Service_BCAT, "[Nextendo] could not create BCAT directory {}/{}", title_hex,
                      dir_name);
            return;
        }
        for (const auto& file : files) {
            const auto out = dir->CreateFile(file.name);
            if (out == nullptr || !out->Resize(file.data->size()) ||
                (!file.data->empty() && out->WriteBytes(*file.data) != file.data->size())) {
                LOG_ERROR(Service_BCAT, "[Nextendo] could not write BCAT file {}/{}/{}",
                          title_hex, dir_name, file.name);
                return;
            }
            ++file_count;
            byte_count += file.data->size();
        }
    }

    WriteStoredHash(root, new_hash);
    LOG_INFO(Service_BCAT,
             "[Nextendo] BCAT package installed for {}: {} directories, {} files, {} bytes",
             title_hex, directories.size(), file_count, byte_count);
}

} // namespace Service::BCAT::NextendoBcat
