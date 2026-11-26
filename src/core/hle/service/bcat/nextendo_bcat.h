// SPDX-FileCopyrightText: Copyright 2026 citron Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include "common/common_types.h"
#include "core/file_sys/vfs/vfs_types.h"

// [Nextendo] Online data (BCAT) for the games that need it. Nextendo publishes one ZIP per title
// at https://nextendo.network/api/bcat/<titleId>; the ZIP is the whole delivery cache of that
// title (<directory>/<file>). Splatoon 3 reads its schedule from it and ends with
// "A communication error has occurred" / 2010-0212 when its delivery cache is empty.
namespace Service::BCAT::NextendoBcat {

// Downloads the package of `title_id` and installs it into `root` (that title's delivery cache
// directory) when it changed since the last installation. Does nothing for titles without a
// package, when Nextendo is disabled, or when the package was checked less than a minute ago.
// Never throws; on any failure (offline, 204, bad archive) the existing cache is kept as it is.
void EnsureInstalled(const FileSys::VirtualDir& root, u64 title_id);

} // namespace Service::BCAT::NextendoBcat
