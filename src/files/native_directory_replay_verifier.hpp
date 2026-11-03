// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "held_child.hpp"
#include "metadata_replay.hpp"
#include "prepared_journal_root.hpp"
namespace ck::files {
// Worker-only, independent read descriptions. No mutation methods or caller
// HANDLE/ID factory; inputs retain actual native owners and Root scope.
class DirectoryReplayVerifier {
public:
    virtual ~DirectoryReplayVerifier()=default;
    virtual OpenedEntry& entry()=0;
    virtual Observation<bool> finish_io()=0;
};
Observation<std::unique_ptr<DirectoryReplayVerifier>> create_directory_replay_verifier(
    HeldChild::Pointer, std::shared_ptr<const DirectoryCursor>, std::unique_ptr<OpenedEntry>,
    const MetadataReplaySnapshot&, PreparedJournalRoot::Pointer, std::stop_token = {});
} // namespace ck::files
