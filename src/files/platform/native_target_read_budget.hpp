// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#pragma once
#include "../metadata_capture_job.hpp"
namespace ck::files::detail {
// Resource accounting only, never file/creation/replay authority. All consumers
// of this budget belong to the same native worker, as MetadataCaptureBudget
// requires. Keep the lease until its actual native owners are consumed.
class NativeTargetReadBudget final {
public:
    static Observation<std::shared_ptr<NativeTargetReadBudget>> acquire(
        std::shared_ptr<MetadataCaptureBudget> budget,std::size_t handles,std::size_t bytes) {
        using R=Observation<std::shared_ptr<NativeTargetReadBudget>>;
        if(!budget||!budget->limits_.valid())return R::unavailable(ObservationState::Failed,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InvalidLimit),"target_read.invalid_budget"});
        const auto& limit=budget->limits_;
        if(budget->handles_>limit.max_retained_handles||handles>limit.max_retained_handles-budget->handles_||
           budget->metadata_>limit.max_metadata_bytes||bytes>limit.max_metadata_bytes-budget->metadata_)
            return R::unavailable(ObservationState::Unsupported,
                {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::InventoryLimit),"target_read.budget_exhausted"});
        auto lease=std::shared_ptr<NativeTargetReadBudget>(new NativeTargetReadBudget(std::move(budget),handles,bytes));
        return R::available(std::move(lease));
    }
    // A real native clone owns a separate bounded lease. Copying the parent
    // lease would undercount its independent descriptor and object lifetime.
    static Observation<std::shared_ptr<NativeTargetReadBudget>> acquire_child(
        const std::shared_ptr<NativeTargetReadBudget>& parent,std::size_t handles,std::size_t bytes) {
        using R=Observation<std::shared_ptr<NativeTargetReadBudget>>;
        if(!parent)return R::unavailable(ObservationState::Unsupported,
            {ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::ProviderReviewRequired),"target_read.parent_lease_required"});
        return acquire(parent->budget_,handles,bytes);
    }
    ~NativeTargetReadBudget(){budget_->handles_-=handles_;budget_->metadata_-=bytes_;}
    NativeTargetReadBudget(const NativeTargetReadBudget&)=delete;
    NativeTargetReadBudget& operator=(const NativeTargetReadBudget&)=delete;
private:
    NativeTargetReadBudget(std::shared_ptr<MetadataCaptureBudget> budget,std::size_t handles,std::size_t bytes)
        :budget_(std::move(budget)),handles_(handles),bytes_(bytes){budget_->handles_+=handles_;budget_->metadata_+=bytes_;}
    std::shared_ptr<MetadataCaptureBudget> budget_;
    std::size_t handles_,bytes_;
};
} // namespace ck::files::detail
