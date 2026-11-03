// SPDX-License-Identifier: LGPL-2.0-or-later
#include "reviewed_tree_plan.hpp"
#include <cassert>
#include <cstdio>
using namespace ck::files;
int main(){
 ReviewedTreeFacts f;f.source_preservation_qualified=true;f.source_present=f.destination_present=true;f.source_kind=f.destination_kind=ObjectKind::RegularFile;
 for(auto c:{ConflictChoice::KeepBothIncoming,ConflictChoice::Rename,ConflictChoice::KeepBothTarget})f.allowed_choices|=std::uint64_t{1}<<unsigned(c);
 ConflictRuleResult d;d.state=ConflictRuleState::Apply;d.choice=ConflictChoice::KeepBothIncoming;
 for(auto choice:{ConflictChoice::KeepBothIncoming,ConflictChoice::Rename}){
  d.choice=choice;
  auto wrong=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,choice,&d,ReviewedTreeNameSide::Target);
  assert(wrong.required_side==ReviewedTreeNameSide::Incoming&&wrong.allowed_sides==1&&wrong.selection_reason==ReviewedTreeNameReason::WrongSide);
  auto missing=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,choice,&d,{});assert(missing.selection_reason==ReviewedTreeNameReason::AwaitingName);
  auto good=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,choice,&d,ReviewedTreeNameSide::Incoming);assert(good.selection_reason==ReviewedTreeNameReason::None);
 }
 d.choice=ConflictChoice::KeepBothTarget;
 auto no_retention=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Target);
 assert(no_retention.required_side==ReviewedTreeNameSide::Target&&!no_retention.allowed_sides&&no_retention.capability_reason==ReviewedTreeNameReason::RetentionUnavailable);
 f.retained_target_available=true;
 f.source_preservation_qualified=false;
 auto strict_unknown=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Target);
 assert(strict_unknown.capability_reason==ReviewedTreeNameReason::SourceMetadataUnqualified&&!strict_unknown.allowed_sides);
 f.source_preservation_qualified=true;
 auto target=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Target);assert(target.allowed_sides==2&&target.selection_reason==ReviewedTreeNameReason::None);
 auto incoming=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Incoming);assert(incoming.selection_reason==ReviewedTreeNameReason::WrongSide);
 auto compare=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Compare,d.choice,&d,ReviewedTreeNameSide::Target);assert(!compare.allowed_sides&&compare.capability_reason==ReviewedTreeNameReason::ReportOnly);
 d.choice=ConflictChoice::KeepTarget;auto ignored=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Incoming);assert(!ignored.required_side&&ignored.selection_reason==ReviewedTreeNameReason::NameNotAllowed);
 d.choice=ConflictChoice::Rename;f.allowed_choices=0;f.source_preservation_qualified=false;auto metadata=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Incoming);assert(metadata.capability_reason==ReviewedTreeNameReason::SourceMetadataUnqualified&&!metadata.allowed_sides);
 auto invalid=assess_reviewed_tree_name_feedback(f,ComparisonProfile::Copy,d.choice,&d,ReviewedTreeNameSide::Incoming,true);assert(invalid.selection_reason==ReviewedTreeNameReason::InvalidSelection);
 std::puts("tree name-side core: Incoming/Rename, genuine retention Target, report-only and rejection reasons PASS");
}
