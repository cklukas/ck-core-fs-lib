// Copyright (c) 2026 C. Klukas. All rights reserved.
// SPDX-License-Identifier: LGPL-2.0-or-later
#include "directory_metadata_apply.hpp"
#include "platform/prepared_journal_root_bridge.hpp"
#include "sha256.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "native_trash.hpp"
#include <windows.h>
#include <winternl.h>
#endif
namespace ck::files {
namespace {
Observation<bool> reject(const char* operation,ObservationState state=ObservationState::Unsupported,
    AdapterError code=AdapterError::ProviderReviewRequired){return Observation<bool>::unavailable(state,{ErrorDomain::Adapter,static_cast<std::int64_t>(code),operation});}
template<class T>Observation<bool> propagate(const Observation<T>& value){const auto&e=*value.unavailable_detail();return Observation<bool>::unavailable(e.state,e.error);}
bool same(const Observation<ObjectIdentity>&a,const Observation<ObjectIdentity>&b){return a.value()&&b.value()&&compare_identity(*a.value(),*b.value())==IdentityComparison::Same;}
bool privileged(const AttributeValue& value){if(attribute_role(value.identifier,value.native_flags.value()?*value.native_flags.value():0)==AttributeRole::Security)return true;
 const auto* name=value.identifier.posix_bytes();return name&&(name->starts_with("security.")||name->starts_with("trusted.")||*name=="com.apple.macl"||*name=="com.apple.rootless");}
void remember(DirectorySourceFailure& first,ObservationState state,ErrorDomain domain,std::int64_t code,std::string_view operation)noexcept {
 if(first.present)return;first.present=true;first.state=state;first.domain=domain;first.code=code;
 std::copy_n(operation.data(),std::min(operation.size(),first.operation.size()-1),first.operation.data());}
class StreamWriter {
public:virtual ~StreamWriter()=default;
 virtual Observation<std::size_t> write(std::uint64_t,std::span<const std::byte>)=0;
 virtual Observation<bool> finish_io()=0;
};
#ifdef _WIN32
template<class T>Observation<T> win_error(DWORD code,const char* operation){return Observation<T>::unavailable(code==ERROR_ACCESS_DENIED?ObservationState::Denied:ObservationState::Failed,{ErrorDomain::Win32,code,operation});}
bool matches(HANDLE handle,const ObjectIdentity& owner){FILE_ID_INFO id{};if(!GetFileInformationByHandleEx(handle,FileIdInfo,&id,sizeof(id)))return false;
 NativeIdentifier object;std::memcpy(object.bytes.data(),id.FileId.Identifier,16);return owner.scheme==IdentityScheme::WindowsFileId128&&
 owner.volume==NativeIdentifier::from_u64(id.VolumeSerialNumber)&&owner.object==object;}
class KernelHandle final {
public:
 KernelHandle(HANDLE handle,PreparedJournalRoot::Pointer root,bool dirty=false):handle_(handle),root_(std::move(root)),dirty_(dirty){}
 ~KernelHandle(){close();}
 KernelHandle(const KernelHandle&)=delete;KernelHandle& operator=(const KernelHandle&)=delete;
 HANDLE get()const noexcept{return handle_;}
 void adopt(HANDLE handle,bool dirty)noexcept{handle_=handle==INVALID_HANDLE_VALUE?nullptr:handle;dirty_=dirty;}
 void close()noexcept {if(!handle_)return;const auto handle=std::exchange(handle_,nullptr);
  const DWORD flush=dirty_&&!FlushFileBuffers(handle)?GetLastError():ERROR_SUCCESS;
  const DWORD close=CloseHandle(handle)?ERROR_SUCCESS:GetLastError();
  if(flush){code_=flush;operation_="directory_apply.stream_FlushFileBuffers";}
  else if(close){code_=close;operation_="directory_apply.stream_CloseHandle";}
  if(code_&&root_)detail::record_prepared_journal_consumer_failure(*root_,ObservationState::Failed,ErrorDomain::Win32,code_,operation_);
  root_.reset();}
 DWORD code()const noexcept{return code_;}const char* operation()const noexcept{return operation_;}
private:HANDLE handle_;PreparedJournalRoot::Pointer root_;bool dirty_;DWORD code_=0;const char* operation_="directory_apply.stream_close";
};
class WindowsStreamWriter final:public StreamWriter {
public:
 WindowsStreamWriter(std::unique_ptr<KernelHandle> handle,ObjectIdentity owner):handle_(std::move(handle)),owner_(std::move(owner)){}
 Observation<std::size_t> write(std::uint64_t offset,std::span<const std::byte> bytes)override {
  if(!handle_||!handle_->get()||!matches(handle_->get(),owner_)||offset>std::uint64_t(std::numeric_limits<LONGLONG>::max())||bytes.size()>MAXDWORD)
   return Observation<std::size_t>::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,static_cast<std::int64_t>(AdapterError::MetadataChanged),"directory_apply.writer_binding"});
  LARGE_INTEGER position{};position.QuadPart=static_cast<LONGLONG>(offset);if(!SetFilePointerEx(handle_->get(),position,nullptr,FILE_BEGIN))return win_error<std::size_t>(GetLastError(),"directory_apply.stream_seek");
  DWORD written=0;if(!WriteFile(handle_->get(),bytes.data(),static_cast<DWORD>(bytes.size()),&written,nullptr))return win_error<std::size_t>(GetLastError(),"directory_apply.WriteFile");
  return Observation<std::size_t>::available(written);
 }
 Observation<bool> finish_io()override {handle_->close();return handle_->code()?win_error<bool>(handle_->code(),handle_->operation()):Observation<bool>::available(true);}
private:std::unique_ptr<KernelHandle> handle_;ObjectIdentity owner_;
};
Observation<std::unique_ptr<KernelHandle>> open_stream(const DirectoryCursor& cursor,const NativeFeatureIdentifier& identifier,
 const ObjectIdentity& owner,PreparedJournalRoot::Pointer root,bool writing){using R=Observation<std::unique_ptr<KernelHandle>>;
 const auto* units=identifier.windows_units();if(!units||units->size()<=7||units->front()!=u':'||!units->ends_with(u":$DATA")||units->size()>32767||
  units->substr(1,units->size()-7).find_first_of(u":/\\\0",0,4)!=std::u16string::npos)return R::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,14,"directory_apply.stream_name"});
 auto duplicated=duplicate_windows_trash_parent(cursor);if(!duplicated.value()){const auto&e=*duplicated.unavailable_detail();return R::unavailable(e.state,e.error);}
 KernelHandle directory(std::move(duplicated).take_value().release(),root);
 FILE_STANDARD_INFO base{};FILE_ATTRIBUTE_TAG_INFO attributes{};
 if(!matches(directory.get(),owner)||!GetFileInformationByHandleEx(directory.get(),FileStandardInfo,&base,sizeof(base))||!base.Directory||base.DeletePending||
  !GetFileInformationByHandleEx(directory.get(),FileAttributeTagInfo,&attributes,sizeof(attributes))||(attributes.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))
  return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,15,"directory_apply.native_directory_binding"});
 std::wstring text(units->begin(),units->end());UNICODE_STRING name{};name.Buffer=text.data();name.Length=static_cast<USHORT>(text.size()*sizeof(wchar_t));name.MaximumLength=name.Length;
 OBJECT_ATTRIBUTES object{};InitializeObjectAttributes(&object,&name,0,directory.get(),nullptr);IO_STATUS_BLOCK io{};HANDLE raw=nullptr;
 auto result=std::make_unique<KernelHandle>(nullptr,root);
 const auto status=NtCreateFile(&raw,FILE_READ_ATTRIBUTES|SYNCHRONIZE|(writing?FILE_WRITE_DATA:DELETE),&object,&io,nullptr,FILE_ATTRIBUTE_NORMAL,
  FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,writing?FILE_OVERWRITE_IF:FILE_OPEN,FILE_OPEN_REPARSE_POINT|FILE_OPEN_NO_RECALL|FILE_SYNCHRONOUS_IO_NONALERT,nullptr,0);
 result->adopt(raw,writing&&status==0);
 if(status!=0)return R::unavailable(ObservationState::Failed,{ErrorDomain::NtStatus,static_cast<std::uint32_t>(status),"directory_apply.NtCreateFile"});
 if((writing?(io.Information!=FILE_CREATED&&io.Information!=FILE_OVERWRITTEN):io.Information!=FILE_OPENED)||!matches(result->get(),owner))
  return R::unavailable(ObservationState::Changed,{ErrorDomain::Adapter,15,"directory_apply.stream_binding"});
 directory.close();if(directory.code())return win_error<std::unique_ptr<KernelHandle>>(directory.code(),directory.operation());
 return R::available(std::move(result));
}
Observation<std::unique_ptr<StreamWriter>> writer_for(const DirectoryCursor& cursor,const NativeFeatureIdentifier& identifier,const ObjectIdentity& owner,
 PreparedJournalRoot::Pointer root){auto opened=open_stream(cursor,identifier,owner,std::move(root),true);if(!opened.value()){const auto&e=*opened.unavailable_detail();return Observation<std::unique_ptr<StreamWriter>>::unavailable(e.state,e.error);}
 return Observation<std::unique_ptr<StreamWriter>>::available(std::make_unique<WindowsStreamWriter>(std::move(opened).take_value(),owner));}
Observation<bool> remove_stream(const DirectoryCursor& cursor,const NativeFeatureIdentifier& identifier,const ObjectIdentity& owner,PreparedJournalRoot::Pointer root){
 auto opened=open_stream(cursor,identifier,owner,std::move(root),false);if(!opened.value())return propagate(opened);auto handle=std::move(opened).take_value();
 FILE_DISPOSITION_INFO_EX disposition{};disposition.Flags=FILE_DISPOSITION_FLAG_DELETE|FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
 const DWORD error=SetFileInformationByHandle(handle->get(),FileDispositionInfoEx,&disposition,sizeof(disposition))?ERROR_SUCCESS:GetLastError();
 handle->close();if(handle->code())return win_error<bool>(handle->code(),handle->operation());
 return error?win_error<bool>(error,"directory_apply.stream_disposition"):Observation<bool>::available(true);
}
#else
Observation<std::unique_ptr<StreamWriter>> writer_for(const DirectoryCursor&,const NativeFeatureIdentifier&,const ObjectIdentity&,PreparedJournalRoot::Pointer){
 return Observation<std::unique_ptr<StreamWriter>>::unavailable(ObservationState::Unsupported,{ErrorDomain::Adapter,14,"directory_apply.native_windows_streams_required"});}
Observation<bool> remove_stream(const DirectoryCursor&,const NativeFeatureIdentifier&,const ObjectIdentity&,PreparedJournalRoot::Pointer){return reject("directory_apply.native_windows_streams_required");}
#endif
}
Observation<bool> qualify_directory_metadata_source(const NativeMetadataProof& proof){if(proof.io_finished())return reject("directory_apply.closed_source",ObservationState::Changed,AdapterError::InvalidAccess);
 const auto& snapshot=proof.snapshot();if(!snapshot.policy.valid()||!snapshot.basic.identity.value()||
 !snapshot.basic.kind.value()||*snapshot.basic.kind.value()!=ObjectKind::Directory)return reject("directory_apply.source_policy_kind");
 if(snapshot.basic.posix_permissions.value()&&(*snapshot.basic.posix_permissions.value()&07000U)&&!snapshot.policy.allow_privilege_metadata)return reject("directory_apply.source_privilege_mode");
 for(std::size_t i=0;i<snapshot.attributes.size();++i){const auto& attribute=snapshot.attributes[i];if(!same(attribute.owner,snapshot.basic.identity))return reject("directory_apply.source_attribute_owner",ObservationState::Changed,AdapterError::UnqualifiedIdentity);
  if((privileged(attribute)&&!snapshot.policy.allow_privilege_metadata)||attribute_role(attribute.identifier,attribute.native_flags.value()?*attribute.native_flags.value():0)==AttributeRole::InterpretationRequired)return reject("directory_apply.source_attribute_interpretation");
  for(std::size_t j=0;j<i;++j)if(attribute.identifier==snapshot.attributes[j].identifier)return reject("directory_apply.source_duplicate",ObservationState::Failed,AdapterError::InvalidIdentifier);
  if(auto* name=attribute.identifier.windows_ea_bytes()){std::string upper=*name;for(auto& byte:upper)if(byte>='a'&&byte<='z')byte=char(byte-'a'+'A');if(upper.starts_with("$KERNEL.")||!attribute.native_flags.value()||*attribute.native_flags.value()!=0)return reject("directory_apply.source_windows_ea");}}
 for(const auto& security:snapshot.security)if(!same(security.owner,snapshot.basic.identity))return reject("directory_apply.source_security_owner",ObservationState::Changed,AdapterError::UnqualifiedIdentity);
 if(snapshot.channel_coverage==DataChannelCoverage::WindowsFileStreamInfo)return verify_native_metadata_replay_channels(snapshot);
 return snapshot.channels.empty()?Observation<bool>::available(true):reject("directory_apply.source_channels_unqualified");
}
struct DirectoryMetadataApplyJob::Impl {
 Impl(OpenedEntry& writer,HeldChild::Pointer target,std::shared_ptr<const DirectoryCursor> cursor,std::shared_ptr<const NativeMetadataProof> source,
  PreparedJournalRoot::Pointer root,ContentReadLimits limits,std::function<Observation<bool>(std::stop_token)> membership)
  :writer(&writer),target(std::move(target)),cursor(std::move(cursor)),source(std::move(source)),root(std::move(root)),limits(limits),membership(std::move(membership)){}
 OpenedEntry* writer;HeldChild::Pointer target;std::shared_ptr<const DirectoryCursor> cursor;std::shared_ptr<const NativeMetadataProof> source;
 PreparedJournalRoot::Pointer root;ContentReadLimits limits;std::function<Observation<bool>(std::stop_token)> membership;
 DirectoryApplyProgress progress;BasicMetadata applied;std::optional<AttributeCatalog> attributes;std::vector<NativeFeatureIdentifier> remove_channels;
 std::size_t index=0,written=0;std::uint64_t offset=0;Sha256 hash;std::vector<std::byte> pending;std::unique_ptr<StreamWriter> stream;
 void failure(const UnavailableObservation& error)noexcept{remember(progress.failure,error.state,error.error.domain,error.error.code,error.error.operation);}
 void close_stream()noexcept{if(!stream)return;try{auto done=stream->finish_io();if(!done.value()){const auto&e=*done.unavailable_detail();remember(progress.finish_failure,e.state,e.error.domain,e.error.code,e.error.operation);}
   else if(!*done.value())remember(progress.finish_failure,ObservationState::Unknown,ErrorDomain::Adapter,2,"directory_apply.finish_false");}
  catch(...){detail::PreparedJournalConsumerFailure first;if(root&&detail::read_prepared_journal_consumer_failure(*root,first)&&!first.pending)remember(progress.finish_failure,first.state,first.domain,first.code,first.operation.data());
   else remember(progress.finish_failure,ObservationState::Unknown,ErrorDomain::Adapter,2,"directory_apply.finish_exception");}
  stream.reset();if(progress.finish_failure.present&&root){const auto&e=progress.finish_failure;detail::record_prepared_journal_consumer_failure(*root,e.state,e.domain,e.code,e.operation.data());}}
 void release()noexcept{close_stream();pending.clear();writer=nullptr;target.reset();cursor.reset();source.reset();membership={};root.reset();progress.worker_drained=true;}
 Observation<bool> attribute(const AttributeValue& expected){if(attributes){const auto found=std::find_if(attributes->attributes.begin(),attributes->attributes.end(),[&](const auto& value){return value.identifier==expected.identifier;});
   if(found!=attributes->attributes.end()){auto value=writer->read_attribute(expected.identifier,source->snapshot().policy.limits);if(!value.value())return propagate(value);auto now=writer->inspect_basic();if(!now.value())return propagate(now);
    if(!same(value.value()->owner,now.value()->identity))return reject("directory_apply.attribute_binding",ObservationState::Changed,AdapterError::MetadataChanged);
    const auto&a=value.value()->native_flags;const auto&b=expected.native_flags;const bool flags=a.value()&&b.value()?*a.value()==*b.value():!a.value()&&!b.value()&&a.state()==b.state();
    if(value.value()->bytes==expected.bytes&&flags)return Observation<bool>::available(true);}}
  progress.effects=true;return writer->apply_replay_attribute(expected,source->snapshot().policy);}
};
DirectoryMetadataApplyJob::DirectoryMetadataApplyJob(std::unique_ptr<Impl> impl):impl_(std::move(impl)){}
DirectoryMetadataApplyJob::~DirectoryMetadataApplyJob(){impl_->release();}
const DirectoryApplyProgress& DirectoryMetadataApplyJob::progress()const noexcept{return impl_->progress;}
const BasicMetadata& DirectoryMetadataApplyJob::applied_basic()const noexcept{return impl_->applied;}
Observation<DirectoryMetadataApplyJob::Pointer> DirectoryMetadataApplyJob::create(OpenedEntry& writer,HeldChild::Pointer target,
 std::shared_ptr<const DirectoryCursor> cursor,std::shared_ptr<const NativeMetadataProof> source,PreparedJournalRoot::Pointer root,
 ContentReadLimits limits,std::function<Observation<bool>(std::stop_token)> membership){if(!target||!cursor||!source||!root||!limits.valid()||!membership)
 return Observation<Pointer>::unavailable(ObservationState::Failed,{ErrorDomain::Adapter,11,"directory_apply.request"});
 auto qualified=qualify_directory_metadata_source(*source);if(!qualified.value()){const auto&e=*qualified.unavailable_detail();return Observation<Pointer>::unavailable(e.state,e.error);}
 return Observation<Pointer>::available(Pointer(new DirectoryMetadataApplyJob(std::make_unique<Impl>(writer,std::move(target),std::move(cursor),std::move(source),std::move(root),limits,std::move(membership)))));}
Observation<bool> DirectoryMetadataApplyJob::continue_metadata(){if(impl_->progress.phase!=DirectoryApplyPhase::AwaitingVerifier)return reject("directory_apply.verifier_gate",ObservationState::Changed,AdapterError::InvalidAccess);
 impl_->index=0;impl_->progress.phase=DirectoryApplyPhase::AttributeCatalog;return Observation<bool>::available(true);}
Observation<bool> DirectoryMetadataApplyJob::finish_io(){impl_->release();auto& p=impl_->progress;
 if(p.finish_failure.present)p.phase=DirectoryApplyPhase::Failed;
 else if(p.phase!=DirectoryApplyPhase::Complete&&p.phase!=DirectoryApplyPhase::Failed)p.phase=DirectoryApplyPhase::Cancelled;
 const auto&e=p.finish_failure;return e.present?Observation<bool>::unavailable(e.state,{e.domain,e.code,e.operation.data()}):Observation<bool>::available(true);}
DirectoryApplyProgress DirectoryMetadataApplyJob::advance(std::stop_token stop){auto&p=impl_->progress;if(p.worker_drained)return p;
 if(stop.stop_requested()){p.phase=DirectoryApplyPhase::Cancelled;impl_->release();return p;}
 try{auto& s=*impl_;auto result=s.root->revalidate();if(result.value()&&*result.value())result=s.membership(stop);
  if(!result.value()||!*result.value()){if(!result.value())s.failure(*result.unavailable_detail());else s.failure(*reject("directory_apply.membership_false",ObservationState::Changed,AdapterError::PlanDecisionStale).unavailable_detail());p.phase=DirectoryApplyPhase::Failed;s.release();return p;}
  const auto& snapshot=s.source->snapshot();
  switch(p.phase){
  case DirectoryApplyPhase::Preflight:{result=qualify_directory_metadata_source(*s.source);if(result.value()&&*result.value())result=s.writer->qualify_metadata_replay(snapshot.policy);
   auto now=s.writer->inspect_basic();if(!now.value()){result=propagate(now);break;}if(!same(now.value()->identity,s.target->metadata().identity)||!now.value()->kind.value()||*now.value()->kind.value()!=ObjectKind::Directory){result=reject("directory_apply.target_binding",ObservationState::Changed,AdapterError::MetadataChanged);break;}
   if(snapshot.policy.scope==RegularMetadataScope::CompleteMetadataV1){if(!snapshot.security_coverage){result=reject("directory_apply.security_coverage");break;}if(result.value()&&*result.value())result=s.writer->preflight_metadata_security_coverage(snapshot);}
   if(result.value()&&*result.value())p.phase=DirectoryApplyPhase::ChannelCatalog;break;}
  case DirectoryApplyPhase::ChannelCatalog:{if(snapshot.channel_coverage!=DataChannelCoverage::WindowsFileStreamInfo){p.phase=DirectoryApplyPhase::AwaitingVerifier;break;}
   auto catalog=s.writer->inspect_data_channels(snapshot.policy.limits);if(!catalog.value()){result=propagate(catalog);break;}if(catalog.value()->coverage!=snapshot.channel_coverage||!same(catalog.value()->owner,s.target->metadata().identity)){result=reject("directory_apply.target_catalog",ObservationState::Changed,AdapterError::MetadataChanged);break;}
   for(const auto& stream:catalog.value()->channels){if(stream.kind!=DataChannelKind::NamedData){result=reject("directory_apply.target_channel_kind");break;}if(std::none_of(snapshot.channels.begin(),snapshot.channels.end(),[&](const auto& source){return source.identifier==stream.identifier;}))s.remove_channels.push_back(stream.identifier);}
   if(result.value()&&*result.value()){s.index=0;p.phase=DirectoryApplyPhase::RemoveChannels;}break;}
  case DirectoryApplyPhase::RemoveChannels:if(s.index==s.remove_channels.size()){s.index=0;p.phase=DirectoryApplyPhase::OpenChannel;break;}
   p.effects=true;result=remove_stream(*s.cursor,s.remove_channels[s.index],*s.target->metadata().identity.value(),s.root);if(result.value()&&*result.value())++s.index;break;
  case DirectoryApplyPhase::OpenChannel:{if(s.index==snapshot.channels.size()){p.phase=DirectoryApplyPhase::AwaitingVerifier;break;}const auto& expected=snapshot.channels[s.index];
   if(!expected.source){result=reject("directory_apply.source_reader",ObservationState::Changed,AdapterError::InvalidNativeResult);break;}auto state=expected.source->inspect();if(!state.value()){result=propagate(state);break;}
   if(state.value()->identifier!=expected.identifier||state.value()->logical_size!=expected.logical_size||compare_identity(state.value()->owner,*snapshot.basic.identity.value())!=IdentityComparison::Same){result=reject("directory_apply.source_binding",ObservationState::Changed,AdapterError::MetadataChanged);break;}
   p.effects=true;auto opened=writer_for(*s.cursor,expected.identifier,*s.target->metadata().identity.value(),s.root);if(!opened.value()){result=propagate(opened);break;}s.stream=std::move(opened).take_value();s.offset=0;s.hash=Sha256{};p.phase=DirectoryApplyPhase::ReadChannel;break;}
  case DirectoryApplyPhase::ReadChannel:{const auto& expected=snapshot.channels[s.index];if(s.offset==expected.logical_size){if(s.hash.digest()!=expected.digest){result=reject("directory_apply.source_digest",ObservationState::Changed,AdapterError::MetadataChanged);break;}auto state=expected.source->inspect();if(!state.value()){result=propagate(state);break;}
    if(state.value()->identifier!=expected.identifier||state.value()->logical_size!=expected.logical_size||compare_identity(state.value()->owner,*snapshot.basic.identity.value())!=IdentityComparison::Same){result=reject("directory_apply.source_final_binding",ObservationState::Changed,AdapterError::MetadataChanged);break;}p.phase=DirectoryApplyPhase::CloseChannel;break;}
   auto limits=s.limits;limits.max_bytes=static_cast<std::size_t>(std::min<std::uint64_t>(limits.max_bytes,expected.logical_size-s.offset));++p.read_calls;auto data=expected.source->read_content(limits,s.offset,stop);if(!data.value()){result=propagate(data);break;}
   if(data.value()->bytes.empty()||data.value()->bytes.size()>limits.max_bytes||(data.value()->complete&&data.value()->bytes.size()!=expected.logical_size-s.offset)){result=reject("directory_apply.source_shape",ObservationState::Changed,AdapterError::MetadataChanged);break;}
   p.read_bytes+=data.value()->bytes.size();s.pending=std::move(data).take_value().bytes;s.hash.update(s.pending);s.written=0;p.phase=DirectoryApplyPhase::WriteChannel;break;}
  case DirectoryApplyPhase::WriteChannel:{++p.write_calls;auto written=s.stream->write(s.offset+s.written,std::span(s.pending).subspan(s.written));if(!written.value()){result=propagate(written);break;}
   if(!*written.value()||*written.value()>s.pending.size()-s.written){result=reject("directory_apply.write_shape",ObservationState::Failed,AdapterError::InvalidNativeResult);break;}s.written+=*written.value();p.write_bytes+=*written.value();
   if(s.written==s.pending.size()){s.offset+=s.pending.size();s.pending.clear();p.phase=DirectoryApplyPhase::ReadChannel;}break;}
  case DirectoryApplyPhase::CloseChannel:s.close_stream();if(p.finish_failure.present){p.phase=DirectoryApplyPhase::Failed;s.release();return p;}++s.index;p.phase=DirectoryApplyPhase::OpenChannel;break;
  case DirectoryApplyPhase::AwaitingVerifier:return p;
  case DirectoryApplyPhase::AttributeCatalog:{auto attributes=s.writer->inspect_attributes(snapshot.policy.limits);if(!attributes.value()){result=propagate(attributes);break;}s.attributes=std::move(attributes).take_value();s.index=0;p.phase=DirectoryApplyPhase::RemoveAttributes;break;}
  case DirectoryApplyPhase::RemoveAttributes:if(s.index==s.attributes->attributes.size()){s.index=0;p.phase=DirectoryApplyPhase::OrdinaryAttributes;break;}
   if(std::none_of(snapshot.attributes.begin(),snapshot.attributes.end(),[&](const auto& source){return source.identifier==s.attributes->attributes[s.index].identifier;})){p.effects=true;result=s.writer->remove_replay_attribute(s.attributes->attributes[s.index].identifier,snapshot.policy);}if(result.value()&&*result.value())++s.index;break;
  case DirectoryApplyPhase::OrdinaryAttributes:case DirectoryApplyPhase::PrivilegedAttributes:{const bool privileged_phase=p.phase==DirectoryApplyPhase::PrivilegedAttributes;
   if(s.index==snapshot.attributes.size()){s.index=0;p.phase=privileged_phase?DirectoryApplyPhase::FinalBasic:DirectoryApplyPhase::Ownership;break;}
   const auto& attribute=snapshot.attributes[s.index];if(privileged(attribute)==privileged_phase)result=s.attribute(attribute);if(result.value()&&*result.value())++s.index;break;}
  case DirectoryApplyPhase::Ownership:p.effects=true;result=s.writer->apply_replay_ownership(snapshot.basic,snapshot.policy);if(result.value()&&*result.value())p.phase=DirectoryApplyPhase::InitialBasic;break;
  case DirectoryApplyPhase::InitialBasic:p.effects=true;result=s.writer->apply_replay_basic(snapshot.basic,snapshot.policy);if(result.value()&&*result.value()){s.index=0;p.phase=DirectoryApplyPhase::Security;}break;
  case DirectoryApplyPhase::Security:if(s.index==snapshot.security.size()){s.index=0;p.phase=DirectoryApplyPhase::PrivilegedAttributes;break;}p.effects=true;result=s.writer->apply_replay_security(snapshot.security[s.index],snapshot.policy);if(result.value()&&*result.value())++s.index;break;
  case DirectoryApplyPhase::FinalBasic:p.effects=true;result=s.writer->apply_replay_basic(snapshot.basic,snapshot.policy);if(result.value()&&*result.value()){auto current=s.writer->inspect_basic();if(!current.value()){result=propagate(current);break;}s.applied=*current.value();p.phase=DirectoryApplyPhase::Complete;s.release();}break;
  default:break;
  }
  if(!result.value()||!*result.value()){if(!result.value())s.failure(*result.unavailable_detail());else s.failure(*reject("directory_apply.unexpected_false",ObservationState::Unknown,AdapterError::InvalidNativeResult).unavailable_detail());p.phase=DirectoryApplyPhase::Failed;s.release();}
 }catch(...){remember(p.failure,ObservationState::Unknown,ErrorDomain::Adapter,2,"directory_apply.worker_exception");p.phase=DirectoryApplyPhase::Failed;impl_->release();}
 return p;
}
} // namespace ck::files
