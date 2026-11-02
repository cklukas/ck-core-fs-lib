// SPDX-License-Identifier: LGPL-2.0-or-later
#include "ck_fs_actions.h"
#include "native_handles.hpp"
#include "action_jobs.hpp"
#include <atomic>
#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>

using namespace ck::files;
struct ckfea_job { std::shared_ptr<ActionJob> value; };
struct ckfea_trash_receipt { std::shared_ptr<const NativeTrashReceipt> value; };
namespace {
std::atomic<uint32_t> live_jobs{0};
struct Slot {
    bool owned=false;
    ~Slot() { if (owned) --live_jobs; }
};
void require(bool ok) { if (!ok) throw std::invalid_argument("invalid action ABI input"); }
template<class F> ckfea_status boundary(F&& f) noexcept {
    try { return f(); }
    catch (const std::bad_alloc&) { return CKFEA_OUT_OF_MEMORY; }
    catch (const std::invalid_argument&) { return CKFEA_INVALID_ARGUMENT; }
    catch (...) { return CKFEA_EXCEPTION; }
}
template<class T> bool header(const T* p) noexcept {
    return p && p->version==CKFEA_VERSION && p->struct_size==sizeof(T);
}
template<class T> void reset(T& p) noexcept { p={}; p.version=CKFEA_VERSION; p.struct_size=sizeof(T); }
bool empty(const ckfea_native_text& t) noexcept { return !t.data && !t.byte_count && t.encoding==CKFEA_POSIX_BYTES; }
void text_header(const ckfea_native_text& t) {
    require(header(&t) && !t.reserved && t.encoding<=CKFEA_WINDOWS_UTF16 && t.byte_count<=CKFEA_MAX_NAME_BYTES &&
        (!t.byte_count || t.data) && (t.encoding!=CKFEA_WINDOWS_UTF16 || !(t.byte_count&1)));
}
std::u16string units(const ckfea_native_text& t) {
    std::u16string out(static_cast<size_t>(t.byte_count/2),u'\0');
    std::memcpy(out.data(),t.data,static_cast<size_t>(t.byte_count)); return out;
}
NativeName name(const ckfea_native_text& t) {
    text_header(t); require(t.data && t.byte_count);
    auto n=t.encoding==CKFEA_POSIX_BYTES ? NativeName::from_posix(std::string(static_cast<const char*>(t.data),static_cast<size_t>(t.byte_count))) :
        NativeName::from_windows(units(t));
    require(n.has_value()); return std::move(*n);
}
NativeAbsolutePath address(const ckfea_native_text& t) {
    text_header(t); require(t.data && t.byte_count);
    auto n=t.encoding==CKFEA_POSIX_BYTES ? NativeAbsolutePath::from_posix(std::string_view(static_cast<const char*>(t.data),static_cast<size_t>(t.byte_count))) :
        NativeAbsolutePath::from_windows(units(t));
    require(n.value()!=nullptr); return std::move(n).take_value();
}
ActionRequest convert(const ckfea_request& in) {
    require(header(&in) && in.operation>=CKFEA_RENAME && in.operation<=CKFEA_VERIFY_RECOVERY &&
        !(in.capabilities&~uint32_t(CKFEA_ALLOW_NATIVE_TRASH|CKFEA_ALLOW_NATIVE_RESTORE)) && in.retry_limit<=2);
    for (auto r:in.reserved) require(!r);
    text_header(in.journal_directory); text_header(in.journal_name);
    ActionRequest out; out.operation=in.operation; out.capabilities=in.capabilities; out.retry_limit=in.retry_limit;
    if (in.operation==CKFEA_VERIFY_RECOVERY) {
        require(!in.items && !in.item_count && !in.capabilities && !in.retry_limit &&
            empty(in.journal_directory) && empty(in.journal_name) && in.recovery &&
            in.recovery_destination && in.recovery_destination->cursor &&
            in.max_verify_bytes && in.max_verify_bytes<=UINT64_C(4)*1024*1024*1024);
        // Bound copied native recovery evidence, including requests created by
        // private adapters. Each receipt remains bound to fresh held identity.
        require(in.recovery->inspection.artifacts.size()<=1'000'000);
        NativeOperationRecoveryInspection selected;
        selected.journal_id=in.recovery->inspection.journal_id;
        selected.has_untrusted_evidence=in.recovery->inspection.has_untrusted_evidence;
        selected.report.has_untrusted_tail=in.recovery->inspection.report.has_untrusted_tail;
        for (const auto& a:in.recovery->inspection.artifacts) if (a.item==in.recovery_item) {
            require(selected.artifacts.size()<2);
            if (a.evidence) {
                auto bounded=encode_native_operation_recovery_evidence(*a.evidence,{256*1024,CKFEA_MAX_NAME_BYTES});
                require(bounded.value()!=nullptr);
            }
            selected.artifacts.push_back(a);
        }
        out.recovery=std::move(selected); out.recovery_destination=in.recovery_destination->cursor;
        out.recovery_item=in.recovery_item; out.max_verify_bytes=in.max_verify_bytes; return out;
    }
    require(in.items && in.item_count && in.item_count<=CKFEA_MAX_ITEMS && !in.recovery &&
        !in.recovery_destination && !in.recovery_item && !in.max_verify_bytes);
    if (in.operation==CKFEA_RENAME || in.operation==CKFEA_TRASH) {
        if(in.operation==CKFEA_RENAME) require(!in.capabilities);
        else require(!in.retry_limit && !(in.capabilities&CKFEA_ALLOW_NATIVE_RESTORE));
        if (!empty(in.journal_directory) || !empty(in.journal_name)) {
            out.journal_directory=address(in.journal_directory); out.journal_name=name(in.journal_name);
            require(out.journal_directory->encoding()==out.journal_name->encoding());
        }
    } else {
        require(!in.retry_limit && empty(in.journal_directory) && empty(in.journal_name));
        require(!(in.capabilities & (in.operation==CKFEA_TRASH ? CKFEA_ALLOW_NATIVE_RESTORE : CKFEA_ALLOW_NATIVE_TRASH)));
    }
    out.items.reserve(in.item_count);
    for (uint32_t i=0;i<in.item_count;++i) {
        const auto& a=in.items[i];
        require(header(&a) && !a.reserved && !(a.flags&~uint32_t(CKFEA_CASE_ONLY)) && a.source && a.source->child);
        text_header(a.destination_name);
        ActionItem item; item.source=a.source->child; item.case_only=a.flags&CKFEA_CASE_ONLY;
        if (in.operation==CKFEA_RENAME) {
            item.destination=name(a.destination_name);
            require(item.destination->encoding()==item.source->name().encoding());
        } else require(!a.flags && empty(a.destination_name));
        out.items.push_back(std::move(item));
    }
    return out;
}
ActionRequest convert_restore(const ckfea_restore_request& in) {
    require(header(&in) && !(in.capabilities&~uint32_t(CKFEA_ALLOW_NATIVE_RESTORE)) && in.items && in.item_count && in.item_count<=CKFEA_MAX_ITEMS);
    for(auto r:in.reserved) require(!r);
    text_header(in.journal_directory);text_header(in.journal_name);
    ActionRequest out;out.operation=CKFEA_RESTORE;out.capabilities=in.capabilities;
    if(!empty(in.journal_directory)||!empty(in.journal_name)) {
        out.journal_directory=address(in.journal_directory);out.journal_name=name(in.journal_name);
        require(out.journal_directory->encoding()==out.journal_name->encoding());
    }
    out.restore_items.reserve(in.item_count);
    for(uint32_t i=0;i<in.item_count;++i) {
        const auto& item=in.items[i];
        require(header(&item)&&!item.reserved[0]&&!item.reserved[1]&&item.receipt&&item.receipt->value&&item.original_parent&&item.original_parent->cursor);
        out.restore_items.push_back({item.receipt->value,item.original_parent->cursor});
    }
    return out;
}
ckfea_status start(ActionRequest request,ckfea_job** out) {
    auto slot=std::make_shared<Slot>();auto count=live_jobs.load();
    do { if(count>=CKFEA_MAX_JOBS)return CKFEA_BUSY; } while(!live_jobs.compare_exchange_weak(count,count+1));
    slot->owned=true;
    auto handle=std::make_unique<ckfea_job>();
    handle->value=std::shared_ptr<ActionJob>(new ActionJob(std::move(request)),[slot](ActionJob* p){delete p;});
    handle->value->start();*out=handle.release();return CKFEA_OK;
}
ckfea_identity durable_id(const NativeDurableIdentity& id) {
    ckfea_identity out{};out.scheme=static_cast<uint32_t>(id.scheme);out.has_generation=id.generation.has_value();out.generation=id.generation.value_or(0);
    std::memcpy(out.volume,id.volume.bytes.data(),16);std::memcpy(out.object,id.object.bytes.data(),16);return out;
}
uint64_t native_bytes(const NativeName& n) {return n.posix_bytes()?n.posix_bytes()->size():n.windows_units()->size()*2;}
}
extern "C" {
void ckfea_native_text_init(ckfea_native_text* p) noexcept { if (p) reset(*p); }
void ckfea_item_init(ckfea_item* p) noexcept { if (p) { reset(*p); ckfea_native_text_init(&p->destination_name); } }
void ckfea_request_init(ckfea_request* p) noexcept {
    if (p) { reset(*p); p->operation=CKFEA_RENAME; ckfea_native_text_init(&p->journal_directory); ckfea_native_text_init(&p->journal_name); }
}
ckfea_status ckfea_job_create(const ckfea_request* in, ckfea_job** out) noexcept {
    if (out) *out=nullptr;
    return boundary([&]() -> ckfea_status {
        require(in && out);
        return start(convert(*in),out);
    });
}
void ckfea_restore_request_init(ckfea_restore_request* p) noexcept {
    if(p){reset(*p);ckfea_native_text_init(&p->journal_directory);ckfea_native_text_init(&p->journal_name);}
}
void ckfea_restore_item_init(ckfea_restore_item* p) noexcept {if(p)reset(*p);}
ckfea_status ckfea_restore_job_create(const ckfea_restore_request* in,ckfea_job** out) noexcept {
    if(out)*out=nullptr;
    return boundary([&]()->ckfea_status{require(in&&out);return start(convert_restore(*in),out);});
}
ckfea_status ckfea_job_trash_receipt(const ckfea_job* job,uint32_t item,ckfea_trash_receipt** out) noexcept {
    if(out)*out=nullptr;
    return boundary([&]()->ckfea_status{
        require(job&&job->value&&out);std::shared_ptr<const NativeTrashReceipt> receipt;
        auto result=job->value->trash_receipt(item,receipt);if(result!=CKFEA_OK)return result;
        auto handle=std::make_unique<ckfea_trash_receipt>();handle->value=std::move(receipt);*out=handle.release();return CKFEA_OK;
    });
}
ckfea_status ckfea_trash_receipt_info(const ckfea_trash_receipt* receipt,ckfea_trash_info* out) noexcept {
    if(!header(out)||out->reserved||out->reserved_words[0]||out->reserved_words[1])return CKFEA_INVALID_ARGUMENT;
    reset(*out);
    return boundary([&]()->ckfea_status{
        require(receipt&&receipt->value&&receipt->value->metadata_identity);const auto& r=*receipt->value;
        out->encoding=static_cast<uint32_t>(r.original_name.encoding());out->original_parent=durable_id(r.original_parent);
        out->object=durable_id(r.object);out->recycle_parent=durable_id(r.recycle_parent);out->metadata_identity=durable_id(*r.metadata_identity);
        out->original_name_bytes=native_bytes(r.original_name);out->data_name_bytes=native_bytes(r.data_name);out->metadata_name_bytes=native_bytes(r.metadata_name);return CKFEA_OK;
    });
}
ckfea_status ckfea_trash_receipt_copy_name(const ckfea_trash_receipt* receipt,uint32_t which,void* buffer,uint64_t capacity,uint64_t* required) noexcept {
    if(required)*required=0;
    return boundary([&]()->ckfea_status{
        require(receipt&&receipt->value&&required&&which<=CKFEA_TRASH_METADATA_NAME&&capacity<=CKFEA_MAX_NAME_BYTES);
        const auto& r=*receipt->value;const auto& n=which==CKFEA_TRASH_ORIGINAL_NAME?r.original_name:which==CKFEA_TRASH_DATA_NAME?r.data_name:r.metadata_name;
        *required=native_bytes(n);if(capacity<*required)return CKFEA_BUFFER_TOO_SMALL;require(buffer);
        const void* source=n.posix_bytes()?static_cast<const void*>(n.posix_bytes()->data()):static_cast<const void*>(n.windows_units()->data());
        std::memcpy(buffer,source,static_cast<size_t>(*required));return CKFEA_OK;
    });
}
void ckfea_trash_receipt_destroy(ckfea_trash_receipt* receipt) noexcept {delete receipt;}
ckfea_status ckfea_trash_receipt_get_kind(const ckfea_trash_receipt* receipt,uint32_t* out) noexcept {
    if(out)*out=CKFE_OBJECT_UNKNOWN;
    return boundary([&]()->ckfea_status {
        require(receipt && receipt->value && out);
        const auto kind=receipt->value->object_kind;
        require(kind==ObjectKind::RegularFile || kind==ObjectKind::Directory);
        *out=kind==ObjectKind::Directory?CKFE_OBJECT_DIRECTORY:CKFE_OBJECT_REGULAR_FILE;
        return CKFEA_OK;
    });
}
ckfea_status ckfea_job_summary(const ckfea_job* job, ckfea_summary* out) noexcept {
    if (!header(out) || out->reserved) return CKFEA_INVALID_ARGUMENT;
    reset(*out);
    return boundary([&]() -> ckfea_status { require(job && job->value); *out=job->value->summary(); return CKFEA_OK; });
}
ckfea_status ckfea_job_item(const ckfea_job* job,uint32_t i,ckfea_result* out) noexcept {
    if (!header(out) || out->reserved) return CKFEA_INVALID_ARGUMENT;
    reset(*out);
    return boundary([&]() -> ckfea_status { require(job && job->value); return job->value->item(i,*out); });
}
ckfea_status ckfea_job_receipt(const ckfea_job* job,ckfea_receipt* out) noexcept {
    if (!header(out) || out->reserved[0] || out->reserved[1]) return CKFEA_INVALID_ARGUMENT;
    reset(*out);
    return boundary([&]() -> ckfea_status { require(job && job->value); return job->value->receipt(*out); });
}
ckfea_status ckfea_job_execute(ckfea_job* job,const ckfea_receipt* in) noexcept {
    return boundary([&]() -> ckfea_status {
        require(job && job->value && header(in) && !in->reserved[0] && !in->reserved[1]);
        return job->value->execute(*in);
    });
}
ckfea_status ckfea_job_evidence(const ckfea_job* job,uint64_t i,ckfea_evidence* out) noexcept {
    if (!header(out) || out->reserved[0] || out->reserved[1]) return CKFEA_INVALID_ARGUMENT;
    reset(*out);
    return boundary([&]() -> ckfea_status { require(job && job->value); return job->value->evidence(i,*out); });
}
ckfea_status ckfea_job_cancel(ckfea_job* job) noexcept {
    return boundary([&]() -> ckfea_status { require(job && job->value); job->value->cancel(); return CKFEA_OK; });
}
void ckfea_job_destroy(ckfea_job* job) noexcept {
    if (!job) return;
    try { if (job->value) job->value->cancel(); } catch (...) {}
    delete job;
}
ckfea_status ckfea_job_wait(ckfea_job* job,uint32_t ms) noexcept {
    return boundary([&]() -> ckfea_status { require(job && job->value && ms<=1000); return job->value->wait(ms); });
}
}
