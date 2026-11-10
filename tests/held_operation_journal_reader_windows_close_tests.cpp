// SOURCE-ONLY: first native-provider validation is sticky; clean close precedence is separate.
#include "reader_close_windows_fixture.hpp"
#include "windows_test_runtime_self_report.hpp"
#include <string_view>
#include <optional>
using namespace reader_fault;
int wmain(int argc,wchar_t** argv){
    if(!ckfs_test::report_runtime_self("journal-reader"))return 1;
    REQUIRE(argc==7);const auto target=std::wstring_view(argv[3]),mode=std::wstring_view(argv[4]);
    const bool is_file=target==L"file",is_root=target==L"root";REQUIRE(is_file||is_root||target==L"parent");
    const bool pass=mode==L"pass",native=mode==L"native"||mode==L"native-oom",oom=mode==L"consumed-oom"||mode==L"native-oom";
    REQUIRE(pass||native||mode==L"consumed"||mode==L"consumed-oom");
    const DWORD expected_native_error=native?DWORD{ERROR_INVALID_HANDLE}:DWORD{ERROR_SUCCESS};
    const DWORD expected_reported_error=native?DWORD{ERROR_INVALID_HANDLE}:DWORD{ERROR_WRITE_FAULT};
    REQUIRE(std::wstring_view(argv[5])==L"ordinary"||std::wstring_view(argv[5])==L"long-raw");
    const bool prior=std::wstring_view(argv[6])==L"prior";REQUIRE(prior||std::wstring_view(argv[6])==L"clean");
    REQUIRE(!prior||(!pass&&!oom));
    Fixture fixture(argv[1],argv[2],std::wstring_view(argv[5])==L"long-raw");
    writer_counter_control(fixture);
    auto cursor=take(open_native_operation_journal_directory(address(fixture.root)));
    auto reader=take(open_held_operation_journal_file(*cursor,basename()));
    const auto bytes=take(reader->size());REQUIRE(bytes==16);std::array<std::byte,16> data{};REQUIRE(take(reader->read_at(0,data))==data.size());
    Watch watch;const auto* tag=is_file?file_tag:(is_root?root_tag:parent_tag);watch.begin(fixture,tag,native,oom,pass);
    auto denied_write=reader->write_at(0,data);REQUIRE(!denied_write.value()&&denied_write.state()==ObservationState::Denied);
    auto denied_flush=reader->flush();REQUIRE(!denied_flush.value()&&denied_flush.state()==ObservationState::Denied);
    bool first_oom=false;std::optional<Observation<bool>> file_first,root_first;
    std::optional<FailureTuple> first_validation;
    if(prior&&!is_root){
        fixture.invalidate_privacy();
        // Genuine retained-reader revalidation, before either close hook.
        const auto checked=reader->size();REQUIRE(checked.unavailable_detail());
        first_validation=capture_failure(*checked.unavailable_detail());
    }
    try{file_first.emplace(reader->finish_io());}catch(const std::bad_alloc&){first_oom=true;}
    if(prior&&!is_root)fixture.restore_privacy();
    if(prior&&is_root){
        fixture.invalidate_privacy();
        const auto checked=detail::qualify_operation_journal_directory(*cursor);
        REQUIRE(checked.unavailable_detail());
        first_validation=capture_failure(*checked.unavailable_detail());
    }
    try{root_first.emplace(finish_operation_journal_directory(*cursor));}catch(const std::bad_alloc&){first_oom=true;}
    if(prior&&is_root)fixture.restore_privacy();
    REQUIRE(watch.selected_before==1&&watch.selected_after==1&&watch.final_closes==3);
    REQUIRE(watch.real_ok!=native);REQUIRE(watch.real_error==expected_native_error);
    if(oom){REQUIRE(first_oom&&allocation_failures.load()>0);bool denied=false;try{auto* p=::operator new(64);::operator delete(p);}catch(const std::bad_alloc&){denied=true;}REQUIRE(denied);}
    assert_physical_close_state(watch);
    if(native)watch.recover_failed_native_handle();
    const auto closed=watch.final_closes;
    // Repeat while OOM is STILL active: even a diagnostic exception must not
    // attempt another native close or touch the actually reused event HANDLE.
    for(unsigned n=0;n<2;++n){try{(void)reader->finish_io();}catch(const std::bad_alloc&){REQUIRE(oom);}try{(void)finish_operation_journal_directory(*cursor);}catch(const std::bad_alloc&){REQUIRE(oom);}}
    watch.assert_no_retry(closed);if(!pass)watch.assert_event();
    stop_oom();
    REQUIRE(!first_oom||oom);
    // Privacy restoration and test-only protected-HANDLE repair precede any
    // diagnostic assertion. Production first-validation priority is unchanged.
    if(prior){
        REQUIRE(first_validation);
        // The native provider detects the real null-DACL edit. It deliberately
        // reports Adapter/InvalidNativeResult, not a fabricated Win32 failure.
        REQUIRE(first_validation->state==ObservationState::Failed&&
            first_validation->domain==ErrorDomain::Adapter&&
            first_validation->code==static_cast<std::int64_t>(AdapterError::InvalidNativeResult)&&
            !std::strcmp(first_validation->operation.data(),"journal_file.private_descriptor.dacl"));
        const auto& first=is_root?root_first:file_first;REQUIRE(first);
        expect_same_failure(*first,*first_validation);
        for(unsigned n=0;n<2;++n){
            const auto cached=is_root?finish_operation_journal_directory(*cursor):reader->finish_io();
            expect_same_failure(cached,*first_validation);
        }
        report_first_validation(*first_validation);
    }else{
        if(!oom){const auto& first=is_root?root_first:file_first;REQUIRE(first);if(pass)REQUIRE(first->value()&&*first->value());else expect_failure(*first,expected_reported_error,tag);}
        if(!pass){if(is_root)expect_failure(finish_operation_journal_directory(*cursor),expected_reported_error,tag);else expect_failure(reader->finish_io(),expected_reported_error,tag);}
    }
    reader.reset();cursor.reset();watch.assert_no_retry(closed);if(!pass)watch.assert_event();
    REQUIRE(watch.writes==0&&watch.flushes==0);watch.end();
    HANDLE verify=CreateFileW(fixture.file.c_str(),GENERIC_READ,7,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);REQUIRE(verify!=INVALID_HANDLE_VALUE);REQUIRE(same_id(identity(verify),fixture.file_id));
    std::array<std::byte,16> after{};DWORD got=0;REQUIRE(ReadFile(verify,after.data(),DWORD(after.size()),&got,nullptr)&&got==after.size()&&after==data);REQUIRE(CloseHandle(verify));
    report_binding(watch);
    std::printf("PASS native reader close target=%ls mode=%ls provider=%ls prior=%d actualClose=%d nativeError=%lu selected=1 adapterOwnersConsumed=3 reused=%d noRetry=1 write0flush0 OOMattempts=%u checks=%u\n",argv[3],argv[4],argv[2],prior,watch.real_ok,watch.real_error,!pass,allocation_failures.load(),checks.load());
    return 0;
}
