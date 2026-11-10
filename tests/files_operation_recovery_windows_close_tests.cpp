// SOURCE-ONLY: links published real controller + file_io, no fake worker.
#include "reader_close_windows_fixture.hpp"
#include "windows_test_runtime_self_report.hpp"
#include "files_operation_recovery.hpp"
#include <chrono>
#include <thread>
#include <optional>
#include <memory>
#include <string_view>
using namespace reader_fault;
int wmain(int argc,wchar_t** argv){
    if(!ckfs_test::report_runtime_self("recovery-worker"))return 1;
    REQUIRE(argc==6);const auto target=std::wstring_view(argv[3]),mode=std::wstring_view(argv[4]);
    REQUIRE(target==L"file"||target==L"root");const bool root=target==L"root";
    const bool native=mode==L"native"||mode==L"native-oom",oom=mode==L"consumed-oom"||mode==L"native-oom";
    REQUIRE(native||mode==L"consumed"||mode==L"consumed-oom");
    const DWORD expected_native_error=native?DWORD{ERROR_INVALID_HANDLE}:DWORD{ERROR_SUCCESS};
    const DWORD expected_reported_error=native?DWORD{ERROR_INVALID_HANDLE}:DWORD{ERROR_WRITE_FAULT};
    REQUIRE(std::wstring_view(argv[5])==L"ordinary"||std::wstring_view(argv[5])==L"long-raw");
    Fixture fixture(argv[1],argv[2],std::wstring_view(argv[5])==L"long-raw");
    writer_counter_control(fixture);
    Watch watch;const auto* tag=root?root_tag:file_tag;watch.begin(fixture,tag,native,oom,false);
    std::atomic<unsigned> wakes{0};auto service=std::make_unique<ck::vision::FilesOperationRecoveryService>([&]{++wakes;});
    REQUIRE(service->request(address(fixture.root))==ck::vision::FilesOperationRecoverySubmission::Accepted);
    std::optional<ck::vision::FilesOperationRecoveryReply> reply;const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    do{reply=service->take();if(reply)break;std::this_thread::sleep_for(std::chrono::milliseconds(1));}while(std::chrono::steady_clock::now()<deadline);
    REQUIRE(reply);service->request_stop();service->join();
    // The worker's persistent allocator gate remains enabled through actual
    // joined teardown. Main can read cached scalar evidence without disabling it.
    REQUIRE(wakes==1&&watch.selected_before==1&&watch.selected_after==1&&watch.final_closes==3);
    REQUIRE(watch.real_ok!=native&&watch.real_error==expected_native_error);
    if(oom){REQUIRE(allocation_failures.load()>0);REQUIRE(reply->state==ck::vision::FilesOperationRecoveryState::WorkerFault&&!reply->error&&!reply->scan);}
    else if(root){REQUIRE(reply->state==ck::vision::FilesOperationRecoveryState::Failed&&reply->error);const auto& e=*reply->error;REQUIRE(e.state==ObservationState::Failed&&e.error.domain==ErrorDomain::Win32&&e.error.code==expected_reported_error&&e.error.operation==tag);}
    else{REQUIRE(reply->state==ck::vision::FilesOperationRecoveryState::Ready&&reply->scan&&reply->scan->requires_reconciliation&&reply->scan->journals.size()==1);const auto& item=reply->scan->journals.front();REQUIRE(item.native_name&&*item.native_name==basename()&&!item.report&&item.error);const auto& e=*item.error;REQUIRE(e.state==ObservationState::Failed&&e.error.domain==ErrorDomain::Win32&&e.error.code==expected_reported_error&&e.error.operation==tag);}
    // Reply/join proves adapter ownership consumed. A protected native failure
    // explicitly leaves one OS HANDLE unconsumed until this fixture repair.
    assert_physical_close_state(watch);
    if(native)watch.recover_failed_native_handle();watch.assert_event();const auto closed=watch.final_closes;
    // Destroying the worker/cache cannot retry a consumed kernel value.
    reply.reset();service.reset();watch.assert_no_retry(closed);watch.assert_event();REQUIRE(watch.writes==0&&watch.flushes==0);watch.end();
    HANDLE file=CreateFileW(fixture.file.c_str(),GENERIC_READ,7,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);REQUIRE(file!=INVALID_HANDLE_VALUE&&same_id(identity(file),fixture.file_id));std::array<std::byte,16> bytes{};DWORD got=0;REQUIRE(ReadFile(file,bytes.data(),DWORD(bytes.size()),&got,nullptr)&&got==bytes.size());for(auto value:bytes)REQUIRE(value==std::byte{});REQUIRE(CloseHandle(file));
    report_binding(watch);
    std::printf("PASS real controller close provider=%ls target=%ls mode=%ls adapterOwnersConsumed=3 workerFault=%d wake1 joined nativeError=%lu noRetry write0flush0 checks=%u\n",argv[2],argv[3],argv[4],oom,watch.real_error,checks.load());
    return 0;
}
