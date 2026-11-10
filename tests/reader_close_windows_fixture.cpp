// SOURCE-ONLY shared native evidence checks. No production implementation edits.
#include "reader_close_windows_fixture.hpp"
namespace reader_fault {
FailureTuple capture_failure(const UnavailableObservation& error) noexcept {
    REQUIRE(error.state!=ObservationState::Available);
    REQUIRE(error.error.domain!=ErrorDomain::None&&error.error.code!=0);
    REQUIRE(!error.error.operation.empty()&&error.error.operation.size()<192);
    FailureTuple result;result.state=error.state;result.domain=error.error.domain;
    result.code=error.error.code;
    std::memcpy(result.operation.data(),error.error.operation.data(),error.error.operation.size());
    return result;
}
void expect_same_failure(const Observation<bool>& result,const FailureTuple& first) noexcept {
    REQUIRE(!result.value());const auto* error=result.unavailable_detail();REQUIRE(error);
    REQUIRE(error->state==first.state&&error->error.domain==first.domain&&
        error->error.code==first.code&&error->error.operation==first.operation.data());
}
void report_first_validation(const FailureTuple& first) noexcept {
    std::printf("FIRST_VALIDATION state=%d domain=%d code=%lld operation=%s cachedExact=1 noFalseComplete=1\n",
        int(first.state),int(first.domain),static_cast<long long>(first.code),first.operation.data());
}
void assert_physical_close_state(const Watch& watch) noexcept {
    REQUIRE(watch.test_repairs==0);
    if(watch.native_failure){
        REQUIRE(!watch.real_ok&&watch.real_error==ERROR_INVALID_HANDLE);
        DWORD flags=0;REQUIRE(GetHandleInformation(watch.selected,&flags));
        REQUIRE(flags&HANDLE_FLAG_PROTECT_FROM_CLOSE);
        REQUIRE(same_id(identity(watch.selected),watch.expected));
    }else if(!watch.control){REQUIRE(watch.real_ok);watch.assert_event();}
}
void report_binding(const Watch& watch) noexcept {
    std::printf("CLOSE_BIND operation=%s provider=%ls volume=%llu FileID=",watch.operation,watch.provider,
        static_cast<unsigned long long>(watch.seen.VolumeSerialNumber));
    for(auto unit:watch.seen.FileId.Identifier)std::printf("%02x",unsigned(unit));
    std::printf(" nativeOkay=%d nativeError=%lu selectedBefore=%u selectedAfter=%u adapterOwnersConsumed=3 selectedOSConsumedByAdapter=%d testRepairs=%u\n",
        watch.real_ok,watch.real_error,watch.selected_before,watch.selected_after,
        watch.real_ok,watch.test_repairs);
}
} // namespace reader_fault
