/* A real C client: include/link only the installed public C ABI. */
#include <ck_file_engine.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(condition) do { if (!(condition)) { \
    fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#condition); return 1; } } while (0)
typedef struct {
    ckfe_engine *engine;
    ckfe_directory *directory;
    ckfe_directory *other;
    ckfe_entry *entry;
    ckfe_job *job;
    ckfe_error error;
    const char *root;
} Context;

static int invalid_outputs(Context *c)
{
    ckfe_directory *directory=(ckfe_directory *)(uintptr_t)1;
    REQUIRE(ckfe_directory_open_utf8(NULL,c->root,0,&directory,&c->error)==CKFE_API_INVALID_ARGUMENT);
    REQUIRE(directory==NULL);
    ckfe_entry *entry=(ckfe_entry *)(uintptr_t)1;
    REQUIRE(ckfe_entry_open_utf8(NULL,"item",&entry,&c->error)==CKFE_API_INVALID_ARGUMENT);
    REQUIRE(entry==NULL);
    return 0;
}

static int metadata_output(Context *c)
{
    ckfe_metadata metadata, empty;
    memset(&metadata,0xa5,sizeof(metadata)); memset(&empty,0,sizeof(empty));
    REQUIRE(ckfe_entry_metadata(NULL,&metadata,&c->error)==CKFE_API_INVALID_ARGUMENT);
    REQUIRE(memcmp(&metadata,&empty,sizeof(metadata))==0);
    return 0;
}

static int invalid_job(Context *c)
{
    ckfe_job *job=(ckfe_job *)(uintptr_t)1;
    REQUIRE(ckfe_job_start_copy_regular(NULL,NULL,"item",c->root,0,&job,&c->error)==CKFE_API_INVALID_ARGUMENT);
    REQUIRE(job==NULL);
    job=(ckfe_job *)(uintptr_t)1;
    REQUIRE(ckfe_job_start_move_regular(NULL,NULL,"item",c->root,0,&job,&c->error)==CKFE_API_INVALID_ARGUMENT);
    REQUIRE(job==NULL);
    return 0;
}

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static char *path(Context *c, const char *name)
{
    size_t base=strlen(c->root), tail=strlen(name);
    char *result=malloc(base+tail+2);
    if (!result) abort();
    memcpy(result,c->root,base); result[base]='/'; memcpy(result+base+1,name,tail+1);
    return result;
}
static int put(Context *c, const char *name, const char *bytes)
{
    char *address=path(c,name);
    int fd=open(address,O_CREAT|O_EXCL|O_WRONLY,0600); free(address);
    REQUIRE(fd>=0);
    size_t length=strlen(bytes);
    REQUIRE(write(fd,bytes,length)==(ssize_t)length && close(fd)==0);
    return 0;
}
static int open_root(Context *c)
{
    REQUIRE(ckfe_directory_open_utf8(c->engine,c->root,0,&c->directory,&c->error)==CKFE_API_OK);
    REQUIRE(c->directory!=NULL);
    return 0;
}
static int inspect(Context *c, ckfe_metadata *metadata)
{
    REQUIRE(ckfe_entry_metadata(c->entry,metadata,&c->error)==CKFE_API_OK);
    REQUIRE((metadata->available_fields & CKFE_METADATA_IDENTITY)!=0);
    REQUIRE((metadata->available_fields & CKFE_METADATA_LOGICAL_SIZE)!=0);
    return 0;
}
static int same_identity(const ckfe_metadata *a, const ckfe_metadata *b)
{
    return a->identity_scheme==b->identity_scheme &&
           !memcmp(a->identity_volume,b->identity_volume,sizeof(a->identity_volume)) &&
           !memcmp(a->identity_object,b->identity_object,sizeof(a->identity_object));
}
static int stale_error(Context *c)
{
    char *missing=path(c,"absent");
    ckfe_api_status status=ckfe_directory_open_utf8(c->engine,missing,0,&c->directory,&c->error);
    free(missing);
    REQUIRE(status==CKFE_API_OPERATION_UNAVAILABLE && !c->directory);
    REQUIRE(c->error.state!=CKFE_OBSERVATION_AVAILABLE);
    REQUIRE(open_root(c)==0);
    REQUIRE(c->error.state==CKFE_OBSERVATION_AVAILABLE && c->error.domain==CKFE_ERROR_NONE);
    REQUIRE(c->error.code==0 && c->error.operation==NULL);
    return 0;
}
static int byte_names(Context *c)
{
    const char name[]="byte-\xff";
    char *address=path(c,name);
    int fd=open(address,O_CREAT|O_EXCL|O_WRONLY,0600);
    int setup_error=errno;
    free(address);
    if (fd<0 && setup_error==EILSEQ) {
        fprintf(stdout,"SKIP: filesystem rejects invalid-byte names with EILSEQ\n");
        return 77;
    }
    REQUIRE(fd>=0);
    REQUIRE(write(fd,"payload",7)==7 && close(fd)==0 && open_root(c)==0);
    REQUIRE(ckfe_entry_open_utf8(c->directory,name,&c->entry,&c->error)==CKFE_API_OK && c->entry);
    ckfe_metadata metadata;
    REQUIRE(inspect(c,&metadata)==0 && metadata.logical_size==7);
    char *raw_directory=path(c,"dir-\xfe");
    REQUIRE(mkdir(raw_directory,0700)==0);
    REQUIRE(ckfe_directory_open_utf8(c->engine,raw_directory,0,&c->other,&c->error)==CKFE_API_OK);
    free(raw_directory); REQUIRE(c->other!=NULL);
    return 0;
}
static int held_parent(Context *c)
{
    char *held=path(c,"held"), *moved=path(c,"moved");
    REQUIRE(mkdir(held,0700)==0 && put(c,"held/item","old")==0);
    REQUIRE(ckfe_directory_open_utf8(c->engine,held,0,&c->directory,&c->error)==CKFE_API_OK);
    REQUIRE(rename(held,moved)==0 && mkdir(held,0700)==0);
    free(held); free(moved);
    REQUIRE(put(c,"held/item","replacement-parent")==0);
    ckfe_api_status status=ckfe_entry_open_utf8(c->directory,"item",&c->entry,&c->error);
    if (status!=CKFE_API_OK) {
        REQUIRE(status==CKFE_API_OPERATION_UNAVAILABLE && !c->entry &&
                (c->error.state==CKFE_OBSERVATION_CHANGED || c->error.state==CKFE_OBSERVATION_GONE));
        return 0;
    }
    ckfe_metadata metadata;
    REQUIRE(inspect(c,&metadata)==0 && metadata.logical_size==3);
    return 0;
}
static int substitution(Context *c)
{
    REQUIRE(put(c,"item","original")==0 && open_root(c)==0);
    REQUIRE(ckfe_entry_open_utf8(c->directory,"item",&c->entry,&c->error)==CKFE_API_OK);
    ckfe_metadata before, after;
    REQUIRE(inspect(c,&before)==0);
    char *item=path(c,"item"), *retained=path(c,"original");
    REQUIRE(rename(item,retained)==0); free(item); free(retained);
    REQUIRE(put(c,"item","different identity")==0);
    ckfe_api_status status=ckfe_entry_metadata(c->entry,&after,&c->error);
    if (status==CKFE_API_OK) REQUIRE(same_identity(&before,&after));
    else REQUIRE(status==CKFE_API_OPERATION_UNAVAILABLE &&
                 (c->error.state==CKFE_OBSERVATION_CHANGED || c->error.state==CKFE_OBSERVATION_GONE));
    return 0;
}
static int final_link(Context *c)
{
    char *actual=path(c,"actual"), *alias=path(c,"alias");
    REQUIRE(mkdir(actual,0700)==0 && symlink("actual",alias)==0); free(actual);
    ckfe_api_status status=ckfe_directory_open_utf8(c->engine,alias,0,&c->directory,&c->error);
    REQUIRE(status==CKFE_API_OPERATION_UNAVAILABLE && !c->directory);
    REQUIRE(ckfe_directory_open_utf8(c->engine,alias,1,&c->directory,&c->error)==CKFE_API_OK);
    free(alias); REQUIRE(c->directory!=NULL);
    return 0;
}
static int terminal(ckfe_job_state state)
{ return state!=CKFE_JOB_READY && state!=CKFE_JOB_RUNNING; }
static int copy_job(Context *c, int cancel, int ordinary, int loss)
{
    REQUIRE(put(c,"source","preserved data")==0 && open_root(c)==0);
    char *source=path(c,"source"), *destination=path(c,"destination"), *journal=path(c,"journal");
    REQUIRE(mkdir(journal,0700)==0 && chmod(source,0640)==0);
    struct timespec times[2]={{1000000000,0},{1000000001,0}};
    REQUIRE(utimensat(AT_FDCWD,source,times,0)==0);
    REQUIRE(ckfe_entry_open_utf8(c->directory,"source",&c->entry,&c->error)==CKFE_API_OK);
    ckfe_copy_options_v1 options={0};
    options.version=CKFE_COPY_OPTIONS_VERSION;
    options.struct_size=sizeof(options);
    options.metadata_scope=CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1;
    options.allow_metadata_loss=(uint32_t)loss;
    ckfe_api_status status=ordinary ?
        ckfe_job_start_copy_regular_v1(c->entry,c->directory,"destination",journal,&options,&c->job,&c->error) :
        ckfe_job_start_copy_regular(c->entry,c->directory,"destination",journal,loss,&c->job,&c->error);
    free(journal);
    if (status!=CKFE_API_OK || !c->job) {
        fprintf(stderr,"Preserving copy unavailable: api=%s observation=%d domain=%d code=%lld\n",
                ckfe_api_status_name(status),c->error.state,c->error.domain,(long long)c->error.code);
        free(source); free(destination); REQUIRE(status==CKFE_API_OK && c->job);
    }
    if (cancel) ckfe_job_cancel(c->job);
    ckfe_job_snapshot snapshot;
    uint64_t previous_bytes=0;
    for (int attempt=0; attempt<2000; ++attempt) {
        REQUIRE(ckfe_job_poll(c->job,&snapshot,&c->error)==CKFE_API_OK);
        REQUIRE(snapshot.processed_bytes>=previous_bytes);
        if (snapshot.total_bytes_known) REQUIRE(snapshot.processed_bytes<=snapshot.total_bytes);
        previous_bytes=snapshot.processed_bytes;
        if (terminal(snapshot.state)) break;
        struct timespec delay={0,5000000}; nanosleep(&delay,NULL);
    }
    if (!terminal(snapshot.state)) {
        fprintf(stderr,"Job did not settle within its deadline\n");
        _Exit(2); /* A broken blocking destroy must not hang the test runner. */
    }
    struct stat original, copied;
    REQUIRE(stat(source,&original)==0);
    ckfe_job_preservation_report_v1 report;
    memset(&report,0,sizeof(report));
    REQUIRE(ckfe_job_get_preservation_report_v1(c->job,&report,sizeof(report),&c->error)==CKFE_API_OK);
    REQUIRE(report.version==1 && report.struct_size==sizeof(report));
    REQUIRE(report.requested_scope==(uint32_t)(ordinary ? CKFE_METADATA_ORDINARY_CALLER_VISIBLE_V1 : CKFE_METADATA_COMPLETE_V1));
    if (snapshot.state==CKFE_JOB_COMPLETED) {
        REQUIRE(snapshot.total_items_known && snapshot.total_items==1 && snapshot.processed_items==1);
        REQUIRE(snapshot.total_bytes_known && snapshot.total_bytes==14 && snapshot.processed_bytes==14);
        REQUIRE(stat(destination,&copied)==0 && original.st_size==copied.st_size);
        REQUIRE((copied.st_mode & 0777)==0640 && copied.st_mtime==times[1].tv_sec);
        REQUIRE(report.provider_qualification==(loss ? CKFE_OBSERVATION_UNKNOWN : CKFE_OBSERVATION_AVAILABLE));
        if (loss) REQUIRE(!report.current_effective_uid_gid_applied);
        const uint64_t required=CKFE_PRESERVED_ORDINARY_MODE|CKFE_PRESERVED_ACCESS_TIME|CKFE_PRESERVED_MODIFIED_TIME;
        REQUIRE((report.source_preserved_fields & required)==required);
        REQUIRE(!(report.source_preserved_fields & report.explicitly_excluded_fields));
        REQUIRE(!(report.source_preserved_fields & report.unknown_fields));
        if (ordinary && !loss) REQUIRE(report.current_effective_uid_gid_applied &&
            copied.st_uid==geteuid() && copied.st_gid==getegid());
        char bytes[32]={0}; int fd=open(destination,O_RDONLY);
        REQUIRE(fd>=0 && read(fd,bytes,sizeof(bytes))==14 && close(fd)==0);
        REQUIRE(!memcmp(bytes,"preserved data",14));
    } else {
        fprintf(stderr,"Noncompleted copy scope=%s state=%s achieved=%llu unknown=%llu qualification=%d\n",
            ordinary ? "ordinary" : "complete",ckfe_job_state_name(snapshot.state),
            (unsigned long long)report.source_preserved_fields,(unsigned long long)report.unknown_fields,
            report.provider_qualification);
        REQUIRE(report.source_preserved_fields==0);
        REQUIRE(cancel && snapshot.state==CKFE_JOB_CANCELLED);
        REQUIRE(access(destination,F_OK)!=0 && errno==ENOENT);
    }
    char original_bytes[32]={0}; int fd=open(source,O_RDONLY);
    REQUIRE(fd>=0 && read(fd,original_bytes,sizeof(original_bytes))==14 && close(fd)==0);
    REQUIRE(!memcmp(original_bytes,"preserved data",14));
    fprintf(stdout,"terminal=%s cancel_requested=%d\n",ckfe_job_state_name(snapshot.state),cancel);
    free(source); free(destination);
    return 0;
}
static int preserving_copy(Context *c) { return copy_job(c,0,0,0); }
static int cancel_copy(Context *c) { return copy_job(c,1,0,0); }
static int ordinary_copy(Context *c) { return copy_job(c,0,1,0); }
static int ordinary_cancel(Context *c) { return copy_job(c,1,1,0); }
/* Deliberate loss is tested ONLY to reject false qualification reporting. */
static int complete_loss_report(Context *c) { return copy_job(c,0,0,1); }
static int ordinary_loss_report(Context *c) { return copy_job(c,0,1,1); }
#else
static int posix_only(Context *c) { (void)c; return 77; }
#define stale_error posix_only
#define byte_names posix_only
#define held_parent posix_only
#define substitution posix_only
#define final_link posix_only
#define preserving_copy posix_only
#define cancel_copy posix_only
#define ordinary_copy posix_only
#define ordinary_cancel posix_only
#define complete_loss_report posix_only
#define ordinary_loss_report posix_only
#endif

int main(int argc, char **argv)
{
    if (argc!=3) return 2;
    struct { const char *name; int (*run)(Context *); } cases[]={
        {"invalid_outputs",invalid_outputs},{"stale_error",stale_error},
        {"metadata_output",metadata_output},{"invalid_job",invalid_job},
        {"byte_names",byte_names},{"held_parent",held_parent},
        {"substitution",substitution},{"final_link",final_link},
        {"preserving_copy",preserving_copy},{"cancel_copy",cancel_copy},
        {"ordinary_copy",ordinary_copy},{"ordinary_cancel",ordinary_cancel},
        {"complete_loss_report",complete_loss_report},{"ordinary_loss_report",ordinary_loss_report}};
    Context c={0}; c.root=argv[2]; ckfe_error_init(&c.error);
    if (ckfe_engine_create(&c.engine)!=CKFE_API_OK || !c.engine) return 2;
    int result=2;
    for (size_t i=0; i<sizeof(cases)/sizeof(cases[0]); ++i)
        if (!strcmp(argv[1],cases[i].name)) { result=cases[i].run(&c); break; }
    ckfe_job_destroy(c.job); ckfe_entry_destroy(c.entry);
    ckfe_directory_destroy(c.other); ckfe_directory_destroy(c.directory);
    ckfe_engine_destroy(c.engine); ckfe_error_free(&c.error); ckfe_error_free(&c.error);
    return result;
}
