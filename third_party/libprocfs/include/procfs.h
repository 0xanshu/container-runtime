#ifndef PROCFS_H
#define PROCFS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <linux/limits.h>   /* PATH_MAX, unconditional — see note below */

/*
 * Unified libprocfs API.
 *
 * This header is the merge of process-inspector's six per-area headers
 * (pinspect.h, util.h, proc_status.h, proc_fd.h, proc_task.h, net.h) into
 * one. Consumers include just "procfs.h" and get every type and function.
 *
 * Note on <linux/limits.h>: PATH_MAX is used in fd_entry_t below, so it must
 * be defined in every translation unit that includes this header. Under the
 * library's strict flag policy (-std=c11 -pedantic, no -D_GNU_SOURCE /
 * -D_POSIX_C_SOURCE on the command line) a bare <limits.h> does NOT define
 * PATH_MAX in a TU lacking a feature-test macro. <linux/limits.h> defines it
 * unconditionally, which is why process-inspector's pinspect.h used it too.
 */

/* ===== Constants ===== */
#define PROC_ROOT     "/proc"
#define PROC_NAME_MAX 16          /* kernel truncates comm to 15 chars + NUL */

/* ===== Process state enum ===== */
typedef enum {
    PROC_STATE_RUNNING,      /* R */
    PROC_STATE_SLEEPING,     /* S */
    PROC_STATE_DISK_SLEEP,   /* D */
    PROC_STATE_ZOMBIE,       /* Z */
    PROC_STATE_STOPPED,      /* T */
    PROC_STATE_IDLE,         /* I */
    PROC_STATE_UNKNOWN,
} proc_state_t;

const char  *state_to_string(proc_state_t state);
proc_state_t char_to_state(char c);

/* ===== /proc/<pid>/status parsing ===== */
typedef struct {
    pid_t         pid;
    char          name[PROC_NAME_MAX];
    proc_state_t  state;
    uid_t         uid_real, uid_effective;
    gid_t         gid_real, gid_effective;
    unsigned long vm_size_kb;
    unsigned long vm_rss_kb;
    unsigned long vm_peak_kb;
    int           thread_count;
} proc_info_t;

int read_proc_status(pid_t pid, proc_info_t *info);

/* ===== /proc/<pid>/fd/ enumeration ===== */
typedef struct {
    int           fd;
    char          target[PATH_MAX];
    bool          is_socket;
    unsigned long socket_inode;
} fd_entry_t;

int  enumerate_fds(pid_t pid, fd_entry_t **entries, int *count);
void fd_entries_free(fd_entry_t *entries);
bool parse_socket_inode(const char *target, unsigned long *inode);

/* ===== /proc/<pid>/task/ enumeration ===== */
typedef struct {
    pid_t        tid;
    char         name[16];
    proc_state_t state;
} thread_info_t;

int  enumerate_threads(pid_t pid, thread_info_t **threads, int *count);
void thread_info_free(thread_info_t *threads);

/* ===== /proc/net/{tcp,udp} correlation ===== */
typedef enum {
    TCP_ESTABLISHED = 1, TCP_SYN_SENT, TCP_SYN_RECV,
    TCP_FIN_WAIT1, TCP_FIN_WAIT2, TCP_TIME_WAIT,
    TCP_CLOSE, TCP_CLOSE_WAIT, TCP_LAST_ACK,
    TCP_LISTEN, TCP_CLOSING,
} tcp_state_t;

typedef struct {
    bool          is_tcp;
    uint32_t      local_addr;
    uint16_t      local_port;
    uint32_t      remote_addr;
    uint16_t      remote_port;
    tcp_state_t   state;
    unsigned long inode;
} socket_info_t;

int  find_process_sockets(pid_t pid, socket_info_t **sockets, int *count);
void socket_list_free(socket_info_t *sockets);

const char *tcp_state_to_string(tcp_state_t state);
void format_ip_port(uint32_t addr, uint16_t port, char *buf, size_t size);

/* ===== Helpers ===== */
int   build_proc_path(pid_t pid, const char *file, char *buf, size_t size);
int   build_task_path(pid_t pid, pid_t tid, const char *file, char *buf, size_t size);
bool  pid_exists(pid_t pid);
pid_t parse_pid(const char *str);
/* De-dup'd during extraction: was a private static is_numeric() duplicated
 * in proc_fd.c and proc_task.c; promoted here so both call one definition. */
bool  is_numeric_entry(const char *name);

#endif /* PROCFS_H */
