#ifndef _NST_TYPES_H_
#define _NST_TYPES_H_

#include <sysexits.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#define LF     (u_char) 10
#define CR     (u_char) 13
#define CRLF   "\x0d\x0a"
#define CRLF_LEN (2)
typedef uint8_t              u8;
typedef uint16_t             u16;
typedef uint32_t             u32;
typedef uint64_t             u64;



typedef int            nst_fd_t;
typedef struct stat    nst_file_info_t;
typedef pid_t          nst_pid_t;
typedef int            nst_err_t;

/*  Use the following if you need absolute performance.
 *     Please refer to "/usr/include/stdint.h" for details.
 */
typedef intptr_t            nst_int_t;
typedef uintptr_t           nst_uint_t;
typedef intptr_t            nst_flag_t;

typedef enum bool bool;
enum bool
{
    FALSE = 0,
    TRUE = 1,
};

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))
#define nst_abs(value)   (((value) >= 0) ? (value) : - (value))

typedef enum nst_status_e {
    OK = 0,
    ERROR =  -1,
    NST_OK = OK,
    NST_ERROR = ERROR,
    NST_AGAIN = -2,
    NST_BUSY = -3,
    NST_DONE = -4,
    NST_DECLINED = -5,
    NST_ABORT = -6,
    NST_ENOMEM = -7,
    NST_CLOSED = -8,
    NST_ECOALESCE = -9,
} nst_status_e;

/** Exit status reported by processes */
typedef enum nst_exit_status {
    NST_EXIT_OK = 0,
    NST_EXIT_RELOAD_FAILED         = EX__MAX + 1,
    NST_EXIT_RELOAD_RESTART_NEEDED = EX__MAX + 2,
    NST_EXIT_CONFIG_FAILED         = EX__MAX + 3,
} nst_exit_status_e;

#endif /*_NST_TYPES_H_*/
