#ifndef __NST_CONNECT_H__
#define __NST_CONNECT_H__

struct nst_connect_context;
enum nst_connect_status {
    NST_CONNECT_STATUS_CONNECTED = 0,
    NST_CONNECT_STATUS_INPROGRESS,
    /* All the error codes -, after errno */
    NST_CONNECT_STATUS_FD_ALLOC_FAILED = -10000, 
    NST_CONNECT_STATUS_MALLOC_FAILED,
    NST_CONNECT_STATUS_BIND_FAILED,
    NST_CONNECT_STATUS_NBSET_FAILED,
    NST_CONNECT_STATUS_EQADD_FAILED,
    NST_CONNECT_STATUS_FAILED,
    NST_CONNECT_STATUS_SOCKNAME_FAILED,
    NST_CONNECT_STATUS_CONNECT_FAILED,
    NST_CONNECT_STATUS_TIMEOUT,
};

typedef enum nst_connect_status nst_connect_status_e;
typedef void (*nst_connect_handler_f)(nst_connect_status_e status, nst_connection_t * c, struct nst_connect_context * ctx);

typedef struct nst_connect_context {
    void                       * data;
    nst_sockaddr_t               peer_sockaddr;
    nst_sockaddr_t               local_sockaddr;
    nst_connect_handler_f        cbf;
    /*
     * Why do we need this here. You may ask. Why can't we
     * just pass it in the cbf. All I can say is this: I tried.
     * Some one decided to do funny stuff to errno, they just
     * #defined errno to (*__errno_location ()). gcc does not
     * like this cruft to be passed into functions pointers. But
     * for some reason, It does not complain when assigning to a variable.
     */
    int                          error;    
    int                          timeout;
} nst_connect_context_t;

void nst_connect_cb (int dobind, nst_conn_type_e type, nst_connect_context_t * ctx);
void nst_connect_connected (nst_connection_t * c);
int nst_connect (int dobind, nst_conn_type_e type, nst_event_handler_f rh, nst_event_handler_f  wh, nst_connect_context_t * ctx);
#endif /*__NST_CONNECT_H__*/
