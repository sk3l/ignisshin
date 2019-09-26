#ifndef SSH_MUX_MISC_H
#define SSH_MUX_MISC_H

#include <string>
#include <unistd.h>
#include <libssh/libssh.h>

namespace sk3l {
namespace ignisshin {

// session mux miscelany
// directly copied from OpenSSH mux.c

/* Context for session open confirmation callback */
struct mux_session_confirm_ctx 
{
    u_int want_tty;
    u_int want_subsys;
    u_int want_x_fwd;
    u_int want_agent_fwd;
    struct sshbuf *cmd;
    char *term;
    //struct termios tio;
    char **env;
    u_int rid;
};

/* Context for stdio fwd open confirmation callback */
struct mux_stdio_confirm_ctx 
{
    u_int rid;
};

/* Context for global channel callback */
struct mux_channel_confirm_ctx 
{
    u_int cid;    /* channel id */
    u_int rid;    /* request id */
    int fid;    /* forward id */
};

enum mux_protocol_messages
{
    MUX_MSG_HELLO           = 0x00000001,
    MUX_C_NEW_SESSION       = 0x10000002,
    MUX_C_ALIVE_CHECK       = 0x10000004,
    MUX_C_TERMINATE         = 0x10000005,
    MUX_C_OPEN_FWD          = 0x10000006,
    MUX_C_CLOSE_FWD         = 0x10000007,
    MUX_C_NEW_STDIO_FWD     = 0x10000008,
    MUX_C_STOP_LISTENING    = 0x10000009,
    MUX_C_PROXY             = 0x1000000f,
    MUX_S_OK                = 0x80000001,
    MUX_S_PERMISSION_DENIED = 0x80000002,
    MUX_S_FAILURE           = 0x80000003,
    MUX_S_EXIT_MESSAGE      = 0x80000004,
    MUX_S_ALIVE             = 0x80000005,
    MUX_S_SESSION_OPENED    = 0x80000006,
    MUX_S_REMOTE_PORT       = 0x80000007,
    MUX_S_TTY_ALLOC_FAIL    = 0x80000008,
    MUX_S_PROXY             = 0x8000000f
};

/* type codes for MUX_C_OPEN_FWD and MUX_C_CLOSE_FWD */
enum mux_fwc_codes 
{
    MUX_FWD_LOCAL  = 1,
    MUX_FWD_REMOTE = 2,
    MUX_FWD_DYNAMIC= 3
};


}
}

#endif
