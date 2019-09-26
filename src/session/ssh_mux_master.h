#ifndef SSH_MUX_MASTER_H
#define SSH_MUX_MASTER_H

#include <string>
#include <unistd.h>
#include <libssh/libssh.h>

#include "ssh_mux_misc.h"

namespace sk3l {
namespace ignisshin {


class ssh_mux_master 
{
    private:
        int mux_sock_;

        /* client request id */
        u_int muxclient_request_id = 0;

        /* Multiplexing control command */
        u_int muxclient_command = 0;

        /* Set when signalled. */
        //static volatile sig_atomic_t muxclient_terminate = 0;

        /* PID of multiplex server */
        u_int muxserver_pid = 0;

        //static Channel *mux_listener_channel = NULL;

        ssh_session session_;

        int process_hello();
        int process_new_session();
        int process_alive_check();
        int process_terminate();
        int process_open_fwd();
        int process_close_fwd();
        int process_stdio_fwd();
        int process_stop_listening();
        int process_proxy();

    public:
        ssh_mux_master(ssh_session s);

        void start_listening();
        void stop_listening();
};

}
}

#endif
