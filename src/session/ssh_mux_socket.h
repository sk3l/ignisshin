#ifndef SSH_MUX_SOCKET_H
#define SSH_MUX_SOCKET_H

#include <string>
#include <unistd.h>

#include "ssh_mux_misc.h"

namespace sk3l {
namespace ignisshin {

class ssh_mux_socket
{
    private:
        int mux_sock_;
        std::string path_;

    public:
        ssh_mux_socket(const std::string & path, size_t backlog);
        ssh_mux_socket(const ssh_mux_socket & rhs) = delete;
        ssh_mux_socket & opererator=(const ssh_mux_socket & rhs) = delete;

        void listen();

        ~ssh_mux_socket();
};

}
}

#endif
