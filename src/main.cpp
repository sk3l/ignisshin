#include <glob.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <stdexcept>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "app_config.h"
#include "agent_mgr.h"
#include "ssh_agent.h"
#include "private_key.h"

static const char * PID_FILE = "/var/run/ignisshind.pid";

static int pid_fd;

static sk3l::keymaster::agent_mgr agentmgr;

using agent_t  = sk3l::keymaster::ssh_agent;
using privkey_t= sk3l::keymaster::private_key;

static void show_usage()
{
   std::cout << std::endl
             << "ignisshin - SSH session management daemon" << std::endl
             << std::endl
             << "Usage:" << std::endl
             << std::endl
             << "   ignisshin [-D] <config>" << std::endl
             << std::endl
             << "Where:" << std::endl
             << "   -D       - run in foreground (don't daemonize)" << std::endl
             << "   <config> - path to ignisshin config file."
             << std::endl
             << std::endl;
}

static void setup_logger(const sk3l::ignisshin::log_config & cfg, bool daemonize)
{
   try
   {
       std::vector<spdlog::sink_ptr> sinks; 
       if (cfg.sinks_ & sk3l::ignisshin::TO_CONSOLE) 
       {
           auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
           console_sink->set_level(spdlog::level::warn);
           console_sink->set_pattern("[multi_sink_example] [%^%l%$] %v");
           sinks.push_back(console_sink);
       }

       if (cfg.sinks_ & sk3l::ignisshin::TO_FILE)
       {
           auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/multisink.txt", true);
           file_sink->set_level(spdlog::level::trace);
       }

       spdlog::set_default_logger
       (
           std::make_shared<spdlog::logger>
           (
              "ignisshin_sinks", 
              begin(sinks),
              end(sinks) 
           )
       );
   }
   catch (const spdlog::spdlog_ex & e)
   {

   }

}

// TO DO - move out of main
static void start_agents(const sk3l::ignisshin::agent_config_list & aclist)
{
   std::stringstream logbuf;
   for (auto itagent = aclist.begin(); itagent != aclist.end(); ++itagent)
   {
      glob_t keyglob;
      try
      {
         auto agent = std::make_shared<agent_t>(
                        itagent->agent_name_,
                        itagent->account_name_,
                        itagent->socket_addr_);

         std::stringstream().swap(logbuf);
         logbuf << "Attempting start of agent='" << itagent->agent_name_
                << "', account='" << itagent->account_name_
                << "', socket_addr='" << itagent->socket_addr_;
          
         spdlog::debug(logbuf.str());

         if (!agent->start(10, 100))
         {
            std::stringstream().swap(logbuf);
            logbuf << "Could not start agent '" << itagent->agent_name_
                   << "'; skipping.";
            spdlog::error(logbuf.str());
            continue;
         }

         std::stringstream().swap(logbuf);
         logbuf << "Agent '" << itagent->agent_name_ << "' "
                << "successfully started.";
         spdlog::info(logbuf.str());

         std::string keypattern(itagent->key_path_ + std::string("/*"));
         glob(keypattern.c_str(), GLOB_TILDE, NULL, &keyglob);

         for (uint32_t i = 0; i < keyglob.gl_pathc; ++i)
         {
            try
            {
               privkey_t key(keyglob.gl_pathv[i]);
               if (!agent->add_key(key))
               {
                  std::stringstream().swap(logbuf);
                  logbuf << "Could not add key at '"
                         << key.get_filename()
                         << "' to agent '"
                         << itagent->agent_name_
                         << "'" << std::endl;

                  spdlog::warn(logbuf.str());
               }
            }
            catch (const std::invalid_argument & e)
            {
               std::stringstream().swap(logbuf);
               logbuf << "File at '" << keyglob.gl_pathv[i] << "' is not a key.";
               spdlog::warn(logbuf.str());
            }
         }
         globfree(&keyglob);

         std::stringstream().swap(logbuf);
         logbuf << "Writing environment file for agent '"
                << itagent->agent_name_ << "'";
         spdlog::debug(logbuf.str());

         agent->write_env();

         std::stringstream().swap(logbuf);
         logbuf << "Adding agent '"
                << itagent->agent_name_ << "' "
                << "to application agent manager.";
         spdlog::debug(logbuf.str());

         agentmgr.add_agent(agent);
      }
      catch (const std::exception & e)
      {
         std::stringstream().swap(logbuf);

         logbuf << "Encountered error attmpeting to start agent '"
                << itagent->agent_name_ << "' "
                << ": " << e.what();
         spdlog::error(logbuf.str());

         globfree(&keyglob);
      }
   }
}

// Execute ignisshin in daemon mode, utilizing double fork to detach the
// process and put under PID 1 (init system).
// TO DO - find reasonable location (syspdlog?) to put log trace for this func.
static void daemonize()
{
   int fd;

   pid_t pid = fork();
   if (pid < 0)
   {
     exit(EXIT_FAILURE);
   }

   if (pid > 0)
   {
      exit(EXIT_SUCCESS);  // Parent completes its job
   }

   // Make child proc session owner
   if (setsid() < 0)
   {
      exit(EXIT_FAILURE);
   }

   // Child proc is now the session owner

   // Ignore child to parent signal
   signal(SIGCHLD, SIG_IGN);

   // Fork again
   pid = fork();
   if (pid < 0)
   {
      exit(EXIT_FAILURE);
   }

   if (pid > 0)
   {
      exit(EXIT_SUCCESS);  // Parent completes its job
   }

   // Set new file perms
   umask(0);

   // Change working dir
   chdir("/");

   // Close open file descriptors
   for (fd = sysconf(_SC_OPEN_MAX); fd > 0; fd--)
      close(fd);

   // Re-attach std handles to bit bucket
   stdin  = fopen("/dev/null", "r");
   stdout = fopen("/dev/null", "w+");
   stderr = fopen("/dev/null", "w+");

   // Attempt output of PID to lockfile
   pid_fd = open(PID_FILE, O_RDWR|O_CREAT, 0640);
   if (pid_fd < 0)
   {
      exit(EXIT_FAILURE);
   }

   if (lockf(pid_fd, F_TLOCK, 0) < 0)
   {
      exit(EXIT_FAILURE);
   }

   pid = getpid();

   std::stringstream pidstr;
   pidstr << pid;
   write(pid_fd, pidstr.str().c_str(), pidstr.str().length());

}

void handle_signal(int sig)
{
   if (sig == SIGINT)
   {
      if (pid_fd != -1)
      {
         lockf(pid_fd, F_ULOCK, 0);
         close(pid_fd);
      }

      // Try to delete lock file
      unlink(PID_FILE);
      signal(SIGINT, SIG_DFL);
   }
   else if (sig == SIGHUP)
   {
      // TO DO : reload config
   }
}

int main(int argc, char ** argv)
{
   try
   {
      bool run_as_daemon = true;

      if (argc < 2 || argc > 3)
      {
         show_usage();
         exit(EXIT_FAILURE);
      }

      if (argc > 2)
      {
         std::string arg(argv[1]);
         if (arg != "-D")
         {
            show_usage();
            exit(EXIT_FAILURE);
         }
         run_as_daemon = false;
      }

      sk3l::ignisshin::app_config kmcfg =
         sk3l::ignisshin::config_parser::read_from_file(argv[argc-1]);

      //signal(SIGCHLD, SIG_IGN);
      signal(SIGINT, handle_signal);
      signal(SIGHUP, handle_signal);

      // logging setup
      setup_logger(kmcfg.service_.log_, run_as_daemon);

      if (!run_as_daemon)
      {

         spdlog::info("Starting ignisshin on console");

         start_agents(kmcfg.agents_);
         agentmgr.monitor();

         spdlog::info("ignisshin porcess terminated successfully");

         return EXIT_SUCCESS;
      }

      daemonize();

      //loggerCollectionConfig.logconsole = false;
      //spdlog::setup(loggerCollectionConfig);

      spdlog::info("Starting ignisshin as daemon");

      signal(SIGCHLD, SIG_DFL);
      start_agents(kmcfg.agents_);
      agentmgr.monitor();

      spdlog::info("ignisshin daemon terminated successfully");

      return EXIT_SUCCESS;
   }
   catch (const std::exception & err)
   {
      std::stringstream logbuf;
      logbuf << "Encountered fatal error in ignisshin: '"
             << err.what() << "'";
      spdlog::error(logbuf.str());
      return EXIT_FAILURE;
   }
}
