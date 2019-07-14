//#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#define CATCH_CONFIG_RUNNER
//#undef CATCH_CONFIG_POSIX_SIGNALS
#include <catch/catch.hpp>

#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include <sftplogging_log.h>

using slog = BloombergLP::sftplogging::log;
using log_verbosity = BloombergLP::sftplogging::log_verbosity;
using logger_config = BloombergLP::sftplogging::logger_config;
using logger_collection_config = BloombergLP::sftplogging::logger_collection_config;

int main(int argc, char ** argv)
{
   logger_collection_config loggerCollectionConfig;
   loggerCollectionConfig.logconsole = true;
   loggerCollectionConfig.location = "./keymaster_test_log.txt";
   loggerCollectionConfig.default_logger.name = "keymaster";
   loggerCollectionConfig.default_logger.verbosity = log_verbosity::error;

   slog::setup(loggerCollectionConfig);

   int result = Catch::Session().run(argc, argv);

   return (result < 0xff ? result : 0xff);
}
