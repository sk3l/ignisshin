#include <fstream>
#include <iostream>
#include <string>

#include <libgen.h>
#include <linux/limits.h>
#include <unistd.h>

#include "keymaster_test_utils.h"

// TO DO - factor out test helpers to common module
std::string getTestDirFQN()
{
   char result[PATH_MAX];
   ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);

   const char * path;
   if (count != -1)
   {
      result[count] = 0;
      path = dirname(result);

   }
   return std::string(path);
}

std::string getFile(const std::string & path)
{
   std::string contents;
   std::ifstream file(path);

   while (file.good())
   {
      std::string line;
      getline(file, line);
      contents += line + "\n";
   }

   return contents;
}


