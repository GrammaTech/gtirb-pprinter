#pragma once

#include <iostream>

/// \todo   Replace these trivial logger macros with boost logger or g3log.

#ifndef NDEBUG
#define LOG_INFO std::cout << "[INFO] (" << __FILE__ << ":" << __LINE__ << ")  "
#define LOG_ERROR                                                              \
  std::cerr << "[ERROR] (" << __FILE__ << ":" << __LINE__ << ") "
#define LOG_WARNING                                                            \
  std::cerr << "[WARNING] (" << __FILE__ << ":" << __LINE__ << ") "
#else
#define LOG_INFO std::cout << "[INFO]  "
#define LOG_ERROR std::cerr << "[ERROR] "
#define LOG_WARNING std::cerr << "[WARNING] "
#endif

#define LOG_DEBUG                                                              \
  std::cout << "[DEBUG] (" << __FILE__ << ":" << __LINE__ << ") "
