#pragma once

#include <iostream>

/// \todo   Replace these trivial logger macros with boost logger or g3log.

#ifdef _DEBUG
#define LOG_INFO std::cout << "[INFO] (" << __FILE__ << ":" << __LINE__ << ")  "
#define LOG_WARN std::cout << "[WARN] (" << __FILE__ << ":" << __LINE__ << ")  "
#define LOG_ERROR                                                              \
  std::cerr << "[ERROR] (" << __FILE__ << ":" << __LINE__ << ") "
#else
#define LOG_INFO std::cout << "[INFO]  "
#define LOG_WARN std::cout << "[WARN]  "
#define LOG_ERROR std::cerr << "[ERROR] "
#endif

#define LOG_DEBUG                                                              \
  std::cout << "[DEBUG] (" << __FILE__ << ":" << __LINE__ << ") "

inline void deprecatedSymAttributeWarning(const char* Deprecated,
                                          const char* Dedicated) {
  LOG_WARN << "DEPRECATED: File uses co-opted expression attribute:"
           << "`gtirb::SymAttribute::" << Deprecated << "'\n";
  LOG_WARN << "            Backward compatibility for co-opted attributes "
              "will be dropped in early 2022.\n";
  LOG_WARN << "      HINT: Recreate your gtirb file with newer tools to use the"
           << "`gtirb::SymAttribute::" << Dedicated << "' attribute.\n";
}

#define DEPRECATED_SYMATTRIBUTE_WARNING(X, Y)                                  \
  {                                                                            \
    static bool Warned;                                                        \
    if (!Warned) {                                                             \
      deprecatedSymAttributeWarning(#X, #Y);                                   \
      Warned = true;                                                           \
    }                                                                          \
  }
