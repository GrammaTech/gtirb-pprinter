#pragma once

///
/// \define DEBLOAT_PrettyPrinter_EXPORTS
///
/// Defined by the build system (CMake or SCons).
/// This should only be defined by the build system which generates the GT-IRB library.  Users of
/// the library should NOT define this.
///

///
/// \define DEBLOAT_PRETTYPRINTER_EXPORT_API
///
/// This controls the visibility of exported symbols (i.e. classes) in Windows DLL's and Linux
/// Shared Objects.
///

#ifdef WIN32
#if defined DEBLOAT_debloatPrettyPrinter_EXPORTS
#define DEBLOAT_PRETTYPRINTER_EXPORT_API _declspec(dllexport)
#else
#define DEBLOAT_PRETTYPRINTER_EXPORT_API _declspec(dllimport)
#endif
#else
#define DEBLOAT_PRETTYPRINTER_EXPORT_API __attribute__((visibility("default")))
#endif
