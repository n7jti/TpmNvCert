// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here

// Define the minimum required platform for Windows 11 24H2
#define _WIN32_WINNT 0x0B00 // Windows 11
#define WINVER 0x0B00       // Windows 11
#define NTDDI_VERSION 0x0B000000 // 24H2


// Include Windows headers
#include <windows.h>
#include <wincrypt.h>

#endif //PCH_H
