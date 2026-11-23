#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntdef.h>
#include <ntimage.h>

// 日志级别定义
#define LOG_LEVEL_NONE    0
#define LOG_LEVEL_FATAL   1
#define LOG_LEVEL_ERROR   2
#define LOG_LEVEL_WARNING 3
#define LOG_LEVEL_INFO    4
#define LOG_LEVEL_DEBUG   5
#define LOG_LEVEL_TRACE   6

// 全局变量来动态设置日志级别，初始值可以为最高等级
EXTERN_C NTSTATUS LogInitialize(VOID);
EXTERN_C VOID LogShutdown(VOID);
EXTERN_C VOID LogPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...);

EXTERN_C ULONG g_LogLevel; // 默认为 LOG_LEVEL_TRACE，可以在运行时进行调整

// 判断当前日志级别是否允许记录
#define LOG_IS_ENABLED(level) (g_LogLevel >= (level))

// 日志宏定义
#define LOG_FATAL(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_FATAL)) { \
            LogPrint("[F][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
            DbgBreakPoint(); \
        } \
    } while (0)

#define LOG_FATAL_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_FATAL)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_ERROR(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_ERROR)) { \
            LogPrint("[E][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_ERROR_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_ERROR)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_WARN(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_WARNING)) { \
            LogPrint("[W][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_WARN_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_WARNING)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_INFO(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_INFO)) { \
            LogPrint("[I][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_INFO_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_INFO)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_DEBUG(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_DEBUG)) { \
            LogPrint("[D][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_DEBUG_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_DEBUG)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_TRACE(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_TRACE)) { \
            LogPrint("[T][%s():%u] " fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOG_TRACE_NOPREFIX(fmt, ...) \
    do { \
        if (LOG_IS_ENABLED(LOG_LEVEL_TRACE)) { \
            LogPrint(fmt, ##__VA_ARGS__); \
        } \
    } while (0)
