#include "logging.h"
#include <ntstrsafe.h>
#include <stdarg.h>

#define LOG_POOL_TAG 'gLmK'
#define LOG_RECORD_COUNT 2048
#define LOG_RECORD_BYTES 1024
#define LOG_BATCH_BYTES (32 * 1024)

typedef struct _LOG_RECORD {
    LIST_ENTRY Link;
    ULONG Length;
    CHAR Text[LOG_RECORD_BYTES];
} LOG_RECORD, *PLOG_RECORD;

ULONG g_LogLevel = LOG_LEVEL_INFO;

static KSPIN_LOCK g_LogLock;
static LIST_ENTRY g_LogFree;
static LIST_ENTRY g_LogPending;
static KEVENT g_LogEvent;
static EX_RUNDOWN_REF g_LogRundown;
static PLOG_RECORD g_LogRecords;
static PCHAR g_LogBatch;
static HANDLE g_LogFile;
static HANDLE g_LogThread;
static PETHREAD volatile g_LogWorkerThread;
static volatile LONG g_LogReady;
static volatile LONG g_LogStopping;
static DECLSPEC_ALIGN(8) volatile LONG64 g_LogDropped;
static NTSTATUS g_LogLastWriteStatus;

// Called only by the worker at PASSIVE_LEVEL. The handle is append-only.
static VOID LogWriteBytes(_In_reads_bytes_(Length) const CHAR* Text, ULONG Length)
{
    ULONG written = 0;
    while (written < Length) {
        IO_STATUS_BLOCK ioStatus = { 0 };
        NTSTATUS status = ZwWriteFile(g_LogFile, NULL, NULL, NULL, &ioStatus,
            (PVOID)(Text + written), Length - written, NULL, NULL);
        if (NT_SUCCESS(status) &&
            (ioStatus.Information == 0 || ioStatus.Information > Length - written)) {
            status = STATUS_UNEXPECTED_IO_ERROR;
        }
        if (!NT_SUCCESS(status)) {
            if (status != g_LogLastWriteStatus) {
                DbgPrintEx(77, 0, "[kernel_monitor] log write failed: 0x%08lX\r\n", (ULONG)status);
            }
            g_LogLastWriteStatus = status;
            return;
        }
        written += (ULONG)ioStatus.Information;
    }
    g_LogLastWriteStatus = STATUS_SUCCESS;
}

static VOID LogReportDropped(VOID)
{
    LONG64 dropped = InterlockedExchange64(&g_LogDropped, 0);
    if (dropped != 0) {
        CHAR message[128];
        size_t length = 0;
        NTSTATUS status = RtlStringCbPrintfA(message, sizeof(message),
            "\r\n[kernel_monitor] dropped %lld file log messages (queue full or IRQL > DISPATCH_LEVEL)\r\n",
            dropped);
        if (NT_SUCCESS(status) && NT_SUCCESS(RtlStringCbLengthA(message, sizeof(message), &length))) {
            DbgPrintEx(77, 0, "%s", message);
            LogWriteBytes(message, (ULONG)length);
        }
    }
}

static VOID LogWorker(_In_opt_ PVOID Context)
{
    IO_STATUS_BLOCK ioStatus;
    UNREFERENCED_PARAMETER(Context);
    g_LogWorkerThread = PsGetCurrentThread();

    for (;;) {
        KeWaitForSingleObject(&g_LogEvent, Executive, KernelMode, FALSE, NULL);
        for (;;) {
            ULONG batchLength = 0;
            BOOLEAN empty = FALSE;
            while (batchLength <= LOG_BATCH_BYTES - LOG_RECORD_BYTES) {
                KIRQL oldIrql;
                PLOG_RECORD record = NULL;
                KeAcquireSpinLock(&g_LogLock, &oldIrql);
                if (!IsListEmpty(&g_LogPending)) {
                    record = CONTAINING_RECORD(RemoveHeadList(&g_LogPending), LOG_RECORD, Link);
                }
                KeReleaseSpinLock(&g_LogLock, oldIrql);
                if (record == NULL) {
                    empty = TRUE;
                    break;
                }
                RtlCopyMemory(g_LogBatch + batchLength, record->Text, record->Length);
                batchLength += record->Length;
                KeAcquireSpinLock(&g_LogLock, &oldIrql);
                InsertTailList(&g_LogFree, &record->Link);
                KeReleaseSpinLock(&g_LogLock, oldIrql);
            }
            if (batchLength != 0) {
                LogWriteBytes(g_LogBatch, batchLength);
            }
            LogReportDropped();
            if (empty) {
                if (InterlockedCompareExchange(&g_LogStopping, 0, 0) != 0) {
                    KIRQL oldIrql;
                    NTSTATUS status;
                    // Producers may have queued records while the batch was writing.
                    // Stopping is published only after every producer has finished.
                    KeAcquireSpinLock(&g_LogLock, &oldIrql);
                    empty = IsListEmpty(&g_LogPending);
                    KeReleaseSpinLock(&g_LogLock, oldIrql);
                    if (!empty) {
                        continue;
                    }
                    status = ZwFlushBuffersFile(g_LogFile, &ioStatus);
                    if (!NT_SUCCESS(status)) {
                        DbgPrintEx(77, 0, "[kernel_monitor] log flush failed: 0x%08lX\r\n", (ULONG)status);
                    }
                    PsTerminateSystemThread(STATUS_SUCCESS);
                    return;
                }
                break;
            }
        }
    }
}

NTSTATUS LogInitialize(VOID)
{
    UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\??\\C:\\kernel_monitor.log");
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    ULONG index;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedCompareExchange(&g_LogReady, 0, 0) != 0) {
        return STATUS_SUCCESS;
    }
    KeInitializeSpinLock(&g_LogLock);
    InitializeListHead(&g_LogFree);
    InitializeListHead(&g_LogPending);
    KeInitializeEvent(&g_LogEvent, SynchronizationEvent, FALSE);
    ExInitializeRundownProtection(&g_LogRundown);
    g_LogStopping = 0;
    g_LogDropped = 0;
    g_LogLastWriteStatus = STATUS_SUCCESS;
    g_LogWorkerThread = NULL;

    g_LogRecords = ExAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(LOG_RECORD) * LOG_RECORD_COUNT, LOG_POOL_TAG);
    g_LogBatch = ExAllocatePoolWithTag(NonPagedPoolNx, LOG_BATCH_BYTES, LOG_POOL_TAG);
    if (g_LogRecords == NULL || g_LogBatch == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }
    for (index = 0; index < LOG_RECORD_COUNT; ++index) {
        InsertTailList(&g_LogFree, &g_LogRecords[index].Link);
    }
    InitializeObjectAttributes(&attributes, &fileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = ZwCreateFile(&g_LogFile, FILE_APPEND_DATA | SYNCHRONIZE,
        &attributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&g_LogThread, SYNCHRONIZE, &attributes,
        NULL, NULL, LogWorker, NULL);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }
    InterlockedExchange(&g_LogReady, 1);
    return STATUS_SUCCESS;

Failure:
    if (g_LogFile != NULL) {
        ZwClose(g_LogFile);
        g_LogFile = NULL;
    }
    if (g_LogBatch != NULL) {
        ExFreePoolWithTag(g_LogBatch, LOG_POOL_TAG);
        g_LogBatch = NULL;
    }
    if (g_LogRecords != NULL) {
        ExFreePoolWithTag(g_LogRecords, LOG_POOL_TAG);
        g_LogRecords = NULL;
    }
    return status;
}

VOID LogShutdown(VOID)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (InterlockedExchange(&g_LogReady, 0) == 0) {
        return;
    }
    // Finish producers already formatting a record before draining the queue.
    ExWaitForRundownProtectionRelease(&g_LogRundown);
    InterlockedExchange(&g_LogStopping, 1);
    KeSetEvent(&g_LogEvent, IO_NO_INCREMENT, FALSE);
    ZwWaitForSingleObject(g_LogThread, FALSE, NULL);
    ZwClose(g_LogThread);
    g_LogThread = NULL;
    g_LogWorkerThread = NULL;
    ZwClose(g_LogFile);
    g_LogFile = NULL;
    ExFreePoolWithTag(g_LogBatch, LOG_POOL_TAG);
    g_LogBatch = NULL;
    ExFreePoolWithTag(g_LogRecords, LOG_POOL_TAG);
    g_LogRecords = NULL;
}

VOID LogPrint(_In_z_ _Printf_format_string_ PCSTR Format, ...)
{
    va_list arguments;
    KIRQL oldIrql;
    PLOG_RECORD record = NULL;
    NTSTATUS status;
    PCHAR end = NULL;

    // File I/O can invoke monitored code. Do not log the logger's own thread.
    if (PsGetCurrentThread() == g_LogWorkerThread) {
        return;
    }
    va_start(arguments, Format);
    vDbgPrintEx(77, 0, Format, arguments);
    va_end(arguments);

    if (InterlockedCompareExchange(&g_LogReady, 0, 0) == 0) {
        return;
    }
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) {
        InterlockedIncrement64(&g_LogDropped);
        return;
    }
    if (!ExAcquireRundownProtection(&g_LogRundown)) {
        return;
    }
    KeAcquireSpinLock(&g_LogLock, &oldIrql);
    if (!IsListEmpty(&g_LogFree)) {
        record = CONTAINING_RECORD(RemoveHeadList(&g_LogFree), LOG_RECORD, Link);
    }
    KeReleaseSpinLock(&g_LogLock, oldIrql);
    if (record == NULL) {
        InterlockedIncrement64(&g_LogDropped);
    }
    else {
        // Format into nonpaged pool, keeping large buffers off the kernel stack.
        va_start(arguments, Format);
        status = RtlStringCbVPrintfExA(record->Text, sizeof(record->Text),
            &end, NULL, 0, Format, arguments);
        va_end(arguments);
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
            record->Length = (ULONG)(end - record->Text);
            if (status == STATUS_BUFFER_OVERFLOW) {
                static const CHAR suffix[] = "...[truncated]\r\n";
                RtlCopyMemory(record->Text + record->Length - (sizeof(suffix) - 1),
                    suffix, sizeof(suffix) - 1);
            }
        }
        else {
            static const CHAR error[] = "[kernel_monitor] log formatting failed\r\n";
            RtlCopyMemory(record->Text, error, sizeof(error) - 1);
            record->Length = sizeof(error) - 1;
        }
        KeAcquireSpinLock(&g_LogLock, &oldIrql);
        InsertTailList(&g_LogPending, &record->Link);
        KeReleaseSpinLock(&g_LogLock, oldIrql);
    }
    KeSetEvent(&g_LogEvent, IO_NO_INCREMENT, FALSE);
    ExReleaseRundownProtection(&g_LogRundown);
}
