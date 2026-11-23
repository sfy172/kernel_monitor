#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>

#include "HookManager.h"
#include "handlers.h"
#include "MonitorAddressManager.h"
#include "logging.h"


static bool g_ImageCallbackRegistered = false;
static bool g_KernelHooksInitialized = false;

VOID ImageLoadCallback(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo)
{

	if (ProcessId == 0 && FullImageName != NULL)
	{

		// 检查是否是 Loader.sys 被加载
		if (wcsstr(FullImageName->Buffer, L"\\ACEDriver.sys"))
		{
			LOG_INFO("ACEDriver.sys" " has been loaded!\n");
			LOG_INFO("Image Base: %p\n", ImageInfo->ImageBase);
			LOG_INFO("Image Size: %llx\n", ImageInfo->ImageSize);

			ADD_MONITOR_RANGE((ULONG64)ImageInfo->ImageBase, (ULONG64)ImageInfo->ImageBase + ImageInfo->ImageSize);
		}
	}
}

VOID my_sleep(ULONG n)
{
	LARGE_INTEGER timeout;
	timeout.QuadPart = -10 * 1000;
	timeout.QuadPart *= n;
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
}


VOID DRIVERUNLOAD(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (g_ImageCallbackRegistered) {
        const NTSTATUS status = PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("PsRemoveLoadImageNotifyRoutine failed, status 0x%08lX\r\n", static_cast<ULONG>(status));
        }
        g_ImageCallbackRegistered = false;
    }
    if (g_KernelHooksInitialized) {
        GLOBAL_HOOK_MANAGER.shutdown();
        g_KernelHooksInitialized = false;
    }
    LOG_INFO("Driver cleanup complete\r\n");
    LogShutdown();
}

struct DriverInitializationGuard {
    bool Complete = false;
    ~DriverInitializationGuard() {
        if (!Complete) {
            DRIVERUNLOAD(nullptr);
        }
    }
};

EXTERN_C NTSTATUS DriverMain(const PDRIVER_OBJECT DriverObject, const PUNICODE_STRING Registry)
{
	UNREFERENCED_PARAMETER(Registry);

	NTSTATUS status = LogInitialize();
	if (!NT_SUCCESS(status)) {
		LOG_ERROR("File logger initialization failed, status 0x%08lX\r\n", static_cast<ULONG>(status));
	}
	DriverInitializationGuard initialization;

	LOG_WARN("driver loaded %p %llx\r\n", DriverObject->DriverStart, (ULONG64)DriverObject->DriverStart + DriverObject->DriverSize);

	LOG_INFO("entry\r\n");


	// 初始化kernel_hook
	status = kernel_hook_init(DriverObject);
	if (!NT_SUCCESS(status))
	{
		LOG_ERROR("kerenl_hook_init failed!\r\n");
		return status;
	}

	g_KernelHooksInitialized = true;

	status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
	if (!NT_SUCCESS(status))
	{
		LOG_ERROR("PsSetLoadImageNotifyRoutine failed\r\n");
		return status;
	}
	g_ImageCallbackRegistered = true;

	if (auto module_info = smallzhong::search::get_sys_module_info("ntoskrnl.exe"))
	{
		auto [base_address, size] = module_info.value();
		LOG_INFO("%p %x\r\n", base_address, size);


		if (auto func_names = smallzhong::get_export_functions_by_imagebase(base_address); !func_names.has_value())
		{
			LOG_ERROR("get_export_functions_by_imagebase failed\r\n");
			return STATUS_UNSUCCESSFUL;
		}
		else
		{
			auto reversed_func_names = func_names.value();
			// 想先hook zw相关函数，因此直接reverse
			std::reverse(reversed_func_names.begin(), reversed_func_names.end());

			for (auto& func : reversed_func_names)
			{
				if (smallzhong::IsFunctionAvailable(func.function_name.c_str()))
				{
#if 1
					if (0) {}
#else 
					if (func.function_name == "KdDisableDebugger")
					{
						auto lambda = [](GuestContext* context) -> BOOLEAN {
							ULONG64 origin_ret_addr = *(PULONG64)(context->mRsp);
							if (FILTER_RET_ADDR(origin_ret_addr))
							{
								LOG_INFO("Function: KdDisableDebugger\nRCX: %llx, RDX: %llx, R8: %llx, R9: %llx\nReturn Address: %llx\n\n",
									context->mRcx, context->mRdx, context->mR8, context->mR9, origin_ret_addr);
							}
							context->mRax = STATUS_SUCCESS;
							return TRUE;
							};

						const NTSTATUS hook_status = GLOBAL_HOOK_MANAGER.add_hook(func.address, reinterpret_cast<ULONG64>(+lambda));
						if (NT_SUCCESS(hook_status)) {
							LOG_INFO("Successfully hooked %s at %llx\r\n", func.function_name.c_str(), func.address);
						}
						else {
							LOG_WARN("Failed to hook %s at %llx, status 0x%08lX\r\n",
								func.function_name.c_str(), func.address, static_cast<ULONG>(hook_status));
						}

					}
					else if (func.function_name == "KdRefreshDebuggerNotPresent")
					{
						//DbgBreakPoint();

						auto lambda = [](GuestContext* context) -> BOOLEAN {
							ULONG64 origin_ret_addr = *(PULONG64)(context->mRsp);
							if (FILTER_RET_ADDR(origin_ret_addr))
							{
								LOG_INFO("Function: KdRefreshDebuggerNotPresent\nRCX: %llx, RDX: %llx, R8: %llx, R9: %llx\nReturn Address: %llx\n\n",
									context->mRcx, context->mRdx, context->mR8, context->mR9, origin_ret_addr);
							}
							context->mRax = 1;
							return TRUE;
							};
						const NTSTATUS hook_status = GLOBAL_HOOK_MANAGER.add_hook(func.address, reinterpret_cast<ULONG64>(+lambda));
						if (NT_SUCCESS(hook_status)) {
							LOG_INFO("Successfully hooked %s at %llx\r\n", func.function_name.c_str(), func.address);
						}
						else {
							LOG_WARN("Failed to hook %s at %llx, status 0x%08lX\r\n",
								func.function_name.c_str(), func.address, static_cast<ULONG>(hook_status));
						}

					}
#endif 
					else
					{
						// 查找对应的处理程序
						PFN_GUEST_CALLBACK handler = find_handler_by_name(func.function_name.c_str());
						if (handler)
						{
							const NTSTATUS hook_status = GLOBAL_HOOK_MANAGER.add_hook(func.address, reinterpret_cast<ULONG64>(handler));
							if (NT_SUCCESS(hook_status)) {
								LOG_INFO("Successfully hooked %s at %llx\r\n", func.function_name.c_str(), func.address);
							}
							else {
								LOG_WARN("Failed to hook %s at %llx, status 0x%08lX\r\n",
									func.function_name.c_str(), func.address, static_cast<ULONG>(hook_status));
							}
						}
					}
				}
				else
				{
					LOG_INFO("%s Does not support hooking, possibly because other code might jump to the first 14 bytes at the beginning.\r\n", func.function_name.c_str());
				}
			}
		}
	}
	else
	{
		LOG_ERROR("get_sys_module_info failed\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->DriverUnload = DRIVERUNLOAD;
	initialization.Complete = true;
	return STATUS_SUCCESS;
}