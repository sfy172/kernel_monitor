#include "HookManager.h"
#include "logging.h"
#include "MonitorAddressManager.h"
#include "handlers.h"

namespace smallzhong
{
	// 检查函数是否在可用列表中
	BOOLEAN IsFunctionAvailable(const char* funcName) {
		uint32_t hash = RuntimeHash(funcName);
		return std::binary_search(kFunctionHashes.begin(), kFunctionHashes.end(), hash);
	}

	bool isFunctionLengthAtLeast16(void* functionAddress) {
		uint8_t* currentAddress = static_cast<uint8_t*>(functionAddress);
		int totalLength = 0;

		while (totalLength < 16) {
			int instructionLength;

			instructionLength = insn_len_x86_64(currentAddress);


			if (*currentAddress == 0xCC) {
				// 遇到 int3 指令 (0xCC),函数结束
				return FALSE;
			}

			totalLength += instructionLength;
			currentAddress += instructionLength;
		}

		return TRUE;
	}


	std::optional<std::vector<ExportedFunction>> get_export_functions_by_imagebase(void* moduleBase) {
		if (!moduleBase) {
			return std::nullopt;
		}

		auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return std::nullopt;
		}

		auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
			reinterpret_cast<BYTE*>(moduleBase) + dosHeader->e_lfanew
			);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			return std::nullopt;
		}

		auto& exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exportDirectory.Size == 0 || exportDirectory.VirtualAddress == 0) {
			return std::nullopt;
		}

		auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDirectory.VirtualAddress
			);

		auto functionAddresses = reinterpret_cast<PDWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfFunctions
			);
		auto functionNames = reinterpret_cast<PDWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfNames
			);
		auto functionOrdinals = reinterpret_cast<PWORD>(
			reinterpret_cast<BYTE*>(moduleBase) + exportDir->AddressOfNameOrdinals
			);

		std::vector<ExportedFunction> exportedFunctions;
		exportedFunctions.reserve(exportDir->NumberOfNames);

		for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
			const char* functionName = reinterpret_cast<const char*>(
				reinterpret_cast<BYTE*>(moduleBase) + functionNames[i]
				);
			WORD ordinal = functionOrdinals[i];
			DWORD functionRVA = functionAddresses[ordinal];
			ULONG64 functionAddress = reinterpret_cast<ULONG64>(moduleBase) + functionRVA;

			exportedFunctions.push_back({ functionName, functionAddress });
		}

		return exportedFunctions;
	}


	// 构造函数
	Hook::Hook(ULONG64 funcAddr, ULONG64 callbackFunc) noexcept
		: m_record_number(std::nullopt), m_func_addr(funcAddr), m_callback_func(callbackFunc) {
	}

	// 移动构造函数
	Hook::Hook(Hook&& other) noexcept
		: m_record_number(std::exchange(other.m_record_number, std::nullopt)),
		m_func_addr(other.m_func_addr),
		m_callback_func(other.m_callback_func) {
	}

	// 移动赋值运算符
	Hook& Hook::operator=(Hook&& other) noexcept {
		if (this != &other) {
			reset();
			m_record_number = std::exchange(other.m_record_number, std::nullopt);
			m_func_addr = other.m_func_addr;
			m_callback_func = other.m_callback_func;
		}
		return *this;
	}

	// 析构函数
	Hook::~Hook() {
		reset();
	}

	// 安装 hook
	NTSTATUS Hook::install() noexcept {
		if (m_record_number.has_value()) {
			return STATUS_SUCCESS;
		}
		if (!m_func_addr || !m_callback_func) {
			return STATUS_INVALID_PARAMETER;
		}

		ULONG64 record_number = 0;
		const NTSTATUS status = hook_by_addr(m_func_addr, m_callback_func, &record_number);
		if (NT_SUCCESS(status)) {
			m_record_number = record_number;
		}
		return status;
	}

	// 重置/卸载 hook
	void Hook::reset() {
		if (m_record_number.has_value()) {
			reset_hook(m_record_number.value());
			m_record_number = std::nullopt;
		}
	}

	// 获取 record number
	ULONG64 Hook::get_record_number() const {
		if (!m_record_number.has_value()) {
			throw std::runtime_error("No active hook");
		}
		return m_record_number.value();
	}

	// 检查 hook 是否有效
	bool Hook::is_valid() const {
		return m_record_number.has_value();
	}

	ULONG64 Hook::get_function_address() const noexcept {
		return m_func_addr;
	}

	NTSTATUS HookManager::add_hook(ULONG64 funcAddr, ULONG64 callbackFunc, size_t* hook_index) {
		if (hook_index) {
			*hook_index = static_cast<size_t>(-1);
		}
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_shutdown) {
			return STATUS_DELETE_PENDING;
		}
		if (hooked_funcs.count(funcAddr)) {
			return STATUS_OBJECT_NAME_COLLISION;
		}

		// Allocate bookkeeping before installing the hook. The constructor cannot throw.
		try {
			hooked_funcs.insert(funcAddr);
			m_hooks.emplace_back(funcAddr, callbackFunc);
		}
		catch (const std::exception&) {
			hooked_funcs.erase(funcAddr);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		const NTSTATUS status = m_hooks.back().install();
		if (!NT_SUCCESS(status)) {
			hooked_funcs.erase(funcAddr);
			m_hooks.pop_back();
			return status;
		}

		if (hook_index) {
			*hook_index = m_hooks.size() - 1;
		}
		return status;
	}

	// 移除特定的 hook (通过索引)
	bool HookManager::remove_hook(size_t index) {
		std::lock_guard<std::mutex> lock(m_mutex);
		if (index >= m_hooks.size()) {
			return false;
		}

		hooked_funcs.erase(m_hooks[index].get_function_address());
		// 使用移动赋值将最后一个元素移动到要删除的位置
		if (index < m_hooks.size() - 1) {
			m_hooks[index] = std::move(m_hooks.back());
		}

		// 移除最后一个元素
		m_hooks.pop_back();
		return true;
	}

	// 移除所有 hooks
	void HookManager::remove_all_hooks() {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_hooks.clear();
		hooked_funcs.clear();
	}

	void HookManager::shutdown() {
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_shutdown) {
			return;
		}
		m_shutdown = true;
		m_hooks.clear();
		hooked_funcs.clear();
		const NTSTATUS status = kernel_hook_unload();
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("kernel hook unload failed, status 0x%08lX\r\n", static_cast<ULONG>(status));
		}
		else {
			LOG_INFO("Hook manager shut down\r\n");
		}
	}

	// 获取当前 hook 数量
	size_t HookManager::hook_count() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_hooks.size();
	}
}


