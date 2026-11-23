#pragma once


#include<ntifs.h> 
#include <ntddk.h>
#include <ntstrsafe.h>
#include <vector>
#include <vector>
#include <ranges>
#include <concepts>
#include <format>
#include "search.h"
#include "AsmCode.h"
#include "hook.h"
#include <unordered_set>
#include <mutex>
#include <set>
#include <array>
#include <algorithm>
#include <atomic>
#include <array>
#include <stdint.h>
#include <string_view>

namespace smallzhong
{
	struct ExportedFunction {
		std::string function_name;
		ULONG64 address;
	};



	// 编译期哈希函数 (FNV-1a 哈希算法)
	constexpr uint32_t CompileTimeHash(std::string_view str, uint32_t hash = 2166136261u) {
		return str.empty() ? hash : CompileTimeHash(
			str.substr(1),
			(hash ^ static_cast<uint32_t>(str[0])) * 16777619u
		);
	}

	// 排序用的比较函数
	constexpr bool HashCompare(uint32_t a, uint32_t b) {
		return a < b;
	}

	constexpr auto  kFunctionHashes = []() {
		auto hashes = std::array{
			//CompileTimeHash("KiComputePriorityFloor"),
	#include "available_funcs.inc"
			// ... 添加更多字符串哈希值
		};

		// 编译期对数组进行排序
		//std::sort(hashes.begin(), hashes.end());

		return hashes;
		}();

	// 二分查找检查函数是否存在
	template<typename Array>
	constexpr bool BinarySearch(const Array& arr, uint32_t value) {
		size_t left = 0;
		size_t right = arr.size() - 1;

		while (left <= right) {
			size_t mid = left + (right - left) / 2;

			if (arr[mid] == value) {
				return true;
			}

			if (arr[mid] < value) {
				left = mid + 1;
			}
			else {
				if (mid == 0) return false;
				right = mid - 1;
			}
		}

		return false;
	}

	// 编译期检查版本 (用于constexpr场景)
	constexpr bool IsFunctionAvailableConstexpr(std::string_view funcName) {
		return BinarySearch(kFunctionHashes, CompileTimeHash(funcName));
	}

	// 编译期验证查找是否正常工作
	static_assert(BinarySearch(kFunctionHashes, CompileTimeHash("ExAllocatePoolWithQuota")),
		"Hash lookup failed at compile time");

	// 检查函数是否在可用列表中
	BOOLEAN IsFunctionAvailable(const char* funcName);

	// 单个 Hook 的封装类
	class Hook {
	public:
		// Construction leaves the hook inactive. install() returns its NTSTATUS.
		Hook(ULONG64 funcAddr, ULONG64 callbackFunc) noexcept;

		// 移动构造函数
		Hook(Hook&& other) noexcept;

		// 移动赋值运算符
		Hook& operator=(Hook&& other) noexcept;

		// 禁用复制
		Hook(const Hook&) = delete;
		Hook& operator=(const Hook&) = delete;

		// 析构函数
		~Hook();

		// 安装 hook
		NTSTATUS install() noexcept;

		// 重置/卸载 hook
		void reset();

		// 获取 record number
		ULONG64 get_record_number() const;

		// 检查 hook 是否有效
		bool is_valid() const;

		ULONG64 get_function_address() const noexcept;
	private:
		std::optional<ULONG64> m_record_number;
		ULONG64 m_func_addr;
		ULONG64 m_callback_func;
	};

	// 全局 Hook 管理器 - 单例模式
	class HookManager {
	public:
		static HookManager& instance() {
			static HookManager instance;
			return instance;
		}

		// Return the installation status and optionally the index of the new hook.
		NTSTATUS add_hook(ULONG64 funcAddr, ULONG64 callbackFunc, size_t* hook_index = nullptr);

		// 使用模板添加 hook 的便捷方法
		template<typename Func>
		NTSTATUS add_hook(ULONG64 funcAddr, Func&& callback, size_t* hook_index = nullptr) {
			return add_hook(funcAddr, reinterpret_cast<ULONG64>(+std::forward<Func>(callback)), hook_index);
		}

		// 移除特定的 hook (通过索引)
		bool remove_hook(size_t index);

		// 移除所有 hooks
		void remove_all_hooks();

		// Stop hooks and wait for deferred cleanup before shutting down logging.
		void shutdown();

		// 获取当前 hook 数量
		size_t hook_count() const;

		// 禁用复制和移动
		HookManager(const HookManager&) = delete;
		HookManager& operator=(const HookManager&) = delete;
		HookManager(HookManager&&) = delete;
		HookManager& operator=(HookManager&&) = delete;

	private:
		// 私有构造函数 (单例模式)
		HookManager()
		{
			LOG_WARN("HookManager is constructed(this is a singleton, if you see this message twice, there must be some error occured.)\r\n");
		}

		// 私有析构函数 (单例模式)
		~HookManager() {
			shutdown();
		}

		bool m_shutdown = false;
		std::vector<Hook> m_hooks;
		std::unordered_set<ULONG64> hooked_funcs;
		mutable std::mutex m_mutex;  // 保护多线程访问
	};




	bool isFunctionLengthAtLeast16(void* functionAddress);

	std::optional<std::vector<ExportedFunction>> get_export_functions_by_imagebase(void* moduleBase);

}

// 辅助宏，便于使用
#define GLOBAL_HOOK_MANAGER smallzhong::HookManager::instance()