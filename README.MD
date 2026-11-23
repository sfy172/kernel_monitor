# kernel_monitor

通过内核 inline hook 记录被监控驱动对内核导出函数的调用，输出函数名、寄存器参数和返回地址。日志同时发送到调试输出，并由后台线程追加写入 `C:\kernel_monitor.log`。

+ 关于本框架的详细说明请见 [https://bbs.kanxue.com/thread-286641.htm](https://bbs.kanxue.com/thread-286641.htm)
+ 本项目使用了 [https://github.com/smallzhong/kernelhook](https://github.com/smallzhong/kernelhook) 这个内核 inlinehook 框架。
+ 本项目的设计初衷是在CTF比赛中提高分析驱动程序逻辑的效率，项目的开发和测试都是在虚拟机中进行的，没有考虑过过PG等在真机中运行会遇到的问题。如果您希望用来分析外挂等带有反虚拟机、反测试模式，必须在真机中运行的程序，请自行解决过PG等问题。

## 功能与修复

- 根据目标系统内核的自动分析结果，为匹配的导出函数安装 Hook，并按调用方返回地址筛选需要记录的调用。当前默认监控 `ACEDriver.sys`。
- Hook 安装通过 `NTSTATUS` 返回结果，失败时回滚管理状态，避免安装失败在容器扩容期间反复触发异常。移除 Hook 时同步清理重复安装记录。
- 日志通过预分配的非分页队列交给系统线程批量写入文件。正常卸载时先清理 Hook，再等待日志队列排空并刷新文件。

## 使用流程

+ 使用 Visual Studio 打开 `KMDF Driver1.sln`，准备 C++ 驱动开发工具、Windows SDK 和 WDK，通过 NuGet 还原 `packages.config` 中的依赖。项目使用米松哥封装的 [Musa.Runtime](https://github.com/MiroKaku/Musa.runtime)。

+ 用 IDA 打开目标系统的 `ntoskrnl.exe`，等待分析完成。打开 `scripts\AutoGen.py`，将其中四处硬编码输出路径改为本机项目的 `KMDF Driver1` 目录，再在 IDA 中运行脚本，生成 `available_funcs.inc`、`handlers.h`、`handlers.c` 和分析报告 `function_analysis.csv`。

  生成文件与目标内核相关，首次构建前需要生成，切换目标内核版本后应重新生成。项目已经引用上述三个源码文件，并将 `handlers.c` 按 C++ 编译。

+ 在 `ImageLoadCallback` 回调中设置目标驱动文件名，记录其加载后的内存区域并加入监控范围。当前配置如下。

  ```cpp
  VOID ImageLoadCallback(
  	PUNICODE_STRING FullImageName,
  	HANDLE ProcessId,
  	PIMAGE_INFO ImageInfo)
  {
  
  	if (ProcessId == 0 && FullImageName != NULL)
  	{
  
  		// 检查是否是 ACEDriver.sys 被加载
  		if (wcsstr(FullImageName->Buffer, L"\\ACEDriver.sys"))
  		{
  			LOG_INFO("ACEDriver.sys" " has been loaded!\n");
  			LOG_INFO("Image Base: %p\n", ImageInfo->ImageBase);
  			LOG_INFO("Image Size: %llx\n", ImageInfo->ImageSize);
  
  			ADD_MONITOR_RANGE((ULONG64)ImageInfo->ImageBase, (ULONG64)ImageInfo->ImageBase + ImageInfo->ImageSize);
  		}
  	}
  }
  ```

+ 在 `DriverMain` 中按需要调整要 Hook 的函数。当前实现遍历 `ntoskrnl.exe` 的导出函数，为自动生成列表中有对应处理函数的项目尝试安装 Hook，安装失败会打印原始 `NTSTATUS`。

+ 选择 `Release | x64` 构建，默认输出到 `x64\Release`。先加载监控驱动，再加载目标驱动，通过调试器或日志文件查看记录。

## 异步文件日志

日志文件为运行监控驱动的系统中的 `C:\kernel_monitor.log`。每次加载会在文件末尾继续追加。需要调整路径时，修改 `logging.c` 中 `LogInitialize` 的 `fileName`。

- `g_LogLevel` 默认值为 `LOG_LEVEL_INFO`，调试输出和文件日志都受该级别控制。
- 队列最多容纳 2048 条待处理记录，每条最多 1023 字节。超长记录会标记 `...[truncated]`。
- 队列满或调用发生在高于 `DISPATCH_LEVEL` 的 IRQL 时，文件日志会丢弃该条记录，并在后续输出中报告丢弃数量。
- 文件日志初始化失败时会输出 `File logger initialization failed` 和状态码，监控驱动继续初始化。写入失败会通过调试输出报告 `log write failed` 和状态码。
- 蓝屏瞬间仍在队列中的日志可能来不及写入磁盘。

已完成 Visual Studio 2022、MSVC 14.42.34433、Windows SDK/WDK 10.0.26100.0 环境下的 `Release | x64` 构建、INF 检查，以及本地 Hook 状态和日志队列模拟回归验证。内核实际加载与运行仍待验证。

## TODO

- [x] 使用消息队列和后台线程异步追加文件日志，并在正常卸载时排空队列。
