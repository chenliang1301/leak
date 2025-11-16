## 快速上手：为 AI 协同编码代理准备的简明说明

以下说明针对本仓库（一个轻量级 C 语言内存泄漏检测工具集合）总结了对 AI 编码代理立即有用的要点：架构、常用命令、代码惯例与可修改的关键位置。旨在让代理能快速、可靠地进行补丁、实现或重构。

**架构概览**:
- **组件**: `src/detector/*` 包含三个检测器实现：`leak_detector.c`（基础），`leak_detector_line.c`（带 caller 地址与 addr2line 分析），`leak_detector_base.c`（更完整的记录并写入 `leak_analysis.txt`）。
- **工作方式**: 检测器以共享库形式构建（`build/libleak_detector*.so`），通过 `LD_PRELOAD` 注入目标进程，从 `malloc/free/calloc/realloc/strdup/...` 拦截并记录分配信息。
- **分析链**: 检测器在进程退出时写入 `leak_analysis.txt`（字段：ptr size caller binary func [type]），随后 `scripts/analyze_leaks.sh` 使用 `addr2line -f -p -e` 将地址转换为函数名和源码位置。

**重要文件/路径**:
- `Makefile`：提供常用目标（`all`, `test_run`, `test_line_run`, `test_ana`, `test_val_run` 等）。代理应优先参考这些目标来构建/运行测试。
- `README.md`：包含高层使用示例与说明，可用于生成帮助信息或 CLI 文档。
- `scripts/analyze_leaks.sh`：解析 `leak_analysis.txt` 的脚本；解析逻辑和 addr2line 调用可直接复用。
- `leak_analysis.txt`：输出格式示例在仓库根部，可用于单元测试或集成测试断言。

**构建 / 运行（可直接用作代理建议的命令）**:
- 构建：
  ```bash
  make all
  ```
- 运行带增强检测器并生成分析文件：
  ```bash
  make test_line_run
  ```
- 解析分析文件：
  ```bash
  make test_ana
  # 或直接
  ./scripts/analyze_leaks.sh leak_analysis.txt
  ```
- 运行 valgrind（对比验证）：
  ```bash
  make test_val_run
  ```

注意：`Makefile` 中使用了 `-g`、`-fno-omit-frame-pointer` 和 `-rdynamic` 等编译标志以便保留符号和帧信息；当添加新目标或修改编译线时保留这些标志以保证 addr2line 与 dladdr 能正常工作。

## 快速上手（供 AI 协同编码代理）

本仓库：轻量级 C 内存泄漏检测器集合。下面是能让代理立刻上手的关键信息、约定与示例。

- **架构要点**：源码在 `src/detector/`，包含三种实现（`leak_detector.c`, `leak_detector_line.c`, `leak_detector_base.c`）。检测器编译为共享库并通过 `LD_PRELOAD` 注入，拦截 `malloc/free/calloc/realloc/strdup/...` 并在进程退出时写 `leak_analysis.txt`。

- **关键文件**：
  - `Makefile`（构建与测试目标）
  - `src/detector/leak_detector_base.c`（详尽记录、使用 `dladdr` 和 `addr2line`）
  - `scripts/analyze_leaks.sh`（将 `leak_analysis.txt` 中地址解析为 `func (file:line)`）

- **常用命令**（WSL/Linux）：
```
make all
make test_line_run   # 运行增强检测器，生成 leak_analysis.txt
make test_ana        # 解析 leak_analysis.txt，或直接 ./scripts/analyze_leaks.sh leak_analysis.txt
make test_val_run    # 使用 valgrind 对比验证
```

- **数据格式与示例**：`leak_analysis.txt` 在头部使用注释列名（仓库当前格式）：
  `#ptr size caller binary func type fileline`
  示例行：
  `0x55a123456780 100 0x1234 /path/to/bin leak_memory_level5 malloc leak_memory_level5 (test.c:8)`

- **代码模式 / 重要约定**：
  - 全局最大记录数：`#define MAX_ALLOCS 10000`（若需要支持更多记录，请同时更新此值与初始化逻辑）。
  - 调用者地址：使用 `__builtin_return_address(0)` 保存返回地址，随后用 `dladdr` 解析到 `dli_fname`/`dli_sname` 并计算 offset（见 `leak_detector_base.c`）。
  - 拦截实现遵循 `dlsym(RTLD_NEXT, "...")` 的懒初始化模式，新增拦截函数时务必对 `real_*` 做空检查。
  - 在析构函数中会调用 `addr2line`（通过 `popen`）以获得 `file:line`，因此构建时应保留调试符号：`-g -fno-omit-frame-pointer -rdynamic`。

- **修改注意事项（可直接作为 PR 检查点）**：
  - 如果改变 `leak_analysis.txt` 的列（例如新增 `tag` 字段），同时更新 `scripts/analyze_leaks.sh` 的解析逻辑。
  - 新增拦截函数或支持更多分配 API（`aligned_alloc` / `posix_memalign`）应遵循现有 `dlsym` 懒初始化和 `record_allocation`/`remove_allocation` 模式。

如需合并更详细的示例（例如：如何在 Windows+WSL 下运行测试或如何扩展 `analyze_leaks.sh` 支持额外字段），告诉我想要的内容，我会把示例片段添加到此文件中。
