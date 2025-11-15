# 内存泄漏检测工具

这是一个轻量级的内存泄漏检测工具集，包含多个版本的内存泄漏检测器，能够帮助开发者发现和分析C程序中的内存泄漏问题。

## 文件说明

### 核心文件

- **`leak_detector_line.c`** - 增强版内存泄漏检测器
  - 记录分配内存的调用者地址
  - 生成详细的分析文件 `leak_analysis.txt`
  - 支持通过地址解析到具体的函数名和偏移量

- **`leak_detector.c`** - 基础版内存泄漏检测器
  - 记录基本的内存分配信息
  - 程序结束时输出泄漏报告到stderr

- **`test.c`** - 测试程序
  - 模拟多层函数调用中的内存泄漏场景
  - 用于验证检测器的功能

- **`analyze_leaks.sh`** - 泄漏分析脚本
  - 解析 `leak_analysis.txt` 文件
  - 使用 `addr2line` 工具将地址转换为函数名和源代码位置
  - 支持自动检测二进制文件并解析调用栈

- **`Makefile.txt`** - 构建配置
  - 编译测试程序和检测器库
  - 提供多种测试目标

## 构建和使用

### 环境要求
- GCC 编译器
- Linux 环境
- 开发工具：addr2line, valgrind, heaptrack（可选）

### 构建步骤

1. **重命名 Makefile**
   ```bash
   mv Makefile.txt Makefile
   ```

2. **编译项目**
   ```bash
   make all
   ```

   这将生成：
   - `build/test` - 测试程序
   - `build/libleak_detector.so` - 基础检测器
   - `build/libleak_detector_line.so` - 增强版检测器

### 使用方法

#### 1. 基础检测器测试
```bash
make test_run
```

#### 2. 增强版检测器测试（推荐）
```bash
make test_line_run
```

#### 3. 分析泄漏报告
```bash
make test_line_ana
```

#### 4. 使用 Valgrind 验证
```bash
make test_val_run
```

#### 5. 使用 Heaptrack 分析
```bash
make test_heaptrack
```

## 输出说明

### 增强版检测器输出

运行 `make test_line_run` 后会产生：

1. **控制台输出**：简要的泄漏信息
2. **`leak_analysis.txt`**：详细的分析文件，包含：
   - 内存地址
   - 分配大小
   - 调用者地址
   - 二进制文件路径
   - 函数名

### 分析脚本输出

运行 `make test_line_ana` 会解析分析文件，显示：
- 泄漏的内存地址和大小
- 泄漏发生的函数名
- 源代码位置（如果可用）

## 示例输出

```
=== Memory Leak Report ===
分析文件: leak_analysis.txt
Leak: 0x55a123456780 (100 bytes) [caller 0x55a123456789]
Leak: 0x55a1234567f0 (100 bytes) [caller 0x55a123456789]

==== 分析文件: leak_analysis.txt ====
Leak: 0x55a123456780 (100 bytes) at leak_memory_level5 (test.c:8)
Leak: 0x55a1234567f0 (100 bytes) at leak_memory_level5 (test.c:8)
```

## 特性对比

| 特性 | 基础检测器 | 增强版检测器 |
|------|------------|--------------|
| 泄漏检测 | ✅ | ✅ |
| 调用栈记录 | ❌ | ✅ |
| 详细分析文件 | ❌ | ✅ |
| 源代码定位 | ❌ | ✅ |
| 函数名解析 | ❌ | ✅ |

## 注意事项

1. **调试符号**：为了获得准确的函数名和行号，编译时需要包含调试信息（`-g` 选项）
2. **动态链接**：检测器通过 `LD_PRELOAD` 注入，适用于动态链接的程序
3. **性能影响**：在生产环境中使用可能会有性能开销
4. **静态函数**：静态函数和内联函数的调用栈可能无法正确解析

## 清理

```bash
make clean
```

这将删除构建文件和生成的泄漏分析报告。