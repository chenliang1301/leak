#!/usr/bin/env bash
# analyze_leaks.sh - analyze leak_analysis.txt using addr2line
# Usage: ./analyze_leaks.sh [leak_analysis.txt]

set -euo pipefail

RAW=${1:-leak_analysis.txt}
if [ ! -f "$RAW" ]; then
  echo "Raw file '$RAW' not found" >&2
  exit 1
fi

# 在报告开头输出分析文件路径
echo "==== 分析文件: $RAW ===="

# Skip header lines starting with #

# 检查分析文件是否有 func 字段（第5列）
HAS_FUNC=$(head -1 "$RAW" | grep -q 'func' && echo 1 || echo 0)

# 收集唯一二进制文件
if [ "$HAS_FUNC" -eq 1 ]; then
  mapfile -t BINS < <(awk '$1!~/^#/ {print $4}' "$RAW" | sort -u)
else
  mapfile -t BINS < <(awk '$1!~/^#/ {print $4}' "$RAW" | sort -u)
fi

for bin in "${BINS[@]}"; do
  if [ "$bin" = "-" ] || [ -z "$bin" ]; then
    # print entries with unknown binary
    awk '$1!~/^#/ && $4=="-" {printf "Leak: %s (%s bytes) at <unknown binary> (addr %s)\n", $1, $2, $3}' "$RAW"
    continue
  fi

  # 收集地址和元数据（支持 func 字段）
  addrs=()
  metas=()
  funcs=()
  while IFS= read -r line; do
    if [ "$HAS_FUNC" -eq 1 ]; then
      ptr=$(printf "%s" "$line" | awk '{print $1}')
      size=$(printf "%s" "$line" | awk '{print $2}')
      addr=$(printf "%s" "$line" | awk '{print $3}')
      b=$(printf "%s" "$line" | awk '{print $4}')
      func=$(printf "%s" "$line" | awk '{print $5}')
      if [ "$b" = "$bin" ]; then
        addrs+=("$addr")
        metas+=("$ptr|$size")
        funcs+=("$func")
      fi
    else
      ptr=$(printf "%s" "$line" | awk '{print $1}')
      size=$(printf "%s" "$line" | awk '{print $2}')
      addr=$(printf "%s" "$line" | awk '{print $3}')
      b=$(printf "%s" "$line" | awk '{print $4}')
      if [ "$b" = "$bin" ]; then
        addrs+=("$addr")
        metas+=("$ptr|$size")
      fi
    fi
  done < <(awk '$1!~/^#/ {print $0}' "$RAW")

  if [ ${#addrs[@]} -eq 0 ]; then
    continue
  fi

  # build addr2line command
  # 地址解析 ：使用 addr2line 工具将内存地址转换为函数名和源代码位置
  cmd=(addr2line -f -p -e "$bin")
  for a in "${addrs[@]}"; do
    cmd+=("$a")
  done

  mapfile -t results < <("${cmd[@]}")

  # 输出映射，优先用 func 字段
  # 结果格式化与输出 ：
  # - 解析 addr2line 的输出，提取函数名和文件名:行号
  # - 处理特殊情况（如未知函数名）
  # - 输出格式化的泄漏信息，包含内存地址、大小、函数名和源代码位置
  for i in "${!results[@]}"; do
    res=${results[$i]}
    meta=${metas[$i]}
    ptr=${meta%%|*}
    size=${meta##*|}
    if [ "$HAS_FUNC" -eq 1 ]; then
      func=${funcs[$i]}
      fileline=$(printf "%s" "$res" | sed -E 's/^.*\(([^)]*)\)$/\1/')
      # 如果 func 为 '-'，则用 addr2line 解析出的函数名
      if [ "$func" = "-" ]; then
        func_parsed=$(printf "%s" "$res" | sed -E 's/^(.*?) \(.*$/\1/')
        if [ -n "$func_parsed" ]; then
          func="$func_parsed"
        else
          func="<unknown>"
        fi
      fi
    else
      func=$(printf "%s" "$res" | sed -E 's/^(.*?) \(.*$/\1/')
      fileline=$(printf "%s" "$res" | sed -E 's/^.*\(([^)]*)\)$/\1/')
    fi
    if [ "$func" = "malloc" ]; then
      printf "Leak: %s (%s bytes) at malloc (%s)\n" "$ptr" "$size" "$fileline"
    else
      printf "Leak: %s (%s bytes) at %s (%s)\n" "$ptr" "$size" "$func" "$fileline"
    fi
  done
done

# done
