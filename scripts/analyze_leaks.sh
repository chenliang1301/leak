#!/usr/bin/env bash
# analyze_leaks.sh - analyze leak_analysis.txt using addr2line
# Usage: ./analyze_leaks.sh [leak_analysis.txt]

set -euo pipefail

SUMMARY=0
DEPTH=999
COMPACT_PATHS=0
NO_DUP=0
FRAME_RANGE=""
SHOW_INTERNAL=0
JSON_MODE=0
NO_RAW=0
HIDE_SYSTEM_ONLY=0
HIDE_SYSTEM=0
HIDE_START=0
HIDE_SYSTEM=0
# Parse options: --summary and --depth N (order-independent)
RAW=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --summary)
      SUMMARY=1; shift ;;
    --compact-paths)
      COMPACT_PATHS=1; shift ;;
    --no-dup)
      NO_DUP=1; shift ;;
    --frame-range)
      if [ -n "${2:-}" ]; then FRAME_RANGE=$2; shift 2; else echo "--frame-range requires an argument" >&2; exit 1; fi ;;
    --frame-range=*)
      FRAME_RANGE=${1#*=}; shift ;;
    --depth)
      if [ -n "${2:-}" ]; then DEPTH=$2; shift 2; else echo "--depth requires an argument" >&2; exit 1; fi ;;
    --depth=*)
      DEPTH=${1#*=}; shift ;;
    --show-internal)
      SHOW_INTERNAL=1; shift ;;
    --json)
      JSON_MODE=1; shift ;;
    --no-raw)
      NO_RAW=1; shift ;;
    --hide-system-only)
      HIDE_SYSTEM_ONLY=1; shift ;;
    --hide-system)
      HIDE_SYSTEM=1; shift ;;
    --hide-start)
      HIDE_START=1; shift ;;
    --*)
      echo "Unknown option: $1" >&2; exit 1 ;;
    *)
      if [ -z "$RAW" ]; then RAW=$1; else
        # ignore extra positional args
        :
      fi
      shift ;;
  esac
done

RAW=${RAW:-leak_analysis.txt}
if [ ! -f "$RAW" ]; then
  echo "Raw file '$RAW' not found" >&2
  exit 1
fi

# 在报告开头输出分析文件路径
echo "==== 分析文件: $RAW ===="

# Skip header lines starting with #

# 检查分析文件是否有 func 字段（第5列）
HAS_FUNC=$(head -1 "$RAW" | grep -q 'func' && echo 1 || echo 0)
# 检查是否为 callers 格式（第3列为 comma-separated addr@binary）
HAS_CALLERS=$(head -1 "$RAW" | grep -q 'callers' && echo 1 || echo 0)

# If the analysis file only contains ptr and size (2 columns), print simple summary
NUM_COLS=$(awk '$1!~/^#/ {print NF; exit}' "$RAW" || echo 0)
if [ "$NUM_COLS" -eq 2 ]; then
  awk '$1!~/^#/ {printf "Leak: %s (%s bytes)\n", $1, $2}' "$RAW"
  exit 0
fi

if [ "$HAS_CALLERS" -eq 1 ]; then
  # parse callers format: ptr size callers
  AGG_TMP=$(mktemp)
  trap 'rm -f "$AGG_TMP"' EXIT
  while IFS= read -r line; do
    # skip header / comments
    case "$line" in
      \#*) continue ;;
    esac
    # read fields
    ptr=$(awk '{print $1}' <<<"$line")
    size=$(awk '{print $2}' <<<"$line")
    type=$(awk '{print $3}' <<<"$line")
    callers_field=$(awk '{print $4}' <<<"$line")

    chain_items=()
    func_names=()
    filelines=()
    bins_items=()
    outer_func="<unknown>"
    outer_fileline="<unknown>"
    outer_bin="-"

    IFS=',' read -r -a parts <<< "$callers_field"
    MAX_DET_FRAMES=32
    if [ "$DEPTH" -lt 1 ]; then DEPTH=1; fi
    lim=$MAX_DET_FRAMES

    for idx in "${!parts[@]}"; do
      if [ "$idx" -ge "$lim" ]; then break; fi
      p=${parts[$idx]}
      addr=${p%%@*}
      bin=${p#*@}
      if [ "$bin" = "-" ] || [ -z "$bin" ]; then
        res="$addr"
      else
        res=$(addr2line -f -p -e "$bin" "$addr" 2>/dev/null || printf "%s" "$addr")
      fi
      func=$(printf "%s" "$res" | sed -E 's/^(.*?)\s*(\(| at ).*$/\1/')
      fileline=$(printf "%s" "$res" | sed -E 's/^.*\(([^)]*)\)$/\1/')
      if [ -z "$func" ]; then func="<unknown>"; fi
      if [ -z "$fileline" ]; then fileline="<unknown>"; fi
      if printf "%s" "$fileline" | grep -q " at "; then
        maybe=$(printf "%s" "$fileline" | sed -E 's/^.* at (.*)$/\1/')
        if [ -n "$maybe" ]; then fileline="$maybe"; fi
      fi
      func_names+=("$func")
      filelines+=("$fileline")
      bins_items+=("$bin")
      if [ "$fileline" = "<unknown>" ]; then
        chain_items+=("$func")
      else
        chain_items+=("$func ($fileline)")
      fi
      outer_func="$func"
      outer_fileline="$fileline"
      outer_bin="$bin"
    done

    # Build filtered lists (apply internal/system hide and no-dup) — DEPTH will be applied after filtering
    filtered_chain=()
    filtered_bins=()
    filtered_funcs=()
    filtered_files=()
    for idx in "${!chain_items[@]}"; do
      binf=${bins_items[$idx]:-"-"}
      # detect internal frames: by default only hide the detector library itself
      is_internal=0
      if [ "$SHOW_INTERNAL" -eq 0 ]; then
        if [ -n "$binf" ]; then
            if [[ "$binf" == *libleak_detector* ]]; then
              is_internal=1
            fi
            # optional: hide system frames when requested
            if [ "$HIDE_SYSTEM" -eq 1 ]; then
              if [[ "$binf" == *libc.so* ]] || [[ "$binf" == *ld-linux* ]] || [[ "$binf" == */lib/* ]] || [[ "$binf" == */lib64/* ]]; then
                is_internal=1
              fi
            fi
            # optional: hide _start frames when requested (function name == _start and fileline contains ??)
            if [ "$HIDE_START" -eq 1 ]; then
              fn="${func_names[$idx]:-}";
              fl="${filelines[$idx]:-}";
              if [ -n "$fn" ] && [ "$fn" = "_start" ]; then
                if printf "%s" "$fl" | grep -q "\?\?"; then
                  is_internal=1
                fi
              fi
            fi
          fi
      fi
      if [ "$is_internal" -eq 1 ]; then
        continue
      fi
      # no-dup: skip consecutive identical frames
      if [ "$NO_DUP" -eq 1 ] && [ "${#filtered_chain[@]}" -gt 0 ]; then
        last="${filtered_chain[-1]}"
        if [ "${chain_items[$idx]}" = "$last" ]; then
          continue
        fi
      fi
      filtered_chain+=("${chain_items[$idx]}")
      filtered_bins+=("$binf")
      filtered_funcs+=("${func_names[$idx]:-}")
      filtered_files+=("${filelines[$idx]:-}")
    done

    total_filtered=${#filtered_chain[@]}
    # If hiding _start-only leaks is requested and no frames remain after filtering, skip printing this leak
    if [ "$HIDE_START" -eq 1 ] && [ "$total_filtered" -eq 0 ]; then
      printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$ptr" "$size" "$type" "$outer_func" "$outer_fileline" "$outer_bin" >> "$AGG_TMP"
      continue
    fi

    common_prefix=""
    if [ "$COMPACT_PATHS" -eq 1 ]; then
      real_bins=()
      for b in "${bins_items[@]}"; do
        if [ -n "$b" ] && [ "$b" != "-" ]; then real_bins+=("$b"); fi
      done
      if [ "${#real_bins[@]}" -gt 0 ]; then
        IFS='/' read -ra segs0 <<< "${real_bins[0]}"
        common=""
        for ((si=0; si<${#segs0[@]}; si++)); do
          seg=${segs0[si]}
          match=1
          for rb in "${real_bins[@]:1}"; do
            IFS='/' read -ra segsrb <<< "$rb"
            if [ "${segsrb[si]:-}" != "$seg" ]; then match=0; break; fi
          done
          if [ "$match" -eq 1 ]; then
            if [ -z "$common" ]; then common="$seg"; else common="$common/$seg"; fi
          else
            break
          fi
        done
        if [ -n "$common" ]; then
          if [[ "${real_bins[0]}" = /* ]]; then common_prefix="/$common"; else common_prefix="$common"; fi
        fi
      fi
    fi

    fr_start=1; fr_end=${#chain_items[@]}
    if [ -n "$FRAME_RANGE" ]; then
      if [[ "$FRAME_RANGE" =~ ^([0-9]+):([0-9]+)$ ]]; then
        fr_start=${BASH_REMATCH[1]}
        fr_end=${BASH_REMATCH[2]}
      elif [[ "$FRAME_RANGE" =~ ^([0-9]+)$ ]]; then
        fr_start=${BASH_REMATCH[1]}; fr_end=${BASH_REMATCH[1]}
      fi
      if [ "$fr_start" -lt 1 ]; then fr_start=1; fi
      if [ "$fr_end" -gt ${#chain_items[@]} ]; then fr_end=${#chain_items[@]}; fi
    fi

    if [ "$JSON_MODE" -eq 1 ]; then
      JSON_TMP_LEAKS=${JSON_TMP_LEAKS:-$(mktemp)}
      if [ ! -f "$JSON_TMP_LEAKS" ]; then echo "[]" > "$JSON_TMP_LEAKS"; fi
    fi

    # Determine whether filtered frames are all system frames
    all_system=1
    for b in "${filtered_bins[@]}"; do
      if [ -z "$b" ] || [ "$b" = "-" ]; then
        continue
      fi
      if [[ "$b" == *libc.so* ]] || [[ "$b" == *ld-linux* ]] || [[ "$b" == */lib/* ]] || [[ "$b" == */lib64/* ]]; then
        # still system
        continue
      else
        all_system=0; break
      fi
    done

    # If user asked to hide system-only leaks and this leak is system-only, skip printing/JSON
    if [ "$HIDE_SYSTEM_ONLY" -eq 1 ] && [ "$all_system" -eq 1 ]; then
      # still append aggregate meta for summary but do not print frames or raw or JSON
      printf "%s	%s	%s	%s	%s
" "$ptr" "$size" "$outer_func" "$outer_fileline" "$outer_bin" >> "$AGG_TMP"
      continue
    fi

    if [ "$JSON_MODE" -eq 0 ]; then
      printf "Leak: %s (%s bytes) [%s]\n" "$ptr" "$size" "$type"
    fi

    # Apply frame-range on filtered list
    total_filtered=${#filtered_chain[@]}
    fr_start=1; fr_end=$total_filtered
    if [ -n "$FRAME_RANGE" ]; then
      if [[ "$FRAME_RANGE" =~ ^([0-9]+):([0-9]+)$ ]]; then
        fr_start=${BASH_REMATCH[1]}
        fr_end=${BASH_REMATCH[2]}
      elif [[ "$FRAME_RANGE" =~ ^([0-9]+)$ ]]; then
        fr_start=${BASH_REMATCH[1]}; fr_end=${BASH_REMATCH[1]}
      fi
      if [ "$fr_start" -lt 1 ]; then fr_start=1; fi
      if [ "$fr_end" -gt $total_filtered ]; then fr_end=$total_filtered; fi
    fi

    last_frame=""
    shown_idx=0
    for fi in $(seq $fr_start $fr_end); do
      idx=$((fi-1))
      display_bin=${filtered_bins[$idx]:-"-"}
      if [ "$COMPACT_PATHS" -eq 1 ] && [ -n "$common_prefix" ] && [ "$display_bin" != "-" ]; then
        display_bin=${display_bin#"$common_prefix"}
        display_bin=${display_bin#/}
        if [ -z "$display_bin" ]; then display_bin="${filtered_bins[$idx]}"; fi
      fi
      if [ "$NO_DUP" -eq 1 ]; then
        if [ "${filtered_chain[$idx]}" = "$last_frame" ]; then
          continue
        fi
      fi
      shown_idx=$((shown_idx+1))
      if [ "$JSON_MODE" -eq 0 ]; then
        printf "  #%02d: %s [binary: %s]\n" "$shown_idx" "${filtered_chain[$idx]}" "$display_bin"
      fi
      last_frame="${filtered_chain[$idx]}"
      if [ "$shown_idx" -ge "$DEPTH" ]; then
        break
      fi
    done
    if [ "$JSON_MODE" -eq 0 ]; then
      if [ "$shown_idx" -eq 0 ]; then
        printf "  (no frames shown -- internal/system frames hidden)\n"
      fi
      if [ "$NO_RAW" -eq 0 ]; then
        printf "  raw: %s\n\n" "$callers_field"
      else
        printf "\n"
      fi
    fi

    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$ptr" "$size" "$type" "$outer_func" "$outer_fileline" "$outer_bin" >> "$AGG_TMP"

    if [ "$JSON_MODE" -eq 1 ]; then
      json_frames=""
      jf_idx=0
      last_frame_j=""
      for fi in $(seq $fr_start $fr_end); do
        idx=$((fi-1))
        binf=${filtered_bins[$idx]:-"-"}
        display_bin="$binf"
        if [ "$COMPACT_PATHS" -eq 1 ] && [ -n "$common_prefix" ] && [ "$binf" != "-" ]; then
          display_bin=${display_bin#"$common_prefix"}
          display_bin=${display_bin#/}
          if [ -z "$display_bin" ]; then display_bin="${filtered_bins[$idx]}"; fi
        fi
        if [ "$NO_DUP" -eq 1 ]; then
          if [ "${filtered_chain[$idx]}" = "$last_frame_j" ]; then
            continue
          fi
        fi
        jf_idx=$((jf_idx+1))
        esc_func=$(printf "%s" "${filtered_funcs[$idx]}" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g' -e ':a;N;s/\n/\\n/;ta')
        esc_file=$(printf "%s" "${filtered_files[$idx]}" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g' -e ':a;N;s/\n/\\n/;ta')
        esc_bin=$(printf "%s" "$display_bin" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g' -e ':a;N;s/\n/\\n/;ta')
        frame_json="{\"index\":$jf_idx,\"function\":\"$esc_func\",\"file\":\"$esc_file\",\"binary\":\"$esc_bin\"}"
        if [ -z "$json_frames" ]; then json_frames="$frame_json"; else json_frames="$json_frames,$frame_json"; fi
        last_frame_j="${filtered_chain[$idx]}"
        if [ "$jf_idx" -ge "$DEPTH" ]; then
          break
        fi
      done
      esc_ptr=$(printf "%s" "$ptr" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g')
      esc_size=$size
      esc_type=$(printf "%s" "$type" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g')
      leak_json="{\"ptr\":\"$esc_ptr\",\"size\":$esc_size,\"type\":\"$esc_type\",\"frames\":[$json_frames]}"
      if grep -q -s "^\[\]$" "$JSON_TMP_LEAKS" 2>/dev/null; then
        echo "$leak_json" > "$JSON_TMP_LEAKS.items"
      else
        if [ -f "$JSON_TMP_LEAKS.items" ]; then
          echo ",$leak_json" >> "$JSON_TMP_LEAKS.items"
        else
          echo "$leak_json" > "$JSON_TMP_LEAKS.items"
        fi
      fi
    fi
  done < "$RAW"

  # If JSON mode, assemble and print JSON array then exit
  if [ "$JSON_MODE" -eq 1 ]; then
    if [ -f "$JSON_TMP_LEAKS.items" ]; then
      echo -n "["
      tr -d '\n' < "$JSON_TMP_LEAKS.items"
      echo "]"
      rm -f "$JSON_TMP_LEAKS.items" "$JSON_TMP_LEAKS" 2>/dev/null || true
    else
      echo "[]"
    fi
    exit 0
  fi

  if [ "$SUMMARY" -eq 1 ]; then
    echo
    echo "==== 汇总 (按 binary / file / function) ===="
    AGG_RES=$(mktemp)
    awk -F"\t" '{ key=$6"\t"$5"\t"$4; cnt[key]++; sum[key]+=($2+0) } END { for (k in cnt) { printf "%d\t%d\t%s\n", cnt[k], sum[k], k } }' "$AGG_TMP" > "$AGG_RES"
    printf "%6s %10s %s\n" "COUNT" "BYTES" "BINARY | FILE | FUNCTION"
    sort -t$'\t' -k2,2nr "$AGG_RES" | awk -F"\t" '{ printf "%6d %10d %s | %s | %s\n", $1, $2, $3, $4, $5 }'
    rm -f "$AGG_RES"
  fi

  exit 0
fi

# 收集唯一二进制文件
if [ "$HAS_FUNC" -eq 1 ]; then
  mapfile -t BINS < <(awk '$1!~/^#/ {print $4}' "$RAW" | sort -u)
else
  mapfile -t BINS < <(awk '$1!~/^#/ {print $4}' "$RAW" | sort -u)
fi

## Parallel addr2line by binary to speed up large files
PIDS=()
TMPDIRS=()
PARALLEL=${PARALLEL:-4}

# temp file to collect all resolved entries for optional summary
AGG_TMP=$(mktemp)
trap 'rm -f "$AGG_TMP"' EXIT

for bin in "${BINS[@]}"; do
  if [ "$bin" = "-" ] || [ -z "$bin" ]; then
    awk '$1!~/^#/ && $4=="-" {printf "Leak: %s (%s bytes) at <unknown binary> (addr %s)\n", $1, $2, $3}' "$RAW"
    continue
  fi

  TMPDIR=$(mktemp -d)
  # remember which binary this tempdir corresponds to
  printf "%s" "$bin" > "$TMPDIR/bin.txt"
  ADDR_FILE="$TMPDIR/addresses.txt"
  META_FILE="$TMPDIR/metas.txt"
  FUNC_FILE="$TMPDIR/funcs.txt"
  RESULT_FILE="$TMPDIR/results.txt"

  # collect lines for this binary
  awk -v bin="$bin" -v hasfunc="$HAS_FUNC" -v addrf="$ADDR_FILE" -v metaf="$META_FILE" -v funcf="$FUNC_FILE" '
    $1!~/^#/ && $4==bin {
      print $3 >> addrf;
      print $1"|"$2 >> metaf;
      if (hasfunc==1) print $5 >> funcf;
    }
  ' "$RAW"

  if [ ! -s "$ADDR_FILE" ]; then
    rm -rf "$TMPDIR"
    continue
  fi

  mapfile -t _addrs < "$ADDR_FILE"
  cmd=(addr2line -f -p -e "$bin")
  for a in "${_addrs[@]}"; do
    cmd+=("$a")
  done

  ("${cmd[@]}") > "$RESULT_FILE" 2>/dev/null &
  PIDS[${#PIDS[@]}]=$!
  TMPDIRS[${#TMPDIRS[@]}]="$TMPDIR"

  # concurrency control
  while :; do
    running=0
    for pid in "${PIDS[@]:-}"; do
      if kill -0 "$pid" 2>/dev/null; then
        running=$((running+1))
      fi
    done
    if [ "$running" -lt "$PARALLEL" ]; then
      break
    fi
    sleep 0.05
  done
done

# wait for all
for pid in "${PIDS[@]:-}"; do
  wait "$pid" 2>/dev/null || true
done

# assemble and print results in original order
for tmp in "${TMPDIRS[@]:-}"; do
  ADDR_FILE="$tmp/addresses.txt"
  META_FILE="$tmp/metas.txt"
  FUNC_FILE="$tmp/funcs.txt"
  RESULT_FILE="$tmp/results.txt"
  BIN_FILE="$tmp/bin.txt"
  if [ ! -f "$RESULT_FILE" ]; then
    rm -rf "$tmp"
    continue
  fi

  mapfile -t results < "$RESULT_FILE"
  mapfile -t metas < "$META_FILE"
  if [ "$HAS_FUNC" -eq 1 ]; then
    mapfile -t funcs < "$FUNC_FILE"
  fi

  if [ -f "$BIN_FILE" ]; then
    bin=$(cat "$BIN_FILE")
  else
    bin="-"
  fi

  # Group results by pointer so each leak prints a header and multiple frames indented
  last_ptr=""
  frame_idx=0
  for i in "${!results[@]}"; do
    res=${results[$i]}
    meta=${metas[$i]}
    ptr=${meta%%|*}
    size=${meta##*|}

    if [ "$ptr" != "$last_ptr" ]; then
      # new leak entry
      last_ptr="$ptr"
      frame_idx=1
      printf "Leak: %s (%s bytes)\n" "$ptr" "$size"
    else
      frame_idx=$((frame_idx+1))
    fi

    if [ "$HAS_FUNC" -eq 1 ]; then
      func=${funcs[$i]}
      fileline=$(printf "%s" "$res" | sed -E 's/^.*\(([^)]*)\)$/\1/')
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

    printf "  #%02d: %s (%s) [binary: %s]\n" "$frame_idx" "$func" "$fileline" "$bin"

    # append to aggregate file: ptr\t size\t func\t fileline\t bin
    type="-"
    printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$ptr" "$size" "$type" "$func" "$fileline" "$bin" >> "$AGG_TMP"
  done

  rm -rf "$tmp"
done

if [ "$SUMMARY" -eq 1 ]; then
  echo
  echo "==== 汇总 (按 binary / file / function) ===="
  # aggregate by binary, file and function: count and total bytes
  AGG_RES=$(mktemp)
  awk -F"\t" '
  { key=$6"\t"$5"\t"$4; cnt[key]++; sum[key]+=($2+0) }
  END {
    for (k in cnt) {
      printf "%d\t%d\t%s\n", cnt[k], sum[k], k
    }
  }' "$AGG_TMP" > "$AGG_RES"

  printf "%6s %10s %s\n" "COUNT" "BYTES" "BINARY | FILE | FUNCTION"
  sort -t$'\t' -k2,2nr "$AGG_RES" | awk -F"\t" '{ printf "%6d %10d %s | %s | %s\n", $1, $2, $3, $4, $5 }'
  rm -f "$AGG_RES"
fi

# done
