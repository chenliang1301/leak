cd /home/linux/leak
make all
LD_PRELOAD=build/libleak_detector_base.so ./build/leak_test
./scripts/analyze_leaks.sh leak_analysis.txt --depth 5 --compact-paths --no-dup --no-raw --hide-system-only --hide-system --hide-start #--json