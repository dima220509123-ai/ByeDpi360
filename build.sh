#!/usr/bin/env bash
set -euo pipefail

BASE=0x91429000          # free region on kernel 17559 (see xsdk docs)
PPC=powerpc-linux-gnu

mkdir -p build imports_gen

curl -fsSL -o elf2xex.py https://raw.githubusercontent.com/xenosworks/xsdk/main/tools/elf2xex.py
curl -fsSL -o gen_imports.py https://raw.githubusercontent.com/xenosworks/xsdk/main/tools/gen_imports.py
curl -fsSL -o xsdk_plugin.ld https://raw.githubusercontent.com/xenosworks/xsdk/main/src/xsdk_plugin.ld

python3 gen_imports.py imports.txt imports_gen

$PPC-gcc -O2 -nostdlib -ffreestanding -fno-builtin \
    -msoft-float -mno-altivec \
    -c plugin.c -o build/plugin.o

for f in imports_gen/*.S; do
    $PPC-gcc -c "$f" -o "build/$(basename "$f" .S).o"
done

$PPC-ld -T xsdk_plugin.ld --defsym=xsdk_plugin_base=$BASE \
    -o build/plugin.elf build/*.o

python3 elf2xex.py build/plugin.elf build/byedpi.xex --dll $BASE

ls -l build/byedpi.xex
