MODDIR=${0%/*}

if [ "$ZYGISK_ENABLED" ]; then
    exit 0
fi

cd "$MODDIR" || exit

LSPOSED=$(realpath ../zygisk_lsposed)

if [ ! -d "$LSPOSED" ] || [ -e "$LSPOSED/disable" ]; then
    exit 0
fi

TMPDIR=/debug_ramdisk/zloader-lsposed

mkdir -p "$TMPDIR"
cp lib/liblsposed_loader.so "$TMPDIR"
cp "$LSPOSED/zygisk/arm64-v8a.so" "$TMPDIR/liblsposed.so"
chcon -R u:object_r:system_file:s0 "$TMPDIR"

chmod +x bin/zloader

export ZLB_NOLOAD=1

bin/zloader --filter "$TMPDIR/liblsposed_loader.so" "$TMPDIR/liblsposed_loader.so" &
