MODDIR=${0%/*}

if [ "$ZYGISK_ENABLED" ]; then
    exit 0
fi

cd "$MODDIR" || exit

TMPDIR=/debug_ramdisk/zloader-zygisk

mkdir -p "$TMPDIR"
cp lib/libzygisk_compat.so "$TMPDIR"
chcon -R u:object_r:system_file:s0 "$TMPDIR"

chmod +x bin/zloader
chmod +x bin/zygiskd

bin/zloader "$TMPDIR/libzygisk_compat.so" &
bin/zygiskd --tmpdir "$TMPDIR" &
