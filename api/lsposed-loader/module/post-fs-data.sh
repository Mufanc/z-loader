MODDIR=${0%/*}

if [ "$ZYGISK_ENABLED" ]; then
    exit 0
fi

cd "$MODDIR" || exit

LSPOSED=$(realpath ../zygisk_lsposed)

if [ ! -d "$LSPOSED" ]; then
    exit 0
fi

if [ ! -e "$LSPOSED/disable" ]; then
    touch "$LSPOSED/disable"
    exit 0
fi

if [ -e "$LSPOSED/post-fs-data.sh" ]; then
    sh $LSPOSED/post-fs-data.sh 
fi

TMPDIR=/debug_ramdisk/zloader-lsposed

mkdir -p "$TMPDIR"
cp lib/liblsposed_loader.so "$TMPDIR"
cp "$LSPOSED/zygisk/$(getprop ro.product.cpu.abi).so" "$TMPDIR/liblsposed.so"
chcon -R u:object_r:system_file:s0 "$TMPDIR"

chmod +x bin/zloader

export ZLB_NOLOAD=1

bin/zloader --filter "$TMPDIR/liblsposed_loader.so" "$TMPDIR/liblsposed_loader.so" &
