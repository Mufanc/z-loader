MODDIR=${0%/*}

if [ "$ZYGISK_ENABLED" ]; then
    exit 0
fi

cd "$MODDIR" || exit

LSPOSED=$(realpath ../zygisk_lsposed)

if [ ! -d "$LSPOSED" ] || [ ! -e "$LSPOSED/disable" ]; then
    exit 0
fi

if [ -e "$LSPOSED/service.sh" ]; then
    sh $LSPOSED/service.sh
fi
