if [ "$API" -lt 31 ]; then
    ui_print "! Unsupported SDK: $API"
    abort    "! Minimal supported SDK is 31 (Android 12)"
else
    ui_print "- Device SDK: $API"
fi

KVER=$(getprop ro.kernel.version)

if [ "${KVER//./}" -lt 510 ]; then
    ui_print "! Unsupported kernel version: $KVER"
    abort    "! Kernel version must be 5.10 or higher"
else
    ui_print "- Kernel version: $KVER"
fi
