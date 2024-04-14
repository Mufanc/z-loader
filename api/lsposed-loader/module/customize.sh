if [ "$API" -lt 31 ]; then
    ui_print "! Unsupported SDK: $API"
    abort    "! Minimal supported SDK is 31 (Android 12)"
else
    ui_print "- Device SDK: $API"
fi

KVER=$(uname -r | awk -F- '{ print $1 }')
KVER_INT=$(getprop ro.kernel.version | tr '.' ' ' | xargs printf '%02d')

if [ "$KVER_INT" -lt 510 ]; then
    ui_print "! Unsupported kernel version: $KVER"
    abort    "! Kernel version must be 5.10 or higher"
else
    ui_print "- Kernel version: $KVER"
fi
