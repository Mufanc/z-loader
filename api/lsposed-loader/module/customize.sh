if [ "$API" -lt 31 ]; then
    ui_print "! Unsupported SDK: $API"
    abort    "! Minimal supported SDK is 31 (Android 12)"
else
    ui_print "- Device SDK: $API"
fi
