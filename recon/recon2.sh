#!/system/bin/sh
echo "===DEV_BIDE==="
ls -la /dev/bide 2>&1
echo "===DMESG_SEC==="
dmesg 2>/dev/null | grep -iE 'bide|bbauth|pathtrust|grsec|pax|security' | tail -40
echo "===KALLSYMS_SEC==="
cat /proc/kallsyms 2>/dev/null | grep -iE 'bide|pathtrust|pax_|grsec|bbsig|bb_|security_|tokn|token'
echo "===KALLSYMS_COUNT==="
cat /proc/kallsyms 2>/dev/null | wc -l
echo "===KALLSYMS_NONZERO==="
cat /proc/kallsyms 2>/dev/null | awk '$1!="0000000000000000"{c++} END{print c+0}'
echo "===PROC_FILES==="
ls -la /proc/ 2>/dev/null | grep -iE 'kallsyms|kcore|config|modules|bide'
echo "===KERNEL_SECURITY==="
cat /sys/kernel/security/lsm 2>&1
ls -la /sys/kernel/security/ 2>&1
echo "===DONE==="
