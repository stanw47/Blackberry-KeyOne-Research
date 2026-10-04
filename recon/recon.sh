#!/system/bin/sh
# Recon helper for BlackBerry KEYone - runs on device as shell user.
echo "===PROC_VERSION==="
cat /proc/version
echo "===BB_PROPS==="
getprop | grep -iE 'bide|pathtrust|token|secure|bbry|blackberry|bb_|vtnvfs|tct'
echo "===BIN_BB==="
ls -la /system/bin/ 2>/dev/null | grep -iE 'bb|secsvr|tctd|dcmd|vtnvfs|token|auth|rim|blackberry|mfg|bcc|bdt'
echo "===LIB64_BB==="
ls -la /system/lib64/ 2>/dev/null | grep -iE 'bb|sec|token|auth|tct|vtnvfs|rim|black'
echo "===LIB_BB==="
ls -la /system/lib/ 2>/dev/null | grep -iE 'bb|sec|token|auth|tct|vtnvfs|rim|black'
echo "===SERVICES==="
service list 2>/dev/null | grep -iE 'bb|token|auth|sec|dcmd|rim|vtnvfs|tct'
echo "===PS_BB==="
ps -A 2>/dev/null | grep -iE 'bb|token|auth|secsvr|tctd|dcmd|vtnvfs|rim|mfg|bcc|bdt'
echo "===INIT_BB==="
cat /init.rc 2>/dev/null | grep -iE 'bb|token|auth|vtnvfs|secsvr|dcmd|rim|tct'
echo "===VENDOR_BIN==="
ls -la /vendor/bin/ 2>/dev/null | head -80
echo "===MOUNTED_SEPOLICY==="
ls -l /sys/fs/selinux/policy
echo "===BIDE_KERNEL==="
ls -l /sys/kernel/ 2>/dev/null
echo "===BIDE_PROC==="
ls -l /proc/ | grep -iE 'bide|bb|tct|rim|sec' 
echo "===DONE==="
