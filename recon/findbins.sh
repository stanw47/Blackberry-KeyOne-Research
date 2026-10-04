#!/system/bin/sh
for b in vtnvfsd vtnvfsd_wrapper bb_tokenserviced secsvr tctd dcmd StoreKeybox RetainsDataSpace bkup_bc_update powerup_reason reset_cause bbauthtoold ATFWD-daemon mfgUtil bcc bdt bb_func; do
  p=$(readlink -f /system/bin/$b 2>/dev/null)
  echo "$b -> [$p]"
done
echo "===PATHSCAN==="
for d in /system/bin /system/xbin /system/vendor/bin /vendor/bin /sbin /system/libexec; do
  echo "-- $d"
  ls -la $d 2>/dev/null | grep -iE 'vtnvfs|token|secsvr|tctd|dcmd|powerup|reset_cause|StoreKeybox|Retains|bkup|bbauthtool|ATFWD|mfg|bb_func|pathtrust|bide' 
done
echo "===WHICH==="
which vtnvfsd bb_tokenserviced bbauthtoold dcmd secsvr tctd 2>/dev/null
echo "===DONE==="
