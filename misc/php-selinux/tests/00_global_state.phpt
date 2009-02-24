--TEST--
SELinux global state APIs
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php

include('config.inc');

/*
 * selinux_is_enabled
 */
$enabled = shell_exec("/usr/sbin/selinuxenabled; echo $?");
if ((intval($enabled) == 0) != selinux_is_enabled())
    die("selinux_is_enabled() : incorrect");

/*
 * selinux_mls_is_enabled
 */
$mls = file_get_contents($selinux_mnt."/mls");
if ((intval($mls) == 1) != selinux_mls_is_enabled())
    die("selinux_mls_is_enabled() : incorrect");

/*
 * selinux_getenforce
 */
$enforce = file_get_contents($selinux_mnt."/enforce");
if ((intval($enforce) == 1) != selinux_getenforce())
    die("selinux_getenforce(): incorrect");

/*
 * selinux_policyvers
 */
$policyver = file_get_contents($selinux_mnt."/policyvers");
if (intval($policyver) != selinux_policyvers())
    die("selinux_policyver() : incorrect");

echo "OK";
?>
--EXPECT--
OK
