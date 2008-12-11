--TEST--
SELinux /proc/<pid>/attrs APIs
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php

include('config.inc');

/*
 * selinux_getcon
 */	
$current = file_get_contents("/proc/self/attr/current");
$current = selinux_raw_to_trans_context($current);
if ($current != selinux_getcon())
    die("selinux_getcon() : incorrect value");

/*
 * selinux_getpidcon
 */
$pidcon = file_get_contents("/proc/1/attr/current");
$pidcon = selinux_raw_to_trans_context($pidcon);
if ($pidcon != selinux_getpidcon(1))
    die("selinux_getpidcon() : incorrect value");

/*
 * selinux_getprevcon
 */	
$prev = file_get_contents("/proc/self/attr/prev");
$prev = selinux_raw_to_trans_context($prev);
if ($prev != selinux_getprevcon())
    die("selinux_getprevcon() : incorrect value");

/*
 * selinux_getexeccon
 */	
$exec = file_get_contents("/proc/self/attr/exec");
$exec = selinux_raw_to_trans_context($exec);
if ($exec != selinux_getexeccon())
    die("selinux_getexeccon() : incorrect value");

/*
 * selinux_getfscreatecon
 */	
$fscreate = file_get_contents("/proc/self/attr/fscreate");
$fscreate = selinux_raw_to_trans_context($fscreate);
echo "hoge4.5\n";
if ($fscreate != selinux_getfscreatecon())
    die("selinux_getfscreatecon() : incorrect value");

/*
 * selinux_getkeycreatecon
 */
$keycreate = file_get_contents("/proc/self/attr/keycreate");
$keycreate = selinux_raw_to_trans_context($keycreate);
if ($keycreate != selinux_getkeycreatecon())
    die("selinux_getkeycreatecon() : incorrect value");

/*
 * selinux_getsockcreatecon
 */
$sockcreate = file_get_contents("/proc/self/attr/sockcreate");
$sockcreate = selinux_raw_to_trans_context($sockcreate);
if ($sockcreate != selinux_getsockcreatecon())
    die("selinux_getsockcreatecon() : incorrect value");

echo "OK";
?>
--EXPECT--
OK
