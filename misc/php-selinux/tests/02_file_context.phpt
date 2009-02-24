--TEST--
SELinux file get/set context APIs
--SKIPIF--
<?php include('skipif.inc'); ?>
--FILE--
<?php

include('config.inc');

/*
 * selinux_getfilecon
 */
$target = "/etc/passwd";
$filecon = shell_exec("env LANG=C ls -Z $target | awk '{print $4}'");
$filecon = trim($filecon);

if ($filecon != selinux_getfilecon($target))
    die("selinux_getfilecon() : incorrect value");

/*
 * selinux_fsetfilecon
 * selinux_fgetfilecon
 */
$tmpfile = tmpfile();
$newcon = "system_u:object_r:tmp_t";

if (!selinux_fsetfilecon($tmpfile, $newcon))
    die("selinux_fsetfilecon() failed");
if ($newcon != selinux_fgetfilecon($tmpfile))
    die("selinux_fgetfilecon() : incorrect value");

fclose($tmpfile);

echo "OK";
?>
--EXPECT--
OK
