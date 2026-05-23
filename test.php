<?php
$line = "AddHandler" . chr(194) . chr(160) . "application/x-httpd-python .php";
var_dump(preg_match('/^AddHandler\s+(\S+)/i', $line, $matches));
var_dump($matches);
