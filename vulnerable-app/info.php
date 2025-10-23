<?php
// RFI vulnerability
$page = $_GET['page'];
if (isset($page)) {
    include($page);
}
?>
<h1>PHP Info Page</h1>
<p>This page is vulnerable to RFI.</p>
<p>Try ?page=http://example.com</p>
