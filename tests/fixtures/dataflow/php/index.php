<?php
require_once 'lib.php';

$host = $_GET['host'];
system("ping -c 1 " . $host);  // EXPECT command-injection direct

$id = $_GET['id'];
$rows = load_user($id);  // EXPECT sql-injection cross-file

$page = intval($_GET['page']);
mysqli_query($conn, "SELECT * FROM posts LIMIT " . $page);

echo "Hello " . $_GET['name'];  // EXPECT template-injection direct
