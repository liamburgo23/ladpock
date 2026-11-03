<?php
ini_set('display_errors', '1');

$conn = mysqli_connect('db', 'app', getenv('DB_PASSWORD'), 'shop');
$result = mysqli_query($conn, "SELECT * FROM products WHERE id = " . $_GET['id']);

$page = $_GET['page'];
include($_GET['page'] . '.php');

echo $_GET['q'];

$password = md5($_POST['password']);
$cart = unserialize($_COOKIE['cart']);
shell_exec('ping -c 1 ' . $_GET['host']);
