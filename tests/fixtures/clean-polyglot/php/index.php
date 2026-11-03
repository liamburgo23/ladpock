<?php
ini_set('display_errors', '0');

$pdo = new PDO('mysql:host=db;dbname=shop', 'app', getenv('DB_PASSWORD'));
$stmt = $pdo->prepare('SELECT * FROM products WHERE id = ?');
$stmt->execute([(int) ($_GET['id'] ?? 0)]);

$pages = ['home', 'about'];
$page = in_array($_GET['page'] ?? '', $pages, true) ? $_GET['page'] : 'home';
require __DIR__ . '/pages/' . $page . '.php';

echo htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES);

$hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
$cart = json_decode($_COOKIE['cart'] ?? '[]', true);
