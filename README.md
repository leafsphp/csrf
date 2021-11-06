<!-- markdownlint-disable no-inline-html -->
<p align="center">
  <br><br>
  <img src="https://leafphp.netlify.app/assets/img/leaf3-logo.png" height="100"/>
  <h1 align="center">Leaf Security Module</h1>
  <br><br>
</p>

# Leaf PHP

[![Latest Stable Version](https://poser.pugx.org/leafs/anchor/v/stable)](https://packagist.org/packages/leafs/anchor)
[![Total Downloads](https://poser.pugx.org/leafs/anchor/downloads)](https://packagist.org/packages/leafs/anchor)
[![License](https://poser.pugx.org/leafs/anchor/license)](https://packagist.org/packages/leafs/anchor)

This package contains leaf's utils for deep sanitizing of data and basic security provided for your app data.

## Installation

You can easily install Leaf using [Composer](https://getcomposer.org/).

```bash
composer require leafs/anchor
```

## Basic Usage

After [installing](#installation) anchor, create an _index.php_ file.

### Base XSS protection

```php
<?php
require __DIR__ . "vendor/autoload.php";

$data = $_POST["data"];
$data = Leaf\Anchor::sanitize($data);

echo $data;
```

This also works on arrays

```php
<?php
require __DIR__ . "vendor/autoload.php";

$data = Leaf\Anchor::sanitize($_POST);

echo $data["input"];
```

You may quickly test this using the built-in PHP server:

```bash
php -S localhost:8000
```

Built with ❤ by [**Mychi Darko**](https://mychi.netlify.app)
