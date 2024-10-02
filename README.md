<!-- markdownlint-disable no-inline-html -->
<p align="center">
  <br><br>
  <img src="https://leafphp.netlify.app/assets/img/leaf3-logo.png" height="100"/>
  <h1 align="center">Leaf Anchor CSRF</h1>
  <br><br>
</p>

# Leaf PHP

[![Latest Stable Version](https://poser.pugx.org/leafs/csrf/v/stable)](https://packagist.org/packages/leafs/csrf)
[![Total Downloads](https://poser.pugx.org/leafs/csrf/downloads)](https://packagist.org/packages/leafs/csrf)
[![License](https://poser.pugx.org/leafs/csrf/license)](https://packagist.org/packages/leafs/csrf)

> This is an experimental module. Please open an issue if you notice any bugs or malfunctions.

This package is leaf's implementation of a CSRF protection module. It integrates directly with Leaf so there's no need to worry about tweaking your app to make it work.

## Setting Up

You can install the CSRF module using the Leaf CLI or Composer.

```bash
leaf install csrf
```

```bash
composer require leafs/csrf
```

## Basic Usage

After installing leaf CSRF, leaf automatically loads the CSRF package for you so you can start using it on the Leaf instance.

```php
app()->csrf();
```

If you have any configuration you want to set, you can pass it as an array to the `csrf` method.

```php
app()->csrf([
  'methods' => ['POST', 'PUT', 'PATCH', 'DELETE'],
  'except' => ['/', '/webhook'],
  'secret' => 'my-secret-key',
  'messages.tokenNotFound' => 'Token not found',
  'messages.tokenInvalid' => 'Token is invalid',
  'onError' => function () {
    response()->redirect('/error');
  }
]);
```

### Usage outside of leaf

Most leaf modules can be used outside of leaf and this is no exception. If you decide to use the CSRF module outside of leaf, you will need to manually initialize the package.

```php
Leaf\Anchor\CSRF::init();
```

This function generates a token with a secret and a random hash and saves that in a session. If no session exists, the CSRF module will create a session for your app and save the token in that session. You can then pass your configuration as an array to the `config()` method.

```php
Leaf\Anchor\CSRF::init();
Leaf\Anchor\CSRF::config([
  ...
]);
```

After initializing the CSRF module, you can then use the `validate()` method as a kind of middleware to check if the CSRF token is valid.

```php
Leaf\Anchor\CSRF::validate();
```

Be sure to do this above the rest of your code so that the CSRF module can properly protect your app.

You can find the full documentation for this module on the [Leaf Documentation](https://leafphp.dev/docs/security/csrf).
