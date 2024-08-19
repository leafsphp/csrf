<?php

if (class_exists('\Leaf\Config')) {
    \Leaf\Config::addScript(function () {
        if (!\Leaf\Anchor\CSRF::token()) {
            \Leaf\Anchor\CSRF::init();
            \Leaf\Anchor\CSRF::config();
        }

        if (!\Leaf\Anchor\CSRF::verify()) {
            $csrfError = \Leaf\Anchor\CSRF::errors()['token'];
            \Leaf\Http\Headers::resetStatus(400);
            echo \Leaf\Exception\General::csrf($csrfError);
            exit();
        }
    });
}
