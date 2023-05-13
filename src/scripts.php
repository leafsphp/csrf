<?php

if (class_exists('\Leaf\App')) {
    app()->attach(function () {
        if (!\Leaf\Anchor\CSRF::token()) {
            \Leaf\Anchor\CSRF::init();
        }

        if (!\Leaf\Anchor\CSRF::verify()) {
            $csrfError = \Leaf\Anchor\CSRF::errors()['token'];
            \Leaf\Http\Headers::resetStatus(400);
            echo \Leaf\Exception\General::csrf($csrfError);
            exit();
        }
    });
}
