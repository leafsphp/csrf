<?php

if (!function_exists('_token')) {
    /**
     * Return CSRF token
     */
    function _token(): array
    {
        return \Leaf\Anchor\CSRF::token();
    }
}

if (!function_exists('_csrfField')) {
    /**
     * Render a CSRF form field
     */
    function _csrfField()
    {
        \Leaf\Anchor\CSRF::form();
    }
}
