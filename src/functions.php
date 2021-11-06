<?php

if (!function_exists('_token')) {
    /**
     * Return CSRF token
     */
    function _token()
    {
        return \Leaf\Anchor\CSRF::token();
    }
}
