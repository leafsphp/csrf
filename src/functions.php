<?php

if (!function_exists('csrf') && class_exists('Leaf\App')) {
    /**
     * Return the leaf csrf object
     * 
     * @return Leaf\Anchor\CSRF
     */
    function csrf()
    {
        if (!(\Leaf\Config::getStatic('csrf'))) {
            \Leaf\Config::singleton('csrf', function () {
                return new \Leaf\Anchor\CSRF();
            });
        }

        return \Leaf\Config::get('csrf');
    }
}
