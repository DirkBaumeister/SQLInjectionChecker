<?php

namespace DirkBaumeister\SQLInjectionChecker;

class Checker
{

    private static $method;

    private static $suspect;

    private static $operators = [
        'select * ',
        'select ',
        'union all ',
        'union ',
        ' all ',
        ' where ',
        ' and 1 ',
        ' and ',
        ' or ',
        ' 1=1 ',
        ' 2=2 ',
        ' -- ',
    ];

    public static function detect()
    {
        self::setMethod();
        if(null !== self::$method) {
            return self::parseQuery();
        }
        return false;
    }

    public static function getSuspectData($json = false)
    {
        $data = [
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'date' => date('d-m-Y H:i:s'),
            'suspect' => self::$suspect,
            'server_vars' => $_SERVER
        ];
        if(true === $json) {
            $data = json_encode($data);
        }
        return $data;
    }

    private static function setMethod()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            self::$method = $_GET;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            self::$method = $_POST;
        }
    }

    private static function parseQuery()
    {
        foreach(self::$method as $key => $val)
        {
            $k = urldecode(strtolower($key));
            $v = urldecode(strtolower($val));

            foreach(self::$operators as $operator)
            {
                if (preg_match("/".$operator."/i", $k)) {
                    self::$suspect = ['operator' => $operator, 'key' => $k, 'value' => $v];
                    return true;
                }
                if (preg_match("/".$operator."/i", $v)) {
                    self::$suspect = ['operator' => $operator, 'key' => $k, 'value' => $v];
                    return true;
                }
            }
        }
        return false;
    }

}