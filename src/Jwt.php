<?php
declare(strict_types=1);

namespace Longxinhong\JwtToken;

use \Exception;

/**
 * 用法
 * Class Jwt
 * @package Longxinhong\JwtToken
 */
class Jwt
{
//头部
    private static $header = array(
        'alg' => 'HS256', //生成signature的算法
        'typ' => 'JWT'  //类型
    );

    //使用HMAC生成信息摘要时所使用的密钥
    private static $key = 'jjj-3#^*';

    private static $time = 0;

    private static $expire = 7200;

    public function setExpire(int $expire): Jwt
    {
        self::$expire = $expire;
        return $this;
    }

    /**
     * 获取时间
     * @return int
     */
    private static function getTime(): int
    {
        return time();
    }

    public static function init(): Jwt
    {
        self::$time = self::getTime();
        return new self();
    }


    public function setKey(string $key): Jwt
    {
        self::$key = $key;
        return $this;
    }

    /**
     * 获取jwt token
     * @param array $payload jwt载荷  格式如下非必须
     * [
     * 'iss'=>'jwt_admin', //该JWT的签发者
     * 'iat'=>time(), //签发时间
     * 'exp'=>time()+7200, //过期时间
     * 'nbf'=>time()+60, //该时间之前不接收处理该Token
     * 'sub'=>'www.admin.com', //面向的用户
     * 'jti'=>md5(uniqid('JWT').time()) //该Token唯一标识
     * ]
     * @return string
     * @throws Exception
     */
    public function getToken(array $payload): string
    {
        if (isset($payload['exp'])) {
            throw new Exception('Jwt中payload不能包含exp键');
        }
        $payload = array_merge($payload, ['exp' => self::$time + self::$expire]);
        $base64header = self::base64UrlEncode(json_encode(self::$header, JSON_UNESCAPED_UNICODE));
        $base64payload = self::base64UrlEncode(json_encode($payload, JSON_UNESCAPED_UNICODE));
        return $base64header . '.' . $base64payload . '.' . self::signature(
                $base64header . '.' . $base64payload,
                self::$key,
                self::$header['alg']
            );
    }


    /**
     * 验证token是否有效,默认验证exp,nbf,iat时间
     * @param string $Token 需要验证的token
     * @return bool|string
     */
    public function verifyToken(string $Token)
    {
        $tokens = explode('.', $Token);
        if (count($tokens) != 3) {
            return false;
        }

        list($base64header, $base64payload, $sign) = $tokens;

        //获取jwt算法
        $base64decodeheader = json_decode(self::base64UrlDecode($base64header), true);
        if (empty($base64decodeheader['alg'])) {
            return false;
        }

        //签名验证
        if (self::signature($base64header . '.' . $base64payload, self::$key, $base64decodeheader['alg']) !== $sign) {
            return false;
        }

        $payload = json_decode(self::base64UrlDecode($base64payload), true);

        //签发时间大于当前服务器时间验证失败
        if (isset($payload['iat']) && $payload['iat'] > self::$time) {
            return false;
        }

        //过期时间小宇当前服务器时间验证失败
        if (isset($payload['exp']) && $payload['exp'] < self::$time) {
            return false;
        }

        //该nbf时间之前不接收处理该Token
        if (isset($payload['nbf']) && $payload['nbf'] > self::$time) {
            return false;
        }

        return $payload;
    }


    /**
     * base64UrlEncode  https://jwt.io/ 中base64UrlEncode编码实现
     * @param string $input 需要编码的字符串
     * @return string
     */
    private static function base64UrlEncode(string $input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * base64UrlEncode https://jwt.io/ 中base64UrlEncode解码实现
     * @param string $input 需要解码的字符串
     * @return bool|string
     */
    private static function base64UrlDecode(string $input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $addlen = 4 - $remainder;
            $input .= str_repeat('=', $addlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * HMACSHA256签名  https://jwt.io/ 中HMACSHA256签名实现
     * @param string $input 为base64UrlEncode(header).".".base64UrlEncode(payload)
     * @param string $key
     * @param string $alg 算法方式
     * @return mixed
     */
    private static function signature(string $input, string $key, string $alg = 'HS256')
    {
        $alg_config = array(
            'HS256' => 'sha256'
        );
        return self::base64UrlEncode(hash_hmac($alg_config[$alg], $input, $key, true));
    }
}