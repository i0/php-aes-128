<?php

namespace App\Classes;


class AES
{
    private $key;
    private $plainText;
    private $sBox;
    private $m;

    function __construct()
    {
        $this->sBox = $this->sBox();
        $this->m = $this->m();
    }

    function m()
    {
        return [
            ['02', '03', '01', '01'],
            ['01', '02', '03', '01'],
            ['01', '01', '02', '03'],
            ['03', '01', '01', '02'],
        ];
    }

    function sBox()
    {
        return [
            ['63', '7C', '77', '7B', 'F2', '6B', '6F', 'C5', '30', '01', '67', '2B', 'FE', 'D7', 'AB', '76'],
            ['CA', '82', 'C9', '7D', 'FA', '59', '47', 'F0', 'AD', 'D4', 'A2', 'AF', '9C', 'A4', '72', 'C0'],
            ['B7', 'FD', '93', '26', '36', '3F', 'F7', 'CC', '34', 'A5', 'E5', 'F1', '71', 'D8', '31', '15'],
            ['04', 'C7', '23', 'C3', '18', '96', '05', '9A', '07', '12', '80', 'E2', 'EB', '27', 'B2', '75'],
            ['09', '83', '2C', '1A', '1B', '6E', '5A', 'A0', '52', '3B', 'D6', 'B3', '29', 'E3', '2F', '84'],
            ['53', 'D1', '00', 'ED', '20', 'FC', 'B1', '5B', '6A', 'CB', 'BE', '39', '4A', '4C', '58', 'CF'],
            ['D0', 'EF', 'AA', 'FB', '43', '4D', '33', '85', '45', 'F9', '02', '7F', '50', '3C', '9F', 'A8'],
            ['51', 'A3', '40', '8F', '92', '9D', '38', 'F5', 'BC', 'B6', 'DA', '21', '10', 'FF', 'F3', 'D2'],
            ['CD', '0C', '13', 'EC', '5F', '97', '44', '17', 'C4', 'A7', '7E', '3D', '64', '5D', '19', '73'],
            ['60', '81', '4F', 'DC', '22', '2A', '90', '88', '46', 'EE', 'B8', '14', 'DE', '5E', '0B', 'DB'],
            ['E0', '32', '3A', '0A', '49', '06', '24', '5C', 'C2', 'D3', 'AC', '62', '91', '95', 'E4', '79'],
            ['E7', 'C8', '37', '6D', '8D', 'D5', '4E', 'A9', '6C', '56', 'F4', 'EA', '65', '7A', 'AE', '08'],
            ['BA', '78', '25', '2E', '1C', 'A6', 'B4', 'C6', 'E8', 'DD', '74', '1F', '4B', 'BD', '8B', '8A'],
            ['70', '3E', 'B5', '66', '48', '03', 'F6', '0E', '61', '35', '57', 'B9', '86', 'C1', '1D', '9E'],
            ['E1', 'F8', '98', '11', '69', 'D9', '8E', '94', '9B', '1E', '87', 'E9', 'CE', '55', '28', 'DF'],
            ['8C', 'A1', '89', '0D', 'BF', 'E6', '42', '68', '41', '99', '2D', '0F', 'B0', '54', 'BB', '16']
        ];
    }

    function setKey($hex)
    {
        $hex = str_split($hex, 2);
        $this->key = $hex;
    }

    function setPlainText($hex)
    {
        $split = str_split($hex, 2);
        $this->plainText = array_chunk($split, 4);
    }


    function RC($i)
    {
        #GF(2^8)[i] with x^8+x^4+x^3+x+1 as irreducible polynomial
        $rc = [
            '00000001', # x^0
            '00000010', # x^1
            '00000100', # x^2
            '00001000', # x^3
            '00010000', # x^4
            '00100000', # x^5
            '01000000', # x^6
            '10000000', # x^7
            '00011011', # x^8
            '00110110', # x^9
        ];
        return base_convert($rc[$i - 1], 2, 10);
    }

    function main()
    {
        $this->setPlainText(bin2hex("Two One Nine Two"));
        $this->setKey(bin2hex("Thats my Kung Fu"));
        $roundKeys = $this->buildRoundKeys();
        $round = 0;
        $key = array_transpose(array_slice($roundKeys, $round, 4));
        $state = array_transpose($this->plainText);
        $state = $this->ARK($state, $key);
        for ($round = 1; $round <= 9; $round++) {
            $key = array_transpose(array_slice($roundKeys, $round * 4, 4));
            $state = $this->BS($state);
            $state = $this->SR($state);
            $state = $this->MC($state);
            $state = $this->ARK($state, $key);
        }
        $key = array_transpose(array_slice($roundKeys, $round * 4, 4));
        $state = $this->BS($state);
        $state = $this->SR($state);
        $state = $this->ARK($state, $key);
        $cipherText = array_flatten(array_transpose($state));
        return $cipherText;
    }

    function MC($state)
    {
        $result = [];
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $result[$i][$j] = 0;
                for ($k = 0; $k < 4; $k++) {
                    # Multiply
                    $first = hexdec($state[$k][$j]);
                    $product = $first;
                    $by = hexdec($this->m[$i][$k]);
                    if ($by > 1) {
                        $product <<= 1;
                    }
                    if ($by == 3) {
                        $product ^= $first;
                    }
                    # Residual
                    if ($product & 0x100) $product ^= 0x11B;
                    # Add
                    $result[$i][$j] ^= $product;
                }
                # format and convert dec to hex
                $result[$i][$j] = format(dechex($result[$i][$j]));
            }
        }
        return $result;
    }

    function SR($state)
    {
        $result = [];
        foreach ($state as $key => $row) {
            $result[$key] = $row;
            for ($i = 0; $i < $key; $i++)
                $result[$key] = $this->shift($result[$key]);
        }
        return $result;
    }

    function BS($state)
    {
        $result = [];
        foreach ($state as $row) {
            $result[] = $this->byteSub($row);
        }
        return $result;
    }

    # Add Round Key
    function ARK($state, $key)
    {
        $xor = $this->matrixXor($state, $key);
        return $xor;
    }

    function buildRoundKeys()
    {
        $roundKeys = array_chunk($this->key, 4);
        $round = 0;
        for ($i = 4; $i <= 43; $i++) {
            # w-4
            $w_4 = $roundKeys[$i - 4];
            # g(w-1) | w-1
            if ($i % 4 == 0) {
                $w_1 = $this->g($roundKeys[$i - 1], ++$round);
            } else {
                $w_1 = $roundKeys[$i - 1];
            }
            $roundKeys[$i] = $this->fourWordXor($w_4, $w_1);
        }

        return $roundKeys;
    }

    #
    function matrixXor($m1, $m2)
    {
        $result = [];
        for ($i = 0; $i < 4; $i++) {
            $result[$i] = $this->fourWordXor($m1[$i], $m2[$i]);
        }
        return $result;
    }

    function fourWordXor($w_4, $w_1)
    {
        $result = [];
        for ($i = 0; $i < 4; $i++) {
            $first = hexdec($w_4[$i]);
            $second = hexdec($w_1[$i]);
            $xor = dechex($first ^ $second);
            $pad = format($xor);
            $result[$i] = $pad;
        }
        return $result;
    }

    function g($arr, $round)
    {
        $arr = $this->shift($arr);
        $arr = $this->byteSub($arr);
        $arr = $this->addRC($arr, $round);
        return $arr;
    }

    function shift($arr)
    {
        array_push($arr, array_shift($arr));
        return $arr;
    }

    function byteSub($arr)
    {
        foreach ($arr as &$item) {
            $row = hexdec($item[0]);
            $col = hexdec($item[1]);
            $item = strtolower($this->sBox[$row][$col]);
        }
        return $arr;
    }

    function addRC($arr, $round)
    {
        $RC = $this->RC($round);
        # the bitwise xor operator ^ needs decimal integers
        $arr[0] = dechex(hexdec($arr[0]) ^ $RC);
        return $arr;
    }
}

function array_transpose($arr)
{
    $out = array();
    foreach ($arr as $key => $subarr) {
        foreach ($subarr as $subkey => $subvalue) {
            $out[$subkey][$key] = $subvalue;
        }
    }
    return $out;
}

function format($str)
{
    return str_pad($str, 2, "0", STR_PAD_LEFT);
}

function array_flatten($array)
{
    if (!is_array($array)) {
        return false;
    }
    $result = array();
    foreach ($array as $key => $value) {
        if (is_array($value)) {
            $result = array_merge($result, array_flatten($value));
        } else {
            $result[$key] = $value;
        }
    }
    return $result;
}
