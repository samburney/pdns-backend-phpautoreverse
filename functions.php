<?php
require_once('ipv6_functions.php');

// Check that IP is in specified network; Source: http://php.net/manual/en/function.ip2long.php#92544
function ip_in_network($ip, $net_addr, $net_mask = false){
	if(!$net_mask && strpos($net_addr, "/") !== false) {
		$cidr_arr = explode("/", $net_addr);
		$net_addr = $cidr_arr[0];
		$net_mask = $cidr_arr[1];
	}

    if($net_mask <= 0){
    	return false;
    }
    
    $ip_binary_string = sprintf("%032b",ip2long($ip));
    $net_binary_string = sprintf("%032b",ip2long($net_addr));

    return (substr_compare($ip_binary_string,$net_binary_string,0,$net_mask) === 0);
}

// Check if IPv6 is in specified network
function ip_in_network6($ip, $net_addr, $net_mask = false){
	if(!$net_mask && strpos($net_addr, "/") !== false) {
		$cidr_arr = explode("/", $net_addr);
		$net_addr = $cidr_arr[0];
		$net_mask = $cidr_arr[1];
	}

	$ip = inet6_expand($ip);
	$net_addr = inet6_expand($net_addr);
	$net_mask_hex = inet6_expand(inet6_prefix_to_mask($net_mask));

  $ip_dec_arr = inet6_to_int64($ip);
  $net_dec_arr = inet6_to_int64($net_addr);
  $mask_dec_arr = inet6_to_int64($net_mask_hex);

  // Need to handle >64 bit net masks
  if($net_mask > 64) {
  	$net_mask_64_arr[0] = 64;
  	$net_mask_64_arr[1] = 64 - (128 - $net_mask);
  }
  else {
  	$net_mask_64_arr[0] = $net_mask;
  	$net_mask_64_arr[1] = false;
  }

  if((substr(gmp_convert($ip_dec_arr[0], 10, 2), 0, $net_mask_64_arr[0]) & substr(gmp_convert($mask_dec_arr[0], 10, 2), 0, $net_mask_64_arr[0])) == substr(gmp_convert($net_dec_arr[0], 10, 2), 0, $net_mask_64_arr[0])) {
  	if($net_mask_64_arr[1]) {
	    if((substr(gmp_convert($ip_dec_arr[1], 10, 2), 0, $net_mask_64_arr[1]) & substr(gmp_convert($mask_dec_arr[1], 10, 2), 0, $net_mask_64_arr[1])) != substr(gmp_convert($net_dec_arr[1], 10, 2), 0, $net_mask_64_arr[1])) {
	    	return false;
	    }
  	}

  	return true;
  }
}

// Convert IPv6 to Decimal
function ip2long6($ipv6) { 
  $ip_n = inet_pton($ipv6); 
  $bits = 15; // 16 x 8 bit = 128bit 
  while ($bits >= 0) { 
    $bin = sprintf("%08b",(ord($ip_n[$bits]))); 
    $ipv6long = $bin.$ipv6long; 
    $bits--; 
  } 
  return gmp_strval(gmp_init($ipv6long,2),10); 
} 

// Convert Decimal to IPv6
function long2ip6($ipv6long) { 
  $bin = gmp_strval(gmp_init($ipv6long,10),2); 
  if (strlen($bin) < 128) { 
    $pad = 128 - strlen($bin); 
    for ($i = 1; $i <= $pad; $i++) { 
    $bin = "0".$bin; 
    } 
  } 
  $bits = 0; 
  while ($bits <= 7) { 
    $bin_part = substr($bin,($bits*16),16); 
    $ipv6 .= str_pad(dechex(bindec($bin_part)), 4, '0', STR_PAD_LEFT).":"; 
    $bits++; 
  } 
  
  // compress 
  //return inet_ntop(inet_pton(substr($ipv6,0,-1))); 
  return substr($ipv6,0,-1);
} 

function createNetmaskAddr($bitcount) {
    $netmask = str_split(str_pad(str_pad('', $bitcount, '1'), 32, '0'), 8);
    foreach ($netmask as &$element) $element = bindec($element);
    return join('.', $netmask);
}

// PHP convert_base() function implemented using gmp; http://blog.rac.me.uk/2008/12/09/php-md5-hashes-base_convert-and-32-bit-limitations/
function gmp_convert($num, $base_a, $base_b)
{
  return gmp_strval ( gmp_init($num, $base_a), $base_b );
}

// Recursive in_array
function in_array_recursive($value, $array) {
    foreach($array as $item) { 
        if(!is_array($item)) { 
            if ($item == $value) return true; 
            else continue; 
        } 
        
        if(in_array($value, $item)) return true; 
        else if(in_array_recursive($value, $item)) return true; 
    } 
    return false; 
} 