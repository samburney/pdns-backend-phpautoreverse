<?php
require('vendor/autoload.php');
require('config.php');
require('functions.php');

// Database
require('db_setup.php');

// Process HTTP Request
$request = file_get_contents("php://input");
//$request = '{"method":"lookup","parameters":{"qtype":"SOA","qname":"static.cust.unitiwireless.com","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"ANY","qname":"10-0-0-1.dynamic.cust.isp.com","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"ANY","qname":"142.209.232.103.in-addr.arpa","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"ANY","qname":"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.8.4.0.3.0.4.2.ip6.arpa","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"SOA","qname":"1.0.0.0.8.4.0.3.0.4.2.ip6.arpa","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"ANY","qname":"vmhost2.adl1.unitiair","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"ANY","qname":"ether10-lns1-adl1.bdr2.adl1.unitiwireless.com","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
//$request = '{"method":"lookup","parameters":{"qtype":"SOA","qname":"0.0.10.in-addr.arpa","remote":"10.108.8.18","local":"0.0.0.0","real-remote":"10.108.8.18/32","zone-id":-1}}';
$query = json_decode($request, true);

/* ?><pre><? print_r($query); ?></pre><? */

// PowerDNS 'Lookup' Method
if($query['method'] == 'lookup') {
    $qname = $query['parameters']['qname'];
    $prefix_supported = false;
    $prefix_soa_qname = false;

    // Autoreverse IPv4 Suffixes
    if(substr($qname, -12, 12) == 'in-addr.arpa') {

      foreach($suffix_ipv4 as $prefix => $suffix) {
        // Check if this is a valid IPv4 Prefix
        if(preg_match("/^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\/([0-9]{1,2})$/", $prefix, $prefix_arr)) {

          // Convert $qname to IP
          $ip_arr = explode(".", substr($qname, 0, strlen($qname) - 13));
          $ip_arr = array_reverse($ip_arr);
          if(sizeof($ip_arr) < 4) {
            for($i = (4 - (4 - sizeof($ip_arr))); $i < 4; $i++) {
              $ip_arr[] = 0;
            }
          }
          $qname_ip = implode(".", $ip_arr);

          // Check if IP is in this prefix
          if(ip_in_network($qname_ip, $prefix)) {
            switch($query['parameters']['qtype']) {
              case 'SOA':
                // Get closest IPv4 Octet Boundary and generate SOA qname
                $octets = floor($prefix_arr[5] / 8);

                for($i = $octets; $i > 0; $i--) {
                  $prefix_soa_qname .= $prefix_arr[$i] . '.';
                }
                $prefix_soa_qname .= 'in-addr.arpa';

                if($prefix_soa_qname == $qname) {
                  $result = array(
                    'result' =>array(
                      array(
                        'qtype' => 'SOA',
                        'qname' => $query['parameters']['qname'],
                        'content' => implode(" ", $soa),
                        'ttl' => $soa[6],
                      ),
                    ),
                  );
                }

                break;

              case 'NS':
                break;

              default:
                $content = implode("-", $ip_arr) . '.' . $suffix['suffix'];

                $result = array('result' => array(array(
                    'qtype' => 'PTR',
                    'qname' => $qname,
                    'content' => $content,
                    'ttl' => $soa[6],
                )));

                break;
            }

            break;
          }
        }
      }
    }

    // Autoreverse IPv6 Suffixes
    if(substr($qname, -8, 8) == 'ip6.arpa') {
      foreach($suffix_ipv6 as $prefix => $suffix) {
        // Ensure this is a valid IPv6 prefix
        $prefix_split_arr = explode("/", $prefix);
        if (!filter_var($prefix_split_arr[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
          $ip_arr = explode(".", substr($qname, 0, strlen($qname) - 9));
          $ip_arr = array_reverse($ip_arr);

          for($i = 0; $i < 32; $i++) {
            $qname_ip .= $ip_arr[$i] ? $ip_arr[$i] : '0';
            if($i % 4 == 3 && $i != 31) $qname_ip .= ":";
          }

          if(ip_in_network6($qname_ip, $prefix)) {
            switch($query['parameters']['qtype']) {
              case 'SOA':
                // Generate SOA name from prefix
                $prefix_expanded = inet6_expand($prefix_split_arr[0]);
                $prefix_expanded = str_replace(':', '', $prefix_expanded);
                $prefix_arr = str_split($prefix_expanded);

                $octets = floor($prefix_split_arr[1] / 4);

                for($i = $octets - 1; $i >= 0; $i--) {
                  $prefix_soa_qname .= $prefix_arr[$i] . '.';
                }
                $prefix_soa_qname .= 'ip6.arpa';

                if($prefix_soa_qname == $qname) {
                  $result = array(
                    'result' =>array(
                      array(
                        'qtype' => 'SOA',
                        'qname' => $query['parameters']['qname'],
                        'content' => implode(" ", $soa),
                        'ttl' => $soa[6],
                      ),
                    ),
                  );
                }

                break;

              case 'NS':
                break;

              default:
                $ip_arr = explode(".", substr($qname, 0, strlen($qname) - 9));
                $ip_arr = array_reverse($ip_arr);
                for($i = 0; $i < 32; $i++) {
                  $content .= $ip_arr[$i];
                  if($i % 4 == 3 && $i != 31) $content .= "-";
                }
                $content .= '.' . $suffix['suffix'];

                $result = array('result' => array(array(
                  'qtype' => 'PTR',
                  'qname' => $qname,
                  'content' => $content,
                  'ttl' => $soa[6],
                )));

                break;
            }

            break;
          }
        };
      }
    }


/*    // Autoreverse IPv6 Suffixes
    foreach($suffix_ipv6 as $suffix) {
      if($qname == $suffix['suffix']) {
        $prefix_supported = true;
      }
    }

    // PHPIPAM Suffixes
    foreach($phpipam_suffixes as $suffix) {
      if($qname == $suffix) {
        $prefix_supported = true;
      }
    }

    if($prefix_supported) {
      $result = array(
        'result' =>array(
          array(
            'qtype' => 'SOA',
            'qname' => $query['parameters']['qname'],
            'content' => implode(" ", $soa),
            'ttl' => $soa[6],
          ),
        ),
      );
    } */

/*        break;

        // 'ANY' type
        default:
          // Detect query type



          // Auto-PTR
          /*if(substr($qname, -4, 4) == 'arpa') {
            // Determine if IPv4
            if(substr($qname, -12, 12) == 'in-addr.arpa') {
              $ip_arr = explode(".", substr($qname, 0, strlen($qname) - 13));
              $ip_arr = array_reverse($ip_arr);
              $content = implode("-", $ip_arr) . $suffix_ipv4;

              $result = array('result' => array(array(
                  'qtype' => 'PTR',
                  'qname' => $qname,
                  'content' => $content,
                  'ttl' => $soa[6],
              )));
            }
            // Or IPv6
            else if(substr($qname, -8, 8) == 'ip6.arpa') {
              $ip_arr = explode(".", substr($qname, 0, strlen($qname) - 9));
              $ip_arr = array_reverse($ip_arr);
              for($i = 0; $i < 32; $i++) {
                $content .= $ip_arr[$i];
                if($i % 4 == 3 && $i != 31) $content .= "-";
              }
              $content .= $suffix_ipv6;

              $result = array('result' => array(array(
                'qtype' => 'PTR',
                'qname' => $qname,
                'content' => $content,
                'ttl' => $soa[6],
              )));
            }
          }*/

          // A from PHPIPAM Hostname
          // Check that we support this domain
/*          $prefix_supported = false;
          foreach($phpipam_suffixes as $suffix) {
            if(strpos($qname, $suffix) !== false) {
              $prefix_supported = true;
            }
          }

          if($prefix_supported) {
            $ips = $db->table('ipaddresses')->where('dns_name', '=', $qname)->lists('ip_addr');
            // Generate $results
            $results = array();
            foreach($ips as $ip) {
              // IPv4
              if($ip <= 4294967294) {
                $results[] = array(
                  'qtype' => 'A',
                  'qname' => $qname,
                  'content' => long2ip($ip),
                  'ttl' => $soa[6],
                );
              }
              // IPv6
              else {
                $results[] = array(
                  'qtype' => 'AAAA',
                  'qname' => $qname,
                  'content' => long2ip6($ip),
                  'ttl' => $soa[6],
                );
              }
            }

            if(sizeof($results)) {
              $result = array('result' => $results);
            }
          }

          // A from Auto-Reverse
          /*if(strpos($qname, $suffix_ipv4) !== false || strpos($qname, $suffix_ipv6) !== false) {
            // IPv4
            if(strpos($qname, $suffix_ipv4) !== false) {
              $ip_raw = substr($qname, 0, strlen($qname) - strlen($suffix_ipv4));
              $content = str_replace("-", ".", $ip_raw);

              $result = array('result' => array(array(
                'qtype' => 'A',
                'qname' => $qname,
                'content' => $content,
                'ttl' => $soa[6],
              )));
            }

            // IPv6
            if(strpos($qname, $suffix_ipv6) !== false) {
              $ip_raw = substr($qname, 0, strlen($qname) - strlen($suffix_ipv6));
              $content = str_replace("-", ":", $ip_raw);

              $result = array('result' => array(array(
                'qtype' => 'AAAA',
                'qname' => $qname,
                'content' => $content,
                'ttl' => $soa[6],
              )));
            }
          }*/

/*          break;
    } */
}

if(!$result) {
  $result = array('result' => false);
}

$result['log'] =  array("query=$request response=" . json_encode($result) . " " . date('U'));

$response = json_encode($result);
echo $response;
?>