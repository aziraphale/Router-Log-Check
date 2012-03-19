<?php

// IP Address of your MikroTik router
$SSH_HOST = '192.168.0.1';

// Username to log in as over SSH
$SSH_USERNAME = 'logviewer';

// Password to use for the SSH authentication
$SSH_PASSWORD = 'password';

// The number of login failures that will trigger a ban
$FAILURE_LIMIT = 7;

// The magic port number to send a request to in order to ban an IP address.
// This requires that your MikroTik router is set up with these (or similar) ip/firewall/filter rules:
//  chain=input action=drop src-address-list=inbound-blacklist
//  chain=forward action=drop src-address-list=inbound-blacklist
//  chain=forward action=add-dst-to-address-list protocol=tcp address-list=inbound-blacklist address-list-timeout=1d dst-port=31337
$BAN_PORT = 31337;

// The failed attempt counter for each IP address in the current failure list will be decremented
//  every x seconds, where x is set by this variable. When the failure count reaches 0 for an
//  address, it is removed from the list
$IP_ATTEMPT_COUNT_DECREMENT_PERIOD = 300;

// Failed login attempts to usernames in this array will cause the fail counter to increment by the
//  specified value instead of the default of 1. The thinking behind this array is that brute-force
//  hack attempts will generally try to log in as a set of user accounts common to public-facing
//  servers in general (root, various DBMS names, etc.), despite these accounts not existing on
//  most MikroTik boards
$INSTANT_BAN_USERNAMES = array(
    'root' => 3,
    'mysql' => 3,
    'oracle' => 3,
    'postgres' => 3,
    'scanner' => 3,
    'user' => 3,
    'testuser' => 3,
    'stats' => 3,
    'test' => 3,
    'vmware' => 3,
    'student' => 3,
    'marketing' => 3,
    'exam' => 3,
);


// --------------------

function sshCallbackDisconnected($reason, $message, $language) {
    die(sprintf("Server disconnected with reason code [%d] and message: %s\n", $reason, $message));
}
$sshConnectCallbacks = array('disconnect' => 'sshCallbackDisconnected');

$bannedIps = array();
$failedIps = array();

$buffer = '';

function output($s) {
    echo date('[Y-m-d H:i:s] ') . rtrim($s) . "\r\n";
}

function banIp($ipAddress) {
    global $BAN_PORT, $bannedIps, $failedIps;
    $bannedIps[] = $ipAddress;
    
    if (isset($failedIps[$ipAddress])) {
        unset($failedIps[$ipAddress]);
    }
    
    $fp = @fsockopen($ipAddress, $BAN_PORT);
    if ($fp) {
        fclose($fp);
    }
}

function readBuffer() {
    global $buffer, $bannedIps, $INSTANT_BAN_USERNAMES, $failedIps, $FAILURE_LIMIT;
//    echo "readBuffer() - buffer is " . strlen($buffer) . " bytes long.\r\n";
    
    $buffer = str_replace(array("\r", "\n"), '', $buffer);
    
    while (preg_match('/login failure for user ([^ ]+) from ([0-9\.a-f:]+) via ssh/i', $buffer, $m, PREG_OFFSET_CAPTURE)) {
        list ($whole, $user, $ip) = $m;
        $user = $user[0];
        $ip = $ip[0];
        
        list($matched, $offset) = $whole;
        
//        echo "Got line '$matched'.\r\n";
        
//            if (in_array($ip, $bannedIps)) {
//                echo "[$ip is already banned]\r\n";
//                continue;
//            }
        
        $failIncrementValue = 1;
        
        $extraMsg = '';
        if (isset($INSTANT_BAN_USERNAMES[$user])) {
//                echo "Failed login attempt by $ip as user '$user' which is on the instant-ban list. Banning.\r\n";
//                banIp($ip);
//                continue;
            $failIncrementValue = $INSTANT_BAN_USERNAMES[$user];
            $extraMsg = ", which is on the blacklist and so counts as $failIncrementValue failed attempts";
        }
        
        if (!isset($failedIps[$ip])) {
            $failedIps[$ip] = $failIncrementValue;
            output("First failed login attempt by $ip as user '$user'$extraMsg.");
        } else {
            $failedIps[$ip] += $failIncrementValue;
            
            if ($failedIps[$ip] >= $FAILURE_LIMIT) {
                output("$ip has reached the failure limit of $FAILURE_LIMIT (attempted to log in as user '$user'$extraMsg). Banning.");
                banIp($ip);
                continue;
            } else {
                output("Login failure #{$failedIps[$ip]} for $ip (attempted to log in as user '$user'$extraMsg).");
            }
        }
        
        $buffer = substr($buffer, 0, $offset) . substr($buffer, $offset + strlen($matched));
    }
    
    //When the buffer gets a bit large, truncate it
    if (strlen($buffer) > 2048) {
//        echo "Buffer is now quite large; truncating it from this:\r\n$buffer\r\n\r\n";
        $buffer = substr($buffer, 1024);
    }
}

output("Connecting to $SSH_HOST...");
$ssh = ssh2_connect($SSH_HOST, 22, array(), $sshConnectCallbacks) or die("Unable to connect.");

output("Connected.");
output("Authenticating as $SSH_USERNAME...");
ssh2_auth_password($ssh, $SSH_USERNAME, $SSH_PASSWORD) or die("Unable to auth.");

output("Authenticated.");
output("Starting an interactive shell...");
$shell = ssh2_shell($ssh);
usleep(500000);

//Clear the MOTD header
stream_get_contents($shell);

output("Executing `/log print follow`...");
fwrite($shell, "/log print follow\r\n");
usleep(500000);

set_time_limit(0);
stream_set_blocking($shell, true);

output("Parsing the result and awaiting more data...");

$lastAddressClear = time();
while(true) {
    if (feof($shell)) {
        output("EOF on STDOUT.");
        die();
    } else {
        while ($data = fread($shell, 1024)) {
//            echo "Appending " . strlen($data) . " bytes to the buffer...\r\n";
            $buffer .= $data;
            readBuffer();
        }
    }
    
    if ($lastAddressClear < (time() - $IP_ATTEMPT_COUNT_DECREMENT_PERIOD)) {
        foreach ($failedIps as $k => &$v) {
            if (--$v <= 0) {
                output("No failed login attempts have been seen from $k for a while.");
                unset($failedIps[$k]);
            }
        }
        $lastAddressClear = time();
    }
}


?>