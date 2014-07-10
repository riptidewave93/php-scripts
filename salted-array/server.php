<?php

//for now, as this IS a test, we will only have one. We will later do a database with a "for each" option, like a array, to cron all listeners in the list.
$srv_location = "./listener.php";

//This would also be pulled from the database. User set key for remote server info pulling
$authkey = "SecretKeyC";

//this is the key we will use to decrypt mixxed with user set key.
//EXACT same as $cryptionkey in listener.php
$decryptkey = 'SecretKeyB' . $authkey;

//This just makes it so if the user uses a null authkey the codes still encrypted
$sendauthkey = 'SecretKeyA' . $authkey;

//pull from the server URL using the request key
$enecyptedarray = file_get_contents($srv_location . "?pullkey=$sendauthkey");

//if there is no output, the listener sent exit(); null, meaning bad key
if ($enecyptedarray == null)
{
	exit("Unable to Pull info from file. Check the link in the config");
}

//This decrypts the data.
$decryptedarray = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5("$decryptkey"), base64_decode($enecyptedarray), MCRYPT_MODE_CBC, md5(md5("$decryptkey"))));

//set array to value after decryption
$arr = explode(";", $decryptedarray);

if ($arr['0'] != "ArrayStart")
{
	exit('Somthing Encrypted/Decrypted Wrong. Exiting.');
}
//DEBUG FOR NOW
//echo vars as it is now a array full of info
//the real script would just database info, and it would send A LOT more info. just some
//random info was sent for now as a test. I will format this better later.
echo "Echo the array: <br /><br />";
echo 'Name: ' . $arr['1'] . '<br />Port: ' . $arr['2'] . '<br />Hostname: ' . $arr['3'];

?>
