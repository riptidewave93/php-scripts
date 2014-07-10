<?php

//config part of script is here, this part would NOT be encrypted

//Same key as you set on the main server. This key is used for encryption, and must be the same.
$authkey = "SecretKeyC";

//Encryption code starts after this

//if someone requests the key
if ($_GET['pullkey'])
{
	//make sure there was a key sent
	if ($_GET['pullkey'] == null)
	{
		exit();
		//make sure it was the CORRECT key
	} elseif ($_GET['pullkey'] != 'SecretKeyA' . $authkey)
	{
		//Wrong key, tell cron.php that info
		exit("Authkey is incorrect. Check your configuration.");
	} else
	{
		//Key we will use in the script that will me added to end of user custom set key for security
		$cryptionkey = 'SecretKeyB' . $authkey;

		//This is the info that needs to be encrypted. Lets do a fake array, and see if it can be used on the other end
		//First part of array is used to auth that array was decrypted correctly on other end. If not, some key is wrong...
		$encryptme = 'ArrayItem1;ArrayItem2;YouGetTheIdea;';

		//This encrpyts the information using a few different mixxes of goodies.
		$encrypt = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5("$cryptionkey"), $encryptme, MCRYPT_MODE_CBC, md5(md5("$cryptionkey"))));

		//echo only encrypted txt. Cron.php will read this, decrpyt, and array it
		echo $encrypt;
	}
} else
{
	//Keep the fake requests away
	exit();
}

?>
