<?php

/**
 * @author riptidewave93 <chris@servernetworktech.com>
 * @name authlib.php - Salted PHP Session Library
 * @uses **CONTENT REMOVED**
 * @version 0.2 Alpha (7/9/2014)
 * @copyright 2014
 * @license GPL v3
 */

########################
#### Documentation #####
########################
#
#   Server Dependencies:
#   php5-crypt
#   mysql-server
#
#   Script Dependencies:
#   $_SESSION['user'] = username, set at login time from login script
#   
#   AuthLib_Start()
#   - Used to start a session
#
#   AuthLib_Destroy($dbserver,$dbname,$dbuser,$dbpass, $us, $x)
#   -   Used to destroy a session properly and remove it from the DB
#       -		$dbserver   -   MySQL Server
#       -		$dbname -   Name of the MySQL Database
#       -		$dbuser -   The user account for the DB
#       -		$dbpass -   The password for the DB Account
#       -		$us -   The sale for the Username
#       -		$x  -   The URL of your login page
#
#   AuthLib_RegenerateID()
#   -   Used to regenerate the Session ID for the current session
#
#   AuthLib_Salt($content,$salt)
#   -   Internal Function Only! Used to salt content with your given salts
#       -		$content    -   Message you want salted
#       -		$salt   -   The salt to use on the message
#
#   AuthLib_UnSalt($content,$salt)
#   -   Internal Function Only! Used to unsalt content with your given salts
#       -		$content    -   Message you want unsalted
#       -		$salt   -   The key to unsalt the message
#
#   AuthLib_CreateSession($dbserver,$dbname,$dbuser,$dbpass,$ss,$ips,$us)
#   -   Used to update or create a session in the database for verification purposes
#       -   $dbserver   -   MySQL Server
#       -   $dbname -   Name of the MySQL Database
#       -   $dbuser -   The user account for the DB
#       -   $dbpass -   The password for the DB Account
#       -   $ss -   The Salt for the Session ID
#       -   $ips    -   The Salt used on the IP
#       -   $us  -   The Salt for the Username
#
#   AuthLib_VerifySession($dbserver,$dbname,$dbuser,$dbpass,$ss,$sid,$ips,$us,$x)
#   -   Used to verify a current session, reject bad sessions, and regen the session ID
#   -   It also hashes everything that gets stored in the DB for security purposes
#       -   $dbserver   -   MySQL Server
#       -   $dbname -   Name of the MySQL Database
#       -   $dbuser -   The user account for the DB
#       -   $dbpass -   The password for the DB Account
#       -   $ss -   The Salt for the Session ID
#       -   $ips    -   The Salt used on the IP
#       -   $us  -   The Salt for the Username
#       -   $x  -   The URL of your login page, it will destroy the session before redirect
#
#########################################################
## Below this are the functions the drive this library ##
#########################################################

# Used to start a session
function AuthLib_Start()
{
    # Not much to do here as we only do saving from the verify part
    session_start();
}

# Time to kill a session
function AuthLib_Destroy($dbserver, $dbname, $dbuser, $dbpass, $us, $x)
{
    # is a user signed in? if not, no need to mess with DB removal
    if (isset($_SESSION['user']))
    {
        # Connect to DB
        try
        {
            $dbn = "mysql:host=$dbserver;dbname=$dbname";
            $db = new PDO($dbn, $dbuser, $dbpass);
        }
        catch (PDOException $e)
        {
            echo "A serious Database Error has Occured!";
            exit();
        }

        # Convert raw input using the salts to be compared to the db
        $user_final = AuthLib_Salt($_SESSION['user'], $us);

        # Pull info from DB based on session
        $query = $db->prepare('DELETE FROM account_sessions WHERE user = ?');
        $DBarray = array($user_final);
        $query->execute($DBarray);
    }
    
    # Kill Session
    session_destroy();

    # Are we on the logout page?
    if (!isset($_SESSION['logout']))
    {
        header("Location: $x");
    }
}

# Regenerate Session ID
function AuthLib_RegenerateID()
{
    # Nothing special here...
    session_regenerate_id();
}

# Function used to salt things
function AuthLib_Salt($content, $salt)
{
    return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5("$salt"), $content, MCRYPT_MODE_CBC, md5(md5("$salt"))));
}

function AuthLib_UnSalt($content, $salt)
{
    return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5("$salt"), base64_decode($content), MCRYPT_MODE_CBC, md5(md5("$salt"))));
}

# Used to create/update a session in the database
function AuthLib_CreateSession($dbserver, $dbname, $dbuser, $dbpass, $ss, $ips, $us)
{
    # Connect to DB
    try
    {
        $dbn = "mysql:host=$dbserver;dbname=$dbname";
        $db = new PDO($dbn, $dbuser, $dbpass);
    }
    catch (PDOException $e)
    {
        echo "A serious Database Error has Occured!";
        exit();
    }

    # Convert raw input using the salts to be compared to the db
    $user_final = AuthLib_Salt($_SESSION['user'], $us);
    $ip_final = AuthLib_Salt($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_X_FORWARDED_FOR'], $ips);
    $session_final = AuthLib_Salt(session_id(), $ss);

    # Pull info from DB based on session
    $query = $db->prepare('REPLACE INTO account_sessions SET user = ?, timestamp = ?, address = ?, session = ? ');
    $DBarray = array(
        $user_final,
        time(),
        $ip_final,
        $session_final);
    $query->execute($DBarray);

    # Lastly set session var for valid
    $_SESSION['valid'] = time() . '*' . $ip_final;
}

# Simple function that will redirect to login page if user is not signed in
function AuthLib_VerifySession($dbserver, $dbname, $dbuser, $dbpass, $ss, $ips, $us, $x)
{
    if (isset($_SESSION['user']))
    {
        # Convert raw input using the salts
        $ip_final = AuthLib_Salt($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_X_FORWARDED_FOR'], $ips);

        # Are we valid? check this way before doing a DB call because lets prevent load if possible.
        if (strstr($_SESSION['valid'], '*', true) < strtotime('-30 minutes') or substr(strstr($_SESSION['valid'], '*'), 1) != $ip_final)
        {
            # Convert rest of strings
            $user_final = AuthLib_Salt($_SESSION['user'], $us);
            $session_final = AuthLib_Salt(session_id(), $ss);

            # Connect to DB
            try
            {
                $dbn = "mysql:host=$dbserver;dbname=$dbname";
                $db = new PDO($dbn, $dbuser, $dbpass);
            }
            catch (PDOException $e)
            {
                echo "A serious Database Error has Occured!";
                exit();
            }

            # Pull info from DB based on session
            $query = $db->prepare('SELECT user, timestamp, address, session, valid FROM account_sessions WHERE user = ? and address = ? and session = ?');
            $DBarray = array(
                $user_final,
                $ip_final,
                $session_final);
            $query->execute($DBarray);
            $fetch = $query->fetch();

            # Do we have anything in the DB?
            if ($query->rowCount() != 0)
            {
                # Check ping status
                if ($fetch['timestamp'] < strtotime('-30 minutes'))
                {
                    # Ping is older then 30 min, guess we need to logout and reset
                    AuthLib_Destroy($dbserver, $dbname, $dbuser, $dbpass, $us, $x);
                } else
                {
                    # Valid login, set session var
                    $_SESSION['valid'] = time() . '*' . $ip_final;
                }
            } else
            {
                # No session found, I don't think we are logged in...
                AuthLib_Destroy($dbserver, $dbname, $dbuser, $dbpass, $us, $x);
            }

            # So if we are here, that means that we are valid in the DB from the last 30 min
            # So we will regen our id, and save it to the DB with an updated timestamp because yay!

            # Update Session ID
            AuthLib_RegenerateID();

            # Save updated session to DB
            AuthLib_CreateSession($dbserver, $dbname, $dbuser, $dbpass, $ss, $ips, $us);
        }
        return 0;
    } else
    {
        AuthLib_Destroy($dbserver, $dbname, $dbuser, $dbpass, $us, $x);
    }
}

?>
