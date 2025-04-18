<?php
require_once __DIR__ . "/vendor/autoload.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\OAuthTokenProvider;

class GoogleOauthClient implements OAuthTokenProvider
{
    private $oauthUserEmail;
    private $client;
    private $tokenPath;

    public function __construct($oauthUserEmail, $credentialsFile, $tokenPath)
    {
        $this->oauthUserEmail = $oauthUserEmail;

        $this->client = new \Google_Client();
        $this->client->setScopes([\Google_Service_Gmail::MAIL_GOOGLE_COM]);
        $this->client->setAuthConfig($credentialsFile);
        $this->client->setAccessType("offline");
        $this->client->setRedirectUri($this->client->getRedirectUri());
        if (!file_exists($tokenPath)) {
            $this->client->setPrompt("consent");
        }

        // Set the token path
        $this->tokenPath = $tokenPath;

        // Load previously stored auth token
        if (file_exists($this->tokenPath)) {
            $accessToken = json_decode(
                file_get_contents($this->tokenPath),
                true
            );
            $this->client->setAccessToken($accessToken);
        }
    }

    public function refreshOAuthToken()
    {
        // If our token has not expired, there is nothing to do
        if (!$this->client->isAccessTokenExpired()) {
            return;
        }

        // If our token has expired, but we do not have a refresh token
        if (!$this->client->getRefreshToken()) {
            $authUrl = $this->client->createAuthUrl();
            printf("Open the following link in your browser:\n%s\n", $authUrl);
            print "Enter verification code: ";
            $authCode = trim(fgets(STDIN));

            $accessToken = $this->client->fetchAccessTokenWithAuthCode(
                $authCode
            );
            $this->client->setAccessToken($accessToken);

            if (array_key_exists("error", $accessToken)) {
                throw new \Exception(join(", ", $accessToken));
            }
        }

        $this->client->fetchAccessTokenWithRefreshToken(
            $this->client->getRefreshToken()
        );

        // Save the token to the token file
        file_put_contents(
            $this->tokenPath,
            json_encode($this->client->getAccessToken())
        );
    }

    /**
     * @see \PHPMailer\PHPMailer\OAuth::getOauth64()
     */
    public function getOauth64(): string
    {
        $this->refreshOAuthToken();
        $oauthToken = $this->client->getAccessToken();
        return base64_encode(
            "user=" .
                $this->oauthUserEmail .
                "\001auth=Bearer " .
                $oauthToken["access_token"] .
                "\001\001"
        );
    }
}

$mailer = new PHPMailer();
$mailer->isSMTP();
$mailer->Host = "smtp.gmail.com";
$mailer->Port = 587;
$mailer->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
$mailer->SMTPAuth = true;
$mailer->AuthType = "XOAUTH2";
$mailer->CharSet = PHPMailer::CHARSET_UTF8;
$mailer->FromName = ""; // FILL: From name
$mailer->From = ""; // FILL: From mail

//Create and pass GoogleOauthClient to PHPMailer
$oauthTokenProvider = new \GoogleOauthClient(
    "", // FILL: From address for your mails
    __DIR__ . "/gmail-xoauth2-credentials.json",
    __DIR__ . "/gmail-xoauth-token.json"
);
$mailer->setOAuth($oauthTokenProvider);

// This is used to issue a refresh token and send test mail on install
if (php_sapi_name() == "cli") {
    $mailer->Subject = "Test mail";
    $mailer->Body = "Test mail for wpa-sec";
    $mailer->AddAddress(""); // FILL: To address for test mail

    if (!$mailer->send()) {
        echo "Mailer Error: " . $mailer->ErrorInfo;
    } else {
        echo "Message sent!";
    }

    $mailer->SmtpClose();
}
?>
