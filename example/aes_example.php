<?php
// Your key and iv from ionic App Put here:
$key = "cdfb03508f7da468a5875bd571565d7d";
$iv =  "67bd32135dbd858b";


$cipher="AES-256-CBC";
$plaintext = "Encryption Test 123";

$ivlen = openssl_cipher_iv_length($cipher);

echo "ivlen :{$ivlen}<br />\n";

$ciphertext_raw = openssl_encrypt($plaintext, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);

echo "Enc : " . base64_encode( $ciphertext_raw );
echo "<br />\n";

$original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options, $iv);

echo "Dec : " . $original_plaintext;
echo "<br />\n";


// Your ionc encrypted text here for checking!
$enc2 = "Na02qA7er4wOFMdn5q/KnC+cEnxas2UEd37StJDFdLI=";
$ciphertext_raw2 = base64_decode($enc2);

$original_plaintext2 = openssl_decrypt($ciphertext_raw2, $cipher, $key, $options, $iv);
echo "Dec2 : " . $original_plaintext2;
echo "<br />\n";

?>