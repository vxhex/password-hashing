<?php
require_once 'PasswordHashClass.php';

/**
 * PKCS #5 PBKDF2 Test Vectors from http://www.ietf.org/rfc/rfc6070.txt
 * Usage: phpunit PasswordHashClassTest.php
 */
class PasswordHashTest extends PHPUnit_Framework_TestCase {

    /**
     * Test vector data provider
     */
    public function data_test_pbkdf2() {
        return array(array('sha1', 'password', 'salt', 1, 20,
                           '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
                     array('sha1', 'password', 'salt', 2, 20,
                           'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'),
                     array('sha1', 'password', 'salt', 4096, 20,
                           '4b007901b765489abead49d926f721d065a429c1'),
                     array('sha1', 'password', 'salt', 16777216, 20,
                           'eefe3d61cd4da4e4e9945b3d6ba2158c2634e984'),
                     array('sha1', 'passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25,
                           '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'),
                     array('sha1', "pass\0word", "sa\0lt", 4096, 16,
                           '56fa6aa75548099dcc37d7f03425e0c3'));
    }

    /**
     * Test PasswordHash::pbkdf2() against RFC6070 test vectors
     * @dataProvider data_test_pbkdf2
     */
    public function test_pbkdf2($algorithm, $password, $salt, $count, $dklen, $expected) {
        $output = PasswordHash::pbkdf2($algorithm, $password, $salt, $count, $dklen);
        $this->assertEquals($expected, $output);
    }
}
?>
