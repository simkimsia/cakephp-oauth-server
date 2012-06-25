<?php
App::uses('AuthCode', 'OAuth.Model');

class AuthCodeTest extends CakeTestCase {

    // Plugin fixtures located in /app/Plugin/Blog/Test/Fixture/
    public $fixtures = array('plugin.o_auth.auth_code');
    public $AuthCode;

    public function testAuthCodeExists() {
        // ClassRegistry makes the model use the test database connection
        $this->AuthCode = ClassRegistry::init('OAuth.AuthCode');

        // do some useful test here
        $this->assertTrue(is_object($this->AuthCode));
    }
}