<?php
App::uses('AccessToken', 'OAuth.Model');

class AccessTokenTest extends CakeTestCase {

    // Plugin fixtures located in /app/Plugin/Blog/Test/Fixture/
    public $fixtures = array('plugin.o_auth.access_token');
    public $AccessToken;

    public function testAccessTokenExists() {
        // ClassRegistry makes the model use the test database connection
        $this->AccessToken = ClassRegistry::init('OAuth.AccessToken');

        // do some useful test here
        $this->assertTrue(is_object($this->AccessToken));
    }
}