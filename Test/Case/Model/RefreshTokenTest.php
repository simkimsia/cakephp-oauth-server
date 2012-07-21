<?php
App::uses('RefreshToken', 'OAuth.Model');

class RefreshTokenTest extends CakeTestCase {

    // Plugin fixtures located in /app/Plugin/Blog/Test/Fixture/
    public $fixtures = array('plugin.o_auth.refresh_token');
    public $RefreshToken;

    public function testRefreshTokenExists() {
        // ClassRegistry makes the model use the test database connection
        $this->RefreshToken = ClassRegistry::init('OAuth.RefreshToken');

        // do some useful test here
        $this->assertTrue(is_object($this->RefreshToken));
    }
}