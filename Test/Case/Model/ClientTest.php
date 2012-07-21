<?php
App::uses('Client', 'OAuth.Model');

class ClientTest extends CakeTestCase {

    // Plugin fixtures located in /app/Plugin/Blog/Test/Fixture/
    public $fixtures = array('plugin.o_auth.client');
    public $Client;

    public function testClientExists() {
        // ClassRegistry makes the model use the test database connection
        $this->Client = ClassRegistry::init('OAuth.Client');

        // do some useful test here
        $this->assertTrue(is_object($this->Client));
    }
}