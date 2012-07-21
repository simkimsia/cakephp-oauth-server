<?php
/**
 * AllModelTest file
 *
 */
/**
 * AllModelTest class
 *
 * This test group will run model class tests
 *
 * @package       Storyzer.Test.Case
 */
class OAuthModelTest extends PHPUnit_Framework_TestSuite {

/**
 * suite method, defines tests for this suite.
 *
 * @return void
 */
	public static function suite() {
		$suite = new PHPUnit_Framework_TestSuite('All Model related class tests in OAuth');

		$testsPath = dirname(__FILE__);
		
		$modelTestsPath = $testsPath . DS . 'Model' . DS;
		
		$suite->addTestFile($modelTestsPath . 'AccessTokenTest.php');
		$suite->addTestFile($modelTestsPath . 'AuthCodeTest.php');		
		$suite->addTestFile($modelTestsPath . 'ClientTest.php');
		$suite->addTestFile($modelTestsPath . 'RefreshTokenTest.php');				

		return $suite;
	}
}
