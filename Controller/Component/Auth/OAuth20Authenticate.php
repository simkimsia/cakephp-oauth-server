<?php
/**
 * PHP 5
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @author KimSia, Sim <kimcity@gmail.com>
 * @see https://github.com/simkimsia/cakephp-oauth-server
**/

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('OAuthComponent', 'OAuth.Controller/Component');
App::uses('AccessToken', 'OAuth.Model');
App::uses('AuthCode', 'OAuth.Model');
App::uses('Client', 'OAuth.Model');
App::uses('RefreshToken', 'OAuth.Model');

App::import('Vendor', 'oauth2-php/lib/OAuth2');
App::import('Vendor', 'oauth2-php/lib/IOAuth2Storage');
App::import('Vendor', 'oauth2-php/lib/IOAuth2RefreshTokens');
App::import('Vendor', 'oauth2-php/lib/IOAuth2GrantUser');
App::import('Vendor', 'oauth2-php/lib/IOAuth2GrantCode');

/**
 * OAuth2.0 Authentication adapter for AuthComponent.
 *
 * OAuth stands for “Open Authorization.” 
 * OAuth 2.0 is an open standard authorization protocol that enables secure data sharing
 * without requiring users to give out their credentials such as login information or passwords. 
 * Through OAuth, users can grant restricted access of their resources 
 * to a third-party or to safely access resources of a third-party themselves.
 *
 * Provides OAuth2.0
 * authentication support for AuthComponent. OAuth2.0 draft 20 is supported. 
 * 
 * OAuth2.0 authentication is stateless authentication
 *
 * Clients using OAuth2.0 Authentication can use two types: 2 legged and 3 legged authentication
 * 
 * ### Using OAuth2.0 auth
 *
 * In your controller's components array, add auth + the required settings.
 * {{{
 *	public $components = array(
 *		'Auth' => array(
 *			'authenticate' => array('OAuth20')
 *		)
 *	);
 * }}}
 *
 *
 * @package       Cake.Controller.Component.Auth
 * @since 2.0
 */
class OAuth20Authenticate extends BaseAuthenticate {

/**
 * Settings for this object.
 *
 * - `fields` The fields to use to identify a user by.
 * - `userModel` The model name of the User, defaults to User.
 * - `scope` Additional conditions to use when looking up and authenticating users,
 *    i.e. `array('User.is_active' => 1).`
 * - `endpoints` List of actions responsible for the 4 basic ENDPOINTS for granting tokens, authorizing, and logging in/out
 *
 * @var array
 */
	public $settings = array(
		'fields' => array(
			'username' => 'username',
			'password' => 'password'
		),
		'userModel' => 'User',
		'scope' => array(),
		'endpoints' => array(
			'token' => array(
				'controller' => 'o_auth',
				'action' => 'token',
			),
			'authorize' => array(
				'controller' => 'o_auth',
				'action' => 'authorize',
			),
			'login' => array(
				'controller' => 'o_auth',
				'action' => 'login',
			),
			'logout' => array(
				'controller' => 'o_auth',
				'action' => 'logout',
			),
		)
	);
	
	
/**
 * AccessToken object.
 *
 * @var object
 */
	public $AccessToken;
/**
 * AuthCode object.
 *
 * @var object
 */
	public $AuthCode;	
			
/**
 * OAuthComponent object.
 *
 * @var object
 */
	public $Client;

/**
 * OAuth2 object.
 *
 * @var object
 */
	public $OAuth;
	
/**
 * OAuthComponent object.
 *
 * @var object
 */
	public $RefreshToken;									
	
	
/**
 * Constructor, completes configuration for digest authentication.
 *
 * @param ComponentCollection $collection The Component collection used on this request.
 * @param array $settings An array of settings.
 */
	public function __construct(ComponentCollection $collection, $settings) {
		parent::__construct($collection, $settings);
		$this->AccessToken = ClassRegistry::init(array('class' => 'OAuth.AccessToken', 'alias' => 'AccessToken'));
		$this->AuthCode = ClassRegistry::init(array('class' => 'OAuth.AuthCode', 'alias' => 'AuthCode'));
		$this->Client = ClassRegistry::init(array('class' => 'OAuth.Client', 'alias' => 'Client'));
		$this->RefreshToken = ClassRegistry::init(array('class' => 'OAuth.RefreshToken', 'alias' => 'RefreshToken'));
		$this->OAuth = new OAuthComponent($collection, $settings);
	}

/**
 * Authenticate a user using Digest HTTP auth.  Will use the configured User model and attempt a
 * login using Digest HTTP auth.
 *
 * @param CakeRequest $request The request to authenticate with.
 * @param CakeResponse $response The response to add headers to.
 * @return mixed Either false on failure, or an array of user data on success.
 */
	public function authenticate(CakeRequest $request, CakeResponse $response) {
		$user = $this->getUser($request);

		if (empty($user)) {
			// need to return some other error about wrong user
			return false;
		}
		return $user;
	}
	
/**
 *
 * add detectors
 *
 */
	public function addDetectors(&$request) {
		$request->addDetector('oauth_token', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsToken')));
		$request->addDetector('oauth_authorize', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsAuthorize')));
		$request->addDetector('oauth_login', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsLogin')));
		$request->addDetector('oauth_logout', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsLogout')));						
		$request->addDetector('oauth_token_grant_password', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsTokenGrantPassword')));						
		$request->addDetector('oauth_token_grant_authorization_code', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsTokenGrantAuthorize')));								
		$request->addDetector('oauth_token_grant_refresh_token', array('callback' => array('OAuth.OAuth20Authenticate', 'checkRequestIsTokenGrantRefresh')));
	}

/**
 * Get a user based on information in the request.  Used by cookie-less auth for stateless clients.
 *
 * specifically for OAuth2.0 
 * 4 types of situation
 * access_token are the params for every other requests
 * client_id, client_secret, username, password are the params for action "token" and grant_type "password"
 * client_id, client_secret, refresh_token are the params for action "token" and grant_type "refresh_token"
 * client_id, client_secret, code are the params for action "token" and grant_type "authorization_code"
 *
 * @param CakeRequest $request Request object.
 * @return mixed Either false or an array of user information
 */
	public function getUser($request) {
		$user = false;
		$this->addDetectors($request);
		
		if ($request->is('oauth_token_grant_password')) {
			$user = $this->_findUserForResourceOwnerCredentialsGrant($request);
		}
		
		else if ($request->is('oauth_token_grant_authorization_code')) {
			$user = $this->_findUserForAuthorizationGrant($request);
		}
		
		else if ($request->is('oauth_token_grant_refresh_token')) {
			$user = $this->_findUserForRefreshGrant($request);
		}
		
		else {
			$user = $this->_findUserByAccessToken($request);
		}		
		
		return $user;
		
	}

/**
 * Find a user record using the standard options.
 *
 * @param string $username The username/identifier.
 * @param string $password Unused password, digest doesn't require passwords.
 * @return Mixed Either false on failure, or an array of user data.
 */
	protected function _findUserForResourceOwnerCredentialsGrant(CakeRequest $request) {
		
		$username = '';
		$password = '';
		
		if ($request->is('get')) {
			if (isset($request->params['username'])) {
				$username = $request->params['username'];
			}
			if (isset($request->params['password'])) {
				$password = $request->params['password'];
			}
		} else if($request->is('post')) {
			if (isset($request->data['username'])) {
				$username = $request->data['username'];
			}
			if (isset($request->data['password'])) {
				$password = $request->data['password'];
			}
		}
		
		return $this->_findUser($username, $password);
	}

/**
 * Find a user record using the standard options.
 *
 * @param string $username The username/identifier.
 * @param string $password Unused password, digest doesn't require passwords.
 * @return Mixed Either false on failure, or an array of user data.
 */
	protected function _findUserForAuthorizationGrant(CakeRequest $request) {

		$authCode = '';

		if ($request->is('get')) {
			if (isset($request->params['code'])) {
				$code = $request->params['code'];
			}
		} else if($request->is('post')) {
			if (isset($request->data['code'])) {
				$code = $request->data['code'];
			}
		}

		$model = 'AuthCode';
		$plugin = 'OAuth';

		$conditions = array(
			$model . '.code' => $code,
		);
		
		$result = $this->AuthCode->find('first', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'fields' => 'AuthCode.user_id'
		));
		
		if (empty($result) || empty($result[$model])) {
			return false;
		}
		
		if (isset($result['AuthCode']['user_id'])) {
			$user_id = $result['AuthCode']['user_id'];
			return $this->_findUserById($user_id);
		}

		return false;
	}

/**
 * Find a user record using the standard options.
 *
 * @param string $username The username/identifier.
 * @param string $password Unused password, digest doesn't require passwords.
 * @return Mixed Either false on failure, or an array of user data.
 */
	protected function _findUserForRefreshGrant(CakeRequest $request) {

		$refreshToken = '';

		if ($request->is('get')) {
			if (isset($request->params['refresh_token'])) {
				$refreshToken = $request->params['refresh_token'];
			}
		} else if($request->is('post')) {
			if (isset($request->data['refresh_token'])) {
				$refreshToken = $request->data['refresh_token'];
			}
		}

		$model = 'RefreshToken';
		$plugin = 'OAuth';

		$conditions = array(
			$model . '.refresh_token' => $refreshToken,
		);

		$result = $this->RefreshToken->find('first', array(
			'conditions' => $conditions,
			'recursive' => -1,
			'fields' => 'RefreshToken.user_id'
		));

		if (empty($result) || empty($result[$model])) {
			return false;
		}

		if (isset($result['RefreshToken']['user_id'])) {
			$user_id = $result['RefreshToken']['user_id'];
			return $this->_findUserById($user_id);
		}

		return false;
	}

/**
 * Find a user based on access token. 
 * Need to use the Vendor OAuth2 to get the access_token 
 * and verify
 *
 * @param string $username The username/identifier.
 * @param string $password Unused password, digest doesn't require passwords.
 * @return Mixed Either false on failure, or an array of user data.
 */
	protected function _findUserByAccessToken(CakeRequest $request) {

		try {
			$token = $this->OAuth->getBearerToken();
			$this->OAuth->verifyAccessToken($token);
		} catch (OAuth2AuthenticateException $e) {
			return false;
		}
		
		// bind the User model to the AccessToken temporarily
		$this->AccessToken->bindModel(array(
		    'belongsTo' => array(
			'User' => array(
			    'className' => $this->settings['userModel'],
			    'foreignKey' => 'user_id'
			
			    )
			)
		    ));
		
		// find AccessToken
		$data = $this->AccessToken->find('first', array(
			'conditions' => array('oauth_token' => $token),
			'recursive' => 1
		));

		if (!$data || empty($data['User'])) {
			return false;
		}

		unset($data['User']['password']);
		return $data['User'];
	}

	
	protected function _findUserById($id) {
		$userModel = $this->settings['userModel'];
		list($plugin, $model) = pluginSplit($userModel);

		$conditions = array(
			$model . '.id' => $id
		);
		if (!empty($this->settings['scope'])) {
			$conditions = array_merge($conditions, $this->settings['scope']);
		}
		$result = ClassRegistry::init($userModel)->find('first', array(
			'conditions' => $conditions,
			'recursive' => $this->settings['recursive']
		));
		if (empty($result) || empty($result[$model])) {
			return false;
		}
		unset($result[$model][$fields['password']]);
		return $result[$model];
	}

/**
 *
 * Check if request is endpoint
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	protected function checkRequestIsEndpoint($endpoint, CakeRequest $request) {
		
		$action = strtolower($request->params['action']);
		$controller = strtolower($request->params['controller']);
		
		$actionMatched = ($action === $this->settings['endpoints'][$endpoint]['action']);
		$controllerMatched = ($controller === $this->settings['endpoints'][$endpoint]['controller']);	
		
		return $actionMatched && $controllerMatched;
	}
	
/**
 *
 * Check if request is endpoint
 * 
 * @param string $expectedGrantType 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	protected function checkRequestGrantType($expectedGrantType, CakeRequest $request) {

		$actualGrantType = '';
		
		if (isset($request->params['grant_type'])) {
			$actualGrantType = $request->params['grant_type'];
		} else if (isset($request->data['grant_type'])) {
			$actualGrantType = $request->data['grant_type'];
		}
		
		return (strtolower($actualGrantType) === strtolower($expectedGrantType));
		
	}	

/**
 *
 * Check if request is token endpoint
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	public function checkRequestIsToken(CakeRequest $request) {

		return $this->checkRequestIsEndpoint('token', $request);
	}
	
/**
 *
 * Check if request is token endpoint
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	public function checkRequestIsAuthorize(CakeRequest $request) {

		return $this->checkRequestIsEndpoint('authorize', $request);
	}
	
/**
 *
 * Check if request is token endpoint
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	public function checkRequestIsLogin(CakeRequest $request) {

		return $this->checkRequestIsEndpoint('login', $request);
	}
	
/**
 *
 * Check if request is token endpoint
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint
 */
	public function checkRequestIsLogout(CakeRequest $request) {

		return $this->checkRequestIsEndpoint('logout', $request);
	}	
	
/**
 *
 * Check if request is token endpoint and grant_type is password
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint and grant_type is password
 */
	public function checkRequestIsTokenGrantPassword(CakeRequest $request) {

		$isToken = $this->checkRequestIsEndpoint('token', $request);
		$isPasswordGrant = $this->checkRequestGrantType('password', $request);
		
		return ($isToken && $isPasswordGrant);
	}	

/**
 *
 * Check if request is token endpoint and grant_type is authorize
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint and grant_type is authorization_code
 */
	public function checkRequestIsTokenGrantAuthorize(CakeRequest $request) {

		$isToken = $this->checkRequestIsEndpoint('token', $request);
		$isAuthorizeGrant = $this->checkRequestGrantType('authorization_code', $request);

		return ($isToken && $isAuthorizeGrant);
	}

/**
 *
 * Check if request is token endpoint and grant_type is refresh_token
 * 
 * @param CakeRequest $request Request to check
 * @return Boolean Return true if request is token endpoint and grant_type is refresh_token
 */
	public function checkRequestIsTokenGrantRefresh(CakeRequest $request) {

		$isToken = $this->checkRequestIsEndpoint('token', $request);
		$isRefreshGrant = $this->checkRequestGrantType('refresh_token', $request);

		return ($isToken && $isRefreshGrant);
	}

}
