<?php

App::uses('OAuthAppModel', 'OAuth.Model');
App::uses('String', 'Utility');
App::uses('Security', 'Utility');

/**
 * Client Model
 *
 * @property AccessToken $AccessToken
 * @property AuthCode $AuthCode
 * @property RefreshToken $RefreshToken
 */
class Client extends OAuthAppModel {
/**
 * Primary key field
 *
 * @var string
 */
	public $primaryKey = 'client_id';
/**
 * Display field
 *
 * @var string
 */
	public $displayField = 'client_id';

/**
 * Secret to distribute when using addClient
 * 
 * @var type 
 */	
	protected $addClientSecret = false;

/**
 * Validation rules
 *
 * @var array
 */
	public $validate = array(
		'client_id' => array(
			'isUnique' => array(
				'rule' => array('isUnique'),
			),
			'notempty' => array(
				'rule' => array('notempty'),
			),
		),
		'redirect_uri' => array(
			'notempty' => array(
				'rule' => array('notempty'),
			),
		),
	);

/**
 * hasMany associations
 *
 * @var array
 */
	public $hasMany = array(
		'AccessToken' => array(
			'className' => 'OAuth.AccessToken',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'AuthCode' => array(
			'className' => 'OAuth.AuthCode',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		),
		'RefreshToken' => array(
			'className' => 'OAuth.RefreshToken',
			'foreignKey' => 'client_id',
			'dependent' => false,
			'conditions' => '',
			'fields' => '',
			'order' => '',
			'limit' => '',
			'offset' => '',
			'exclusive' => '',
			'finderQuery' => '',
			'counterQuery' => ''
		)
	);

/**
 * AddClient
 * 
 * Convinience function for adding client, will create a uuid client_id and random secret
 * 
 * @param mixed $data Either an array (e.g. $controller->request->data) or string redirect_uri
 * @return booleen Success of failure
 */
	public function add($data = null) {
		$this->data['Client'] = array();

		if (is_array($data['Client']) && array_key_exists('redirect_uri', $data['Client'])) {
			$this->data['Client']['redirect_uri'] = $data['Client']['redirect_uri'];
		} elseif (is_string($data)){
			$this->data['Client']['redirect_uri'] = $data;
		} else {
			return false;
		}
		
		/**
		 * in case you have additional fields in the clients table such as name, description etc
		 * and you are using $data['Client']['name'], etc to save
		 **/
		if (is_array($data['Client'])) {
			$this->data['Client'] = array_merge($data['Client'], $this->data['Client']);
		}

		//You may wish to change this
		$this->data['Client']['client_id'] = base64_encode(uniqid() . substr(uniqid(), 11, 2));	// e.g. NGYcZDRjODcxYzFkY2Rk (seems popular format)
		//$this->data['Client']['client_id'] = uniqid();					// e.g. 4f3d4c8602346
		//$this->data['Client']['client_id'] = str_replace('.', '', uniqid('', true));		// e.g. 4f3d4c860235a529118898
		//$this->data['Client']['client_id'] = str_replace('-', '', String::uuid());		// e.g. 4f3d4c80cb204b6a8e580a006f97281a

		$this->addClientSecret = $this->newClientSecret();
		$this->data['Client']['client_secret'] = $this->addClientSecret;

		return $this->save($this->data);
	}

/**
 * Create a new, pretty (as in moderately, not beautiful - that can't be guaranteed ;-) random client secret
 *
 * @return string The client secret is plaintext
 */
	public function newClientSecret($length = 40, $options = array()) {
		// initialize variables
		$password 	= "";
		$i 			= 0;
        $possible 	= '';

        $numerals = '0123456789';
        $lowerAlphabet = 'abcdefghijklmnopqrstuvwxyz';
        $upperAlphabet = strtoupper($lowerAlphabet);

        $defaultOptions = array(
			'type'=>'alphanumeric', // possible values alphabets, numbers, upperalpha, loweralpha, alphanumeric, possible,
			'allow_repeat_characters' => false,
			'possible' => ''
		);

        $options = array_merge($defaultOptions, $options);
		$possible = '';

		switch($options['type']) {
			case 'alphabets' :
				$possible = $lowerAlphabet . $upperAlphabet;
			break;
			case 'numbers' :
				$possible = $numerals;
			break;
			case 'upperalpha' :
				$possible = $upperAlphabet;
			break;
			case 'loweralpha' :
				$possible = $lowerAlphabet;
			break;
			case 'possible' :
				if (isset($options['possible']) && !empty($options['possible']) && is_string($options['possible'])) {
					$possible = $options['possible'];
				} else {
					$possible = $numerals . $lowerAlphabet . $upperAlphabet;
				}
			break;
			default :
				$possible = $numerals . $lowerAlphabet . $upperAlphabet;
			break;
		}


		
		
		/**
		 * 3 situations
		 * situation 1 if we disallow repeat:
		 * we need to allow repeat characters once the length of random string required is more than 20% of possible keyspace
		 * e.g. 20% of alphanumeric aka 62 characters is 12.4 so if 13 char long is required, we switch to allow repeat
		 * situation 2 will then apply.
		 *
		 * situation 2 if we allow repeat:
		 * any single character must not show up more than 5% of the time round up
		 * e.g. length needed is 45, 5% of 45 is 2.25 rounded to 3.
		 * e.g. length needed is 40, 5% of 40 is 2 stay as 2.
		 *
		 * situation 3 if keyspace length greater than required length
		 * if length of keyspace is less than random string length, we allow repeat characters up to lengthOverKeySpaceRatio rounded up
		 * e.g., length needed is 200 keyspace is 62, then 200 / 62 = 3.22, we allow single characters appear up to 4 times
		 **/
		
		
		// length of random string needed divided by total possible characters to be used
		$keyspaceLength = strlen($possible);
		$lengthOverKeySpaceRatio = floatval($length) / floatval($keyspaceLength);
		$appearancesAllowed = 1; // default value means no repeats

		// for situation 1
		if ($options['allow_repeat_characters'] == false && $lengthOverKeySpaceRatio > 0.2) {
			$options['allow_repeat_characters'] = true;
		}
		
		// for situation 2
		if ($options['allow_repeat_characters']) {
			$appearancesAllowed = ceil(0.05 * $length);
		}

		// for situation 3
		if ($lengthOverKeySpaceRatio > 1.0) {
			$options['allow_repeat_characters'] = true;
			$appearancesAllowed = ceil($lengthOverKeySpaceRatio);
		}


		// add random characters to $password until $length is reached
		while ($i < $length) {
			// pick a random character from the possible ones
			$char = substr($possible, mt_rand(0, strlen($possible)-1), 1);

			// we don't want this character show up more than necessary 
			// and we don't want two same characters show up back to back
			$appearances = substr_count($password, $char);
			$lastCharacter = substr($password, -1);
			if ($appearances < $appearancesAllowed && $char != $lastCharacter) {
				$password .= $char;
				$i++;
			}
		}
		return $password;
	}

	/**
	 *
	 * Set the client_secret back into the $this->data after a successful save
	 *
	 * @param $created Boolean that is true for new Client record
	 * @return Boolean True if successful
	 */
	public function afterSave($created) {
		if ($this->addClientSecret) {
			$this->data['Client']['client_secret'] = $this->addClientSecret;
		}
		return true;
	}

}