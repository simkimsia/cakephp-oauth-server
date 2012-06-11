<?php

Router::connect('/oauth/:action/*', array('controller' => 'o_auth', 'plugin' => 'OAuth'));

?>
