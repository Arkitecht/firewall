<?php

namespace PragmaRX\Firewall\Filters;

use PragmaRX\Firewall\Support\Redirectable;

class Whitelist
{
    use Redirectable;

    public function filter($group = '*') {
        $firewall = app()->make('firewall');

        if (!$firewall->isWhitelisted(null,$group)) {
            if ($to = app()->make('firewall.config')->get('redirect_non_whitelisted_to')) {
                $action = 'redirected';

                $response = $this->redirectTo($to);
            }
            else {
                $action = 'blocked';
                $response = $firewall->blockAccess();
            }

            $message = sprintf('[%s] IP not whitelisted for %s: %s', $action, $group, $firewall->getIp());

            $firewall->log($message);

            return $response;
        }
    }
}
