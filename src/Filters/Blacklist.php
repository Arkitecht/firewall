<?php

namespace PragmaRX\Firewall\Filters;

class Blacklist
{
    public function filter($group = '*') {
        $firewall = app()->make('firewall');

        if ($firewall->isBlacklisted($ipAddress = $firewall->getIp(), $group)) {
            $firewall->log('[blocked] IP blacklisted for %s: ' . $ipAddress, $group);

            return $firewall->blockAccess();
        }
    }
}
