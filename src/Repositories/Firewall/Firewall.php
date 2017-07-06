<?php

namespace PragmaRX\Firewall\Repositories\Firewall;

use ReflectionClass;
use PragmaRX\Support\Config;
use PragmaRX\Support\IpAddress;
use PragmaRX\Support\CacheManager;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Database\Eloquent\Collection;

class Firewall implements FirewallInterface
{
	const CACHE_BASE_NAME = 'firewall.';

	const IP_ADDRESS_LIST_CACHE_NAME = 'firewall.ip_address_list';

	/**
	 * @var object
	 */
	private $model;

	/**
	 * @var Cache|CacheManager
	 */
	private $cache;

	/**
	 * @var Config
	 */
	private $config;

	/**
	 * @var Filesystem
	 */
	private $fileSystem;

	/**
	 * Create an instance of Message
	 *
	 * @param object $model
	 * @param Cache|CacheManager $cache
	 * @param Config $config
	 * @param Filesystem $fileSystem
	 */
	public function __construct($model, CacheManager $cache, Config $config, Filesystem $fileSystem)
	{
		$this->model = $model;

		$this->cache = $cache;

		$this->config = $config;

		$this->fileSystem = $fileSystem;
	}

    /**
     * @param $model
     */
    private function addToSession($model)
    {
        $current = $this->getSessionIps();

        $current = $current->push($model)->unique('ip_address');

        $this->getSession()->put('pragmarx.firewall', $current);

        return $model;
    }

    /**
     * @param $whitelist
     * @param $ip
     * @return object
     */
    private function createModel($whitelist, $ip, $group = '*')
    {
        $class = new ReflectionClass(get_class($this->model));

        $model = $class->newInstanceArgs([
                                             [
                                                 'ip_address'  => $ip,
                                                 'whitelisted' => $whitelist,
                                                 'group'       => $group
                                             ]
                                         ]);

        return $model;
    }

    /**
     * Find a Ip in the data source
	 *
	 * @param  string $ip
	 * @return object|null
	 */
	public function find($ip, $group = '*')
	{
		if ($this->cacheHas($ip,$group))
		{
			return $this->cacheGet($ip,$group);
		}

		if ($model = $this->findIp($ip,$group))
		{
			$this->cacheRemember($model,$group);
		}

		return $model;
	}

	/**
	 * Find a Ip in the data source
	 *
	 * @param  string $ip
	 * @return object|null
	 */
	public function addToList($whitelist, $ip, $group = '*')
	{
		$this->model->unguard();

		$model = $this->model->create(array(
										'ip_address' => $ip,
										'whitelisted' => $whitelist,
                                        'group' => $group
									));

		$this->cacheRemember($model, $group);

		return $model;
	}

    /**
     * Find a Ip in the data source
     *
     * @param  string $ip
     * @return object|null
     */
    public function addToSessionList($whitelist, $ip, $group = '*')
    {
        $this->removeFromSession($model = $this->createModel($whitelist, $ip, $group = '*'));

        return $this->addToSession($model, $group);
    }

	public function delete($ipAddress, $group = '*')
	{
		if ($ip = $this->find($ipAddress, $group))
		{
			$ip->delete();

			$this->cacheForget($ipAddress, $group);

			return true;
		}

		return false;
	}

	public function cacheKey($ip, $group = '*')
	{
		return static::CACHE_BASE_NAME."ip_address.$group.$ip";
	}

	public function cacheHas($ip, $group = '*')
	{
		if ($this->config->get('cache_expire_time'))
		{
			return $this->cache->has($this->cacheKey($ip));
		}

		return false;
	}

	public function cacheGet($ip, $group = '*')
	{
		return $this->cache->get($this->cacheKey($ip, $group));
	}

	public function cacheForget($ip, $group = '*')
	{
		$this->cache->forget($this->cacheKey($ip, $group));
	}

	public function cacheRemember($model, $group = '*')
	{
		if ($timeout = $this->config->get('cache_expire_time'))
		{
			$this->cache->put($this->cacheKey($model->ip_address, $group), $model, $timeout);
		}
	}

	public function all($group = '*')
	{
		$cacheTime = $this->config->get('ip_list_cache_expire_time');

		if ($cacheTime && $this->cache->has(static::IP_ADDRESS_LIST_CACHE_NAME))
		{
			return $this->cache->get(static::IP_ADDRESS_LIST_CACHE_NAME);
		}

		$list = $this->mergeLists(
			$this->getAllFromDatabase($group),
			$this->toModels($this->getNonDatabaseIps($group)),
            $this->getSessionIps($group)
		);

		if ($cacheTime)
		{
			$this->cache->put(
				static::IP_ADDRESS_LIST_CACHE_NAME,
				$list,
				$this->config->get('ip_list_cache_expire_time')
			);
		}

		return $list;
	}

	public function clear()
	{
		/**
		 * Deletes one by one to also remove them from cache
		 */
        $deleted = 0;

        foreach ($this->all() as $ip)
        {
            if ($this->delete($ip['ip_address']))
            {
                $deleted++;
            }
        }

        return $deleted;
	}

	private function findIp($ip, $group = '*')
	{
		if ($model = $this->nonDatabaseFind($ip, $group))
		{
			return $model;
		}

		if ($this->config->get('use_database'))
		{
			return $this->model->where('ip_address', $ip)
                ->where(function($where) use ( $group ) {
                    $where->whereNull('group')
                        ->orWhere('group', $group)
                        ->orWhere('group', '*');
                })
                ->first();
		}

		return null;
	}

    /**
     * @return \Illuminate\Foundation\Application|mixed
     */
    private function getSession()
    {
        return app($this->config->get('session_binding'));
    }

    private function getSessionIps()
    {
        return collect($this->getSession()->get('pragmarx.firewall', []));
    }

    private function nonDatabaseFind($ip, $group = '*')
	{
		$ips = $this->getNonDatabaseIps();

		if ($ip = $this->ipArraySearch($ip, $ips, $group))
		{
			return $this->makeModel($ip, $group);
		}

        $ips = $this->getSessionIps()->toArray();

        if ($ip = $this->ipArraySearch($ip, $ips, $group))
        {
            return $this->makeModel($ip, $group);
        }

		return null;
	}

	private function getNonDatabaseIps()
	{
		return array_merge_recursive(
			array_map(function($ip) { $ip['whitelisted'] = true; return $ip; }, $this->formatIpArray($this->config->get('whitelist'))),

			array_map(function($ip) { $ip['whitelisted'] = false; return $ip; }, $this->formatIpArray($this->config->get('blacklist')))
		);
	}

    private function removeFromSession($ip)
    {
        $current = $this->getSessionIps();

        $current = $current->filter(function ($model) use ($ip) {
            return $model->ip_address !== $ip->ip_address;
        });

        $this->getSession()->put('pragmarx.firewall', $current);
    }

    /**
     * Find a Ip in the data source
     *
     * @param  string $ip
     * @return object|null
     */
    public function removeFromSessionList($ip)
    {
        $this->removeFromSession($this->createModel(false, $ip));
    }

    private function toModels($ipList)
	{
		$ips = array();

		foreach ($ipList as $ip)
		{
			$ips[] = $this->makeModel($ip);
		}

		return $ips;
	}

	/**
	 * @param $ip
	 * @return mixed
	 */
	private function makeModel($ip)
	{
		return $this->model->newInstance($ip);
	}

	private function readFile($file)
	{
		if ($this->fileSystem->exists($file))
		{
			$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

			return $this->makeArrayOfIps($lines);
		}

		return array();
	}

	private function toCollection($array)
	{
		return new Collection($array);
	}

	private function formatIpArray($list)
	{
		return array_map(function($ip)
		{
			return array('ip_address' => $ip);
		}, $this->makeArrayOfIps($list));
	}

	private function makeArrayOfIps($list)
	{
		$list = $list ?: array();

		$ips = array();

		foreach($list as $item)
		{
			$ips = array_merge($ips, $this->getIpsFromAnything($item));
		}

		return $ips;
	}

	private function getIpsFromAnything($item)
	{
		if (starts_with($item, 'country:'))
		{
			return array($item);
		}

		if (IpAddress::ipV4Valid($item))
		{
			return array($item);
		}

		return $this->readFile($item);
	}

	private function ipArraySearch($ip, $ips)
	{
		foreach($ips as $key => $value)
		{
			if (
				(isset($value['ip_address']) && $value['ip_address'] == $ip) ||
				(strval($key) == $ip) ||
				($value == $ip)
			)
			{
				return $value;
			}
		}

		return false;
	}

	/**
	 * @return array
	 */
	private function getAllFromDatabase($group = '*')
	{
		if ($this->config->get('use_database'))
		{
		    if ( !$group ) {
                $database_ips = $this->model->all();
            } else {
                $database_ips = $this->model->where('group',$group)->get();
            }
			return $database_ips;
		}
		else
		{
			$database_ips = $this->toCollection(array());
			return $database_ips;
		}
	}

	private function mergeLists($database_ips, $config_ips, $session_ips = [])
	{
	    return collect($database_ips)
                ->merge(collect($config_ips))
                ->merge(collect($session_ips));
	}
}
