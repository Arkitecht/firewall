<?php

namespace PragmaRX\Firewall\Database;

use PragmaRX\Support\Migration;

class Migrator extends Migration
{
    protected $tables = [
        'firewall',
    ];

    protected function migrateDown() {
        $this->dropAllTables();
    }

    protected function migrateUp() {
        $this->builder->create(
            'firewall',
            function ($table) {
                $table->increments('id');

                $table->string('ip_address', 39)->index();
                $table->string('group')->default('*')->index();

                $table->unique(['ip_address','group']);

                $table->boolean('whitelisted')->default(false); /// default is blacklist

                $table->timestamps();
            }
        );
    }
}
