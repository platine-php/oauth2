<?php

declare(strict_types=1);

namespace Platine\Framework\Migration;

use Platine\Database\Schema\CreateTable;
use Platine\Framework\Migration\AbstractMigration;

class AddOauth2ScopesTable20230802144938 extends AbstractMigration
{
    public function up(): void
    {
      //Action when migrate up
        $this->create('oauth_scopes', function (CreateTable $table) {
            $table->integer('id')
                  ->autoincrement()
                 ->primary();

            $table->string('name')
                 ->notNull();

            $table->string('description');

            $table->boolean('is_default')
                 ->description('Whether is the default scope')
                 ->notNull();

            $table->timestamps();

            $table->engine('INNODB');
        });
    }

    public function down(): void
    {
      //Action when migrate down
        $this->drop('oauth_scopes');
    }
}
