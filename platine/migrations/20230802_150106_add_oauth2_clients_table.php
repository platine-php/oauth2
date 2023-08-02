<?php

declare(strict_types=1);

namespace Platine\Framework\Migration;

use Platine\Database\Schema\CreateTable;
use Platine\Framework\Migration\AbstractMigration;

class AddOauth2ClientsTable20230802150106 extends AbstractMigration
{
    public function up(): void
    {
      //Action when migrate up
        $this->create('oauth_clients', function (CreateTable $table) {
            $table->string('id', 100)
                  ->notNull()
                  ->description('The client id')
                 ->primary();

            $table->string('name', 80)
                  ->description('The client or app name')
                 ->notNull();

            $table->string('secret', 80)
                   ->description('The client secret must be null for public client');

            $table->string('redirect_uri', 2000)
                   ->notNull()
                   ->description('The client redirect uri separated with space if many');

            $table->string('scope', 2000)
                   ->description('The client scopes separated with space if many');

            $table->string('grant_types', 100)
                   ->description('The client supported grant types separated with space if many');

            $table->integer('user_id')
                ->description('The owner or client developer');

            $table->timestamps();

            $table->engine('INNODB');
        });
    }

    public function down(): void
    {
      //Action when migrate down
        $this->drop('oauth_clients');
    }
}
