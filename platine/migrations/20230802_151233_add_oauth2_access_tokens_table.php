<?php

declare(strict_types=1);

namespace Platine\Framework\Migration;

use Platine\Database\Schema\CreateTable;
use Platine\Framework\Migration\AbstractMigration;

class AddOauth2AccessTokensTable20230802151233 extends AbstractMigration
{
    public function up(): void
    {
      //Action when migrate up
        $this->create('oauth_access_tokens', function (CreateTable $table) {
            $table->string('access_token', 100)
                  ->notNull()
                  ->description('The access token')
                 ->primary();

            $table->string('scope', 2000)
                   ->description('The access token scopes separated with space if many');

            $table->datetime('expires')
                   ->notNull()
                   ->description('The access token expire time');

            $table->integer('user_id')
                ->description('The owner of access token');

            $table->string('client_id')
                ->description('The access token client')
                ->notNull();

            $table->timestamps();

            $table->foreign('client_id')
                ->references('oauth_clients', 'id')
                ->onDelete('NO ACTION')
                ->onUpdate('CASCADE');

            $table->engine('INNODB');
        });
    }

    public function down(): void
    {
      //Action when migrate down
        $this->drop('oauth_access_tokens');
    }
}
