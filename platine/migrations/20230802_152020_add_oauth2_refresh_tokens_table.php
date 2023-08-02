<?php

declare(strict_types=1);

namespace Platine\Framework\Migration;

use Platine\Database\Schema\CreateTable;
use Platine\Framework\Migration\AbstractMigration;

class AddOauth2RefreshTokensTable20230802152020 extends AbstractMigration
{
    public function up(): void
    {
      //Action when migrate up
        $this->create('oauth_refresh_tokens', function (CreateTable $table) {
            $table->string('refresh_token', 100)
                  ->notNull()
                  ->description('The refresh token')
                 ->primary();

            $table->string('scope', 2000)
                   ->description('The refresh token scopes separated with space if many');

            $table->datetime('expires')
                   ->notNull()
                   ->description('The refresh token expire time');

            $table->integer('user_id')
                ->description('The owner of refresh token');

            $table->string('client_id')
                ->description('The refresh token client')
                ->notNull();

            $table->timestamps();

            $table->foreign('client_id')
                ->references('oauth_clients', 'id')
                ->onDelete('NO ACTION');

            $table->engine('INNODB');
        });
    }

    public function down(): void
    {
      //Action when migrate down
        $this->drop('oauth_refresh_tokens');
    }
}
