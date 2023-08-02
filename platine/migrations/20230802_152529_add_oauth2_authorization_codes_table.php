<?php

declare(strict_types=1);

namespace Platine\Framework\Migration;

use Platine\Database\Schema\CreateTable;
use Platine\Framework\Migration\AbstractMigration;

class AddOauth2AuthorizationCodesTable20230802152529 extends AbstractMigration
{
    public function up(): void
    {
      //Action when migrate up
        $this->create('oauth_authorization_codes', function (CreateTable $table) {
            $table->string('authorization_code', 100)
                  ->notNull()
                  ->description('The authorization code')
                 ->primary();

            $table->string('redirect_uri', 2000)
                   ->description('The client redirect uri');

            $table->string('scope', 2000)
                   ->description('The authorization code scopes separated with space if many');

            $table->datetime('expires')
                   ->notNull()
                   ->description('The authorization code expire time');

            $table->integer('user_id')
                ->description('The owner of authorization code');

            $table->string('client_id')
                ->description('The authorization code client')
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
        $this->drop('oauth_authorization_codes');
    }
}
