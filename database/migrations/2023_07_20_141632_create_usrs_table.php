<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('usrs', function (Blueprint $table) {
            $table->uuid('user_id')->primary();
            $table->text('password');
            $table->text('email');
            $table->text('name');
            $table->text('validate_email_str')->nullable();
            $table->text('reset_password_str')->nullable();
            $table->boolean('is_validate')->nullable();
            $table->text('refresh_token')->nullable();
            $table->timestamp('refresh_token_expired_time')->nullable();
            $table->text('password_salt')->nullable();
            $table->text('role');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('usrs');
    }
};
