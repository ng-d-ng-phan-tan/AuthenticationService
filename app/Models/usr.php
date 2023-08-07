<?php

namespace App\Models;

use Illuminate\Contracts\Auth\Authenticatable as AuthAuthenticatable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Tymon\JWTAuth\Contracts\JWTSubject;

class usr extends Model implements AuthAuthenticatable, JWTSubject
{
    // Khai báo tên bảng tương ứng trong database
    protected $table = 'usrs';
    protected $primaryKey = 'user_id';
    protected $keyType = 'string';

    // Khai báo các trường (columns) có thể được gán giá trị và truy xuất thông qua thuộc tính của model
    protected $fillable = [
        'user_id',
        'name',
        'email',
        'password',
        'role',
        'reset_password_str',
        'validate_email_str',
        'is_validate'
    ];

    public function getAuthIdentifierName()
    {
        return 'user_id';
    }

    public function getAuthIdentifier()
    {
        return $this->getKey();
    }

    public function getAuthPassword()
    {
        return $this->password;
    }
    

    public function getRememberToken()
    {
        
    }

    public function setRememberToken($value)
    {
        
    }

    public function getRememberTokenName()
    {
        
    }

    // Triển khai phương thức của JWTSubject interface
    public function getJWTIdentifier()
    {
        return $this->getKey(); // Giá trị ID người dùng
    }

    public function getJWTCustomClaims()
    {
        return [
            'user_id' => $this->user_id,
            'role' => $this->role, // Vai trò của người dùng
            'name' => $this->name,
            'email' => $this->email
        ];
    }
}
