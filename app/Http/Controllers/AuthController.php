<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\usr;
use Illuminate\Support\Facades\Hash;
use Ramsey\Uuid\Uuid;
use App\Models\ResponseMsg;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Str;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:usrs',
            'password' => 'required|string|min:8',
            'role' => 'required|string',
        ]);

        if ($validator->fails()) {
            $response = new ResponseMsg(400, $validator->errors(), null);
            return response()->json($response);
        }

        $user = new usr([
            'user_id' => Uuid::uuid4()->toString(),
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => $request->role,
        ]);

        if($user->save()){
            $response = new ResponseMsg(200, 'Register success', null);
            return response()->json($response);
        }
        else{
            $response = new ResponseMsg(400, 'Register failed', null);
            return response()->json($response);
        }

            // if ($validator->fails()) {
            //     $errors = $validator->errors();

            //     if ($errors->has('name')) {
            //         $nameError = $errors->first('name');
            //         return response()->json(['error' => $nameError], 400);
            //     }

            //     if ($errors->has('email')) {
            //         $emailError = $errors->first('email');
            //         return response()->json(['error' => $emailError], 400);
            //     }

            //     if ($errors->has('password')) {
            //         $passwordError = $errors->first('password');
            //         return response()->json(['error' => $passwordError], 400);
            //     }

            //     if ($errors->has('role')) {
            //         $roleError = $errors->first('role');
            //     }
            // }
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
    
        $user = usr::where('email', $request->email)->first();
    
        if (!$user) {
            $response = new ResponseMsg(400, 'Login failed, account not exist', null);
            return response()->json($response);
        }
    
        if (Hash::check($request->password, $user->password)) {
            try {
                $token = JWTAuth::attempt($credentials);
                if (!$token) {
                    $response = new ResponseMsg(400, 'Login failed, account not exist', null);
                    return response()->json($response);
                }

                $refreshToken = Str::random(32);
                $expiredRefreshTokenTime = now()->addDays(2);
                $user->refresh_token_expired_time = $expiredRefreshTokenTime;
                $user->refresh_token = $refreshToken;
                $user->save();

                $response = new ResponseMsg(200, 'Login success', ['token' => $token, 'refreshToken' => $refreshToken]);
                return response()->json($response);
            } catch (JWTException $e) {
                $response = new ResponseMsg(400, 'Login failed, can not create user accesstoken, please try again latter', null);
                return response()->json($response);
            }
        } else {
            $response = new ResponseMsg(400, 'Login failed, account not exist', null);
            return response()->json($response);
        }
    }

    public function changePassword(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'currentPassword' => 'required|string',
            'newPassword' => 'required|string|min:8',
        ]);

        $user = usr::where('email', $request->email)->first();

        if ($user) {
            if (Hash::check($request->currentPassword, $user->password)) {
                $user->update([
                    'password' => Hash::make($request->newPassword),
                ]);
                $response = new ResponseMsg(200, 'Password changed successfully', null);
                return response()->json($response);
            }
        }

        $response = new ResponseMsg(400, 'Password changed failed, account not exist', null);
        return response()->json($response);
    }

    public function getTokenPayload(Request $request){
        $accessToken = $request->header('Authorization');
        try{
            // $payload = JWTAuth::setToken($accessToken)->getPayload();
            // $expirationTime = $payload->getClaim('exp');
                        
            //https://stackoverflow.com/questions/52108465/how-to-parse-the-jwt-token-from-controller-jwtmanager-decodejwt-using-pure
            // $tokenParts = explode(".", $accessToken);  
            // $tokenHeader = base64_decode($tokenParts[0]);
            // $tokenPayload = base64_decode($tokenParts[1]);
            // $jwtHeader = json_decode($tokenHeader);
            // $jwtPayload = json_decode($tokenPayload);

            $user = JWTAuth::setToken($accessToken)->getPayload()->toArray();

            // // Lấy thời gian hết hạn của token
            $expirationTime = $user['exp'];
            $user['exp'] = date('Y-m-d H:i:s', $expirationTime);

            //$user = JWTAuth::setToken($accessToken)->authenticate();
            $response = new ResponseMsg(200, 'User info in token', ['user' => $user]);
            return response()->json($response);
        } catch (JWTException $e) {
            $response = new ResponseMsg(400, 'Can not get user info from token', null);
            return response()->json($response);
        }
    }
    
    public function getUserRole(Request $request){
        $user = $request->user();
        $response = new ResponseMsg(200, 'Get user role success', ['role' => $user->role]);
        return response()->json($response);
    }

    public function checkUserInRole(Request $request){
        $user = $request->user();
        $role = strtolower($request->query('role'));
        $response = new ResponseMsg(200, $user->role == $role? 'User role is valid':'User role is invalid', null);
        return response()->json($response);
    }

    public function logout(Request $request)
    {
        $accessToken = $request->header('Authorization');
        // $token = substr($accessToken, 7, strlen($accessToken)); 
        
        try {
            $user = JWTAuth::setToken($accessToken)->authenticate();
            // JWTAuth::invalidate(JWTAuth::getToken());
            $user->refresh_token_expired_time = null;
            $user->refresh_token = '';
            $user->save();
            $response = new ResponseMsg(200, 'Logout successful', null);
            return response()->json($response);
        } catch (JWTException $e) {
            $response = new ResponseMsg(200, 'Failed to logout, you may logged out already', null);
            return response()->json($response);
        }
    }
}
