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
use GuzzleHttp\Client;

class AuthController extends Controller
{
    public function sendHttpRequest($url, $type, $data){
        $client = new Client();
        $response = null;
        if($type == 'get'){
            $response = $client->get($url);
        }
        else{
            $response = $client->post($url, [
                'json' => $data,
            ]);
        }
        return json_decode($response->getBody()->getContents());
    }

    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'string|max:255',
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
            'name' => $request->name ? $request->name:$request->email,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => $request->role,
        ]);

        if($user->save()){
            $res = $this->sendHttpRequest('http://127.0.0.3:8080/api/crud/add', 'post', $user);
            $status = $res->status;
            if($status == '201'){
                $rdStr = $this->genRandomStr(18);
                $user->update(['validate_email_str' => $rdStr]);
                $data = [
                    "to" => $user->email,
                    "subject" => "Activate Account",
                    "data" => [
                        "link" => "http://localhost:4200/auth/activate?email={$user->email}&activate={$rdStr}",
                        "useremail" => $user->email
                    ],
                    "template" => "activate_account"
                ];
                $res2 = $this->sendHttpRequest(env('SERVICE_NOTI_SENDMAIL_URL'),'post',$data);
                $status2 = $res2->status;
                if($status2 == '200'){
                    $response = new ResponseMsg(200, 'Register success, please check your mail to proceed activate your account', null);
                    return response()->json($response);
                }
                $response = new ResponseMsg(200, 'Register success, but the activation email failed to send to your email', null);
                return response()->json($response);
            }
            else{
                $response = new ResponseMsg(400, 'Register failed', null);
                return response()->json($response);
            }
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

    public function genRandomStr($len) {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charLen = strlen($characters);
        $randomStr = '';
        for ($i = 0; $i < $len; $i++) {
            $randomStr .= $characters[rand(0, $charLen - 1)];
        }
        return $randomStr;
    }

    public function registResetPassword(Request $request){
        $email = $request->input('email');
        $user = usr::where('email', $email)->first();
        if($user){
            $resetPswStr = $this->genRandomStr(12);
            try{
                $user->update(['reset_password_str' => $resetPswStr]);
                $data = [
                    "to" => $user->email,
                    "subject" => "Reset Password",
                    "data" => [
                        "otp" => $resetPswStr,
                        "link" => env('BASE_URL_AUTH_FE') . "/auth/resetpassword",
                        "useremail" => $user->email
                    ],
                    "template" => "reset_password"
                ];
                $res2 = $this->sendHttpRequest(env('SERVICE_NOTI_SENDMAIL_URL'),'post',$data);
            }
            catch (\Illuminate\Database\QueryException $e){
                $response = new ResponseMsg(200, 'aaa', $user);
                return response()->json($response);
            }
            $response = new ResponseMsg(200, 'Reset password OTP and instructions has been sent to your email', $user);
            return response()->json($response);
        }
        $response = new ResponseMsg(400, 'Request failed, invalid email', null);
        return response()->json($response);
    }

    public function registActivateEmail($user){
        $activateStr = $this->genRandomStr(16);
        $user->update(['validate_email_str' => $activateStr]);
        return true;
    }

    public function activateAccount(Request $request){
        // $request->validate([
        //     'email' => 'required|string|email',
        //     'activateStr' => 'required|string',
        // ]);

        $email = $request->query('email');
        $activateStr = $request->query('activate');
        $user = usr::where('email', $email)
        ->where('validate_email_str', $activateStr)
        ->first();

        if($user){
            $user->update(['validate_email_str' => null,
                           'is_validate' => true]);
            $response = new ResponseMsg(200, 'Validate email success', null);
            return response()->json($response);
        }
        $response = new ResponseMsg(400, 'Validate email failed, invalid input', $email);
        return response()->json($response);
    }

    public function resetPassword(Request $request){
        $request->validate([
            'email' => 'required|string|email',
            'resetPasswordStr' => 'required|string',
            'passwordReset' => 'required|string|min:8',
        ]);

        $user = usr::where('email', $request->email)->first();

        if ($user) {
            if ($request->resetPasswordStr == $user->reset_password_str) {
                $user->update([
                    'password' => Hash::make($request->passwordReset),
                    'reset_password_str' => null
                ]);
                $response = new ResponseMsg(200, 'Password reset successfully', null);
                return response()->json($response);
            }
        }
        $response = new ResponseMsg(400, 'Password reset failed, invalid reset password string or invalid email', null);
        return response()->json($response);
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
        $response = new ResponseMsg(200, $user->role == $role? 'Yes':'No', null);
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
