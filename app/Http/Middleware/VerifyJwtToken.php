<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Tymon\JWTAuth\Facades\JWTAuth;
use App\Models\ResponseMsg;

class VerifyJwtToken
{
    public function handle($request, Closure $next)
    {
        $token = $request->header('Authorization');
        $response = null;

        if (!$token) {
            $response = new ResponseMsg(401, 'Token not provided', null);
        }
        else{
            try {
                $user = JWTAuth::setToken($token)->authenticate();
            } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
                $response = new ResponseMsg(401, 'Your token has expired', null);
            } catch (\Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {
                $response = new ResponseMsg(401, 'Your token is invalid', null);
            } catch (\Tymon\JWTAuth\Exceptions\JWTException $e) {
                $response = new ResponseMsg(401, 'Could not authenticate your token', null);
            }
        }

        if($response != null){
            return response()->json($response);
        }

        $request->merge(['user' => $user]);
        return $next($request);
    }
}
