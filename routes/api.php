<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/
Route::post('/register', [AuthController::class, 'register']);
Route::get('/activateAccount', [AuthController::class, 'activateAccount']);
Route::get('/registResetPassword', [AuthController::class, 'registResetPassword']);
Route::post('/resetPassword', [AuthController::class, 'resetPassword']);
Route::post('/changePassword', [AuthController::class, 'changePassword']);
Route::post('/login', [AuthController::class, 'login'])->withoutMiddleware(['jwt.verify']);
Route::get('/logout', [AuthController::class, 'logout']);
Route::get('/getTokenPayload', [AuthController::class, 'getTokenPayload']);

Route::middleware('jwt.verify')->group(function () {
    Route::get('/getUserRole', [AuthController::class, 'getUserRole']);
    Route::get('/checkUserInRole', [AuthController::class, 'checkUserInRole']);
});
// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });
