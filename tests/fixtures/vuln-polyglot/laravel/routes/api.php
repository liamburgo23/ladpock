<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\CommentController;
use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login']);
Route::get('/orders/{order}', [OrderController::class, 'show'])->middleware('auth:sanctum');
Route::delete('/orders/{order}', [OrderController::class, 'destroy']);
Route::apiResource('comments', CommentController::class)->only(['store']);
