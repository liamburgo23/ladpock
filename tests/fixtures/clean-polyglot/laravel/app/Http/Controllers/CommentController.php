<?php

namespace App\Http\Controllers;

use App\Models\Comment;
use Illuminate\Http\Request;

class CommentController extends Controller
{
    public function store(Request $request)
    {
        $data = $request->validate(['text' => 'required|string|max:2000']);
        return Comment::create(['text' => $data['text'], 'user_id' => auth()->id()]);
    }
}
