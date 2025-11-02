<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;

use App\Observers\UserObserver;
use Filament\Models\Contracts\FilamentUser;
use Filament\Models\Contracts\HasAvatar;
use Filament\Panel;
use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Spatie\Permission\Traits\HasRoles;

#[ObservedBy([UserObserver::class])]
class User extends Authenticatable implements FilamentUser, HasAvatar
{
    use HasFactory, HasRoles, HasUuids, Notifiable, SoftDeletes;

    protected $dateFormat = 'Y-m-d H:i:s.u';

    protected $fillable = [
        'name',
        'email',
        'password',
        'profile_picture',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function getFilamentAvatarUrl(): ?string
    {
        return $this->profile_picture ?? null;
    }

    public function canAccessPanel(Panel $panel): bool
    {
        if ($this->hasRole('Super Admin')) {
            return true;
        }
    
        return match($panel->getId()) {
            'admin' => $this->can('access_admin_panel'),
            'citizen' => $this->can('access_citizen_panel'),
            default => false,
        };
    }
}
