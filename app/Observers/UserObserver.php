<?php

namespace App\Observers;

use App\Models\User;
use App\Services\ActivityLoggerService;

class UserObserver
{
    public function __construct(
        protected ActivityLoggerService $activityLog,
    ) {}

    public function created(User $user): void
    {
        $message = "nuevo usuario: {$user->name}";
        $this->activityLog->default('created', $message, $user);
    }

    public function updated(User $user): void
    {
        if ($user->wasChanged('deleted_at') && is_null($user->deleted_at)) {
            return;
        }
        $message = "usuario actualizado: {$user->name}";
        $this->activityLog->default('updated', $message, $user);
    }

    public function deleted(User $user): void
    {
        if ($user->isForceDeleting()) {
            return;
        }
        $message = "usuario eliminado: {$user->name}";
        $this->activityLog->default('deleted', $message, $user);
    }

    public function restored(User $user): void
    {
        $message = "usuario restaurado: {$user->name}";
        $this->activityLog->default('restored', $message, $user);
    }

    public function forceDeleted(User $user): void
    {
        $message = "usuario eliminado permanentemente: {$user->name}";
        $this->activityLog->default('force_deleted', $message, $user);
    }
}
