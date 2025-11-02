<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

class RolePermissionSeeder extends Seeder
{
    public function run(): void
    {
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        $roles = [
            'Super Admin',
            'Admin',
            'User',
        ];

        $permissions = [
            'view_any_users',
            'create_users',
            'update_users',
            'view_users',
            'delete_users',
            'delete_any_users',
            'force_delete_users',
            'force_delete_any_users',
        ];

        foreach ($permissions as $permission) {
            Permission::create(['name' => $permission]);
        }

        foreach ($roles as $role) {
            Role::create(['name' => $role]);
        }

        $superAdmin = Role::where('name', 'Super Admin')->first();
        $admin = Role::where('name', 'Admin')->first();
        $user = Role::where('name', 'User')->first();

        $superAdmin->givePermissionTo(Permission::all());
        $admin->givePermissionTo(['view_any_users', 'view_users']);
        $user->givePermissionTo([]);

        User::where('email', 'superadmin@example.com')->first()->assignRole('Super Admin');
        User::where('email', 'admin@example.com')->first()->assignRole('Admin');
        User::where('email', 'ciudadano@example.com')->first()->assignRole('User');
    }
}
