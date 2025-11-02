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
            'Citizen',
        ];
        foreach ($roles as $role) {
            Role::create(['name' => $role]);
        }

        $access_panels = [
            'access_super_admin_panel',
            'access_admin_panel',
            'access_citizen_panel',
        ];
        foreach ($access_panels as $access_panel) {
            Permission::create(['name' => $access_panel]);
        }

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

        $superAdmin = Role::where('name', 'Super Admin')->first();
        $admin = Role::where('name', 'Admin')->first();
        $citizen = Role::where('name', 'Citizen')->first();

        $superAdmin->givePermissionTo(Permission::all());
        $admin->givePermissionTo(['access_admin_panel', 'view_any_users', 'view_users']);
        $citizen->givePermissionTo(['access_citizen_panel']);

        User::where('email', 'superadmin@example.com')->first()->assignRole('Super Admin');
        User::where('email', 'admin@example.com')->first()->assignRole('Admin');
        User::where('email', 'ciudadano@example.com')->first()->assignRole('Citizen');
    }
}
