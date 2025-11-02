<?php

namespace App\Services;

use App\Enums\SecurityEventTypeEnum;
use App\Enums\SeverityEnum;
use App\Models\IpBlacklist;
use App\Models\SecurityEvent;
use DeviceDetector\DeviceDetector;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

class ActivityLoggerService
{
    /**
     * Cache TTL for device detection results (24 hours)
     */
    protected const DEVICE_CACHE_TTL = 86400;

    /**
     * Throttle period for authenticated user access logs (5 minutes)
     */
    protected const ACCESS_LOG_THROTTLE = 300;

    /**
     * Log HTTP access (public or authenticated)
     */
    public function logAccess(Request $request, Response $response): void
    {
        $user = Auth::check() ? Auth::user() : null;

        // Rate limiting: Skip logging for authenticated users if recently logged
        if ($user && ! $this->shouldLogAccess($user->id)) {
            return;
        }

        $deviceDetails = $this->getDeviceDetails();
        $isBot = $deviceDetails['is_bot'] ?? false;

        // Determine visitor type
        $visitorType = $isBot ? 'bot' : ($user ? 'authenticated_user' : 'anonymous_visitor');

        activity('access')
            ->causedBy($user)
            ->withProperties([
                'visitor_type' => $visitorType,
                'is_bot' => $isBot,
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'path' => $request->path(),
                'query_params' => $request->query(),
                'referrer' => $request->header('referer'),
                'status_code' => $response->getStatusCode(),
                'device' => $deviceDetails,
            ])
            ->log("Access: {$request->method()} {$request->path()}");

        // Mark this user as logged (throttle)
        if ($user) {
            $this->markAccessLogged($user->id);
        }
    }

    /**
     * Determine if we should log this access for an authenticated user
     */
    protected function shouldLogAccess(int|string $userId): bool
    {
        $cacheKey = "access_log_throttle:{$userId}";

        return ! Cache::has($cacheKey);
    }

    /**
     * Mark that we've logged access for this user (throttle future logs)
     */
    protected function markAccessLogged(int|string $userId): void
    {
        $cacheKey = "access_log_throttle:{$userId}";

        Cache::put($cacheKey, true, self::ACCESS_LOG_THROTTLE);
    }

    public function default(string $event, string $message, Model $model): void
    {
        $user = Auth::user();
        $oldValues = [];
        if ($event === 'updated') {
            $oldValues = array_intersect_key(
                $model->getOriginal(),
                $model->getChanges()
            );
        }
        activity('default')
            ->performedOn($model)
            ->event($event)
            ->causedBy($user)
            ->withProperties([
                'attributes' => $model->getAttributes(),
                'old' => $oldValues,
                'device' => $this->getDeviceDetails(),
            ])
            ->log($message);
    }

    /**
     * Get device details with caching for performance
     *
     * Optimizations:
     * - Authenticated users skip bot detection (always false)
     * - Device detection results cached by User-Agent hash (24h)
     * - Reduces ~90% of DeviceDetector parsing calls
     */
    public function getDeviceDetails(): array
    {
        $userAgent = request()->userAgent() ?? 'Unknown';
        $isAuthenticated = Auth::check();

        // Optimization: Authenticated users are never bots
        if ($isAuthenticated) {
            return $this->getCachedDeviceDetails($userAgent, skipBotDetection: true);
        }

        // Anonymous visitors: full detection with cache
        return $this->getCachedDeviceDetails($userAgent, skipBotDetection: false);
    }

    /**
     * Get cached device details or parse and cache them
     */
    protected function getCachedDeviceDetails(string $userAgent, bool $skipBotDetection): array
    {
        // Create a cache key based on user agent hash and detection mode
        $cacheKey = 'device_details:'.md5($userAgent).':'.($skipBotDetection ? 'auth' : 'anon');

        return Cache::remember($cacheKey, self::DEVICE_CACHE_TTL, function () use ($userAgent, $skipBotDetection) {
            // Performance optimization: Skip expensive bot detection for authenticated users
            if ($skipBotDetection) {
                return [
                    'ip' => request()->ip(),
                    'user_agent' => $userAgent,
                    'is_bot' => false,
                    'bot_name' => null,
                    'bot_category' => null,
                    'device_name' => 'Unknown',
                    'brand' => null,
                    'model' => null,
                    'os' => null,
                    'client' => null,
                ];
            }

            // Full device detection for anonymous visitors
            $dd = new DeviceDetector($userAgent);
            $dd->parse();

            return [
                'ip' => request()->ip(),
                'user_agent' => $dd->getUserAgent(),
                'is_bot' => $dd->isBot(),
                'bot_name' => $dd->getBot()['name'] ?? null,
                'bot_category' => $dd->getBot()['category'] ?? null,
                'device_name' => $dd->getDeviceName(),
                'brand' => $dd->getBrandName(),
                'model' => $dd->getModel(),
                'os' => $dd->getOs(),
                'client' => $dd->getClient(),
            ];
        });
    }

    /**
     * Log a security event
     */
    /* public function logSecurityEvent(
        SecurityEventTypeEnum $type,
        SeverityEnum $severity,
        string $description,
        ?string $ip = null,
        ?array $metadata = null,
        int|string|null $userId = null
    ): SecurityEvent {
        return SecurityEvent::create([
            'user_id' => $userId ?? Auth::id(),
            'type' => $type,
            'severity' => $severity,
            'ip' => $ip ?? request()->ip(),
            'description' => $description,
            'metadata' => array_merge(
                $metadata ?? [],
                [
                    'device' => $this->getDeviceDetails(),
                    'timestamp' => now()->toIso8601String(),
                ]
            ),
        ]);
    } */

    /**
     * Check if an IP should be blocked based on failed attempts
     */
    /* public function shouldBlockIp(string $ip, int $failedAttempts = 10, int $withinMinutes = 5): bool
    {
        if ($this->isIpBlocked($ip)) {
            return true;
        }

        $recentAttempts = SecurityEvent::where('ip', $ip)
            ->where('type', SecurityEventTypeEnum::login_failed)
            ->where('created_at', '>=', now()->subMinutes($withinMinutes))
            ->count();

        return $recentAttempts >= $failedAttempts;
    } */

    /**
     * Check if an IP is currently blocked
     */
    /* public function isIpBlocked(string $ip): bool
    {
        return IpBlacklist::where('ip', $ip)->active()->exists();
    } */

    /**
     * Block an IP address
     */
    /* public function blockIp(
        string $ip,
        string $reason,
        bool $isPermanent = false,
        int|string|null $blockedBy = null,
        ?int $attemptsCount = 0
    ): IpBlacklist {
        $expiresAt = $isPermanent ? null : now()->addDays(7);

        return IpBlacklist::create([
            'ip' => $ip,
            'reason' => $reason,
            'blocked_by' => $blockedBy ?? Auth::id(),
            'expires_at' => $expiresAt,
            'is_permanent' => $isPermanent,
            'attempts_count' => $attemptsCount,
        ]);
    } */

    /**
     * Calculate risk score for a request (0-100)
     */
    /* public function calculateRiskScore(Request $request): int
    {
        $score = 0;
        $ip = $request->ip();

        if ($this->isIpBlocked($ip)) {
            $score += 50;
        }

        $recentAttempts = SecurityEvent::where('ip', $ip)
            ->where('type', SecurityEventTypeEnum::login_failed)
            ->where('created_at', '>=', now()->subHour())
            ->count();
        $score += min($recentAttempts * 5, 25);

        $deviceDetails = $this->getDeviceDetails();
        if ($deviceDetails['is_bot'] ?? false) {
            $botCategory = $deviceDetails['bot_category'] ?? '';
            if (! in_array($botCategory, ['Search bot'])) {
                $score += 15;
            }
        }

        $url = $request->fullUrl();
        $suspiciousPatterns = ['<script', 'javascript:', '../', 'DROP TABLE', 'SELECT * FROM'];
        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($url, $pattern) !== false) {
                $score += 10;
                break;
            }
        }

        return min($score, 100);
    } */
}