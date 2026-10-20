<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * What a two-parameter handler gets next to the body: the caller (null when
 * the hub sent none, e.g. hub-lite), the forwarding hub's key, the full request
 * context and the called path.
 */
final class Request
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public readonly ?Caller $caller,
        public readonly ?string $hubKey,
        public readonly array $context,
        public readonly string $path,
    ) {
    }

    /**
     * @param array<string, mixed> $request the channel-php handler argument
     */
    public static function fromChannel(array $request): self
    {
        $context = is_array($request['context'] ?? null) ? $request['context'] : [];
        $hub = is_array($context['hub'] ?? null) ? $context['hub'] : [];

        return new self(
            Caller::parse($hub['caller'] ?? null),
            is_string($hub['hubKey'] ?? null) ? $hub['hubKey'] : null,
            $context,
            (string) ($request['path'] ?? ''),
        );
    }
}
