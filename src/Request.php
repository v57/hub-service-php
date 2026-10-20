<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * What a two-parameter handler gets next to the body: the caller, the request
 * context without ``hub``, and the called path. The caller is null unless the
 * hub that forwarded the request is the pinned hub: a hub that predates caller
 * identity may pass a client's context.hub through unchanged.
 */
final class Request
{
    /**
     * @param array<string, mixed> $context
     */
    public function __construct(
        public readonly ?Caller $caller,
        public readonly array $context,
        public readonly string $path,
    ) {
    }

    /**
     * @param array<string, mixed> $request the channel-php handler argument
     */
    public static function fromChannel(array $request, ?string $hubKey): self
    {
        $context = is_array($request['context'] ?? null) ? $request['context'] : [];
        $hub = $context['hub'] ?? null;
        unset($context['hub']);
        $trusted = is_array($hub) && $hubKey !== null && ($hub['hubKey'] ?? null) === $hubKey;

        return new self(
            $trusted ? Caller::parse($hub['caller'] ?? null) : null,
            $context,
            (string) ($request['path'] ?? ''),
        );
    }
}
