<?php

declare(strict_types=1);

namespace HubServicePhp;

use RuntimeException;

/**
 * The local hub-net agent was unavailable, refused or answered badly.
 * ``code``: agent-unavailable, agent-timeout, agent-rejected,
 * invalid-agent-response, attestation-mismatch, attestation-expired.
 */
final class LocalAgentError extends RuntimeException
{
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly ?int $status = null,
    ) {
        parent::__construct($message);
    }
}
