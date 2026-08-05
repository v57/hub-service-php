<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * A hub app: a header plus a UI body of elements (TS app.ts parity).
 *
 * Body is a list of plain strings (shorthand text) or element arrays built
 * with the static helpers below, matching the TS wire shapes verbatim.
 */
final class App
{
    public AppHeader $header;

    /** @var list<mixed> */
    public array $body;

    public mixed $top = null;

    public mixed $bottom = null;

    /** @var array<string, mixed> */
    public array $data;

    /**
     * @param list<mixed> $body
     * @param array<string, mixed> $data
     */
    public function __construct(AppHeader $header, array $body = [], array $data = [])
    {
        $this->header = $header;
        $this->body = $body;
        $this->data = $data;
    }

    /** @return array{type: string, value: string} */
    public static function text(string $value): array
    {
        return ['type' => 'text', 'value' => $value];
    }

    /** @return array{type: string, value: mixed, min?: mixed, max?: mixed} */
    public static function progress(mixed $value, mixed $min = null, mixed $max = null): array
    {
        $element = ['type' => 'progress', 'value' => $value];
        if ($min !== null) {
            $element['min'] = $min;
        }
        if ($max !== null) {
            $element['max'] = $max;
        }

        return $element;
    }

    /** @return array{type: string, value: string, placeholder?: string, action?: array<string, mixed>} */
    public static function textField(string $value, ?string $placeholder = null, ?array $action = null): array
    {
        $element = ['type' => 'textField', 'value' => $value];
        if ($placeholder !== null) {
            $element['placeholder'] = $placeholder;
        }
        if ($action !== null) {
            $element['action'] = $action;
        }

        return $element;
    }

    /** @param array<string, mixed> $action @return array{type: string, title: string, action: array<string, mixed>} */
    public static function button(string $title, array $action): array
    {
        return ['type' => 'button', 'title' => $title, 'action' => $action];
    }

    /** @return array{type: string, value: mixed, defaultValue?: mixed, min?: mixed, max?: mixed, step?: mixed, action?: array<string, mixed>} */
    public static function slider(
        mixed $value,
        mixed $defaultValue = null,
        mixed $min = null,
        mixed $max = null,
        mixed $step = null,
        ?array $action = null,
    ): array {
        $element = ['type' => 'slider', 'value' => $value];
        if ($defaultValue !== null) {
            $element['defaultValue'] = $defaultValue;
        }
        if ($min !== null) {
            $element['min'] = $min;
        }
        if ($max !== null) {
            $element['max'] = $max;
        }
        if ($step !== null) {
            $element['step'] = $step;
        }
        if ($action !== null) {
            $element['action'] = $action;
        }

        return $element;
    }

    /** @return array{type: string, data: mixed, content: mixed} */
    public static function list(mixed $data, mixed $content): array
    {
        return ['type' => 'list', 'data' => $data, 'content' => $content];
    }

    /** @param list<string> $options @return array{type: string, options: list<string>, selected: string} */
    public static function picker(array $options, string $selected): array
    {
        return ['type' => 'picker', 'options' => $options, 'selected' => $selected];
    }

    /** @return array{type: string, title?: mixed, subtitle?: mixed} */
    public static function cell(mixed $title = null, mixed $subtitle = null): array
    {
        $element = ['type' => 'cell'];
        if ($title !== null) {
            $element['title'] = $title;
        }
        if ($subtitle !== null) {
            $element['subtitle'] = $subtitle;
        }

        return $element;
    }

    /** @param array<string, mixed> $action @return array{type: string, value: mixed, action: array<string, mixed>, title?: mixed} */
    public static function files(mixed $value, mixed $title = null, array $action = []): array
    {
        $element = ['type' => 'files', 'value' => $value, 'action' => $action];
        if ($title !== null) {
            $element['title'] = $title;
        }

        return $element;
    }

    /** @param array<string, mixed> $action @return array{type: string, action: array<string, mixed>, format?: string, title?: mixed} */
    public static function fileOperation(?string $format = null, mixed $title = null, array $action = []): array
    {
        $element = ['type' => 'fileOperation', 'action' => $action];
        if ($format !== null) {
            $element['format'] = $format;
        }
        if ($title !== null) {
            $element['title'] = $title;
        }

        return $element;
    }

    /** @param list<mixed> $content @return array{type: string, content: list<mixed>, spacing?: mixed} */
    public static function hstack(array $content, mixed $spacing = null): array
    {
        $element = ['type' => 'hstack', 'content' => $content];
        if ($spacing !== null) {
            $element['spacing'] = $spacing;
        }

        return $element;
    }

    /** @param list<mixed> $content @return array{type: string, content: list<mixed>, spacing?: mixed} */
    public static function vstack(array $content, mixed $spacing = null): array
    {
        $element = ['type' => 'vstack', 'content' => $content];
        if ($spacing !== null) {
            $element['spacing'] = $spacing;
        }

        return $element;
    }

    /** @param list<mixed> $content @return array{type: string, content: list<mixed>} */
    public static function zstack(array $content): array
    {
        return ['type' => 'zstack', 'content' => $content];
    }

    /** @return array{type: string} */
    public static function spacer(): array
    {
        return ['type' => 'spacer'];
    }

    /**
     * Action referencing an API call from a UI element (path, body?, output?).
     *
     * @return array{path: string, body?: mixed, output?: mixed}
     */
    public static function action(string $path, mixed $body = null, mixed $output = null): array
    {
        $action = ['path' => $path];
        if ($body !== null) {
            $action['body'] = $body;
        }
        if ($output !== null) {
            $action['output'] = $output;
        }

        return $action;
    }
}
