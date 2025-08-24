<?php

declare(strict_types=1);

namespace ReactInspector\DNS;

use Composer\InstalledVersions;
use OpenTelemetry\API\Instrumentation\CachedInstrumentation;
use OpenTelemetry\API\Trace\Span;
use OpenTelemetry\API\Trace\SpanKind;
use OpenTelemetry\API\Trace\StatusCode;
use OpenTelemetry\Context\Context;
use OpenTelemetry\Context\ContextStorageScopeInterface;
use OpenTelemetry\SemConv\Attributes\CodeAttributes;
use OpenTelemetry\SemConv\Incubating\Attributes\DnsIncubatingAttributes;
use OpenTelemetry\SemConv\Version;
use React\Dns\Model\Message;
use React\Dns\Query\ExecutorInterface;
use React\Dns\Query\Query;
use React\Dns\Resolver\ResolverInterface;
use React\Promise\PromiseInterface;
use Throwable;

use function array_key_exists;
use function assert;
use function count;
use function filter_var;
use function is_array;
use function is_string;
use function OpenTelemetry\Instrumentation\hook;
use function sprintf;

use const FILTER_VALIDATE_IP;

final class DNSInstrumentation
{
    public const string NAME = 'reactphp';

    /**
     * The name of the Composer package.
     *
     * @see https://getcomposer.org/doc/04-schema.md#name
     */
    private const string COMPOSER_NAME = 'react-inspector/dns';

    /**
     * Name of this instrumentation library which provides the instrumentation for Bunny.
     *
     * @see https://opentelemetry.io/docs/specs/otel/glossary/#instrumentation-library
     */
    private const string INSTRUMENTATION_LIBRARY_NAME = 'io.opentelemetry.contrib.php.react-dns';

    /** @phpstan-ignore shipmonk.deadMethod */
    public static function register(): void
    {
        $instrumentation = new CachedInstrumentation(
            self::INSTRUMENTATION_LIBRARY_NAME,
            InstalledVersions::getPrettyVersion(self::COMPOSER_NAME),
            Version::VERSION_1_32_0->url(),
        );

        hook(
            ResolverInterface::class,
            'resolve',
            pre: static function (
                ResolverInterface $resolver,
                array $params,
                string $class,
                string $function,
                string|null $filename,
                int|null $lineno,
            ) use ($instrumentation): void {
                [$hostName] = $params;
                assert(is_string($hostName));

                $parentContext = Context::getCurrent();

                $spanBuilder = $instrumentation
                    ->tracer()
                    ->spanBuilder('Resolve ' . $hostName)
                    ->setParent($parentContext)
                    ->setSpanKind(SpanKind::KIND_INTERNAL)
                    // dns
                    ->setAttribute(DnsIncubatingAttributes::DNS_QUESTION_NAME, $hostName)
                    // code
                    ->setAttribute(CodeAttributes::CODE_FUNCTION_NAME, sprintf('%s::%s', $class, $function))
                    ->setAttribute(CodeAttributes::CODE_FILE_PATH, $filename)
                    ->setAttribute(CodeAttributes::CODE_LINE_NUMBER, $lineno);

                $span    = $spanBuilder->startSpan();
                $context = $span->storeInContext($parentContext);

                Context::storage()->attach($context);
            },
            post: static function (
                ResolverInterface $resolver,
                array $params,
                PromiseInterface $promise,
            ): PromiseInterface {
                $scope = Context::storage()->scope();
                if (! $scope instanceof ContextStorageScopeInterface) {
                    return $promise;
                }

                $scope->detach();
                $span = Span::fromContext($scope->context());
                if (! $span->isRecording()) {
                    return $promise;
                }

                return $promise->then(static function (mixed $stuff) use ($span): mixed {
                    $span = $span->setAttribute(DnsIncubatingAttributes::DNS_ANSWERS, [$stuff]);
                    $span->end();

                    return $stuff;
                }, static function (Throwable $exception) use ($span): never {
                    $span->recordException($exception);
                    $span->setStatus(StatusCode::STATUS_ERROR);
                    $span->end();

                    /** @phpstan-ignore shipmonk.checkedExceptionInCallable */
                    throw $exception;
                });
            },
        );

        hook(
            ResolverInterface::class,
            'resolveAll',
            pre: static function (
                ResolverInterface $resolver,
                array $params,
                string $class,
                string $function,
                string|null $filename,
                int|null $lineno,
            ) use ($instrumentation): void {
                [$hostName] = $params;
                assert(is_string($hostName));
                $typeString = '';
                if (array_key_exists(1, $params)) {
                    foreach (
                        [
                            Message::TYPE_A => 'A',
                            Message::TYPE_NS => 'NS',
                            Message::TYPE_CNAME => 'CNAME',
                            Message::TYPE_SOA => 'SOA',
                            Message::TYPE_PTR => 'PTR',
                            Message::TYPE_MX => 'MX',
                            Message::TYPE_TXT => 'TXT',
                            Message::TYPE_AAAA => 'AAAA',
                            Message::TYPE_SRV => 'SRV',
                            Message::TYPE_SSHFP => 'SSHFP',
                        ] as $type => $humanReadable
                    ) {
                        if ($params[1] === $type) {
                            $typeString = ' ' . $humanReadable;
                            break;
                        }
                    }
                }

                $parentContext = Context::getCurrent();

                $spanBuilder = $instrumentation
                    ->tracer()
                    ->spanBuilder('ResolveAll ' . $hostName . $typeString)
                    ->setParent($parentContext)
                    ->setSpanKind(SpanKind::KIND_INTERNAL)
                    // dns
                    ->setAttribute(DnsIncubatingAttributes::DNS_QUESTION_NAME, $hostName)
                    // code
                    ->setAttribute(CodeAttributes::CODE_FUNCTION_NAME, sprintf('%s::%s', $class, $function))
                    ->setAttribute(CodeAttributes::CODE_FILE_PATH, $filename)
                    ->setAttribute(CodeAttributes::CODE_LINE_NUMBER, $lineno);

                $span    = $spanBuilder->startSpan();
                $context = $span->storeInContext($parentContext);

                Context::storage()->attach($context);
            },
            post: static function (
                ResolverInterface $resolver,
                array $params,
                PromiseInterface $promise,
            ): PromiseInterface {
                $scope = Context::storage()->scope();
                if (! $scope instanceof ContextStorageScopeInterface) {
                    return $promise;
                }

                $scope->detach();
                $span = Span::fromContext($scope->context());
                if (! $span->isRecording()) {
                    return $promise;
                }

                return $promise->then(static function (mixed $stuff) use ($span): mixed {
                    if (is_array($stuff)) {
                        $ips = [];
                        foreach ($stuff as $item) {
                            $ip = filter_var($item, FILTER_VALIDATE_IP);
                            if ($ip === false) {
                                continue;
                            }

                            $ips[] = $ip;
                        }

                        if (count($ips) > 0) {
                            $span = $span->setAttribute(DnsIncubatingAttributes::DNS_ANSWERS, $ips);
                        }
                    }

                    $span->end();

                    return $stuff;
                }, static function (Throwable $exception) use ($span): never {
                    $span->recordException($exception);
                    $span->setStatus(StatusCode::STATUS_ERROR, $exception->getMessage());
                    $span->end();

                    /** @phpstan-ignore shipmonk.checkedExceptionInCallable */
                    throw $exception;
                });
            },
        );

        hook(
            ExecutorInterface::class,
            'query',
            pre: static function (
                ExecutorInterface $executor,
                array $params,
                string $class,
                string $function,
                string|null $filename,
                int|null $lineno,
            ) use ($instrumentation): void {
                $parentContext = Context::getCurrent();

                $spanBuilder = $instrumentation
                    ->tracer()
                    ->spanBuilder(sprintf('%s::%s', $class, $function))
                    ->setParent($parentContext)
                    ->setSpanKind(SpanKind::KIND_INTERNAL)
                    // code
                    ->setAttribute(CodeAttributes::CODE_FUNCTION_NAME, sprintf('%s::%s', $class, $function))
                    ->setAttribute(CodeAttributes::CODE_FILE_PATH, $filename)
                    ->setAttribute(CodeAttributes::CODE_LINE_NUMBER, $lineno);

                [$query] = $params;
                if ($query instanceof Query) {
                    // dns
                    $spanBuilder = $spanBuilder->setAttribute(DnsIncubatingAttributes::DNS_QUESTION_NAME, $query->name);
                }

                $span    = $spanBuilder->startSpan();
                $context = $span->storeInContext($parentContext);

                Context::storage()->attach($context);
            },
            post: static function (
                ExecutorInterface $executor,
                array $params,
                PromiseInterface $promise,
            ): PromiseInterface {
                $scope = Context::storage()->scope();
                if (! $scope instanceof ContextStorageScopeInterface) {
                    return $promise;
                }

                $scope->detach();
                $span = Span::fromContext($scope->context());
                if (! $span->isRecording()) {
                    return $promise;
                }

                return $promise->then(static function (mixed $stuff) use ($span): mixed {
                    $span->end();

                    return $stuff;
                }, static function (Throwable $exception) use ($span): never {
                    $span->recordException($exception);
                    $span->setStatus(StatusCode::STATUS_ERROR);
                    $span->end();

                    /** @phpstan-ignore shipmonk.checkedExceptionInCallable */
                    throw $exception;
                });
            },
        );
    }
}
