<?php

declare(strict_types=1);

namespace ReactInspector\Tests\DNS;

use ArrayObject;
use OpenTelemetry\API\Instrumentation\Configurator;
use OpenTelemetry\API\Trace\Propagation\TraceContextPropagator;
use OpenTelemetry\Context\ScopeInterface;
use OpenTelemetry\SDK\Trace\ImmutableSpan;
use OpenTelemetry\SDK\Trace\SpanExporter\InMemoryExporter;
use OpenTelemetry\SDK\Trace\SpanProcessor\SimpleSpanProcessor;
use OpenTelemetry\SDK\Trace\TracerProvider;
use OpenTelemetry\SemConv\Incubating\Attributes\DnsIncubatingAttributes;
use PHPUnit\Framework\Attributes\After;
use PHPUnit\Framework\Attributes\Before;
use PHPUnit\Framework\Attributes\Test;
use React\Dns\Model\Message;
use React\Dns\Resolver\Factory;
use React\Dns\Resolver\ResolverInterface;
use WyriHaximus\AsyncTestUtilities\AsyncTestCase;

use function assert;
use function in_array;
use function React\Async\await;

final class DNSInstrumentationTest extends AsyncTestCase
{
    private ScopeInterface $scope;
    /** @var ArrayObject<int, ImmutableSpan> */
    private ArrayObject $storage;
    private TracerProvider $tracerProvider;
    private ResolverInterface $resolver;

    #[Before]
    public function resetBeforeNextTest(): void
    {
        $this->storage        = new ArrayObject();
        $this->tracerProvider = new TracerProvider(
            new SimpleSpanProcessor(
                new InMemoryExporter($this->storage),
            ),
        );
        $this->scope          = Configurator::create()
            ->withTracerProvider($this->tracerProvider)
            ->withPropagator(new TraceContextPropagator())
            ->activate();

        $this->resolver = new Factory()->createCached('1.1.1.1');
    }

    #[After]
    public function detachScopeAfterTests(): void
    {
        $this->scope->detach();
    }

    #[Test]
    public function resolve(): void
    {
        self::assertCount(0, $this->storage);
        $record = await($this->resolver->resolve('example.com'));
        self::assertCount(9, $this->storage);
        $spanOne = $this->storage->offsetGet(0);
        assert($spanOne instanceof ImmutableSpan);
        $spanTwo = $this->storage->offsetGet(1);
        assert($spanTwo instanceof ImmutableSpan);
        $spanThree = $this->storage->offsetGet(2);
        assert($spanThree instanceof ImmutableSpan);
        $spanFour = $this->storage->offsetGet(3);
        assert($spanFour instanceof ImmutableSpan);
        $spanFive = $this->storage->offsetGet(4);
        assert($spanFive instanceof ImmutableSpan);
        $spanSix = $this->storage->offsetGet(5);
        assert($spanSix instanceof ImmutableSpan);
        $spanSeven = $this->storage->offsetGet(6);
        assert($spanSeven instanceof ImmutableSpan);
        $spanEight = $this->storage->offsetGet(7);
        assert($spanEight instanceof ImmutableSpan);
        $spanNine = $this->storage->offsetGet(8);
        assert($spanNine instanceof ImmutableSpan);
        self::assertSame('React\Dns\Query\UdpTransportExecutor::query', $spanOne->getName());
        self::assertSame('React\Dns\Query\TimeoutExecutor::query', $spanTwo->getName());
        self::assertSame('React\Dns\Query\SelectiveTransportExecutor::query', $spanThree->getName());
        self::assertSame('React\Dns\Query\RetryExecutor::query', $spanFour->getName());
        self::assertSame('React\Dns\Query\CoopExecutor::query', $spanFive->getName());
        self::assertSame('React\Dns\Query\CachingExecutor::query', $spanSix->getName());
        self::assertSame('React\Dns\Query\HostsFileExecutor::query', $spanSeven->getName());
        self::assertSame('ResolveAll example.com A', $spanEight->getName());
        self::assertSame('Resolve example.com', $spanNine->getName());
        foreach ([$spanOne, $spanTwo, $spanThree, $spanFour, $spanFive, $spanSix, $spanSeven, $spanEight, $spanNine] as $span) {
            self::assertSame('example.com', $span->getAttributes()->get(DnsIncubatingAttributes::DNS_QUESTION_NAME));
        }

        foreach ([$spanEight, $spanNine] as $span) {
            $dnsAnswers = $span->getAttributes()->get(DnsIncubatingAttributes::DNS_ANSWERS);
            self::assertIsArray($dnsAnswers);
            self::assertTrue(in_array($record, $dnsAnswers, true));
        }
    }

    #[Test]
    public function resolveAll(): void
    {
        self::assertCount(0, $this->storage);
        $records = await($this->resolver->resolveAll('example.com', Message::TYPE_AAAA));

        self::assertCount(8, $this->storage);
        $spanOne = $this->storage->offsetGet(0);
        assert($spanOne instanceof ImmutableSpan);
        $spanTwo = $this->storage->offsetGet(1);
        assert($spanTwo instanceof ImmutableSpan);
        $spanThree = $this->storage->offsetGet(2);
        assert($spanThree instanceof ImmutableSpan);
        $spanFour = $this->storage->offsetGet(3);
        assert($spanFour instanceof ImmutableSpan);
        $spanFive = $this->storage->offsetGet(4);
        assert($spanFive instanceof ImmutableSpan);
        $spanSix = $this->storage->offsetGet(5);
        assert($spanSix instanceof ImmutableSpan);
        $spanSeven = $this->storage->offsetGet(6);
        assert($spanSeven instanceof ImmutableSpan);
        $spanEight = $this->storage->offsetGet(7);
        assert($spanEight instanceof ImmutableSpan);
        self::assertSame('React\Dns\Query\UdpTransportExecutor::query', $spanOne->getName());
        self::assertSame('React\Dns\Query\TimeoutExecutor::query', $spanTwo->getName());
        self::assertSame('React\Dns\Query\SelectiveTransportExecutor::query', $spanThree->getName());
        self::assertSame('React\Dns\Query\RetryExecutor::query', $spanFour->getName());
        self::assertSame('React\Dns\Query\CoopExecutor::query', $spanFive->getName());
        self::assertSame('React\Dns\Query\CachingExecutor::query', $spanSix->getName());
        self::assertSame('React\Dns\Query\HostsFileExecutor::query', $spanSeven->getName());
        self::assertSame('ResolveAll example.com AAAA', $spanEight->getName());
        foreach ([$spanOne, $spanTwo, $spanThree, $spanFour, $spanFive, $spanSix, $spanSeven, $spanEight] as $span) {
            self::assertSame('example.com', $span->getAttributes()->get(DnsIncubatingAttributes::DNS_QUESTION_NAME));
        }

        foreach ([$spanEight] as $span) {
            self::assertSame($records, $span->getAttributes()->get(DnsIncubatingAttributes::DNS_ANSWERS));
        }
    }
}
