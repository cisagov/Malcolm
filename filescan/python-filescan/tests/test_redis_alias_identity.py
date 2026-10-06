"""Typed Redis aliases must remain usable through repeated normalization."""

from pathlib import Path
import sys
from unittest.mock import AsyncMock, Mock

import anyio
from pydantic import BaseModel
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from filescan import redis as messages


@pytest.mark.parametrize('text', ['', 'results', 'scan:status', 'résultats'])
def test_existing_alias_preserves_identity_value_and_hash(text):
    alias = messages.Alias(text)
    original_hash = hash(alias)
    lookup = {alias: 'value'}
    for _ in range(3):
        assert messages.Alias(alias) is alias
    assert str(alias) == text and alias == text
    assert hash(alias) == original_hash
    assert lookup[messages.Alias(alias)] == 'value'


@pytest.mark.parametrize('value', [None, 1, [], object()])
def test_unsupported_alias_inputs_keep_the_existing_rejection(value):
    with pytest.raises(AssertionError):
        messages.Alias(value)


@pytest.mark.parametrize('typed', [False, True])
def test_alias_mapping_accepts_both_key_forms_and_reassignment(typed):
    first = messages.Alias('results') if typed else 'results'
    mapping = messages.AliasMapping({first: 'scan:results'})
    assert str(mapping.alias('scan:results')) == 'results'
    assert mapping.unalias(messages.Alias('results')) == 'scan:results'
    mapping.add_alias(messages.Alias('results'), 'new:results')
    assert not mapping.contains_key('scan:results')
    assert mapping.unalias(messages.Alias('results')) == 'new:results'
    mapping.remove_alias(messages.Alias('results'))
    assert not mapping.contains_key('new:results')


@pytest.fixture
def client(monkeypatch):
    pubsub = Mock()
    pubsub.subscribe = AsyncMock()
    pubsub.unsubscribe = AsyncMock()
    redis = Mock()
    redis.pubsub.return_value = pubsub
    redis.publish = AsyncMock(return_value=1)
    redis.pubsub_numsub = AsyncMock(return_value=[('scan:results', 2)])
    monkeypatch.setattr(messages.redis.asyncio, 'Redis', Mock(return_value=redis))
    return redis, pubsub


@pytest.mark.parametrize('typed', [False, True])
def test_automatic_handlers_and_explicit_channels_subscribe_and_dispatch(client, typed):
    redis, pubsub = client

    class Subscriber(messages.RedisSubscriber):
        async def on_message_results(self, data):
            self.delivered.append(data)

    channel = messages.Alias('manual') if typed else 'manual'
    subscriber = Subscriber(host='unused', channels=[channel], aliases_to_keys={'results': 'scan:results'})
    subscriber.delivered = []
    assert set(map(str, subscriber.channels)) == {'results', 'manual'}

    async def scenario():
        await subscriber.ensure_subscribed()
        assert set(pubsub.subscribe.call_args.args) == {'scan:results', 'manual'}
        await subscriber.dispatch_message({'type': 'message', 'channel': 'scan:results', 'data': 'payload'})
        assert subscriber.delivered == ['payload']
        await subscriber.remove_subscribed_channel(messages.Alias('manual'))
        pubsub.unsubscribe.assert_awaited_once_with('manual')
        await subscriber.add_subscribed_channel(messages.Alias('manual'))
        assert set(map(str, subscriber.subscribed)) == {'results', 'manual'}

    anyio.run(scenario)


@pytest.mark.parametrize('typed', [False, True])
def test_publisher_routes_existing_aliases_and_serializes_data(client, typed):
    redis, _ = client

    class Payload(BaseModel):
        value: int

    publisher = messages.RedisPublisher(host='unused', aliases_to_keys={'results': 'scan:results'})
    channel = messages.Alias('results') if typed else 'results'

    async def scenario():
        assert await publisher.publish(Payload(value=7), channel) == 1
        redis.publish.assert_awaited_once_with('scan:results', '{"value":7}')
        assert await publisher.subscribers(channel) == {messages.Alias('results'): 2}
        redis.pubsub_numsub.assert_awaited_once_with('scan:results')

    anyio.run(scenario)


def test_normalization_keeps_an_existing_subclass_instance():
    class DerivedAlias(messages.Alias):
        pass

    alias = DerivedAlias('results')
    assert messages.Alias(alias) is alias
