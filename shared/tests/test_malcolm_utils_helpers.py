"""Regression tests for the general-purpose helpers in scripts/malcolm_utils.py."""

import hashlib
import io
import os
import threading
from base64 import b64encode

import pytest

import malcolm_utils


###################################################################################################
# isprivateip / isipaddress


@pytest.mark.parametrize(
    'value, expected',
    [
        ('10.0.0.1', True),
        ('192.168.1.1', True),
        ('172.16.5.4', True),
        ('8.8.8.8', False),
        ('fd12:3456:789a:1::5', True),
        ('2001:4860:4860::8888', False),
        ('10.0.0.0/8', True),
        ('8.8.8.0/24', False),
        ('not an ip', False),
        ('', False),
        (None, False),
    ],
)
def test_isprivateip_scalar(value, expected):
    assert malcolm_utils.isprivateip(value) is expected


@pytest.mark.parametrize('container', [list, tuple, set])
def test_isprivateip_collection_of_private_addresses(container):
    assert malcolm_utils.isprivateip(container(['10.0.0.1', '192.168.1.1', 'fd00::1'])) is True


@pytest.mark.parametrize('container', [list, tuple, set])
def test_isprivateip_collection_with_a_public_address(container):
    assert malcolm_utils.isprivateip(container(['10.0.0.1', '8.8.8.8'])) is False


def test_isprivateip_collection_with_garbage():
    assert malcolm_utils.isprivateip(['10.0.0.1', 'garbage']) is False


@pytest.mark.parametrize(
    'value, expected',
    [
        ('10.0.0.1', True),
        ('::1', True),
        ('10.0.0.0/8', False),
        ('256.0.0.1', False),
        ('', False),
        (['10.0.0.1', '8.8.8.8'], True),
        (('10.0.0.1', 'garbage'), False),
    ],
)
def test_isipaddress(value, expected):
    assert malcolm_utils.isipaddress(value) is expected


###################################################################################################
# EVP_BytesToKey

SALT = bytes.fromhex('0102030405060708')


@pytest.mark.parametrize(
    'md, key_hex, iv_hex',
    [
        # from: openssl enc -aes-256-cbc -P -md <md> -S 0102030405060708 -pass pass:malcolm
        (
            hashlib.md5,
            'FEEA89F5FBFA10A7091845021DC8F42C609E39D7A9F6995B12270795F2B75C6C',
            'AE64227BEDF95CBCFEB22A4933F35A84',
        ),
        (
            hashlib.sha256,
            '1FC3EF25918132CFDAA9E03890BAC30B9D50EBFC1DD361482DCDECD305EB80A7',
            '986E0925FAC496F76DAA199F6DA92170',
        ),
    ],
)
def test_evp_bytes_to_key_matches_openssl(md, key_hex, iv_hex):
    key, iv = malcolm_utils.EVP_BytesToKey(32, 16, md, SALT, b'malcolm')
    assert key.hex().upper() == key_hex
    assert iv.hex().upper() == iv_hex


@pytest.mark.parametrize('count', [2, 3, 10])
def test_evp_bytes_to_key_iteration_count(count):
    # with md5, the first 16 bytes of the key are D_1 = md5^count(data || salt)
    expected = hashlib.md5(b'malcolm' + SALT).digest()
    for _ in range(1, count):
        expected = hashlib.md5(expected).digest()
    key, iv = malcolm_utils.EVP_BytesToKey(32, 16, hashlib.md5, SALT, b'malcolm', count=count)
    assert key[:16] == expected
    assert (len(key), len(iv)) == (32, 16)


def test_evp_bytes_to_key_iteration_count_changes_output():
    one = malcolm_utils.EVP_BytesToKey(32, 16, hashlib.sha256, SALT, b'malcolm', count=1)
    two = malcolm_utils.EVP_BytesToKey(32, 16, hashlib.sha256, SALT, b'malcolm', count=2)
    assert one != two


@pytest.mark.parametrize('key_length, iv_length', [(16, 0), (24, 16), (32, 16), (64, 32)])
def test_evp_bytes_to_key_lengths(key_length, iv_length):
    key, iv = malcolm_utils.EVP_BytesToKey(key_length, iv_length, hashlib.md5, SALT, b'malcolm')
    assert (len(key), len(iv)) == (key_length, iv_length)


###################################################################################################
# dictionary helpers

NESTED = {'meta': {'status': 'OK', 'status_code': 200, 'tags': ['a', 'b']}, 'name': 'x'}


@pytest.mark.parametrize(
    'keys, default, expected',
    [
        (['meta', 'status_code'], None, 200),
        (['meta', 'status'], None, 'OK'),
        ('name', None, 'x'),
        (['garbage', 'status_code'], None, None),
        (['meta', 'garbage'], '-', '-'),
        (['meta'], None, NESTED['meta']),
        ([], None, NESTED),
        # walking through a value that isn't a mapping returns the default
        (['name', 'child'], 'dflt', 'dflt'),
        (['meta', 'status', 'child'], 'dflt', 'dflt'),
        (['meta', 'tags', 0], 'dflt', 'dflt'),
        (['meta', 'status_code', 'child'], 'dflt', 'dflt'),
    ],
)
def test_deep_get(keys, default, expected):
    assert malcolm_utils.deep_get(NESTED, keys, default) == expected


def test_deep_get_none_dict_returns_default():
    assert malcolm_utils.deep_get(None, ['a'], 'dflt') == 'dflt'


def test_deep_get_explicit_none_value_returns_default():
    assert malcolm_utils.deep_get({'a': None}, ['a', 'b'], 'dflt') == 'dflt'


def test_deep_set_creates_intermediate_dicts():
    d = {}
    malcolm_utils.deep_set(d, ['a', 'b', 'c'], 1)
    assert d == {'a': {'b': {'c': 1}}}


def test_deep_set_replaces_non_dict_intermediate():
    d = {'a': 'scalar'}
    malcolm_utils.deep_set(d, ['a', 'b'], 1)
    assert d == {'a': {'b': 1}}


def test_deep_set_single_key():
    d = {}
    malcolm_utils.deep_set(d, 'a', 1)
    assert d == {'a': 1}


def test_deep_set_delete_if_none():
    d = {'a': {'b': 1, 'c': 2}}
    malcolm_utils.deep_set(d, ['a', 'b'], None, deleteIfNone=True)
    assert d == {'a': {'c': 2}}


def test_deep_set_none_without_delete_keeps_key():
    d = {'a': {'b': 1}}
    malcolm_utils.deep_set(d, ['a', 'b'], None)
    assert d == {'a': {'b': None}}


def test_deep_merge_overrides_and_merges_nested():
    destination = {'a': 1, 'b': {'x': 1, 'y': 2}, 'c': {'z': 1}}
    source = {'a': 2, 'b': {'y': 3, 'w': 4}, 'c': 'replaced'}
    result = malcolm_utils.deep_merge(source, destination)
    assert result is destination
    assert destination == {'a': 2, 'b': {'x': 1, 'y': 3, 'w': 4}, 'c': 'replaced'}


def test_deep_merge_dict_replaces_scalar():
    destination = {'a': 1}
    malcolm_utils.deep_merge({'a': {'b': 2}}, destination)
    assert destination == {'a': {'b': 2}}


def test_deep_merge_in_place_mutates_destination():
    destination = {'a': {'x': 1}}
    assert malcolm_utils.deep_merge_in_place({'a': {'y': 2}, 'b': 3}, destination) is None
    assert destination == {'a': {'x': 1, 'y': 2}, 'b': 3}


def test_dictsearch_finds_all_matches_at_any_depth():
    d = {'id': 1, 'child': {'id': 2, 'grandchild': {'id': 3}}, 'other': {'name': 'x'}}
    assert sorted(malcolm_utils.dictsearch(d, 'id')) == [1, 2, 3]
    assert malcolm_utils.dictsearch(d, 'missing') == []


@pytest.mark.parametrize(
    'func, expected',
    [
        (malcolm_utils.min_hash_value_by_value, 'one'),
        (malcolm_utils.max_hash_value_by_value, 'zz'),
        (malcolm_utils.min_hash_value_by_key, 'zz'),
        (malcolm_utils.max_hash_value_by_key, 'two'),
    ],
)
def test_min_max_hash_value(func, expected):
    # values sort as one < two < zz; keys sort as a < b < c
    assert func({'b': 'one', 'c': 'two', 'a': 'zz'}) == expected


@pytest.mark.parametrize(
    'func',
    [
        malcolm_utils.min_hash_value_by_value,
        malcolm_utils.max_hash_value_by_value,
        malcolm_utils.min_hash_value_by_key,
        malcolm_utils.max_hash_value_by_key,
    ],
)
def test_min_max_hash_value_empty(func):
    assert func({}) is None


def test_remove_falsy():
    obj = {'a': 0, 'b': '', 'c': [], 'd': {'e': None, 'f': 1}, 'g': [0, '', 'x', {}], 'h': {'i': {}}}
    assert malcolm_utils.remove_falsy(obj) == {'d': {'f': 1}, 'g': ['x']}


def test_flatten():
    assert list(malcolm_utils.flatten([1, [2, (3, [4])], 'abc', [['de']]])) == [1, 2, 3, 4, 'abc', 'de']


@pytest.mark.parametrize(
    'value, expected',
    [
        ('abc', ('abc',)),
        (1, (1,)),
        (None, (None,)),
        ([1, 2], [1, 2]),
        ((1,), (1,)),
    ],
)
def test_get_iterable(value, expected):
    assert malcolm_utils.get_iterable(value) == expected


###################################################################################################
# curl escaping


@pytest.mark.parametrize(
    'value',
    [
        'plain',
        'with "quotes"',
        'back\\slash',
        'literal backslash-n \\n not a newline',
        'tab\tnewline\ncr\rvt\v',
        '\\\\double\\\\',
        'trailing backslash\\',
        'p@ss:w0rd!$%^&*()',
        '',
    ],
)
def test_escape_for_curl_round_trip(value):
    assert malcolm_utils.UnescapeForCurl(malcolm_utils.EscapeForCurl(value)) == value


def test_escape_for_curl_output():
    assert malcolm_utils.EscapeForCurl('a"b\\c\nd') == 'a\\"b\\\\c\\nd'


###################################################################################################
# string conversions


@pytest.mark.parametrize('value', ['yes', 'YES', 'true', 'True', 't', 'y', '1', True])
def test_str2bool_true(value):
    assert malcolm_utils.str2bool(value) is True


@pytest.mark.parametrize('value', ['no', 'NO', 'false', 'f', 'n', '0', '', False, None, 0])
def test_str2bool_false(value):
    assert malcolm_utils.str2bool(value) is False


@pytest.mark.parametrize('value', ['maybe', '2', 1, ['x']])
def test_str2bool_invalid(value):
    with pytest.raises(ValueError):
        malcolm_utils.str2bool(value)


@pytest.mark.parametrize(
    'value, expected',
    [
        ('yes', True),
        ('T', True),
        ('no', False),
        ('F', False),
        (True, True),
        (False, False),
        (None, False),
    ],
)
def test_val2bool(value, expected):
    assert malcolm_utils.val2bool(value) is expected


@pytest.mark.parametrize('value', ['1', '0', 'maybe', 5, ['x']])
def test_val2bool_passes_unrecognized_values_through(value):
    # unlike str2bool, '1' and '0' aren't booleans here; the value comes back unchanged for the caller to handle
    assert malcolm_utils.val2bool(value) == value


@pytest.mark.parametrize(
    'value, expected',
    [
        (True, 'true'),
        (False, 'false'),
        ('x', 'x'),
        (1, '1'),
    ],
)
def test_bool_to_str(value, expected):
    assert malcolm_utils.bool_to_str(value) == expected
    assert malcolm_utils.true_or_false_no_quotes(value) == expected


@pytest.mark.parametrize('value, expected', [(True, "'true'"), (False, "'false'"), ('x', 'x')])
def test_true_or_false_quotes(value, expected):
    assert malcolm_utils.true_or_false_quotes(value) == expected


@pytest.mark.parametrize(
    'value, expected',
    [
        ('50', 50),
        ('50%', 50),
        ('0%', 0),
        ('100%', 100),
        ('150%', 100),
        ('-5', 0),
        ('', 0),
        (None, 0),
    ],
)
def test_str2percent(value, expected):
    assert malcolm_utils.str2percent(value) == expected


@pytest.mark.parametrize('value', ['abc', '50.5%'])
def test_str2percent_invalid(value):
    with pytest.raises(ValueError):
        malcolm_utils.str2percent(value)


@pytest.mark.parametrize(
    'value, expected',
    [
        ('1.5', True),
        ('-2', True),
        ('1e3', True),
        ('nan', True),
        (3, True),
        ('abc', False),
        ('', False),
        (None, False),
        ([1], False),
    ],
)
def test_isfloat(value, expected):
    assert malcolm_utils.isfloat(value) is expected


@pytest.mark.parametrize(
    'num, expected',
    [
        (0, '0.0B'),
        (1023, '1023.0B'),
        (1024, '1.0KiB'),
        (1536, '1.5KiB'),
        (1024**3, '1.0GiB'),
        (-2048, '-2.0KiB'),
        (1024**8, '1.0YiB'),
    ],
)
def test_sizeof_fmt(num, expected):
    assert malcolm_utils.sizeof_fmt(num) == expected


@pytest.mark.parametrize(
    'text, prefix, expected',
    [
        ('foobar', 'foo', 'bar'),
        ('foobar', 'bar', 'foobar'),
        ('foobar', '', 'foobar'),
        ('foo', 'foo', ''),
    ],
)
def test_remove_prefix(text, prefix, expected):
    assert malcolm_utils.remove_prefix(text, prefix) == expected


@pytest.mark.parametrize(
    'text, suffix, expected',
    [
        ('foobar', 'bar', 'foo'),
        ('foobar', 'foo', 'foobar'),
        ('foobar', '', 'foobar'),
        ('bar', 'bar', ''),
    ],
)
def test_remove_suffix(text, suffix, expected):
    assert malcolm_utils.remove_suffix(text, suffix) == expected


@pytest.mark.parametrize('value, expected', [('Hello', 'hello'), ('HELLO', 'hELLO'), ('', ''), (None, None)])
def test_decapitalize(value, expected):
    assert malcolm_utils.decapitalize(value) == expected


@pytest.mark.parametrize('value, expected', [('a b', True), ('a\tb', True), ('a\n', True), ('ab', False), ('', False)])
def test_contains_whitespace(value, expected):
    assert malcolm_utils.contains_whitespace(value) is expected


def test_aggressive_url_encode():
    assert malcolm_utils.aggressive_url_encode('a b/') == '%61%20%62%2f'


def test_escape_ansi():
    assert malcolm_utils.EscapeAnsi('\x1b[31mred\x1b[0m plain') == 'red plain'


def test_custom_make_translation():
    assert malcolm_utils.custom_make_translation('a.b*c', {'.': '-', '*': '+'}) == 'a-b+c'


@pytest.mark.parametrize(
    'value, expected',
    [
        ('base64:' + b64encode(b'secret').decode(), 'secret'),
        ('base64:', ''),
        ('secret', 'secret'),
        ('BASE64:c2VjcmV0', 'BASE64:c2VjcmV0'),
    ],
)
def test_base64_decode_if_prefixed(value, expected):
    assert malcolm_utils.base64_decode_if_prefixed(value) == expected


###################################################################################################
# JSON loading


@pytest.mark.parametrize(
    'value, expected',
    [
        ('{"a": 1}', {'a': 1}),
        ('[1, 2]', [1, 2]),
        ('"x"', 'x'),
        ('not json', 'dflt'),
        ('', 'dflt'),
        (None, 'dflt'),
    ],
)
def test_load_str_if_json(value, expected):
    assert malcolm_utils.LoadStrIfJson(value, default='dflt') == expected


def test_load_file_if_json_document():
    assert malcolm_utils.LoadFileIfJson(io.StringIO('{"a": 1}')) == {'a': 1}


def test_load_file_if_json_lines():
    handle = io.StringIO('{"a": 1}\nnot json\n{"b": 2}\n')
    assert malcolm_utils.LoadFileIfJson(handle, attemptLines=True) == [{'a': 1}, {'b': 2}]


def test_load_file_if_json_lines_not_attempted():
    assert malcolm_utils.LoadFileIfJson(io.StringIO('{"a": 1}\n{"b": 2}\n'), default='dflt') == 'dflt'


def test_load_file_if_json_no_valid_lines():
    assert malcolm_utils.LoadFileIfJson(io.StringIO('x\ny\n'), attemptLines=True, default='dflt') == 'dflt'


def test_load_file_if_json_none_handle():
    assert malcolm_utils.LoadFileIfJson(None, default='dflt') == 'dflt'


###################################################################################################
# file helpers


def test_base64_files_round_trip(tmp_path):
    src = tmp_path / 'src'
    (src / 'sub').mkdir(parents=True)
    (src / 'app.env').write_bytes(b'A=1\n')
    (src / 'sub' / 'what.env').write_bytes(b'\x00\xffbinary')
    (src / 'skip.txt').write_bytes(b'nope')

    encoded = malcolm_utils.base64_encode_files_in_dir(str(src), '*.env')
    assert sorted(encoded) == ['app.env', os.path.join('sub', 'what.env')]

    dest = tmp_path / 'dest'
    assert malcolm_utils.base64_decode_files_to_dir(encoded, str(dest)) == 2
    assert (dest / 'app.env').read_bytes() == b'A=1\n'
    assert (dest / 'sub' / 'what.env').read_bytes() == b'\x00\xffbinary'


@pytest.mark.parametrize(
    'rel_path',
    [
        '/etc/passwd',
        '../escape.env',
        'sub/../../escape.env',
        '',
        '.',
    ],
)
def test_base64_decode_files_to_dir_rejects_unsafe_paths(tmp_path, rel_path):
    dest = tmp_path / 'dest'
    written = malcolm_utils.base64_decode_files_to_dir({rel_path: b64encode(b'x').decode()}, str(dest))
    assert written == 0
    assert not (tmp_path / 'escape.env').exists()


def test_base64_decode_files_to_dir_rejects_symlink_escape(tmp_path):
    dest = tmp_path / 'dest'
    outside = tmp_path / 'outside'
    dest.mkdir()
    outside.mkdir()
    (dest / 'link').symlink_to(outside, target_is_directory=True)
    written = malcolm_utils.base64_decode_files_to_dir({'link/evil.env': b64encode(b'x').decode()}, str(dest))
    assert written == 0
    assert not (outside / 'evil.env').exists()


def test_base64_decode_files_to_dir_skips_pattern_mismatch_and_bad_base64(tmp_path):
    dest = tmp_path / 'dest'
    encoded = {
        'good.env': b64encode(b'ok').decode(),
        'bad.txt': b64encode(b'no').decode(),
        'broken.env': '!!!not base64!!!',
    }
    assert malcolm_utils.base64_decode_files_to_dir(encoded, str(dest), pattern='*.env') == 1
    assert sorted(os.listdir(dest)) == ['good.env']


def test_sha256sum_matches_hashlib(tmp_path):
    data = os.urandom(200 * 1024 + 17)  # more than one 64 KiB read
    path = tmp_path / 'data.bin'
    path.write_bytes(data)
    assert malcolm_utils.sha256sum(str(path)) == hashlib.sha256(data).hexdigest()


def test_sha256sum_empty_file(tmp_path):
    path = tmp_path / 'empty'
    path.write_bytes(b'')
    assert malcolm_utils.sha256sum(str(path)) == hashlib.sha256(b'').hexdigest()


def test_file_contents(tmp_path):
    text = tmp_path / 'text.txt'
    text.write_text('héllo', encoding='utf-8')
    binary = tmp_path / 'binary.bin'
    binary.write_bytes(b'\xff\xfe\x00')

    assert malcolm_utils.file_contents(str(text)) == 'héllo'
    assert malcolm_utils.file_contents(str(binary), binary_fallback=True) == b'\xff\xfe\x00'
    assert malcolm_utils.file_contents(str(tmp_path / 'missing')) is None
    with pytest.raises(UnicodeDecodeError):
        malcolm_utils.file_contents(str(binary))


def test_append_to_file(tmp_path):
    path = tmp_path / 'out.txt'
    malcolm_utils.append_to_file(str(path), 'a')
    malcolm_utils.append_to_file(str(path), ['\nb', 'c'])
    assert path.read_text() == 'a\nb\nc'


def test_rmtree_except_keeps_matching_files(tmp_path):
    root = tmp_path / 'root'
    (root / 'keep' / 'deep').mkdir(parents=True)
    (root / 'empty').mkdir()
    (root / 'a.keep').write_text('x')
    (root / 'b.del').write_text('x')
    (root / 'keep' / 'deep' / 'c.keep').write_text('x')
    (root / 'keep' / 'd.del').write_text('x')

    malcolm_utils.rmtree_except(str(root), exclude_patterns=['*.keep'])

    remaining = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
    assert remaining == ['a.keep', 'keep', os.path.join('keep', 'deep'), os.path.join('keep', 'deep', 'c.keep')]


def test_rmtree_except_removes_everything_without_exclusions(tmp_path):
    root = tmp_path / 'root'
    (root / 'sub').mkdir(parents=True)
    (root / 'sub' / 'f').write_text('x')
    malcolm_utils.rmtree_except(str(root))
    assert not root.exists()


def test_remove_empty_folders(tmp_path):
    root = tmp_path / 'root'
    (root / 'empty' / 'nested').mkdir(parents=True)
    (root / 'full').mkdir()
    (root / 'full' / 'f').write_text('x')

    malcolm_utils.RemoveEmptyFolders(str(root), removeRoot=False)
    assert sorted(p.name for p in root.iterdir()) == ['full']

    (root / 'full' / 'f').unlink()
    malcolm_utils.RemoveEmptyFolders(str(root))
    assert not root.exists()


def test_same_file_or_dir(tmp_path):
    path = tmp_path / 'f'
    path.write_text('x')
    assert malcolm_utils.same_file_or_dir(str(path), str(tmp_path / '.' / 'f')) is True
    assert malcolm_utils.same_file_or_dir(str(path), str(tmp_path)) is False
    assert malcolm_utils.same_file_or_dir(str(path), str(tmp_path / 'missing')) is False


###################################################################################################
# counters


def test_atomic_int_increment_decrement():
    counter = malcolm_utils.AtomicInt(5)
    assert counter.increment() == 6
    assert counter.decrement() == 5
    assert counter.value() == 5


def test_atomic_int_context_manager():
    counter = malcolm_utils.AtomicInt(0)
    with counter as value:
        assert value == 1
        assert counter.value() == 1
    assert counter.value() == 0


@pytest.mark.parametrize('starting_value', [0, 1, 5])
def test_atomic_int_context_manager_propagates_exceptions(starting_value):
    # a worker thread that raises inside "with workerThreadCount" must not have the exception swallowed
    counter = malcolm_utils.AtomicInt(starting_value)
    with pytest.raises(RuntimeError, match='boom'):
        with counter:
            raise RuntimeError('boom')
    assert counter.value() == starting_value


def test_atomic_int_is_thread_safe():
    counter = malcolm_utils.AtomicInt(0)

    def work():
        for _ in range(1000):
            counter.increment()

    threads = [threading.Thread(target=work) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert counter.value() == 8000


def test_count_until_exception():
    counter = malcolm_utils.CountUntilException(max=3, err='too many')
    assert counter.increment() is True
    assert counter.increment() is True
    with pytest.raises(ValueError, match='too many'):
        counter.increment()
