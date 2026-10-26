"""Regression tests for the configuration and parsing helpers in scripts/malcolm_common.py."""

import json
import os
import shutil
from types import SimpleNamespace

import pytest

import malcolm_common

###################################################################################################
# ParseK8sMemoryToMib


@pytest.mark.parametrize(
    'value, expected',
    [
        ('512Mi', 512),
        ('2Gi', 2048),
        ('1.5Gi', 1536),
        ('1Ti', 1024 * 1024),
        ('1024Ki', 1),
        ('2G', 1907),
        ('500M', 476),
        ('2000000k', 1907),
        ('1073741824', 1024),
        ('1e9', 953),
        ('1E', 953674316406),  # exabyte suffix, not an exponent
        (' 4Gi ', 4096),
        (2147483648, 2048),
    ],
)
def test_parse_k8s_memory_to_mib(value, expected):
    assert malcolm_common.ParseK8sMemoryToMib(value) == expected


@pytest.mark.parametrize('value', ['', 'junk', 'Gi', '2g', '2gi', '2 Gi', None])
def test_parse_k8s_memory_to_mib_unparseable(value):
    assert malcolm_common.ParseK8sMemoryToMib(value) == 0


###################################################################################################
# GetExposedPorts


def compose_with_ports(*ports, **services):
    services = services or {'svc': {'ports': list(ports)}}
    return {'services': services}


@pytest.mark.parametrize(
    'ports, expected',
    [
        (['8080:80'], ['8080']),
        (['0.0.0.0:443:443'], ['443']),
        (['127.0.0.1:9200:9200'], []),
        (['[::]:443:443'], ['443']),
        (['[::1]:9200:9200'], []),
        (['443'], []),
        ([443], []),
        (['443:443/tcp', '514:514/udp'], ['443', '514']),
        (['8000-8010:8000-8010'], ['8000:8010/tcp']),
        (['0.0.0.0:6000-6002:6000-6002/udp'], ['6000:6002/udp']),
        ([{'target': 80, 'published': '8443', 'host_ip': '0.0.0.0'}], ['8443']),
        ([{'target': 80, 'published': 8443}], ['8443']),
        ([{'target': 80, 'published': 8443, 'protocol': 'udp'}], ['8443']),
        ([{'target': 80}], []),
        ([{'target': 9200, 'published': 9200, 'host_ip': '127.0.0.1'}], []),
        (['9200:9200', '443:443', '80:80'], ['80', '443', '9200']),
    ],
)
def test_get_exposed_ports(ports, expected):
    assert malcolm_common.GetExposedPorts(compose_with_ports(*ports)) == expected


def test_get_exposed_ports_deduplicates_across_services():
    compose = compose_with_ports(a={'ports': ['443:443']}, b={'ports': ['0.0.0.0:443:443', '80:80']})
    assert malcolm_common.GetExposedPorts(compose) == ['80', '443']


@pytest.mark.parametrize('exclude', [{'8005'}, {8005}, ['8005']])
def test_get_exposed_ports_exclusions(exclude):
    compose = compose_with_ports('8005:8005', '443:443')
    assert malcolm_common.GetExposedPorts(compose, exclude_ports=exclude) == ['443']


@pytest.mark.parametrize(
    'compose',
    [
        {},
        {'services': None},
        {'services': {}},
        {'services': {'a': None}},
        {'services': {'a': {}}},
        {'services': {'a': {'ports': None}}},
    ],
)
def test_get_exposed_ports_missing_sections(compose):
    assert malcolm_common.GetExposedPorts(compose) == []


###################################################################################################
# NetBox autopopulation subnet filter

# examples from the "Subnets considered for autopopulation" section of docs/asset-interaction-analysis.md
DOCUMENTED_FILTERS = [
    '192.168.100.0/24',
    '!172.16.0.0/12',
    '!10.0.0.0/8,10.0.10.0/24',
    '10.0.0.0/8,!10.0.0.0/16,10.0.10.5/32',
    '!fc00::/7,fd12:3456:789a:1::/64',
    'site1:10.0.0.0/8,!10.0.0.0/16,10.0.10.5/32;site2:!172.16.0.0/12;site3:!fc00::/7,fd12:3456:789a:1::/64;!192.168.0.0/16',
]

# a real-world multi-site filter, with site names containing spaces and digits
MULTI_SITE_FILTER = (
    'Cyberville:10.10.10.0/24,10.10.20.0/24,10.10.30.0/24,192.168.0.0/24,10.10.100.0/24,10.0.0.0/24,103.82.4.0/24;'
    'NEIN:10.9.0.0/24,172.16.249.0/24;'
    'Virtual Boy:192.168.122.0/24;'
    'Digital Bond S4:10.200.1.0/24,10.100.1.0/24,10.50.1.0/24;'
    'M57 Patents:192.168.1.0/24,192.168.16.0/24,192.168.15.0/24'
)
MULTI_SITE_ENTRIES = [
    (
        'Cyberville',
        '10.10.10.0/24,10.10.20.0/24,10.10.30.0/24,192.168.0.0/24,10.10.100.0/24,10.0.0.0/24,103.82.4.0/24',
    ),
    ('NEIN', '10.9.0.0/24,172.16.249.0/24'),
    ('Virtual Boy', '192.168.122.0/24'),
    ('Digital Bond S4', '10.200.1.0/24,10.100.1.0/24,10.50.1.0/24'),
    ('M57 Patents', '192.168.1.0/24,192.168.16.0/24,192.168.15.0/24'),
]


@pytest.mark.parametrize(
    'entry, expected',
    [
        ('192.168.100.0/24', ('*', '192.168.100.0/24')),
        ('fe80::/10', ('*', 'fe80::/10')),
        ('2001:db8::/32', ('*', '2001:db8::/32')),
        ('fd12:3456:789a:1::5/64', ('*', 'fd12:3456:789a:1::5/64')),
        ('!fc00::/7,fd12:3456:789a:1::/64', ('*', '!fc00::/7,fd12:3456:789a:1::/64')),
        ('site3:!fc00::/7,fd12:3456:789a:1::/64', ('site3', '!fc00::/7,fd12:3456:789a:1::/64')),
        ('site1:10.0.0.0/8', ('site1', '10.0.0.0/8')),
        ('1:10.0.0.0/8', ('1', '10.0.0.0/8')),
        ('*:fe80::/10', ('*', 'fe80::/10')),
        (' site1 : 10.0.0.0/8 ', ('site1', ' 10.0.0.0/8')),
        ('my site:10.0.0.0/8', ('my site', '10.0.0.0/8')),
    ],
)
def test_split_netbox_subnet_filter_site(entry, expected):
    assert malcolm_common.SplitNetBoxSubnetFilterSite(entry) == expected


def test_split_netbox_subnet_filter_site_documented_ambiguity():
    # a numeric site ID followed by IPv6 can fuse into one valid IPv6 CIDR; the docs say to use a site name instead
    assert malcolm_common.SplitNetBoxSubnetFilterSite('2:2001:db8::/32') == ('*', '2:2001:db8::/32')


@pytest.mark.parametrize('value', DOCUMENTED_FILTERS + [MULTI_SITE_FILTER])
def test_documented_filters_are_valid(value):
    assert malcolm_common.ValidNetBoxSubnetFilter(value) is True


@pytest.mark.parametrize(
    'value',
    DOCUMENTED_FILTERS + [MULTI_SITE_FILTER, 'fe80::/10, 10.0.0.0/8', ' site1: 10.0.0.0/8 , !10.1.0.0/16 ; '],
)
def test_formatted_filters_stay_valid_and_stable(value):
    formatted = malcolm_common.FormatNetBoxSubnetFilter(value)
    assert malcolm_common.ValidNetBoxSubnetFilter(formatted) is True
    assert malcolm_common.FormatNetBoxSubnetFilter(formatted) == formatted
    # every formatted entry carries an explicit site key
    for entry in formatted.split(';'):
        site_key, cidr_list = entry.split(':', 1)
        assert site_key
        assert malcolm_common.SplitNetBoxSubnetFilterSite(entry) == (site_key, cidr_list)


def test_multi_site_filter_splits_into_named_sites():
    entries = [malcolm_common.SplitNetBoxSubnetFilterSite(e) for e in MULTI_SITE_FILTER.split(';')]
    assert entries == MULTI_SITE_ENTRIES


def test_multi_site_filter_format_keeps_spaces_in_site_names():
    # whitespace is stripped from the CIDR lists only, so "Virtual Boy" doesn't become "VirtualBoy"
    assert malcolm_common.FormatNetBoxSubnetFilter(MULTI_SITE_FILTER) == MULTI_SITE_FILTER


@pytest.mark.parametrize(
    'value, expected',
    [
        ('192.168.100.0/24', '*:192.168.100.0/24'),
        ('fe80::/10', '*:fe80::/10'),
        ('fe80::/10, 10.0.0.0/8', '*:fe80::/10,10.0.0.0/8'),
        ('site1: 10.0.0.0/8 , !10.1.0.0/16 ; ', 'site1:10.0.0.0/8,!10.1.0.0/16'),
        ('site1:10.0.0.0/8;!192.168.0.0/16', 'site1:10.0.0.0/8;*:!192.168.0.0/16'),
        ('', ''),
        ('   ', ''),
        (None, ''),
    ],
)
def test_format_netbox_subnet_filter(value, expected):
    assert malcolm_common.FormatNetBoxSubnetFilter(value) == expected


@pytest.mark.parametrize(
    'value, expected',
    [
        ('', True),
        ('   ', True),
        ('10.0.0.5', True),
        ('10.0.0.0/8,,', True),
        ('site:garbage', False),
        (':10.0.0.0/8', False),
        ('10.0.0.0/33', False),
        ('site1:', False),
        ('site1:10.0.0.0/8;site2:nope', False),
        ('!', False),
    ],
)
def test_valid_netbox_subnet_filter(value, expected):
    assert malcolm_common.ValidNetBoxSubnetFilter(value) is expected


###################################################################################################
# compose volume helpers


def test_local_path_for_container_bind_mount_short_syntax():
    compose = {'services': {'zeek': {'volumes': ['./zeek-logs:/zeek/logs:rw', '/abs/pcap:/pcap:ro']}}}
    assert malcolm_common.LocalPathForContainerBindMount('zeek', compose, '/pcap') == '/abs/pcap'
    assert malcolm_common.LocalPathForContainerBindMount('zeek', compose, '/zeek/logs') == './zeek-logs'


def test_local_path_for_container_bind_mount_relative_to_base(tmp_path):
    compose = {'services': {'zeek': {'volumes': ['./zeek-logs:/zeek/logs', '/abs/pcap:/pcap']}}}
    assert malcolm_common.LocalPathForContainerBindMount(
        'zeek', compose, '/zeek/logs', local_base_path=str(tmp_path)
    ) == os.path.realpath(tmp_path / 'zeek-logs')
    # absolute sources are left alone
    assert (
        malcolm_common.LocalPathForContainerBindMount('zeek', compose, '/pcap', local_base_path=str(tmp_path))
        == '/abs/pcap'
    )


def test_local_path_for_container_bind_mount_long_syntax(tmp_path):
    compose = {'services': {'zeek': {'volumes': [{'type': 'bind', 'source': './pcap', 'target': '/pcap'}]}}}
    assert malcolm_common.LocalPathForContainerBindMount('zeek', compose, '/pcap') == './pcap'
    assert malcolm_common.LocalPathForContainerBindMount(
        'zeek', compose, '/pcap', local_base_path=str(tmp_path)
    ) == os.path.realpath(tmp_path / 'pcap')


@pytest.mark.parametrize(
    'service, compose, container_path',
    [
        ('zeek', {'services': {'zeek': {'volumes': ['./x:/other']}}}, '/pcap'),
        ('zeek', {'services': {'zeek': {}}}, '/pcap'),
        ('missing', {'services': {'zeek': {'volumes': ['./x:/pcap']}}}, '/pcap'),
        ('zeek', {'services': {'zeek': {'volumes': ['./x:/pcap/upload']}}}, '/pcap'),
        (None, {'services': {}}, '/pcap'),
        ('zeek', None, '/pcap'),
        ('zeek', {'services': {'zeek': {'volumes': ['./x:/pcap']}}}, None),
    ],
)
def test_local_path_for_container_bind_mount_not_found(service, compose, container_path):
    assert malcolm_common.LocalPathForContainerBindMount(service, compose, container_path) is None


def test_remap_bound_paths():
    compose = {
        'services': {
            'zeek': {
                'volumes': [
                    './pcap:/pcap:ro',
                    './pcap/upload:/pcap/upload',
                    {'type': 'bind', 'source': './zeek-logs', 'target': '/zeek/logs'},
                    'named-volume:/var/lib/data',
                ]
            },
            'arkime': {'volumes': ['./pcap:/pcap']},
            'novolumes': {},
        }
    }
    replacers = (
        malcolm_common.BoundPathReplacer('zeek', '/pcap', '/new/pcap'),
        malcolm_common.BoundPathReplacer('zeek', '/zeek/logs', '/new/logs'),
        malcolm_common.BoundPathReplacer('novolumes', '/pcap', '/new/pcap'),
        malcolm_common.BoundPathReplacer('missing', '/pcap', '/new/pcap'),
    )
    assert malcolm_common.RemapBoundPaths(compose, replacers) == 2
    assert compose['services']['zeek']['volumes'] == [
        '/new/pcap:/pcap:ro',
        './pcap/upload:/pcap/upload',
        {'type': 'bind', 'source': '/new/logs', 'target': '/zeek/logs'},
        'named-volume:/var/lib/data',
    ]
    assert compose['services']['arkime']['volumes'] == ['./pcap:/pcap']


def test_build_bound_path_replacers_uses_supplied_dirs():
    replacers = malcolm_common.BuildBoundPathReplacers(
        pcap_dir='/p', suricata_log_dir='/s', zeek_log_dir='/z', filescan_log_dir='/f', index_dir='/i', index_snapshot_dir='/b'
    )
    by_key = {(r.service, r.target): r.source for r in replacers}
    assert by_key[('arkime', malcolm_common.PCAP_DATA_CONTAINER_PATH)] == '/p'
    assert by_key[('zeek', malcolm_common.ZEEK_EXTRACT_FILES_CONTAINER_PATH)] == os.path.join('/z', 'extract_files')
    assert by_key[('opensearch', malcolm_common.OPENSEARCH_DATA_CONTAINER_PATH)] == '/i'
    assert by_key[('opensearch', malcolm_common.OPENSEARCH_BACKUP_CONTAINER_PATH)] == '/b'
    assert len(by_key) == len(replacers)


###################################################################################################
# memory, CPU and value parsing


@pytest.mark.parametrize(
    'value, expected',
    [
        ('-Xmx4g -Xms4g', 4096),
        ('-Xms1g -Xmx4g', 4096),  # Xmx wins over Xms regardless of order
        ('-Xms2g', 2048),
        ('-Xmx512m', 512),
        ('-XMX2G', 2048),
        ('-Xmx512k', 1),
        ('-Xmx2048k', 2),
        ('-Xmx4096', 0),
        ('-Dfoo=bar', 0),
        ('', 0),
    ],
)
def test_get_mem_megabytes_from_java_opts_line(value, expected):
    assert malcolm_common.GetMemMegabytesFromJavaOptsLine(value) == expected


@pytest.mark.parametrize(
    'total_gb, expected',
    [
        (2, '4g'),
        (8, '4g'),
        (10, '5g'),
        (32, '16g'),
        (62, '31g'),
        (64, '31g'),
        (512, '31g'),
    ],
)
def test_suggest_os_memory(total_gb, expected):
    assert malcolm_common.suggest_os_memory(total_gb) == expected


@pytest.mark.parametrize(
    'total_gb, expected',
    [
        (4, '2500m'),
        (16, '2500m'),
        (17, '2901m'),
        (24, '3072m'),
        (32, '3072m'),
        (64, '3072m'),
    ],
)
def test_suggest_ls_memory(total_gb, expected):
    assert malcolm_common.suggest_ls_memory(total_gb) == expected


@pytest.mark.parametrize('cores, expected', [(1, 1), (2, 1), (3, 1), (4, 2), (6, 3), (64, 3)])
def test_suggest_ls_workers(cores, expected):
    assert malcolm_common.suggest_ls_workers(cores) == expected


def test_suggestions_use_system_facts_by_default(monkeypatch):
    monkeypatch.setattr(malcolm_common, 'total_memory_gb', lambda: 20)
    monkeypatch.setattr(malcolm_common, 'cpu_cores', lambda: 8)
    assert malcolm_common.suggest_os_memory() == '10g'
    assert malcolm_common.suggest_ls_memory() == '3072m'
    assert malcolm_common.suggest_ls_workers() == 3


@pytest.mark.parametrize('value, expected', [('5', 5), (5, 5), ('1', 1), (None, None)])
def test_pos_int(value, expected):
    assert malcolm_common.posInt(value) == expected


@pytest.mark.parametrize('value', ['0', 0, '-1', 'abc', '1.5'])
def test_pos_int_invalid(value):
    with pytest.raises(ValueError):
        malcolm_common.posInt(value)


@pytest.mark.parametrize(
    'value, expected',
    [
        (True, malcolm_common.BoolOrExtra.TRUE),
        (False, malcolm_common.BoolOrExtra.FALSE),
        ('Yes', malcolm_common.BoolOrExtra.TRUE),
        ('1', malcolm_common.BoolOrExtra.TRUE),
        ('n', malcolm_common.BoolOrExtra.FALSE),
        ('0', malcolm_common.BoolOrExtra.FALSE),
        ('b', malcolm_common.BoolOrExtra.EXTRA),
        ('Back', malcolm_common.BoolOrExtra.EXTRA),
        ('previous', malcolm_common.BoolOrExtra.EXTRA),
        ('extra', malcolm_common.BoolOrExtra.EXTRA),
    ],
)
def test_str2boolorextra(value, expected):
    assert malcolm_common.str2boolorextra(value) == expected


@pytest.mark.parametrize('value', ['maybe', '', None, 1])
def test_str2boolorextra_invalid(value):
    with pytest.raises(ValueError):
        malcolm_common.str2boolorextra(value)


###################################################################################################
# dialog sizing


@pytest.fixture
def terminal_size(monkeypatch):
    def set_size(columns, lines):
        monkeypatch.setattr(shutil, 'get_terminal_size', lambda fallback=None: os.terminal_size((columns, lines)))

    return set_size


def test_dialog_size_short_prompt_uses_minimums(terminal_size):
    terminal_size(200, 60)
    assert malcolm_common._dialog_size_for('Short prompt') == (
        malcolm_common._DIALOG_MIN_HEIGHT,
        malcolm_common._DIALOG_MIN_WIDTH,
    )


def test_dialog_size_long_prompt_is_capped(terminal_size):
    terminal_size(400, 200)
    height, width = malcolm_common._dialog_size_for('x' * 1000 + '\n' + 'y\n' * 100)
    assert width == malcolm_common._DIALOG_MAX_WIDTH
    assert height == malcolm_common._DIALOG_MAX_HEIGHT


@pytest.mark.parametrize('columns, lines', [(30, 10), (10, 5), (5, 3)])
def test_dialog_size_fits_small_terminals(terminal_size, columns, lines):
    terminal_size(columns, lines)
    height, width = malcolm_common._dialog_size_for('A prompt that is longer than the terminal is wide\nand two lines')
    assert 1 <= width <= max(1, columns - malcolm_common._DIALOG_TERMINAL_WIDTH_MARGIN)
    assert 1 <= height <= max(1, lines - malcolm_common._DIALOG_TERMINAL_HEIGHT_MARGIN)


def test_dialog_size_wraps_long_lines_into_height(terminal_size):
    terminal_size(80, 60)
    one_line = malcolm_common._dialog_size_for('x' * 72)
    wrapped = malcolm_common._dialog_size_for('x' * 300)
    assert wrapped[1] == one_line[1] == 76
    assert wrapped[0] > one_line[0]


def test_dialog_menu_width():
    assert malcolm_common._dialog_menu_width_for([]) == malcolm_common._DIALOG_MIN_WIDTH
    assert malcolm_common._dialog_menu_width_for(None) == malcolm_common._DIALOG_MIN_WIDTH
    assert malcolm_common._dialog_menu_width_for([('tag', 'x' * 60, False)]) == 3 + 2 + 60 + 8 + 6
    assert malcolm_common._dialog_menu_width_for([('tag', 'x' * 500, False)]) == malcolm_common._DIALOG_MAX_WIDTH
    # malformed choices are ignored
    assert malcolm_common._dialog_menu_width_for([('tag', 'x' * 60)]) == malcolm_common._DIALOG_MIN_WIDTH


###################################################################################################
# get_malcolm_version

# the compose file is written as JSON (which is also YAML) and read with a stand-in for ruamel.yaml
_JSON_YAML = SimpleNamespace(YAML=lambda typ=None, pure=None: SimpleNamespace(load=json.load))


@pytest.fixture
def compose_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(malcolm_common, 'YAMLDynamic', lambda *a, **k: _JSON_YAML)
    monkeypatch.setattr(malcolm_common, 'get_malcolm_dir', lambda: str(tmp_path))
    return tmp_path


def write_compose(directory, *images):
    services = {f'svc{i}': ({'image': image} if image else {}) for i, image in enumerate(images)}
    (directory / 'docker-compose.yml').write_text(json.dumps({'services': services}))


@pytest.mark.parametrize(
    'images, expected',
    [
        (['ghcr.io/idaholab/malcolm/zeek:26.10.0', 'ghcr.io/idaholab/malcolm/arkime:26.9.1'], '26.10.0'),
        (['ghcr.io/idaholab/malcolm/zeek:26.10.0', 'ghcr.io/idaholab/malcolm/arkime:26.10.1-rc1'], '26.10.1'),
        (['ghcr.io/idaholab/malcolm/zeek:26.9.0+build5', 'redis:7.2'], '26.9.0'),
        (['ghcr.io/idaholab/malcolm/zeek:26.10.0', 'ghcr.io/idaholab/malcolm/arkime:main', None], '26.10.0'),
    ],
)
def test_get_malcolm_version_highest_calver(compose_dir, images, expected):
    write_compose(compose_dir, *images)
    assert malcolm_common.get_malcolm_version() == expected


@pytest.mark.parametrize(
    'images',
    [
        ['ghcr.io/idaholab/malcolm/zeek:main', 'ghcr.io/idaholab/malcolm/arkime:latest'],
        ['ghcr.io/idaholab/malcolm/zeek'],
        [None],
    ],
)
def test_get_malcolm_version_falls_back_without_calver_tags(compose_dir, images):
    write_compose(compose_dir, *images)
    assert malcolm_common.get_malcolm_version() == malcolm_common.MALCOLM_VERSION


def test_get_malcolm_version_falls_back_without_compose_file(compose_dir):
    assert malcolm_common.get_malcolm_version() == malcolm_common.MALCOLM_VERSION


def test_get_malcolm_version_falls_back_without_yaml(monkeypatch, tmp_path):
    monkeypatch.setattr(malcolm_common, 'YAMLDynamic', lambda *a, **k: None)
    monkeypatch.setattr(malcolm_common, 'get_malcolm_dir', lambda: str(tmp_path))
    write_compose(tmp_path, 'ghcr.io/idaholab/malcolm/zeek:1.0.0')
    assert malcolm_common.get_malcolm_version() == malcolm_common.MALCOLM_VERSION
