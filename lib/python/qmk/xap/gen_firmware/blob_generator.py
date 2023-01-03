"""This script generates the XAP info.json payload header to be compiled into QMK.
"""
import json
import gzip
from milc import cli
from pathlib import Path
from pprint import pformat

from qmk.info import keymap_json
from qmk.commands import get_chunks, dump_lines
from qmk.json_schema import deep_update, json_load
from qmk.json_encoders import InfoJSONEncoder
from qmk.constants import GPL2_HEADER_C_LIKE, GENERATED_HEADER_C_LIKE


def _build_info(keyboard, keymap, consolidate_layouts=True):
    """Build the xap version of info.json
    """
    defaults_json = json_load(Path('data/mappings/xap_defaults.json'))
    km_info_json = keymap_json(keyboard, keymap)

    info_json = {}
    deep_update(info_json, defaults_json)
    deep_update(info_json, km_info_json)

    # TODO: Munge to XAP requirements
    info_json.pop('config_h_features', None)
    info_json.pop('keymaps', None)
    info_json.pop('parse_errors', None)
    info_json.pop('parse_warnings', None)
    info_json.get('usb', {}).pop('device_ver', None)
    for layout in info_json.get('layouts', {}).values():
        layout.pop('filename', None)
        layout.pop('c_macro', None)
        for item in layout.get('layout', []):
            item.pop('label', None)

    if consolidate_layouts:
        # Determine the layout we want to use as the base
        base_layout = 'LAYOUT_all'
        if 'layout_aliases' in info_json:
            if 'LAYOUT_all' in info_json['layout_aliases']:
                base_layout = info_json['layout_aliases']['LAYOUT_all']
            elif 'LAYOUT' in info_json['layout_aliases']:
                base_layout = info_json['layout_aliases']['LAYOUT']
        if base_layout not in info_json['layouts']:
            base_layout = list(info_json['layouts'].keys())[0]
            cli.log.warning('Unable to find base layout, selecting %s: %s', base_layout, pformat(set(info_json['layouts'].keys())))
        info_json['base_layout'] = base_layout

        base_layout_keys = set([pformat(k) for k in info_json['layouts'][base_layout]['layout']])
        for name in info_json['layouts'].keys():
            keys = info_json['layouts'][name]['layout']
            this_keys = set()
            for key in keys:
                this_keys.add(pformat(key))
            if name != base_layout:
                del info_json['layouts'][name]['layout']
                removed_keys = sorted([{'matrix': eval(k)['matrix']} for k in base_layout_keys.difference(this_keys)], key=lambda k: k['matrix'])
                info_json['layouts'][name]['remove'] = removed_keys
                added_keys = sorted([eval(k) for k in this_keys.difference(base_layout_keys)], key=lambda k: k['matrix'])
                info_json['layouts'][name]['add'] = added_keys

    return info_json


def generate_blob(output_file, keyboard, keymap):
    """Generate XAP payload
    """

    def _generate_compressed_blob(consolidate_layouts):
        info_json = _build_info(keyboard, keymap, consolidate_layouts)

        # Minify
        str_data = json.dumps(info_json, separators=(',', ':'))

        # Compress
        return (info_json, gzip.compress(str_data.encode("utf-8"), compresslevel=9))

    # Work out which one is smaller
    (info_json_a, compressed_a) = _generate_compressed_blob(True)
    (info_json_b, compressed_b) = _generate_compressed_blob(False)
    info_json = info_json_a if len(compressed_a) < len(compressed_b) else info_json_b
    compressed = compressed_a if len(compressed_a) < len(compressed_b) else compressed_b

    # split into lines to match xxd output
    hex_array = ["0x{:02X}".format(b) for b in compressed]
    data_len = len(hex_array)

    data = ""
    for chunk in get_chunks(hex_array, 12):
        data += f'  {", ".join(chunk)},\n'

    lines = [GPL2_HEADER_C_LIKE, GENERATED_HEADER_C_LIKE, '#pragma once', '']

    lines.append('#if 0')
    lines.append('// Blob contains a minified+gzipped version of the following:')
    lines.append(json.dumps(info_json, cls=InfoJSONEncoder))
    lines.append('#endif')
    lines.append('')

    # Gen output file
    lines.append('static const unsigned char config_blob_gz[] PROGMEM = {')
    lines.append(data)
    lines.append('};')
    lines.append(f'#define CONFIG_BLOB_GZ_LEN {data_len}')

    dump_lines(output_file, lines)
