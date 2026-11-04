# pa-permission-access-path-tracer

Traces the exact path through permissions (groups, roles, policies) that grants a user or service principal access to a specific resource. Outputs a visual representation (for example, graphviz format) of the access chain for easy understanding. Focused on tools for analyzing and assessing file system permissions.

The permissions data file is JSON in one of two shapes. It may be a plain list of permission entries, each an object with `principals`, `resource`, and `access_type`, and optionally `resource_type`. Or it may be an object with two keys: `permissions`, holding that same list of entries, and `memberships`, an optional map from a user name to the list of group and role names that user belongs to, for example `{"memberships": {"alice": ["devs", "readers"]}, "permissions": [...]}`. Before matching, group and role principals are expanded through the membership map, so a grant to one of the user's groups or roles counts. An entry that names a `resource_type` matches only a resource of that type.

Every run states how many permission entries were loaded. When no usable entries were loaded, the tool prints a no permission entries loaded line and exits 1 instead of reporting a no access verdict. In graphviz format there is one edge per granting entry.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-access-path-tracer.git
cd pa-permission-access-path-tracer
pip install -r requirements.txt
```

## Usage

```
python3 main.py --user USER --resource RESOURCE --permissions_data FILE [options]
```

## Parameters

- `--user`: Required. The user or service principal to trace access for.
- `--resource`: Required. The resource (file or directory path) to trace access to.
- `--resource_type`: File or directory, default `file`.
- `--permissions_data`: Required. Path to a JSON file containing permissions data.
- `--output_format`: `text` or `graphviz`, default `text`.
- `--log_level`: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL`, default `INFO`.

## Verified in this wave

`python3 main.py --help` could not run in this sandbox: the import guard exits 1 with "Error: Missing dependencies. Please install them using: pip install pathspec rich" because `pathspec` and `rich` are not installed, and installs are not made in this wave. Parameters above are taken from the argument parser in `main.py`, and `main.py` passes `py_compile`. Limits stated from the code, not recorded as passed runs: group expansion is one level only, so nested group membership is missed; no requested access type is supplied, so an entry granting only write still appears as an access path and the reader must check the printed type; in text mode the result is printed twice, once as a plain block and once as a rich tree.

## License

See LICENSE.
