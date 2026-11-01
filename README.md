# pa-permission-access-path-tracer
Traces the exact path through permissions (groups, roles, policies) that grants a user or service principal access to a specific resource. Outputs a visual representation (e.g., graphviz format) of the access chain for easy understanding. - Focused on Tools for analyzing and assessing file system permissions

The permissions data file is JSON in one of two shapes. It may be a plain list of permission entries, each an object with `principals`, `resource`, and `access_type`, and optionally `resource_type`. Or it may be an object with two keys: `permissions`, holding that same list of entries, and `memberships`, an optional map from a user name to the list of group and role names that user belongs to, for example `{"memberships": {"alice": ["devs", "readers"]}, "permissions": [...]}`. Before matching, group and role principals are expanded through the membership map, so a grant to one of the user's groups or roles counts. An entry that names a `resource_type` matches only a resource of that type.

Every run states how many permission entries were loaded. When no usable entries were loaded, the tool prints a no permission entries loaded line and exits 1 instead of reporting a no access verdict. In graphviz format there is one edge per granting entry.

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-access-path-tracer`

## Usage
`./pa-permission-access-path-tracer [params]`

## Parameters
- `-h`: Show help message and exit
- `--user`: The user or service principal to trace access for.
- `--resource`: No description provided
- `--resource_type`: No description provided
- `--permissions_data`: Path to a JSON file containing permissions data.
- `--output_format`: No description provided
- `--log_level`: Set the logging level.

## License
Copyright (c) ShadowGuardAI
