# pa-permission-access-path-tracer
Traces the exact path through permissions (groups, roles, policies) that grants a user or service principal access to a specific resource. Outputs a visual representation (e.g., graphviz format) of the access chain for easy understanding. - Focused on Tools for analyzing and assessing file system permissions

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
