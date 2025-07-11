import argparse
import logging
import sys
import os
from typing import List, Dict, Any

# Dependencies from the tool definition
try:
    import pathspec
    from rich.console import Console
    from rich.tree import Tree
    from rich.style import Style
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them using: pip install pathspec rich", file=sys.stderr)
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

# Constants
RESOURCE_TYPE_FILE = "file"
RESOURCE_TYPE_DIRECTORY = "directory"


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Traces the permission access path for a user/service principal to a resource."
    )
    parser.add_argument(
        "--user",
        type=str,
        required=True,
        help="The user or service principal to trace access for.",
    )
    parser.add_argument(
        "--resource",
        type=str,
        required=True,
        help="The resource (file or directory path) to trace access to.",
    )
    parser.add_argument(
        "--resource_type",
        type=str,
        choices=[RESOURCE_TYPE_FILE, RESOURCE_TYPE_DIRECTORY],
        default=RESOURCE_TYPE_FILE,
        help="The type of resource (file or directory).",
    )
    parser.add_argument(
        "--permissions_data",
        type=str,
        required=True,
        help="Path to a JSON file containing permissions data.",
    )
    parser.add_argument(
        "--output_format",
        type=str,
        choices=["text", "graphviz"],
        default="text",
        help="Output format (text or graphviz).",
    )
    parser.add_argument(
        "--log_level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set the logging level.",
    )
    return parser


def load_permissions_data(file_path: str) -> List[Dict[str, Any]]:
    """
    Loads permissions data from a JSON file.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        List[Dict[str, Any]]: A list of permission objects.
    """
    import json

    try:
        with open(file_path, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError("Permissions data must be a list of dictionaries.")
            return data
    except FileNotFoundError:
        logging.error(f"Permissions data file not found: {file_path}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in file: {file_path}")
        raise
    except ValueError as e:
        logging.error(str(e))
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        raise


def check_access(
    user: str,
    resource: str,
    resource_type: str,
    permissions_data: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Checks if a user has access to a resource based on the provided permissions data.

    Args:
        user (str): The user to check access for.
        resource (str): The resource to check access to.
        resource_type (str): The type of resource (file or directory).
        permissions_data (List[Dict[str, Any]]): The permissions data.

    Returns:
        List[Dict[str, Any]]: A list of permission entries that grant access. Empty list if no access.
    """

    access_path: List[Dict[str, Any]] = []

    for permission_entry in permissions_data:
        try:
            # Input Validation
            if not isinstance(permission_entry, dict):
                logging.warning(
                    f"Skipping invalid permission entry: {permission_entry}.  Expected a dictionary."
                )
                continue

            if "principals" not in permission_entry or "resource" not in permission_entry or "access_type" not in permission_entry:
                logging.warning(f"Skipping permission entry due to missing keys: {permission_entry}")
                continue

            principals = permission_entry["principals"]
            resource_pattern = permission_entry["resource"]
            access_type = permission_entry["access_type"] # e.g., "read", "write", "execute"


            if not isinstance(principals, list):
                logging.warning(f"Skipping permission entry. Principals must be a list: {permission_entry}")
                continue

            # Check if the user is in the list of principals
            if user not in principals:
                continue

            # Use pathspec to match resource paths. Handle errors during pathspec compilation.
            try:
                spec = pathspec.PathSpec.from_lines(
                    pathspec.patterns.GitWildMatchPattern, [resource_pattern]
                )
                if spec.match_file(resource):  # Use match_file for safety
                    access_path.append(permission_entry)
            except Exception as e:
                logging.error(f"Error processing pathspec for resource {resource_pattern}: {e}")


        except Exception as e:
            logging.error(f"Error processing permission entry: {permission_entry} - {e}")

    return access_path


def format_access_path(access_path: List[Dict[str, Any]], output_format: str) -> str:
    """
    Formats the access path into a human-readable string or graphviz format.

    Args:
        access_path (List[Dict[str, Any]]): The list of permission entries that grant access.
        output_format (str): The desired output format ("text" or "graphviz").

    Returns:
        str: The formatted access path.
    """
    if not access_path:
        return "No access granted."

    if output_format == "text":
        output = "Access granted via the following permissions:\n"
        for i, entry in enumerate(access_path):
            output += f"  {i+1}. Resource: {entry['resource']}, Principals: {entry['principals']}, Access Type: {entry['access_type']}\n"
        return output
    elif output_format == "graphviz":
        # Graphviz output (requires graphviz library) - Not fully implemented as per reqs.
        # This is a placeholder.  A full implementation would generate DOT language output.
        output = "digraph AccessPath {\n"
        output += '  node [shape=box];\n'
        output += f'  "{user}" -> "{resource}" [label="{access_path[0]["access_type"] if access_path else "N/A"}"];\n' # Placeholder
        output += "}"
        return output
    else:
        return "Invalid output format."


def display_access_path(access_path: List[Dict[str, Any]], user: str, resource:str):
    """
    Displays the access path using rich.tree.

    Args:
        access_path (List[Dict[str, Any]]): The list of permission entries that grant access.
        user (str): User to analyze
        resource(str): Resource to analyze
    """

    console = Console()
    tree = Tree(f"[bold blue]Access Path for User: {user} to Resource: {resource}[/]")

    if not access_path:
        tree.add("[red]No access granted.[/]")
        console.print(tree)
        return

    for i, entry in enumerate(access_path):
        branch = tree.add(f"[bold green]Permission Entry {i+1}[/]")
        branch.add(f"Resource: [yellow]{entry['resource']}[/]")
        branch.add(f"Principals: [cyan]{', '.join(entry['principals'])}[/]")
        branch.add(f"Access Type: [magenta]{entry['access_type']}[/]")

    console.print(tree)

def main():
    """
    Main function to execute the permission access path tracer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging level
    logging.getLogger().setLevel(args.log_level)

    # Input validation for file existence
    if not os.path.exists(args.permissions_data):
        logging.error(f"Permissions data file not found: {args.permissions_data}")
        print(f"Error: Permissions data file not found: {args.permissions_data}", file=sys.stderr)
        sys.exit(1)

    try:
        permissions_data = load_permissions_data(args.permissions_data)
        access_path = check_access(
            args.user, args.resource, args.resource_type, permissions_data
        )

        if args.output_format == 'text':
            formatted_output = format_access_path(access_path, args.output_format)
            print(formatted_output)
        else:
            formatted_output = format_access_path(access_path, args.output_format)
            print(formatted_output)
            # To visualize this graphviz output, you'd need to save it to a .dot file
            # and then use the graphviz command-line tools (e.g., `dot -Tpng output.dot -o output.png`).

        display_access_path(access_path, args.user, args.resource)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Example Usage:
    # To run this, you would first need a permissions_data.json file.
    # Example permissions_data.json:
    # [
    #   {"principals": ["user1", "group1"], "resource": "/data/*", "access_type": "read"},
    #   {"principals": ["user2"], "resource": "/logs/*.log", "access_type": "write"},
    #   {"principals": ["group1"], "resource": "/config/app.conf", "access_type": "read"}
    # ]
    #
    # Command line example:
    # python main.py --user user1 --resource /data/sensitive_file.txt --resource_type file --permissions_data permissions_data.json --output_format text
    main()