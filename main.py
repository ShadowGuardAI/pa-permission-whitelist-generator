import argparse
import logging
import json
import os
import sys
from typing import List, Dict

try:
    import pathspec
    from rich.console import Console
    from rich.table import Column, Table
    from rich.syntax import Syntax
except ImportError:
    print("Required packages not found. Please install them with: pip install pathspec rich")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_OUTPUT_FILE = "permission_whitelist.json"
DEFAULT_CONFIG_FILE = "config.json"  #Configurable whitelist config options

def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Generates a least-privilege permission whitelist based on observed application behavior."
    )

    parser.add_argument(
        "-i",
        "--input",
        dest="input_file",
        required=True,
        help="Path to the input file containing observed application behavior (e.g., system calls, file access).",
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        default=DEFAULT_OUTPUT_FILE,
        help=f"Path to the output file to store the generated permission whitelist (default: {DEFAULT_OUTPUT_FILE}).",
    )

    parser.add_argument(
        "-c",
        "--config",
        dest="config_file",
        default=DEFAULT_CONFIG_FILE,
        help=f"Path to the configuration file containing filtering rules (default: {DEFAULT_CONFIG_FILE}).",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode for more verbose logging.",
    )

    parser.add_argument(
        "-s",
        "--simulate",
        action="store_true",
        help="Simulate the whitelist generation without writing to the output file.",
    )

    return parser


def load_observed_behavior(input_file: str) -> List[str]:
    """
    Loads observed application behavior from the input file.

    Args:
        input_file (str): Path to the input file.

    Returns:
        List[str]: A list of strings, where each string represents an observed action (e.g., file access path).

    Raises:
        FileNotFoundError: If the input file does not exist.
        IOError: If there is an error reading the input file.
    """
    try:
        with open(input_file, "r") as f:
            observed_behavior = [line.strip() for line in f]
        logging.info(f"Successfully loaded {len(observed_behavior)} observed behaviors from {input_file}")
        return observed_behavior
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
        raise
    except IOError as e:
        logging.error(f"Error reading input file: {e}")
        raise


def load_config(config_file: str) -> Dict:
    """
    Loads configuration options from a JSON file.  Includes whitelist and blacklist rules.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        Dict: A dictionary containing configuration options.

    Raises:
        FileNotFoundError: If the config file does not exist.
        json.JSONDecodeError: If the config file is not valid JSON.
    """
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        logging.info(f"Successfully loaded configuration from {config_file}")
        return config
    except FileNotFoundError:
        logging.error(f"Config file not found: {config_file}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON in config file: {e}")
        raise


def filter_observed_behavior(observed_behavior: List[str], config: Dict) -> List[str]:
    """
    Filters the observed behavior based on whitelist and blacklist rules defined in the config.

    Args:
        observed_behavior (List[str]): A list of observed behaviors.
        config (Dict): A dictionary containing filtering rules (whitelist and blacklist).

    Returns:
        List[str]: A filtered list of observed behaviors.
    """

    whitelists = config.get("whitelists", [])
    blacklists = config.get("blacklists", [])

    # Compile whitelist patterns
    whitelist_spec = pathspec.PathSpec.from_lines("gitwildmatch", whitelists)
    blacklist_spec = pathspec.PathSpec.from_lines("gitwildmatch", blacklists)


    filtered_behavior = []
    for behavior in observed_behavior:
        if blacklist_spec.match_file(behavior):
            logging.debug(f"Behavior '{behavior}' matched blacklist, skipping.")
            continue  # Skip if matches a blacklist pattern. Prevents items in both lists from being allowed.
        if whitelist_spec.match_file(behavior):
            filtered_behavior.append(behavior)
            logging.debug(f"Behavior '{behavior}' matched whitelist, adding to whitelist.")
        else:
            logging.debug(f"Behavior '{behavior}' did not match whitelist and not in blacklist, skipping.")

    logging.info(f"Filtered observed behavior: {len(filtered_behavior)} entries remain after filtering.")
    return filtered_behavior


def generate_permission_whitelist(filtered_behavior: List[str]) -> Dict:
    """
    Generates a permission whitelist from the filtered observed behavior.

    Args:
        filtered_behavior (List[str]): A list of filtered observed behaviors.

    Returns:
        Dict: A dictionary representing the permission whitelist.  This can be extended to include permissions information
              beyond just file paths.
    """
    # Basic implementation: Just returns the unique set of file paths.
    #  This could be extended to analyze the paths and group them or assign permissions.

    permission_whitelist = {"allowed_paths": sorted(list(set(filtered_behavior)))} #remove duplicates, sort list

    logging.info(f"Generated permission whitelist with {len(permission_whitelist['allowed_paths'])} entries.")
    return permission_whitelist


def save_permission_whitelist(permission_whitelist: Dict, output_file: str) -> None:
    """
    Saves the permission whitelist to the output file in JSON format.

    Args:
        permission_whitelist (Dict): The permission whitelist to save.
        output_file (str): The path to the output file.

    Raises:
        IOError: If there is an error writing to the output file.
    """
    try:
        with open(output_file, "w") as f:
            json.dump(permission_whitelist, f, indent=4)
        logging.info(f"Successfully saved permission whitelist to {output_file}")
    except IOError as e:
        logging.error(f"Error writing to output file: {e}")
        raise


def print_whitelist_rich(whitelist: Dict) -> None:
  """Prints the generated whitelist using Rich for enhanced readability."""
  console = Console()

  table = Table(title="Generated Permission Whitelist")
  table.add_column("Path", style="cyan", width=60)

  for path in whitelist["allowed_paths"]:
    table.add_row(path)

  console.print(table)


def main():
    """
    Main function to orchestrate the permission whitelist generation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled.")

    try:
        # 1. Load Observed Behavior
        observed_behavior = load_observed_behavior(args.input_file)

        # 2. Load Configuration
        config = load_config(args.config_file)

        # 3. Filter Observed Behavior
        filtered_behavior = filter_observed_behavior(observed_behavior, config)

        # 4. Generate Permission Whitelist
        permission_whitelist = generate_permission_whitelist(filtered_behavior)

        # 5. Output
        print_whitelist_rich(permission_whitelist)  # Print to console

        if not args.simulate:
            save_permission_whitelist(permission_whitelist, args.output_file)
        else:
            logging.info("Simulation mode: Whitelist not saved to file.")

        logging.info("Permission whitelist generation completed successfully.")

    except FileNotFoundError:
        sys.exit(1)
    except json.JSONDecodeError:
        sys.exit(1)
    except IOError:
        sys.exit(1)
    except Exception as e:  # Catch-all for unexpected errors
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()