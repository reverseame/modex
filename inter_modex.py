import os
import logging
import argparse
from typing import Dict, Any

from modex import get_current_utc_timestamp, create_logger


def perform_mixture(modex_outputs_directory: str, remove_modex_outputs: bool, perform_derelocation: bool,
                    output_directory: str, logger) -> None:
    pass


def perform_extraction(module: str, memory_dumps_directory: str, remove_modex_outputs: bool, perform_derelocation: bool,
                       output_directory: str, logger) -> None:
    # Invoke the Modex plugin for each memory dump inside the memory dumps directory

    # Move all the Modex outputs to the same directory
    modex_outputs_directory: str = os.path.join(output_directory, 'modex_outputs')

    # Mix the modules previously extracted
    perform_mixture(modex_outputs_directory, remove_modex_outputs, perform_derelocation, output_directory, logger)


def validate_arguments() -> Dict[str, Any]:
    """Parse and validate command line arguments."""
    arg_parser = argparse.ArgumentParser(
        description='Extracts a module as complete as possible from multiple memory dumps')
    arg_parser.version = '0.0.1'
    arg_parser.add_argument('-d',
                            '--memory-dumps-directory',
                            help='directory where the memory dumps are (the Modex plugin will be called)')
    arg_parser.add_argument('-l',
                            '--log-level',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            default='INFO',
                            help='logging level')
    arg_parser.add_argument('-m',
                            '--module',
                            help='name of the module to extract')
    arg_parser.add_argument('-o',
                            '--modex-outputs-directory',
                            help='directory where the Modex outputs are (the Modex plugin will not be called)')
    arg_parser.add_argument('-p',
                            '--perform-derelocation',
                            action='store_true',
                            help='perform a derelocation process after extracting the module')
    arg_parser.add_argument('-r',
                            '--remove-modex-outputs',
                            action='store_true',
                            help='remove the outputs generated by the Modex plugin (only if the Modex plugin is called)')
    arg_parser.add_argument('-v',
                            '--version',
                            action='version',
                            help='show the program version and exit')

    args = arg_parser.parse_args()

    module = args.module
    memory_dumps_directory = args.memory_dumps_directory
    modex_outputs_directory = args.modex_outputs_directory
    remove_modex_outputs = args.remove_modex_outputs
    perform_derelocation = args.perform_derelocation

    if memory_dumps_directory is not None and modex_outputs_directory is not None:
        raise ValueError(
            'You cannot supply the --memory-dumps-directory and the --modex-outputs-directory options at the same time (either the modules have already been extracted with the Modex plugin or not)')

    if memory_dumps_directory is None and modex_outputs_directory is None:
        raise ValueError(
            'You have to indicate a directory (either where the memory dumps are or where the Modex outputs are)')

    if memory_dumps_directory is not None and module is None:
        raise ValueError(
            'If you supply the --memory-dumps-directory option, then the --module option also has to be supplied')

    if modex_outputs_directory is not None and module is not None:
        raise ValueError(
            'If you supply the --modex-outputs-directory option, then the --module option cannot be supplied (all the Modex outputs inside the directory supplied are supposed to correspond to the same module)')

    if modex_outputs_directory is not None and remove_modex_outputs:
        raise ValueError(
            'You cannot supply the --remove-modex-outputs alongside the --modex-outputs-directory option (the Modex outputs can only be deleted if the Modex plugin is called within InterModex)')

    if memory_dumps_directory is not None and not os.path.exists(memory_dumps_directory):
        raise FileNotFoundError(
            f'The directory supplied with the --memory-dumps-directory option ({memory_dumps_directory}) does not exist')

    if modex_outputs_directory is not None and not os.path.exists(modex_outputs_directory):
        raise FileNotFoundError(
            f'The directory supplied with the --modex-outputs-directory option ({modex_outputs_directory}) does not exist')

    if module is not None and len(module) > 255:
        raise ValueError('The module name is too long')

    if args.log_level == 'DEBUG':
        log_level_supplied = logging.DEBUG
    elif args.log_level == 'INFO':
        log_level_supplied = logging.INFO
    elif args.log_level == 'WARNING':
        log_level_supplied = logging.WARNING
    elif args.log_level == 'ERROR':
        log_level_supplied = logging.ERROR
    elif args.log_level == 'CRITICAL':
        log_level_supplied = logging.CRITICAL
    else:
        raise ValueError(
            f'Log level not supported (you supplied {args.log_level}). These are the ones supported: DEBUG, INFO, WARNING, ERROR, CRITICAL')

    logging.basicConfig(level=log_level_supplied)
    arguments: Dict[str, Any] = {'module': module, 'memory_dumps_directory': memory_dumps_directory,
                                 'modex_outputs_directory': modex_outputs_directory,
                                 'remove_modex_outputs': remove_modex_outputs,
                                 'perform_derelocation': perform_derelocation}
    return arguments


def execute() -> None:
    try:
        validated_arguments: Dict[str, Any] = validate_arguments()

        # Directory where the InterModex output will be placed
        output_directory: str = f'inter_modex_output_{get_current_utc_timestamp()}'
        os.makedirs(output_directory)

        log_file_path = os.path.join(output_directory, 'inter_modex_log.txt')
        logger = create_logger(log_file_path, 'inter_modex_logger')

        modex_outputs_directory = validated_arguments['modex_outputs_directory']
        if modex_outputs_directory is not None:
            perform_mixture(modex_outputs_directory, validated_arguments['remove_modex_outputs'],
                            validated_arguments['perform_derelocation'], output_directory, logger)
        else:
            perform_extraction(validated_arguments['module'], validated_arguments['memory_dumps_directory'],
                               validated_arguments['remove_modex_outputs'], validated_arguments['perform_derelocation'],
                               output_directory, logger)

    except Exception as exception:
        print(f'Error: {exception}')


def main():
    execute()


if __name__ == '__main__':
    main()