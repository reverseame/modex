import os
import logging
import argparse
import traceback
import subprocess
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def perform_derelocation(sum_path: str, module_path: str, output_directory: str) -> None:
    logger.debug(f'Performing a derelocation process in the module {module_path}')
    elements_inside_output_directory_before: List[str] = os.listdir(output_directory)
    sum_command = ['python2', sum_path, module_path, '--dump-dir', output_directory]
    with subprocess.Popen(sum_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as sum_tool:
        sum_exit_code = sum_tool.wait()
    if sum_exit_code == 0:
        print(f'SUM executed successfully')
        is_module_renamed: bool = False
        elements_inside_output_directory_after: List[str] = os.listdir(output_directory)
        for element_inside_output_directory_after in elements_inside_output_directory_after:
            if not is_module_renamed and element_inside_output_directory_after not in elements_inside_output_directory_before and element_inside_output_directory_after.endswith(
                    '.dmp'):
                os.rename(os.path.join(output_directory, element_inside_output_directory_after),
                          os.path.join(output_directory, 'module_after_derelocation.dmp'))
                is_module_renamed = True
    else:
        print(f'The execution of SUM was not successful (exit code {sum_exit_code})')


def validate_arguments() -> Dict[str, Any]:
    """Parse and validate command line arguments."""
    arg_parser = argparse.ArgumentParser(
        description='Performs a derelocation process on a given module.')
    arg_parser.version = '0.1.0'
    arg_parser.add_argument('module_path',
                            help='module path')
    arg_parser.add_argument('output_directory',
                            help='directory where the derelocated module will be placed')
    arg_parser.add_argument('sum_path',
                            help='path where the sum.py file is')
    arg_parser.add_argument('-l',
                            '--log-level',
                            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            default='INFO',
                            help='logging level')
    arg_parser.add_argument('-v',
                            '--version',
                            action='version',
                            help='show the program version and exit')

    args = arg_parser.parse_args()

    module_path = args.module_path
    output_directory = args.output_directory
    sum_path = args.sum_path

    if not os.path.isfile(module_path):
        raise FileNotFoundError(
            f'The module path supplied ({module_path}) does not correspond to a file')

    if not os.path.exists(output_directory):
        raise FileNotFoundError(
            f'The output directory supplied ({output_directory}) does not exist')

    if not os.path.isfile(sum_path):
        raise FileNotFoundError(
            f'The path for the sum.py file supplied ({sum_path}) does not correspond to a file')

    module_path = os.path.abspath(module_path)
    output_directory = os.path.abspath(output_directory)
    sum_path = os.path.abspath(sum_path)

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
    arguments: Dict[str, Any] = {'module_path': module_path, 'output_directory': output_directory, 'sum_path': sum_path}
    return arguments


def execute() -> None:
    try:
        validated_arguments: Dict[str, Any] = validate_arguments()
        perform_derelocation(validated_arguments['sum_path'], validated_arguments['module_path'],
                             validated_arguments['output_directory'])
    except Exception as exception:
        print(f'An error occurred ({exception}). Here are more details about the error:\n')
        print(traceback.format_exc())


def main():
    execute()


if __name__ == '__main__':
    main()
