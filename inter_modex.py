import os
import logging
import argparse
import traceback
import subprocess
import shutil
from typing import Dict, Any, List

from modex import get_current_utc_timestamp, create_logger, check_if_all_elements_are_equal


def obtain_modex_outputs_directory_name(output_directory: str) -> str:
    """Obtain the directory name where the outputs generated after calling the Modex plugin will be stored."""
    return os.path.join(output_directory, 'modex_outputs')


def create_output_directory(output_directory: str, create_modex_outputs_directory: bool) -> None:
    """Create the directory that will contain the InterModex output."""
    if create_modex_outputs_directory:
        os.makedirs(obtain_modex_outputs_directory_name(output_directory))
    else:
        os.makedirs(output_directory)


def get_not_hidden_files_inside_directory(directory: str) -> List[str]:
    """Get the non-hidden files inside a directory (the file paths returned also include the directory)."""
    elements_inside_directory: List[str] = os.listdir(directory)
    all_files_inside_directory: List[str] = []
    not_hidden_files_inside_directory: List[str] = []
    for element_inside_directory in elements_inside_directory:
        if os.path.isfile(os.path.join(directory, element_inside_directory)):
            all_files_inside_directory.append(element_inside_directory)
    for file_inside_directory in all_files_inside_directory:
        if not file_inside_directory.startswith('.'):
            not_hidden_files_inside_directory.append(os.path.join(directory, file_inside_directory))
    return not_hidden_files_inside_directory


def check_if_modex_run_successfully(modex_output_directory: str) -> bool:
    """Check if an output from the Modex plugin contains the files it should contain for a successful execution."""
    # An output from the Modex plugin, without taking directories into account, should contain 3 files if the execution was successful:
    # - A .dmp file
    # - A .json file
    # - A .txt file
    not_hidden_files_inside_modex_output: List[str] = get_not_hidden_files_inside_directory(modex_output_directory)
    if len(not_hidden_files_inside_modex_output) == 3:
        extensions: List[str] = ['.dmp', '.json', '.txt']
        presence_of_extensions: List[bool] = [False, False, False]
        for file_inside_modex_output in not_hidden_files_inside_modex_output:
            file_has_required_extension: bool = False
            i: int = 0
            while i < len(extensions) and not file_has_required_extension:
                if file_inside_modex_output.endswith(extensions[i]):
                    presence_of_extensions[i] = True
                    file_has_required_extension = True
                i += 1
        if presence_of_extensions[0] and check_if_all_elements_are_equal(presence_of_extensions):
            return True
        else:
            return False
    else:
        return False


def perform_mixture(modex_outputs_directory: str, perform_derelocation: bool, output_directory: str, logger) -> None:
    pass


def perform_extraction(module: str, memory_dumps_directory: str, remove_modex_outputs: bool, perform_derelocation: bool,
                       volatility_path: str, output_directory: str, logger) -> None:
    memory_dumps: List[str] = get_not_hidden_files_inside_directory(memory_dumps_directory)
    logger.info('Memory dumps provided:')
    for memory_dump in memory_dumps:
        logger.info(f'\t{memory_dump}')
    current_working_directory: str = os.getcwd()
    logger.debug(f'Working directory before changing it: {current_working_directory}')
    modex_outputs_directory_name: str = obtain_modex_outputs_directory_name(output_directory)
    os.chdir(modex_outputs_directory_name)  # Change the working directory
    logger.debug(f'Working directory after changing it: {os.getcwd()}')

    # Invoke the Modex plugin for each memory dump inside the memory dumps directory
    logger.info('\nModex plugin execution:')
    for memory_dump in memory_dumps:
        volatility_command = ['python3', volatility_path, '-f', memory_dump, 'windows.modex', '--module', module,
                              '--dump-anomalies']
        with subprocess.Popen(volatility_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as modex_plugin:
            print(f'Running the Modex plugin for the following memory dump: {memory_dump}')
            modex_plugin_exit_code = modex_plugin.wait()
        if modex_plugin_exit_code == 0:
            logger.info(f'\tThe Modex plugin executed successfully for the following memory dump: {memory_dump}')
        else:
            logger.info(
                f'\tThe execution of the Modex plugin was not successful (exit code {modex_plugin_exit_code}) for the following memory dump: {memory_dump}')

    os.chdir(current_working_directory)  # Restore the working directory
    logger.debug(f'Working directory after restoring it: {os.getcwd()}')

    # Mix the modules previously extracted
    perform_mixture(modex_outputs_directory_name, perform_derelocation, output_directory, logger)

    if remove_modex_outputs:
        shutil.rmtree(modex_outputs_directory_name)


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
    arg_parser.add_argument('-t',
                            '--volatility-path',
                            help='path where the vol.py file is')
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
    volatility_path = args.volatility_path

    if memory_dumps_directory is not None and modex_outputs_directory is not None:
        raise ValueError(
            'You cannot supply the --memory-dumps-directory and the --modex-outputs-directory options at the same time (either the modules have already been extracted with the Modex plugin or not)')

    if memory_dumps_directory is None and modex_outputs_directory is None:
        raise ValueError(
            'You have to indicate a directory (either where the memory dumps are or where the Modex outputs are)')

    if memory_dumps_directory is not None and module is None:
        raise ValueError(
            'If you supply the --memory-dumps-directory option, then the --module option also has to be supplied')

    if memory_dumps_directory is not None and volatility_path is None:
        raise ValueError(
            'If you supply the --memory-dumps-directory option, then the --volatility-path option also has to be supplied')

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

    if volatility_path is not None and not os.path.isfile(volatility_path):
        raise FileNotFoundError(
            f'The path supplied with the --volatility-path option ({volatility_path}) does not correspond to a file')

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
                                 'perform_derelocation': perform_derelocation,
                                 'volatility_path': volatility_path, 'log_level_supplied': log_level_supplied}
    return arguments


def execute() -> None:
    try:
        validated_arguments: Dict[str, Any] = validate_arguments()

        # Directory where the InterModex output will be placed
        output_directory: str = f'inter_modex_output_{get_current_utc_timestamp()}'
        os.makedirs(output_directory)

        log_file_path = os.path.join(output_directory, 'inter_modex_log.txt')
        logger = create_logger(log_file_path, 'inter_modex_logger', validated_arguments['log_level_supplied'])
        logger.propagate = False

        modex_outputs_directory = validated_arguments['modex_outputs_directory']
        if modex_outputs_directory is not None:
            create_output_directory(output_directory, False)
            perform_mixture(modex_outputs_directory, validated_arguments['perform_derelocation'], output_directory,
                            logger)
        else:
            create_output_directory(output_directory, True)
            perform_extraction(validated_arguments['module'], validated_arguments['memory_dumps_directory'],
                               validated_arguments['remove_modex_outputs'], validated_arguments['perform_derelocation'],
                               validated_arguments['volatility_path'], output_directory, logger)

    except Exception as exception:
        print(f'An error occurred ({exception}). Here are more details about the error:\n')
        print(traceback.format_exc())


def main():
    execute()


if __name__ == '__main__':
    main()
