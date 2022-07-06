import os
import logging
import argparse
import traceback
import subprocess
import shutil
import json
from typing import Dict, Any, List

from modex import Module, Page, get_current_utc_timestamp, create_logger, check_if_all_elements_are_equal, \
    check_if_modules_can_be_mixed, mix_modules, get_detection_information_filename, log_detection_process_common_parts, \
    get_most_common_element


class ModexDetectionAttempt:
    def __init__(self, memory_dump_location: str, mapped_modules: List[Module], result: bool,
                 suspicious_processes: List[int]):
        self.memory_dump_location: str = memory_dump_location
        self.mapped_modules: List[Module] = mapped_modules
        self.result: bool = result
        self.suspicious_processes: List[int] = suspicious_processes


class ModexExtraction:
    def __init__(self, modex_output: str, module_path: str, metadata_path: str):
        self.modex_output: str = modex_output
        self.module_path: str = module_path
        self.metadata_path: str = metadata_path


def get_logger(output_directory: str, log_level):
    log_file_path = os.path.join(output_directory, 'inter_modex_log.txt')
    logger = create_logger(log_file_path, 'inter_modex_logger', log_level)
    logger.propagate = False
    return logger


def obtain_modex_outputs_directory_name(output_directory: str) -> str:
    """Obtain the directory name where the outputs generated after calling the Modex plugin will be stored."""
    return os.path.join(output_directory, 'modex_outputs')


def create_output_directory(output_directory: str, create_modex_outputs_directory: bool) -> None:
    """Create the directory that will contain the InterModex output."""
    if create_modex_outputs_directory:
        os.makedirs(obtain_modex_outputs_directory_name(output_directory))
    else:
        os.makedirs(output_directory)


def get_file_from_modex_output(modex_output: str, extension: str) -> str:
    """Get a file stored inside a Modex output which is not hidden and has a particular extension."""
    elements_inside_modex_output: List[str] = os.listdir(modex_output)
    for element_inside_modex_output in elements_inside_modex_output:
        if os.path.isfile(
                os.path.join(modex_output, element_inside_modex_output)) and not element_inside_modex_output.startswith(
            '.') and element_inside_modex_output.endswith(extension):
            return os.path.join(modex_output, element_inside_modex_output)


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


def convert_page_dictionary_to_page_object(page: Dict[str, Any], module_path: str, module_base_address: int) -> Page:
    return Page(module_base_address + page['offset'], page['size'], 'True' if page['is_shared'] else 'False',
                module_path, page['sha_256_digest'], page['is_anomalous'])


def convert_modex_extraction_to_module(modex_extraction: ModexExtraction) -> Module:
    with open(modex_extraction.metadata_path) as metadata_file:
        metadata: Dict[str, Any] = json.load(metadata_file)
    # Path inside the system whose memory contents where dumped (do not confuse with the module path inside the modex extraction)
    module_path: str = metadata['module_path']
    module_base_address: int = int(metadata['module_base_address'], 16)
    module_size: int = metadata['module_size']
    pages: List[Page] = []
    for page_as_dictionary in metadata['pages']:
        pages.append(convert_page_dictionary_to_page_object(page_as_dictionary, modex_extraction.module_path,
                                                            module_base_address))
    # The name and the process_id are irrelevant for InterModex
    return Module('', module_path, module_base_address, module_size, 0, modex_extraction.module_path, pages)


def check_if_modex_ran_successfully(modex_output_directory: str, was_detect_option_supplied: bool) -> bool:
    """Check if an output from the Modex plugin contains the files it should contain for a successful execution."""
    # An output from the Modex plugin, without taking directories into account and without supplying the --detect option, should contain 3 files if the execution was successful:
    # - A .dmp file
    # - A .json file
    # - A .txt file
    # Note: If the --detect option was supplied to Modex, then a .dmp file will not be created

    number_of_generated_files: int = 2 if was_detect_option_supplied else 3
    extensions: List[str] = ['.json', '.txt'] if was_detect_option_supplied else ['.dmp', '.json', '.txt']
    not_hidden_files_inside_modex_output: List[str] = get_not_hidden_files_inside_directory(modex_output_directory)
    if len(not_hidden_files_inside_modex_output) == number_of_generated_files:
        presence_of_extensions: List[bool] = [False, False] if was_detect_option_supplied else [False, False, False]
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


def get_succesful_modex_outputs(modex_outputs_directory: str, was_detect_option_supplied: bool, logger) -> List[str]:
    modex_outputs: List[str] = os.listdir(modex_outputs_directory)
    for i in range(0, len(modex_outputs)):
        modex_outputs[i] = os.path.join(modex_outputs_directory, modex_outputs[i])

    logger.info('\nModex outputs before checking if the Modex executions were successful:')
    for modex_output in modex_outputs:
        if os.path.isdir(modex_output):
            logger.info(f'\t{modex_output}')

    logger.info('\nChecking if the Modex executions were successful:')
    successful_modex_outputs: List[str] = []
    for modex_output in modex_outputs:
        if os.path.isdir(modex_output):
            if check_if_modex_ran_successfully(modex_output, was_detect_option_supplied):
                successful_modex_outputs.append(modex_output)
                logger.info(f'\t{modex_output} meets the requirements for a successful Modex execution')
            else:
                logger.info(
                    f'\t{modex_output} does not meet the requirements for a successful Modex execution. As a result, it will not be considered for the mixture.')
    return successful_modex_outputs


def convert_mapped_modules_from_json_to_objects(mapped_modules: List[Dict[str, Any]]) -> List[Module]:
    mapped_modules_converted: List[Module] = []
    for mapped_module in mapped_modules:
        mapped_modules_converted.append(
            Module('', mapped_module['path'], mapped_module['base_address'], mapped_module['size'],
                   mapped_module['process_id'], '', []))
    return mapped_modules_converted


def detect_dll_proxying_across_several_memory_dumps(modex_detection_attempts: List[ModexDetectionAttempt],
                                                    output_directory: str, logger) -> None:
    detection_info: Dict[str, Any] = {}
    mapped_modules: List[Module] = []
    for modex_detection_attempt in modex_detection_attempts:
        mapped_modules += modex_detection_attempt.mapped_modules

    most_common_path: str = get_most_common_element([module.path.casefold() for module in mapped_modules])
    most_common_size: int = get_most_common_element([module.size for module in mapped_modules])

    suspicious_processes: Dict[str, Any] = {}  # The keys are memory dumps
    for modex_detection_attempt in modex_detection_attempts:
        for module in modex_detection_attempt.mapped_modules:
            if module.path.casefold() != most_common_path or module.size != most_common_size:
                if modex_detection_attempt.memory_dump_location not in suspicious_processes.keys():
                    suspicious_processes[modex_detection_attempt.memory_dump_location] = [module.process_id]
                else:
                    suspicious_processes[modex_detection_attempt.memory_dump_location].append(module.process_id)

    detection_info['dll_proxying_detection_result'] = True if suspicious_processes else False
    detection_info['suspicious_processes'] = suspicious_processes

    detection_info_path: str = os.path.join(output_directory, get_detection_information_filename())
    with open(detection_info_path, 'w') as detection_info_file:
        json.dump(detection_info, detection_info_file, ensure_ascii=False, indent=4)

    log_detection_process_common_parts(logger)


def perform_detection(modex_outputs_directory: str, output_directory: str, logger) -> None:
    successful_modex_outputs: List[str] = get_succesful_modex_outputs(modex_outputs_directory, True, logger)
    modex_detection_attempts: List[ModexDetectionAttempt] = []

    # Get the .json files from each successful Modex output and perform the detection
    for successful_modex_output in successful_modex_outputs:
        json_file: str = get_file_from_modex_output(successful_modex_output, '.json')
        if json_file is not None:
            with open(json_file) as detection_info_file:
                detection_info: Dict[str, Any] = json.load(detection_info_file)
            mapped_modules: List[Module] = convert_mapped_modules_from_json_to_objects(detection_info['mapped_modules'])
            modex_detection_attempts.append(
                ModexDetectionAttempt(detection_info['memory_dump_location'], mapped_modules,
                                      detection_info['dll_proxying_detection_result'],
                                      detection_info['suspicious_processes']))
        else:
            logger.info(
                f'\tThe Modex output {successful_modex_output} was considered successful, but the .json file does not exist, and it must exist for a Modex output to be successful. As a result, this output will not be considered in the detection process.')

    detect_dll_proxying_across_several_memory_dumps(modex_detection_attempts, output_directory, logger)


def perform_mixture(modex_outputs_directory: str, perform_derelocation: bool, sum_path: str, dump_anomalies: bool,
                    output_directory: str, logger) -> None:
    successful_modex_outputs: List[str] = get_succesful_modex_outputs(modex_outputs_directory, False, logger)

    # Take the .dmp and .json files from each successful Modex output and perform the mixture
    modex_extractions: List[ModexExtraction] = []
    for successful_modex_output in successful_modex_outputs:
        dmp_file: str = get_file_from_modex_output(successful_modex_output, '.dmp')
        json_file: str = get_file_from_modex_output(successful_modex_output, '.json')
        if dmp_file is not None and json_file is not None:
            modex_extractions.append(ModexExtraction(successful_modex_output, dmp_file, json_file))
        else:
            logger.info(
                f'\tThe Modex output {successful_modex_output} was considered successful, but the .dmp file is {dmp_file} and the .json file is {json_file}, and both of them have to exist for a Modex output to be successful. As a result, this output will not be considered for the mixture.')

    logger.info('\nModex outputs that will be mixed:')
    for modex_extraction in modex_extractions:
        logger.info(f'\t{modex_extraction.modex_output}')

    modules_to_mix: List[Module] = []
    for modex_extraction in modex_extractions:
        modules_to_mix.append(convert_modex_extraction_to_module(modex_extraction))

    can_modules_be_mixed: bool = check_if_modules_can_be_mixed(modules_to_mix, logger)
    mixed_module_filename: str = 'mixed_module.dmp'
    mixed_module_metadata_filename: str = 'mixed_module.description.json'
    if can_modules_be_mixed:
        mix_modules(modules_to_mix, output_directory, mixed_module_filename, mixed_module_metadata_filename,
                    dump_anomalies, logger, False, None)

    if perform_derelocation and os.path.exists(os.path.join(output_directory, mixed_module_filename)):
        derelocator_command = [f'python3 {os.path.join(os.path.dirname(os.path.abspath(__file__)), "derelocator.py")}',
                               os.path.join(os.getcwd(), output_directory, mixed_module_filename),
                               os.path.join(os.getcwd(), output_directory), sum_path]
        with subprocess.Popen(derelocator_command) as derelocator_tool:
            derelocator_exit_code = derelocator_tool.wait()
        if derelocator_exit_code == 0:
            logger.info(f'\nThe derelocation process was successful')
        else:
            logger.info(f'\nThe derelocation process was not successful (exit code {derelocator_exit_code})')


def perform_operation_after_getting_modex_outputs(module: str, memory_dumps_directory: str, remove_modex_outputs: bool,
                                                  perform_derelocation: bool, sum_path: str, volatility_path: str,
                                                  dump_anomalies: bool, detect: bool, output_directory: str,
                                                  logger) -> None:
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
        if detect:
            volatility_command = ['python3', volatility_path, '-f', memory_dump, 'windows.modex', '--module', module,
                                  '--detect']
        else:
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

    if detect:
        perform_detection(modex_outputs_directory_name, output_directory, logger)
    else:
        # Mix the modules previously extracted
        perform_mixture(modex_outputs_directory_name, perform_derelocation, sum_path, dump_anomalies, output_directory,
                        logger)

    if remove_modex_outputs:
        shutil.rmtree(modex_outputs_directory_name)


def validate_arguments() -> Dict[str, Any]:
    """Parse and validate command line arguments."""
    arg_parser = argparse.ArgumentParser(
        description='Extracts a module as complete as possible from multiple memory dumps')
    arg_parser.version = '0.1.0'
    arg_parser.add_argument('-a',
                            '--dump-anomalies',
                            action='store_true',
                            help='When there are different shared pages at the same offset, dump those pages')
    arg_parser.add_argument('-d',
                            '--memory-dumps-directory',
                            help='directory where the memory dumps are (the Modex plugin will be called)')
    arg_parser.add_argument('--detect',
                            action='store_true',
                            help='detect the presence of the DLL proxying technique')
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
    arg_parser.add_argument('-s',
                            '--sum-path',
                            help='path where the sum.py file is')
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
    dump_anomalies = args.dump_anomalies
    sum_path = args.sum_path
    detect = args.detect

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

    if perform_derelocation and sum_path is None:
        raise ValueError(
            'If you supply the --perform-derelocation option, then the --sum-path also has to be supplied')

    if memory_dumps_directory is not None and not os.path.exists(memory_dumps_directory):
        raise FileNotFoundError(
            f'The directory supplied with the --memory-dumps-directory option ({memory_dumps_directory}) does not exist')

    if modex_outputs_directory is not None and not os.path.exists(modex_outputs_directory):
        raise FileNotFoundError(
            f'The directory supplied with the --modex-outputs-directory option ({modex_outputs_directory}) does not exist')

    if volatility_path is not None and not os.path.isfile(volatility_path):
        raise FileNotFoundError(
            f'The path supplied with the --volatility-path option ({volatility_path}) does not correspond to a file')

    if sum_path is not None and not os.path.isfile(sum_path):
        raise FileNotFoundError(
            f'The path supplied with the --sum-path option ({sum_path}) does not correspond to a file')

    if module is not None and len(module) > 255:
        raise ValueError('The module name is too long')

    if (perform_derelocation or dump_anomalies) and detect:
        raise ValueError(
            'You cannot supply the --detect option alongside the --perform-derelocation or --dump-anomalies options')

    if memory_dumps_directory is not None:
        memory_dumps_directory = os.path.abspath(memory_dumps_directory)

    if volatility_path is not None:
        volatility_path = os.path.abspath(volatility_path)

    if sum_path is not None:
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

    arguments: Dict[str, Any] = {'module': module, 'memory_dumps_directory': memory_dumps_directory,
                                 'modex_outputs_directory': modex_outputs_directory,
                                 'remove_modex_outputs': remove_modex_outputs,
                                 'perform_derelocation': perform_derelocation, 'volatility_path': volatility_path,
                                 'log_level_supplied': log_level_supplied, 'dump_anomalies': dump_anomalies,
                                 'sum_path': sum_path, 'detect': detect}
    return arguments


def execute() -> None:
    try:
        validated_arguments: Dict[str, Any] = validate_arguments()

        # Directory where the InterModex output will be placed
        output_directory: str = f'inter_modex_output_{get_current_utc_timestamp()}'

        modex_outputs_directory = validated_arguments['modex_outputs_directory']
        if modex_outputs_directory is not None:
            create_output_directory(output_directory, False)
            logger = get_logger(output_directory, validated_arguments['log_level_supplied'])
            if validated_arguments['detect']:
                perform_detection(modex_outputs_directory, output_directory, logger)
            else:
                perform_mixture(modex_outputs_directory, validated_arguments['perform_derelocation'],
                                validated_arguments['sum_path'], validated_arguments['dump_anomalies'],
                                output_directory,
                                logger)
        else:
            create_output_directory(output_directory, True)
            logger = get_logger(output_directory, validated_arguments['log_level_supplied'])
            perform_operation_after_getting_modex_outputs(validated_arguments['module'],
                                                          validated_arguments['memory_dumps_directory'],
                                                          validated_arguments['remove_modex_outputs'],
                                                          validated_arguments['perform_derelocation'],
                                                          validated_arguments['sum_path'],
                                                          validated_arguments['volatility_path'],
                                                          validated_arguments['dump_anomalies'],
                                                          validated_arguments['detect'], output_directory,
                                                          logger)

    except Exception as exception:
        print(f'An error occurred ({exception}). Here are more details about the error:\n')
        print(traceback.format_exc())


def main():
    execute()


if __name__ == '__main__':
    main()
