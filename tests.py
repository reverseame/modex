import argparse
import logging
import os
import json
import hashlib
import binascii
from typing import Tuple, List, Dict, Any
from datetime import datetime

from modex import get_page_from_dumped_module

utc_now = datetime.utcnow()
log_filename: str = f'tests_log_{utc_now.strftime("%d-%m-%Y_%H-%M-%S_UTC")}.txt'
logger = logging.getLogger('tests_logger')


class Anomaly:
    def __init__(self, page_offset: int, anomaly_number_at_offset: int, page_contents: bytes):
        self.page_offset: int = page_offset
        self.anomaly_number_at_offset: int = anomaly_number_at_offset  # Inside the same offset, there can be 2 or more anomalies
        self.page_contents: bytes = page_contents


def validate_output(directory: str) -> None:
    # A Modex output will only have 1 .dmp file
    # An InterModex output will have 2 .dmp files if a derelocation process is performed
    # In the case of InterModex, the validation focuses on the module to which a derelocation process has not been applied
    module_path = None
    metadata_path = None

    for filename in os.listdir(directory):
        if filename.endswith('.dmp') and 'after_derelocation' not in filename:
            module_path = os.path.join(directory, filename)
        elif filename.endswith('.json'):
            metadata_path = os.path.join(directory, filename)

    if not module_path:
        raise FileNotFoundError('The directory supplied does not contain a .dmp file')

    if not metadata_path:
        raise FileNotFoundError('The directory supplied does not contain a .json file')

    is_output_correct: bool = True

    with open(metadata_path) as metadata_file:
        metadata: Dict[str, Any] = json.load(metadata_file)

    # Validate that each page listed in the metadata is in the module
    logger.info('Check that the extracted module and the information in the metadata match:')
    dumped_module_size: int = os.path.getsize(module_path)
    module_size_in_metadata: int = metadata['module_size']
    if dumped_module_size == module_size_in_metadata:
        logger.info('\tThe module size has been correctly validated')
    else:
        is_output_correct = False
        logger.info(
            f'\tThe module size has not been correctly validated (it is {dumped_module_size} bytes and should be {module_size_in_metadata} bytes)')
    # Each element in the metadata['pages'] list contains information about one page
    for page in metadata['pages']:
        page_contents: bytes = get_page_from_dumped_module(module_path, page['offset'], page['size'])
        page_contents_digest: str = hashlib.sha256(page_contents).hexdigest()
        if page_contents_digest == page['sha_256_digest']:
            logger.info(f'\tThe page at offset {page["offset"]} has been correctly validated')
        else:
            is_output_correct = False
            logger.info(
                f'\tThe page at offset {page["offset"]} has not been correctly validated, its digest should be {page["sha_256_digest"]} but it is {page_contents_digest}')

    # Validate that no pages are overlapping
    logger.info(
        '\nCheck that there are not overlapping pages (module offset:number of times that offset was written to):')
    # Each byte/offset/address of the module should not be written to more than once
    times_module_offsets_were_written: List[int] = [0] * os.path.getsize(module_path)
    for page in metadata['pages']:
        page_offset = page['offset']
        page_size = page['size']
        for i in range(page_offset, page_offset + page_size):
            times_module_offsets_were_written[i] = times_module_offsets_were_written[i] + 1

    for i in range(0, len(times_module_offsets_were_written)):
        if times_module_offsets_were_written[i] > 1:
            is_output_correct = False
            logger.info(
                f'\t{i}:{times_module_offsets_were_written[i]} (Each offset of the module should not be written to more than once)')
        else:
            logger.info(
                f'\t{i}:{times_module_offsets_were_written[i]}')

    if is_output_correct:
        logger.info('\nThe output has been correctly validated')
        print(
            f'The output has been correctly validated. More details can be found in the generated log file ({log_filename}).')
    else:
        logger.info('\nThe output has not passed the validations')
        print(
            f'The output has not passed the validations. You can see why in the generated log file ({log_filename}).')


def create_representation_of_anomaly(anomaly_file_path: str) -> Anomaly:
    anomaly_filename: str = os.path.basename(anomaly_file_path)
    page_offset: int = int(anomaly_filename.split('_')[-1].split('.')[0])
    anomaly_number_at_offset: int = int(anomaly_filename.split('_')[2])
    with open(anomaly_file_path, mode='rb') as anomaly:
        page_contents = anomaly.read()
    return Anomaly(page_offset, anomaly_number_at_offset, page_contents)


def investigate_anomalies(directory: str) -> None:
    # The anomalies investigated here are cases where shared pages with the same offset have different contents
    anomalies_directory_name = 'anomalies'
    anomalies_directory_not_found_message: str = f'The directory supplied does not contain a directory named "{anomalies_directory_name}"'
    filenames: List[str] = os.listdir(directory)
    if anomalies_directory_name not in filenames:
        raise FileNotFoundError(anomalies_directory_not_found_message)

    anomalies_directory = os.path.join(directory, anomalies_directory_name)
    if not os.path.isdir(anomalies_directory):
        raise FileNotFoundError(anomalies_directory_not_found_message)

    filenames_inside_anomalies: List[str] = os.listdir(anomalies_directory)
    all_anomalies: List[Anomaly] = []
    for filename_inside_anomalies in filenames_inside_anomalies:
        all_anomalies.append(
            create_representation_of_anomaly(os.path.join(anomalies_directory, filename_inside_anomalies)))

    organized_anomalies: Dict[int, List[Anomaly]] = {}  # The keys in this dictionary are the page offsets
    for anomaly in all_anomalies:
        page_offset: int = anomaly.page_offset
        if page_offset not in organized_anomalies.keys():
            organized_anomalies[page_offset] = [anomaly]
        else:
            organized_anomalies[page_offset].append(anomaly)

    logger.info('Results after investigating the anomalies:')
    for page_offset in organized_anomalies.keys():
        all_anomalies_at_certain_offset: List[Anomaly] = organized_anomalies[page_offset]
        logger.info(f'\tThere are {len(all_anomalies_at_certain_offset)} anomalies at offset {page_offset}:')
        for anomaly in all_anomalies_at_certain_offset:
            logger.info(
                f'\t\tSHA-256 digest of the page contents that belong to anomaly {anomaly.anomaly_number_at_offset}: {hashlib.sha256(anomaly.page_contents).hexdigest()}')
        for anomaly_i in all_anomalies_at_certain_offset:
            for anomaly_j in all_anomalies_at_certain_offset:
                if anomaly_i.anomaly_number_at_offset < anomaly_j.anomaly_number_at_offset:
                    if len(anomaly_i.page_contents) != len(anomaly_j.page_contents):
                        logger.info(
                            f'\t\tThe anomaly {anomaly_i.anomaly_number_at_offset} has a size of {len(anomaly_i.page_contents)} bytes and the anomaly {anomaly_j.anomaly_number_at_offset} has a size of {anomaly_j.page_contents} bytes. These sizes should be equal, but they are not.')
                    else:
                        anomaly_i_page_contents: bytes = anomaly_i.page_contents
                        anomaly_j_page_contents: bytes = anomaly_j.page_contents
                        different_bytes_count: int = 0
                        current_difference_in_anomaly_i: bytearray = bytearray()
                        current_difference_in_anomaly_j: bytearray = bytearray()
                        is_index_in_difference: bool = False
                        current_difference_start_index: int = 0

                        logger.info(
                            f'\t\tDifferences between anomaly {anomaly_i.anomaly_number_at_offset} and anomaly {anomaly_j.anomaly_number_at_offset} (they have the same size ({len(anomaly_i_page_contents)} bytes)):')

                        for z in range(0, len(anomaly_i_page_contents)):
                            are_bytes_different: bool = anomaly_i_page_contents[z] != anomaly_j_page_contents[z]
                            if are_bytes_different:
                                different_bytes_count += 1
                                if is_index_in_difference:
                                    current_difference_in_anomaly_i.append(anomaly_i_page_contents[z])
                                    current_difference_in_anomaly_j.append(anomaly_j_page_contents[z])
                                else:
                                    is_index_in_difference = True
                                    current_difference_start_index = z
                                    current_difference_in_anomaly_i.clear()
                                    current_difference_in_anomaly_j.clear()
                                    current_difference_in_anomaly_i.append(anomaly_i_page_contents[z])
                                    current_difference_in_anomaly_j.append(anomaly_j_page_contents[z])
                            elif not are_bytes_different and is_index_in_difference:
                                is_index_in_difference = False
                                logger.info(
                                    f'\t\t\tAt offset {current_difference_start_index}: anomaly {anomaly_i.anomaly_number_at_offset} has 0x{binascii.hexlify(bytes(current_difference_in_anomaly_i)).decode("utf-8")} and anomaly {anomaly_j.anomaly_number_at_offset} has 0x{binascii.hexlify(bytes(current_difference_in_anomaly_j)).decode("utf-8")}')

                        logger.info(f'\t\t\tNumber of different bytes: {different_bytes_count}')
    print(f'The results after investigating the anomalies are in the generated log file ({log_filename})')


def validate_arguments() -> Tuple[str, bool]:
    """Parse and validate command line arguments."""
    arg_parser = argparse.ArgumentParser(
        description='Validate and investigate the output produced by the Modex Volatility 3 plugin or the InterModex tool (only if the --detect option was not supplied)')
    arg_parser.version = '0.1.0'
    arg_parser.add_argument('directory',
                            help='Directory generated by Modex or InterModex')
    arg_parser.add_argument('-i',
                            '--only-investigate-anomalies',
                            action='store_true',
                            help='Do not validate the output, instead, only investigate the anomalies already found')
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

    logger.setLevel(log_level_supplied)
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(log_level_supplied)
    logger.addHandler(file_handler)

    directory: str = args.directory
    if not os.path.exists(directory):
        raise FileNotFoundError(f'The directory supplied ({directory}) does not exist')

    arguments: Tuple[str, bool] = (directory, args.only_investigate_anomalies)
    return arguments


def execute() -> None:
    try:
        validated_arguments: Tuple[str, bool] = validate_arguments()
        directory: str = validated_arguments[0]
        only_investigate_anomalies: bool = validated_arguments[1]
        if only_investigate_anomalies:
            investigate_anomalies(directory)
        else:
            validate_output(directory)
    except Exception as exception:
        logger.exception(exception)
        print(f'Error: {exception}')


def main():
    execute()


if __name__ == '__main__':
    main()
