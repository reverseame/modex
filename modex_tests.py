import argparse
import logging
import os
import json
import hashlib
from typing import Tuple, List, Dict, Any
from datetime import datetime

utc_now = datetime.utcnow()
log_filename: str = f'modex_tests_log_{utc_now.strftime("%d-%m-%Y_%H-%M-%S_UTC")}.txt'
logger = logging.getLogger('modex_tests_logger')


def get_page_from_dumped_module(module_filename: str, page_offset: int, page_size: int) -> bytes:
    with open(module_filename, mode='rb') as dumped_module:
        dumped_module.seek(page_offset)
        page_contents = dumped_module.read(page_size)
        return page_contents


def validate_modex_output(module_path: str, metadata_path: str) -> None:
    is_modex_output_correct: bool = True

    with open(metadata_path) as metadata_file:
        # Each element in the metadata list contains information about one page
        metadata: List[Dict[str, Any]] = json.load(metadata_file)

    # Validate that each page listed in the metadata is in the module
    logger.info(f'Check that the extracted module and the information in the metadata match:')
    for page in metadata:
        page_contents: bytes = get_page_from_dumped_module(module_path, page['offset'], page['size'])
        page_contents_digest: str = hashlib.sha256(page_contents).hexdigest()
        if page_contents_digest == page['sha_256_digest']:
            logger.info(f'\tThe page at offset {page["offset"]} has been correctly validated')
        else:
            is_modex_output_correct = False
            logger.info(
                f'\tThe page at offset {page["offset"]} has not been correctly validated, its digest should be {page["sha_256_digest"]} but it is {page_contents_digest}')

    # Validate that no pages are overlapping
    logger.info(
        f'\nCheck that there are not overlapping pages (module offset:number of times that offset was written to):')
    # Each byte/offset/address of the module should not be written to more than once
    times_module_offsets_were_written: List[int] = [0] * os.path.getsize(module_path)
    for page in metadata:
        page_offset = page['offset']
        page_size = page['size']
        for i in range(page_offset, page_offset + page_size):
            times_module_offsets_were_written[i] = times_module_offsets_were_written[i] + 1

    for i in range(0, len(times_module_offsets_were_written)):
        if times_module_offsets_were_written[i] > 1:
            is_modex_output_correct = False
            logger.info(
                f'\t{i}:{times_module_offsets_were_written[i]} (Each offset of the module should not be written to more than once)')
        else:
            logger.info(
                f'\t{i}:{times_module_offsets_were_written[i]}')

    if is_modex_output_correct:
        logger.info(f'\nThe Modex output has been correctly validated')
        print(
            f'The Modex output has been correctly validated. More details can be found in the generated log file ({log_filename}).')
    else:
        logger.info(f'\nThe Modex output has not passed the validations')
        print(
            f'The Modex output has not passed the validations. You can see why in the generated log file ({log_filename}).')


def validate_arguments() -> Tuple[str, str]:
    """Parse and validate command line arguments."""
    arg_parser = argparse.ArgumentParser(description='Validate the output produced by the modex Volatility 3 plugin')
    arg_parser.version = '0.0.1'
    arg_parser.add_argument('module',
                            help='Path of the extracted module')
    arg_parser.add_argument('metadata',
                            help='Path of the JSON file that describes the extracted module')
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

    module: str = args.module
    if not os.path.exists(module):
        raise FileNotFoundError(f'The module supplied ({module}) does not exist')

    metadata: str = args.metadata
    if not os.path.exists(metadata):
        raise FileNotFoundError(f'The metadata supplied ({metadata}) does not exist')

    arguments: Tuple[str, str] = (module, metadata)
    return arguments


def execute() -> None:
    try:
        validated_arguments: Tuple[str, str] = validate_arguments()
        validate_modex_output(validated_arguments[0], validated_arguments[1])
    except Exception as exception:
        logger.exception(exception)
        print(f'Error: {exception}')


def main():
    execute()


if __name__ == '__main__':
    main()
