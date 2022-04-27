import os
import re
import logging
import hashlib
import json
import tlsh
import time
from typing import List, Dict, Any
from datetime import datetime
from collections import Counter
from tabulate import tabulate

from volatility3.framework import renderers, interfaces, automagic, plugins, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, dlllist, simple_pteenum


def get_current_utc_timestamp() -> str:
    utc_now = datetime.utcnow()
    return utc_now.strftime("%d-%m-%Y_%H-%M-%S_UTC")


def create_logger(file_path: str, logger_name: str, log_level):
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    file_handler = logging.FileHandler(file_path)
    file_handler.setLevel(log_level)
    logger.addHandler(file_handler)
    return logger


def get_relevant_page_details(page: List[Any]) -> Dict[str, str]:
    relevant_page_details = {}
    page_details = page[3]

    page_vaddr_match = re.search(r'\nvaddr: (\w+)\n', page_details)
    if page_vaddr_match:
        page_vaddr = page_vaddr_match.group(1)
    else:
        page_vaddr = None

    page_length_match = re.search(r'\nlength: (\w+)\n', page_details)
    if page_length_match:
        page_length = page_length_match.group(1)
    else:
        page_length = None

    page_pfn_db_entry_prototype_pte_flag_match = re.search(r'\nhas_proto_set: (\w+)\n', page_details)
    if page_pfn_db_entry_prototype_pte_flag_match:
        page_pfn_db_entry_prototype_pte_flag = page_pfn_db_entry_prototype_pte_flag_match.group(1)
    else:
        page_pfn_db_entry_prototype_pte_flag = None

    relevant_page_details['virtual_address'] = page_vaddr
    relevant_page_details['size'] = page_length
    relevant_page_details['pfn_db_entry_prototype_pte_flag'] = page_pfn_db_entry_prototype_pte_flag
    return relevant_page_details


def check_if_all_elements_are_equal(elements: List[Any]) -> bool:
    return all(element == elements[0] for element in elements)


class Page:
    def __init__(self, virtual_address: int, size: int, pfn_db_entry_prototype_pte_flag: str, module_filename: str,
                 contents_digest: str = None, is_anomalous: bool = False):
        self.virtual_address: int = virtual_address
        self.size: int = size  # In bytes
        # pfn_db_entry_prototype_pte_flag can be 'True', 'False', or 'Undetermined'
        self.pfn_db_entry_prototype_pte_flag: str = pfn_db_entry_prototype_pte_flag
        self.module_filename: str = module_filename  # Filename of the dumped module where the page is
        # Regarding the digest of the page contents:
        # - For shared pages: SHA-256 digest
        # - For pages considered private: TLSH digests will be used to choose a representative page. However, SHA-256 digests will be used in the metadata file.
        self.contents_digest: str = contents_digest
        self.is_anomalous: bool = is_anomalous  # This attribute is for InterModex compatibility

    def get_basic_information(self):
        return {'virtual_address': hex(self.virtual_address), 'size': hex(self.size),
                'pfn_db_entry_prototype_pte_flag': self.pfn_db_entry_prototype_pte_flag}

    def is_shared(self):
        return True if self.pfn_db_entry_prototype_pte_flag == 'True' else False

    def is_private(self):
        return True if self.pfn_db_entry_prototype_pte_flag == 'False' else False

    def is_pfn_db_entry_prototype_pte_flag_undetermined(self):
        return True if self.pfn_db_entry_prototype_pte_flag == 'Undetermined' else False

    def is_considered_private(self):
        # If it is not clear that a page is shared, it is considered private
        return True if self.is_private() or self.is_pfn_db_entry_prototype_pte_flag_undetermined() else False


class Module:
    def __init__(self, name: str, path: str, base_address: int, size: int, process_id: int, filename: str,
                 pages: List[Page]):
        self.name: str = name
        self.path: str = path
        self.base_address: int = base_address  # Virtual base address
        self.size: int = size  # In bytes
        self.process_id: int = process_id  # Identifier of the process where the module is mapped
        self.filename: str = filename  # Filename of the dumped module
        self.pages: List[Page] = pages

    def get_basic_information(self):
        return {'name': self.name, 'path': self.path, 'base_address': hex(self.base_address), 'size': hex(self.size),
                'process_id': self.process_id, 'filename': self.filename,
                'number_of_retrieved_pages': len(self.pages)}


def delete_dmp_files(modules: List[Module]) -> None:
    for module in modules:
        os.remove(module.filename)


def delete_zero_bytes_dmp_files() -> None:
    elements_inside_current_working_directory: List[str] = os.listdir(os.getcwd())
    for element_inside_current_working_directory in elements_inside_current_working_directory:
        if os.path.isfile(
                element_inside_current_working_directory) and element_inside_current_working_directory.endswith(
            '.dmp') and element_inside_current_working_directory.startswith('pid.') and os.path.getsize(
            element_inside_current_working_directory) == 0:
            os.remove(element_inside_current_working_directory)


def delete_modules_under_syswow64(modules: List[Module], logger) -> List[Module]:
    modules_not_under_syswow64: List[Module] = []
    modules_under_syswow64: List[Module] = []
    syswow64_directory = 'C:\\Windows\\SysWOW64\\'
    syswow64_directory_case_insensitive = syswow64_directory.casefold()
    for module in modules:
        if syswow64_directory_case_insensitive not in module.path.casefold():
            modules_not_under_syswow64.append(module)
        else:
            modules_under_syswow64.append(module)
            logger.info(f'\nModule under C:\\Windows\\SysWOW64 identified: {module.path}')
    delete_dmp_files(modules_under_syswow64)
    return modules_not_under_syswow64


def check_if_modules_can_be_mixed(modules: List[Module], logger) -> bool:
    # Make sure that the modules to mix:
    # - Have the same path
    # - Have the same size (check the sizes reported by the Module objects and the sizes of the dumped files)
    # - Are mapped at the same virtual base address
    paths: List[str] = []
    sizes: List[int] = []
    base_addresses: List[int] = []
    for module in modules:
        paths.append(module.path.casefold())
        sizes.append(module.size)
        sizes.append(os.path.getsize(module.filename))
        base_addresses.append(module.base_address)

    are_all_paths_equal: bool = check_if_all_elements_are_equal(paths)
    are_all_sizes_equal: bool = check_if_all_elements_are_equal(sizes)
    are_all_base_addresses_equal: bool = check_if_all_elements_are_equal(base_addresses)
    if False in (are_all_paths_equal, are_all_sizes_equal, are_all_base_addresses_equal):
        logger.info(f'''\nThe modules cannot be mixed:
    Are all paths equal? {are_all_paths_equal}
    Are all sizes equal? {are_all_sizes_equal}
    Are all base addresses equal? {are_all_base_addresses_equal}''')
        return False
    else:
        logger.info('\nThe modules can be mixed')
        return True


def get_shared_pages(pages: List[Page]) -> List[Page]:
    shared_pages: List[Page] = []
    for page in pages:
        if page.is_shared():
            shared_pages.append(page)
    return shared_pages


def count_instances_of_each_element(elements: List[Any]) -> Dict[Any, int]:
    """Count how many times each element is present in a list."""
    return dict(Counter(elements))


def get_page_from_dumped_module(module_filename: str, page_offset: int, page_size: int) -> bytes:
    with open(module_filename, mode='rb') as dumped_module:
        dumped_module.seek(page_offset)
        page_contents = dumped_module.read(page_size)
        return page_contents


def create_entry_for_page_in_mixed_module_metadata(page_offset: int, page_size: int, is_page_shared: bool,
                                                   page_contents_sha_256_digest: str,
                                                   is_page_anomalous: bool) -> Dict[str, Any]:
    return {'offset': page_offset, 'size': page_size, 'is_shared': is_page_shared,
            'sha_256_digest': page_contents_sha_256_digest, 'is_anomalous': is_page_anomalous}


def get_most_common_element(elements: List[Any]) -> Any:
    return max(set(elements), key=elements.count)


def find_page_with_certain_digest(pages: List[Page], digest: str) -> Page:
    for page in pages:
        if page.contents_digest == digest:
            return page


def insert_page_into_mixed_module(page: Page, module_base_address: int, mixed_module: bytearray,
                                  mixed_module_pages_metadata: List[Dict[str, Any]], is_page_anomalous: bool) -> None:
    page_offset: int = page.virtual_address - module_base_address  # Offset of the page inside the module
    page_contents: bytes = get_page_from_dumped_module(page.module_filename, page_offset, page.size)
    mixed_module[page_offset: page_offset + page.size] = page_contents
    mixed_module_pages_metadata.append(
        create_entry_for_page_in_mixed_module_metadata(page_offset, page.size, page.is_shared(), page.contents_digest,
                                                       is_page_anomalous))


def calculate_page_digests(pages: List[Page], module_base_address: int, use_similarity_digest_algorithm: bool) -> None:
    for page in pages:
        page_offset_inside_module: int = page.virtual_address - module_base_address
        page_contents: bytes = get_page_from_dumped_module(page.module_filename, page_offset_inside_module,
                                                           page.size)
        if use_similarity_digest_algorithm:
            page.contents_digest = tlsh.hash(page_contents)
        else:
            page.contents_digest = hashlib.sha256(page_contents).hexdigest()


def get_page_digests(pages: List[Page]) -> List[str]:
    page_digests: List[str] = []
    for page in pages:
        page_digests.append(page.contents_digest)
    return page_digests


def check_if_all_tlsh_digests_are_valid(tlsh_digests: List[str]) -> bool:
    for tlsh_digest in tlsh_digests:
        if tlsh_digest == 'TNULL':
            return False
    return True


def choose_representative_page_digest(page_similarity_digests: List[str], logger) -> str:
    """Compare all the page similarity digests received and choose one that is representative."""
    are_all_tlsh_digests_valid: bool = check_if_all_tlsh_digests_are_valid(page_similarity_digests)
    if len(page_similarity_digests) < 3 or not are_all_tlsh_digests_valid:
        return 'INVALID_DIGEST'

    # similarity_scores_table is a table with the similarity scores obtained after comparing all the similarity digests between each other
    similarity_scores_table: List[List[int]] = []
    for page_similarity_digest_i in page_similarity_digests:
        similarity_scores_row: List[int] = []
        for page_similarity_digest_j in page_similarity_digests:
            similarity_scores_row.append(tlsh.diff(page_similarity_digest_i, page_similarity_digest_j))
        similarity_scores_table.append(similarity_scores_row)

    sums_of_individual_similarity_scores_rows: List[int] = []
    for similarity_scores_row in similarity_scores_table:
        sums_of_individual_similarity_scores_rows.append(sum(similarity_scores_row))
    minimum_sum: int = min(sums_of_individual_similarity_scores_rows)
    index_of_minimum_sum: int = sums_of_individual_similarity_scores_rows.index(minimum_sum)
    representative_page_digest: str = page_similarity_digests[index_of_minimum_sum]

    # Log the process
    table_for_log: List[List[str]] = [[''] + page_similarity_digests]
    for page_similarity_digest in page_similarity_digests:
        table_for_log.append([page_similarity_digest])
    current_index_in_table_for_log: int = 1
    for similarity_scores_row in similarity_scores_table:
        for similarity_score in similarity_scores_row:
            table_for_log[current_index_in_table_for_log].append(str(similarity_score))
        current_index_in_table_for_log += 1

    logger.info('\t\tSimilarity scores table:')
    logger.info(tabulate(table_for_log, tablefmt='grid'))
    logger.info(
        f'\t\tThe minimum sum ({minimum_sum}) is in the row that corresponds to the digest {page_similarity_digests[index_of_minimum_sum]}')

    return representative_page_digest


def dump_page(page: Page, page_offset: int, file_path: str) -> None:
    page_contents: bytes = get_page_from_dumped_module(page.module_filename, page_offset, page.size)
    with open(file_path, 'wb') as dumped_page:
        dumped_page.write(page_contents)


def mix_modules(modules: List[Module], output_directory: str, mixed_module_filename: str,
                mixed_module_metadata_filename: str, dump_anomalies: bool, logger, is_modex_calling: bool,
                start_time) -> List[str]:
    if not modules:
        return []
    module_size: int = modules[0].size
    module_base_address: int = modules[0].base_address
    module_path: str = modules[0].path
    mixed_module: bytearray = bytearray(module_size)  # The mixed module is initialized with zeros
    mixed_module_pages_metadata: List[Dict[str, Any]] = []  # Metadata about the retrieved pages
    files_generated: List[str] = []

    # In the mixture dictionary:
    # - The keys are virtual addresses (the virtual address acts here as an id for a page inside a module)
    # - The values are lists of pages that all start at the same virtual address

    # In the mixture_shared_state dictionary:
    # - The idea for the keys is the same as in the mixture dictionary
    # - Each value is a boolean indicating if the page with that virtual address will be marked as shared (True) or not (False) in the mixed module

    mixture: Dict[int, List[Page]] = {}
    mixture_shared_state: Dict[int, bool] = {}
    for module in modules:
        for page in module.pages:
            if page.virtual_address not in mixture.keys():
                mixture[page.virtual_address] = [page]
                mixture_shared_state[page.virtual_address] = False
            else:
                mixture[page.virtual_address].append(page)

    for virtual_address in mixture.keys():
        shared_pages: List[Page] = get_shared_pages(mixture[virtual_address])
        if shared_pages:
            mixture[virtual_address] = shared_pages
            mixture_shared_state[virtual_address] = True
            calculate_page_digests(mixture[virtual_address], module_base_address, False)
        else:
            calculate_page_digests(mixture[virtual_address], module_base_address, True)

    logger.info('\nResults after choosing a page for each available virtual address:')
    for virtual_address in mixture.keys():
        if mixture_shared_state[virtual_address]:
            # The following code (until indicated) is only useful for InterModex
            non_anomalous_pages: List[Page] = []
            for page in mixture[virtual_address]:
                if not page.is_anomalous:
                    non_anomalous_pages.append(page)
            if 0 < len(non_anomalous_pages) < len(mixture[virtual_address]):
                mixture[virtual_address] = non_anomalous_pages
            # The code only useful fot InterModex ends here

            # Check the contents that a list of shared pages with the same virtual address have, and write to the mixed module accordingly
            page_digests: List[str] = get_page_digests(mixture[virtual_address])  # SHA-256 digests
            are_all_shared_pages_equal: bool = check_if_all_elements_are_equal(page_digests)
            if are_all_shared_pages_equal:
                # All the shared pages have the same contents, it does not matter which one is picked
                shared_page: Page = mixture[virtual_address][0]
                insert_page_into_mixed_module(shared_page, module_base_address, mixed_module,
                                              mixed_module_pages_metadata, shared_page.is_anomalous)
                logger.info(
                    f'\tAll the shared pages whose virtual address is {hex(virtual_address)} ({len(mixture[virtual_address])}) (offset {virtual_address - module_base_address}) are equal (SHA-256 digest: {shared_page.contents_digest})')
            else:
                most_common_page_digest: str = get_most_common_element(page_digests)
                # Find a page with the most common digest, it does not matter which page is picked as long as its digest matches with the most common one
                most_common_shared_page: Page = find_page_with_certain_digest(mixture[virtual_address],
                                                                              most_common_page_digest)
                insert_page_into_mixed_module(most_common_shared_page, module_base_address, mixed_module,
                                              mixed_module_pages_metadata, True)
                instances_of_each_page_digest: Dict[str, int] = count_instances_of_each_element(page_digests)
                logger.info(
                    f'\tAll the shared pages whose virtual address is {hex(virtual_address)} ({len(mixture[virtual_address])}) (offset {virtual_address - module_base_address}) are not equal (there are {len(instances_of_each_page_digest.keys())} different instances), here is how many times each SHA-256 digest is present:')
                for page_digest in instances_of_each_page_digest.keys():
                    logger.info(f'\t\t{page_digest}: {instances_of_each_page_digest[page_digest]}')

                if dump_anomalies:
                    different_page_digests = instances_of_each_page_digest.keys()
                    different_pages: List[Page] = []
                    for page_digest in different_page_digests:
                        different_pages.append(find_page_with_certain_digest(mixture[virtual_address], page_digest))
                    anomalies_directory: str = os.path.join(output_directory, 'anomalies')
                    if not os.path.exists(anomalies_directory):
                        os.makedirs(anomalies_directory)
                    for i in range(0, len(different_pages)):
                        page: Page = different_pages[i]
                        page_offset: int = page.virtual_address - module_base_address
                        page_filename: str = f'shared_page_{i + 1}_at_offset_{page_offset}.dmp'
                        page_file_path: str = os.path.join(anomalies_directory, page_filename)
                        dump_page(page, page_offset, page_file_path)
                        files_generated.append(page_file_path)
        else:
            # In this case, no shared pages were found that started with the current virtual address.
            # As a result, a representative page has to be chosen to be inserted in the mixed module.
            logger.info(
                f'\tNo shared pages were found that started with the virtual address {hex(virtual_address)} (offset {virtual_address - module_base_address}). As a result, a representative page of the total {len(mixture[virtual_address])} pages has to be chosen. Below is the process followed to choose the representative page:')
            page_similarity_digests: List[str] = get_page_digests(mixture[virtual_address])  # TLSH digests

            # 3 or more digests need to exist in order to make a comparison between all of them to finally choose a representative one, so:
            #   - If only one digest exists, that digest will be chosen
            #   - If only two digests exist, the first one is chosen
            if len(page_similarity_digests) < 3:
                representative_page_digest: str = page_similarity_digests[0]
                logger.info(
                    '\t\tNo comparison could be done because there were less than 3 page digests, so the first digest was chosen')
            else:
                representative_page_digest = choose_representative_page_digest(page_similarity_digests, logger)
                if representative_page_digest == 'INVALID_DIGEST':
                    # If a representative digest cannot be chosen through a comparison, then the first one is chosen
                    representative_page_digest = page_similarity_digests[0]
                    logger.info(
                        '\t\tNo comparison could be done because not all TLSH digests were valid, so the first digest was chosen')

            representative_page: Page = find_page_with_certain_digest(mixture[virtual_address],
                                                                      representative_page_digest)
            calculate_page_digests([representative_page], module_base_address,
                                   False)  # Calculate the SHA-256 digest of the representative page
            insert_page_into_mixed_module(representative_page, module_base_address, mixed_module,
                                          mixed_module_pages_metadata, False)

    # Statistics about the information extracted
    bytes_retrieved: int = 0
    shared_bytes_retrieved: int = 0
    private_bytes_retrieved: int = 0
    for page_metadata_entry in mixed_module_pages_metadata:
        page_size: int = page_metadata_entry['size']
        bytes_retrieved += page_size
        if page_metadata_entry['is_shared']:
            shared_bytes_retrieved += page_size
        else:
            private_bytes_retrieved += page_size

    logger.info('\nInformation about the extracted module:')
    logger.info(f'\tModule size: {module_size} bytes')
    logger.info(
        f'\tTotal bytes retrieved: {bytes_retrieved}. As a result the {bytes_retrieved / module_size:.2%} of the module was retrieved. The pages that were not retrieved are filled with zeros.')
    logger.info('\tOf the bytes retrieved:')
    logger.info(
        f'\t\t{shared_bytes_retrieved / bytes_retrieved:.2%} were shared ({shared_bytes_retrieved} shared bytes in total)')
    logger.info(
        f'\t\t{private_bytes_retrieved / bytes_retrieved:.2%} were private ({private_bytes_retrieved} private bytes in total)')

    # Join all the metadata about the mixed module
    mixed_module_metadata: Dict[str, Any] = {'module_path': module_path.casefold(),
                                             'module_base_address': hex(module_base_address),
                                             'module_size': module_size,
                                             'general_statistics': {'bytes_retrieved': bytes_retrieved,
                                                                    'shared_bytes_retrieved': shared_bytes_retrieved,
                                                                    'private_bytes_retrieved': private_bytes_retrieved},
                                             'pages': mixed_module_pages_metadata}

    # Statistics regarding a Modex extraction
    if is_modex_calling:
        process_ids_where_module_is_mapped: List[int] = []
        number_of_pages_mapped_in_each_process: Dict[int, Any] = {}  # The keys are process IDs

        for module in modules:
            process_ids_where_module_is_mapped.append(module.process_id)
            number_of_shared_pages: int = 0
            number_of_private_pages: int = 0
            for page in module.pages:
                if page.is_shared():
                    number_of_shared_pages += 1
                else:
                    number_of_private_pages += 1
            number_of_pages_mapped_in_each_process[module.process_id] = {
                'number_of_shared_pages': number_of_shared_pages,
                'number_of_private_pages': number_of_private_pages}

        end_time = time.time()
        mixed_module_metadata['modex_statistics'] = {
            'process_ids_where_module_is_mapped': process_ids_where_module_is_mapped,
            'number_of_pages_mapped_in_each_process': number_of_pages_mapped_in_each_process,
            'execution_time_in_seconds': end_time - start_time}

    mixed_module_path: str = os.path.join(output_directory, mixed_module_filename)
    mixed_module_metadata_path: str = os.path.join(output_directory, mixed_module_metadata_filename)

    with open(mixed_module_path, mode='wb') as dumped_mixed_module:
        dumped_mixed_module.write(mixed_module)

    with open(mixed_module_metadata_path, 'w') as mixed_module_metadata_file:
        json.dump(mixed_module_metadata, mixed_module_metadata_file, ensure_ascii=False, indent=4)

    files_generated.append(mixed_module_path)
    files_generated.append(mixed_module_metadata_path)

    return files_generated


class Modex(interfaces.plugins.PluginInterface):
    """Extracts a module as complete as possible."""
    _required_framework_version = (2, 0, 0)
    _version = (0, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description='Memory layer for the kernel',
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name="nt_symbols",
                                                description="Windows kernel symbols"),
            requirements.PluginRequirement(name='pslist',
                                           plugin=pslist.PsList,
                                           version=(2, 0, 0)),
            requirements.PluginRequirement(name='dlllist',
                                           plugin=dlllist.DllList,
                                           version=(2, 0, 0)),
            requirements.PluginRequirement(name='simple_pteenum',
                                           plugin=simple_pteenum.SimplePteEnumerator,
                                           version=(0, 9, 0)),
            requirements.StringRequirement(name="module",
                                           description="Module name",
                                           optional=False),
            requirements.BooleanRequirement(name='dump_anomalies',
                                            description="When there are different shared pages at the same offset, dump those pages",
                                            default=False,
                                            optional=True)
        ]

    def run(self):
        start_time = time.time()
        output_directory: str = f'modex_output_{get_current_utc_timestamp()}'  # Directory where the Modex output will be placed
        os.makedirs(output_directory)

        log_file_path = os.path.join(output_directory, 'modex_log.txt')
        logger = create_logger(log_file_path, 'modex_logger', logging.INFO)

        module_supplied: str = self.config['module'].casefold()
        dump_anomalies: bool = self.config['dump_anomalies']
        modules_to_mix: List[Module] = []
        files_finally_generated: List[str] = [log_file_path]

        # For each process, find if the supplied module is mapped on it. If so, dump the module.
        processes = pslist.PsList.list_processes(self.context,
                                                 self.config['primary'],
                                                 self.config['nt_symbols'])

        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                'windows',
                                                                'pe',
                                                                class_types=pe.class_types)

        for process in processes:
            process_id = process.UniqueProcessId
            process_layer_name = process.add_process_layer()
            for entry in process.load_order_modules():
                try:
                    module_name = entry.BaseDllName.get_string()
                    module_path = entry.FullDllName.get_string()
                    if module_name.casefold() == module_supplied:
                        try:
                            module_base_address = format_hints.Hex(entry.DllBase)
                        except exceptions.InvalidAddressException:
                            module_base_address = None

                        try:
                            module_size = format_hints.Hex(entry.SizeOfImage)
                        except exceptions.InvalidAddressException:
                            module_size = None

                        if module_base_address is not None and module_size is not None:
                            file_handle = dlllist.DllList.dump_pe(self.context,
                                                                  pe_table_name,
                                                                  entry,
                                                                  self.open,
                                                                  process_layer_name,
                                                                  prefix=f'pid.{process_id}.')
                            if file_handle:
                                file_handle.close()
                                dumped_module_filename = file_handle.preferred_filename
                                modules_to_mix.append(
                                    Module(module_name, module_path, module_base_address, module_size,
                                           process_id, dumped_module_filename, []))
                except exceptions.InvalidAddressException:
                    pass

        if not modules_to_mix:
            logger.info('The module supplied is not mapped in any process')
            return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

        logger.info(f'Modules to mix (before validation) ({len(modules_to_mix)}):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix.get_basic_information()}')

        # The modules under C:\Windows\SysWOW64 are not taken into account
        modules_to_mix = delete_modules_under_syswow64(modules_to_mix, logger)

        if not modules_to_mix:
            logger.info(
                '\nAll the identified modules are under the C:\\Windows\\SysWOW64 directory, as a result, they cannot be mixed')
            return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

        # Make sure that the modules can be mixed
        can_modules_be_mixed: bool = check_if_modules_can_be_mixed(modules_to_mix, logger)
        if not can_modules_be_mixed:
            delete_dmp_files(modules_to_mix)
            delete_zero_bytes_dmp_files()
            return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

        logger.info(f'\nModules to mix (after validation) ({len(modules_to_mix)}):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix.get_basic_information()}')

        # For each dumped module, retrieve information about its pages
        for module_to_mix in modules_to_mix:
            pages: List[List[Any]] = self.get_module_pages(module_to_mix)
            for page in pages:
                relevant_page_details: Dict[str, str] = get_relevant_page_details(page)
                page_virtual_address = relevant_page_details['virtual_address']
                page_size = relevant_page_details['size']
                page_pfn_db_entry_prototype_pte_flag = relevant_page_details['pfn_db_entry_prototype_pte_flag']
                if None not in (page_virtual_address, page_size, page_pfn_db_entry_prototype_pte_flag):
                    module_to_mix.pages.append(
                        Page(int(page_virtual_address, 16), int(page_size, 16), page_pfn_db_entry_prototype_pte_flag,
                             module_to_mix.filename))

        # Check if the last page retrieved for each module is out of bounds
        for module_to_mix in modules_to_mix:
            first_out_of_bounds_address: int = module_to_mix.base_address + module_to_mix.size
            if module_to_mix.pages[-1].virtual_address == first_out_of_bounds_address:
                del module_to_mix.pages[-1]

        logger.info('\nModules to mix (after validation and alongside the retrieved pages for each one):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix.get_basic_information()}')
            for page in module_to_mix.pages:
                logger.info(f'\t\t{page.get_basic_information()}')

        mixed_module_filename: str = f'{module_supplied.lower()}.dmp'
        mixed_module_metadata_filename: str = f'{module_supplied.lower()}.description.json'

        # Perform the mixture
        files_finally_generated += mix_modules(modules_to_mix, output_directory, mixed_module_filename,
                                               mixed_module_metadata_filename, dump_anomalies, logger, True, start_time)

        # Delete the .dmp files that were used to create the final .dmp file
        delete_dmp_files(modules_to_mix)

        delete_zero_bytes_dmp_files()

        return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

    def _generator(self, filenames):
        for filename in filenames:
            yield 0, [filename]

    def get_module_pages(self, module: Module) -> List[List[Any]]:
        pages: List[List[Any]] = []
        self.context.config['plugins.Modex.SimplePteEnumerator.pid'] = [module.process_id]
        self.context.config['plugins.Modex.SimplePteEnumerator.start'] = module.base_address
        self.context.config['plugins.Modex.SimplePteEnumerator.end'] = module.base_address + module.size
        self.context.config['plugins.Modex.SimplePteEnumerator.include_image_files'] = True
        self.context.config['plugins.Modex.SimplePteEnumerator.check_valid'] = True
        self.context.config['plugins.Modex.SimplePteEnumerator.print_pages'] = True

        automagics = automagic.choose_automagic(automagic.available(self._context),
                                                simple_pteenum.SimplePteEnumerator)
        simple_pteenum_plugin = plugins.construct_plugin(self.context, automagics,
                                                         simple_pteenum.SimplePteEnumerator,
                                                         self.config_path, self._progress_callback, self.open)
        treegrid = simple_pteenum_plugin.run()

        def visitor(node, _accumulator):
            pages.append(node.values)
            return None

        treegrid.populate(visitor, None)
        return pages
