import os
import re
import logging
from typing import List, Dict, Any
from datetime import datetime

from volatility3.framework import renderers, interfaces, automagic, plugins, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, dlllist, simple_pteenum


def create_log_filename():
    utc_now = datetime.utcnow()
    return f'modex_log_{utc_now.strftime("%d-%m-%Y_%H-%M-%S_UTC")}.txt'


def create_logger(filename: str):
    modex_logger = logging.getLogger('modex_logger')
    modex_logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(filename)
    file_handler.setLevel(logging.INFO)
    modex_logger.addHandler(file_handler)
    return modex_logger


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
    def __init__(self, virtual_address: int, size: int, pfn_db_entry_prototype_pte_flag: str):
        self.virtual_address: int = virtual_address
        self.size: int = size
        # pfn_db_entry_prototype_pte_flag can be 'True', 'False', or 'Undetermined'
        self.pfn_db_entry_prototype_pte_flag: str = pfn_db_entry_prototype_pte_flag

    def get_all_information(self):
        return {'virtual_address': hex(self.virtual_address), 'size': hex(self.size),
                'pfn_db_entry_prototype_pte_flag': self.pfn_db_entry_prototype_pte_flag}


class Module:
    def __init__(self, name: str, path: str, base_address: int, size: int, process_id: int, dumped_filename: str,
                 pages: List[Page]):
        self.name: str = name
        self.path: str = path
        self.base_address: int = base_address  # Virtual base address
        self.size: int = size  # Size in bytes
        self.process_id: int = process_id  # Identifier of the process where the module is mapped
        self.dumped_filename: str = dumped_filename  # Filename of the dumped module
        self.pages: List[Page] = pages

    def get_basic_information(self):
        return {'name': self.name, 'path': self.path, 'base_address': hex(self.base_address), 'size': hex(self.size),
                'process_id': self.process_id, 'dumped_filename': self.dumped_filename,
                'number_of_retrieved_pages': len(self.pages)}


def delete_dmp_files(modules: List[Module]) -> None:
    for module in modules:
        os.remove(module.dumped_filename)


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
            logger.info(f'\nModule under {syswow64_directory} identified: {module.path}')
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
        sizes.append(os.path.getsize(module.dumped_filename))
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


class Modex(interfaces.plugins.PluginInterface):
    """Modex Volatility 3 plugin."""
    _required_framework_version = (2, 0, 0)
    _version = (0, 0, 1)

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
                                           optional=False)
        ]

    def run(self):
        log_filename = create_log_filename()
        logger = create_logger(log_filename)

        module_supplied: str = self.config['module'].casefold()
        modules_to_mix: List[Module] = []
        files_finally_generated: List[str] = [log_filename]

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
            logger.info(f'The module supplied is not mapped in any process')
            return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

        logger.info(f'Modules to mix (before validation) ({len(modules_to_mix)}):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix.get_basic_information()}')

        # The modules under C:\Windows\SysWOW64 are not taken into account
        modules_to_mix = delete_modules_under_syswow64(modules_to_mix, logger)

        # Make sure that the modules can be mixed
        can_modules_be_mixed: bool = check_if_modules_can_be_mixed(modules_to_mix, logger)
        if not can_modules_be_mixed:
            delete_dmp_files(modules_to_mix)
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
                        Page(int(page_virtual_address, 16), int(page_size, 16), page_pfn_db_entry_prototype_pte_flag))

        # Check if the last page retrieved for each module is out of bounds
        for module_to_mix in modules_to_mix:
            first_out_of_bounds_address: int = module_to_mix.base_address + module_to_mix.size
            if module_to_mix.pages[-1].virtual_address == first_out_of_bounds_address:
                del module_to_mix.pages[-1]

        logger.info(f'\nModules to mix (after validation and alongside the retrieved pages for each one):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix.get_basic_information()}')
            for page in module_to_mix.pages:
                logger.info(f'\t\t{page.get_all_information()}')

        # Delete the .dmp files that were used to create the final .dmp file
        delete_dmp_files(modules_to_mix)

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
