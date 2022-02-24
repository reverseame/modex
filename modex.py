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


def create_module_representation(name: str, base_address: str, size: str, process_id: int,
                                 filename: str) -> Dict[str, Any]:
    return {'name': name, 'base_address': base_address, 'size': size, 'process_id': process_id,
            'filename': filename}


log_filename = create_log_filename()
logger = create_logger(log_filename)


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
        module_supplied: str = self.config['module'].casefold()
        modules_to_mix: List[Dict[str, Any]] = []
        files_finally_generated: List[str] = [log_filename]

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
                                module_filename = file_handle.preferred_filename
                                modules_to_mix.append(create_module_representation(module_name,
                                                                                   hex(module_base_address),
                                                                                   hex(module_size),
                                                                                   process_id,
                                                                                   module_filename))
                except exceptions.InvalidAddressException:
                    pass

        logger.info(f'Modules to mix ({len(modules_to_mix)}):')
        for module_to_mix in modules_to_mix:
            logger.info(f'\t{module_to_mix}')

        # Delete the .dmp files that were used to create the final .dmp file
        for module_to_mix in modules_to_mix:
            os.remove(module_to_mix['filename'])

        return renderers.TreeGrid([("Filename", str)], self._generator(files_finally_generated))

    def _generator(self, filenames):
        for filename in filenames:
            yield 0, [filename]
