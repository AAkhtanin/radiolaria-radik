"""Fresh-process native afterimage loader; reference bytes are never rewritten."""
import hashlib
import importlib.abc
import importlib.util
from importlib.machinery import ModuleSpec
import sys

from .application_profile_gate import select, _read, _path, require


class _Loader(importlib.abc.Loader):
    def __init__(self, path, raw):
        self.path,self.raw=path,raw

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__=str(self.path)
        exec(compile(self.raw,str(self.path),'exec',dont_inherit=True),module.__dict__)


class _Finder(importlib.abc.MetaPathFinder):
    def __init__(self, project, rows):
        self.project,self.rows=project,rows

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] not in ('hedgehog','demo'):
            return None
        logical=fullname.replace('.','/')
        candidates=(logical+'.py',logical+'/__init__.py')
        names=[name for name in candidates if name in self.rows]
        if not names and any(name.startswith(logical+'/')for name in self.rows):
            spec=ModuleSpec(fullname,loader=None,is_package=True)
            spec.submodule_search_locations=[str(self.project/'review/g2e_successor_passage/proposals/g2e_no_effects_v28_ordinary_entry_owner_scenario/native_runtime'/logical)]
            return spec
        require(len(names)==1,'native_profile_import_not_admitted')
        name=names[0]
        reference=self.rows[name]
        raw=_read(self.project,reference['path'])
        require(hashlib.sha256(raw).hexdigest()==reference['sha256'],'native_profile_source_changed')
        source=_path(self.project,reference['path'])
        return importlib.util.spec_from_file_location(fullname,source,
            loader=_Loader(source,raw),submodule_search_locations=[str(source.parent)] if name.endswith('/__init__.py') else None)


def install(project):
    selected=select(project)
    require(selected is not None,'native_profile_not_selected')
    require(not any(name.split('.')[0] in ('hedgehog','demo') for name in sys.modules),
        'native_profile_requires_fresh_process')
    rows=selected['manifest']['native_files']
    require(type(rows) is dict and len(rows)==77,'native_profile_finite_map')
    modules={logical:reference for logical,reference in rows.items()
        if logical.startswith(('hedgehog/','demo/')) and logical.endswith('.py')}
    require(len(modules)==43,'native_profile_module_map')
    for logical,reference in rows.items():
        require(type(logical) is str and not logical.startswith('/') and '..' not in logical.split('/')
            and selected['manifest']['pins'].get(reference['path'])==reference['sha256'],
            'native_profile_review_binding')
        require(hashlib.sha256(_read(project,reference['path'])).hexdigest()==reference['sha256'],
            'native_profile_source_changed')
    finder=_Finder(project,modules)
    sys.meta_path.insert(0,finder)
    return finder
