"""Owned dependency setup and exact installed-wheel identity, stdlib only.

Owner setup uses reviewed lock files; current receipts are not source pins.
No installation or network operation happens at import time.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import venv
import zipfile
import socket
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit

from review.transport.direct_plan_gate import owned, read, require, digest, canonical

LOCKS = ('config/requirements-plan-base.txt', 'config/requirements-plan-auth.txt')
ENVIRONMENT = '.venv-plan'
CACHE = 'review/dependencies/direct_plan/wheels'


def normalize(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def locked_packages(project):
    result = {}
    for relative in LOCKS:
        for line in read(project, relative).decode('ascii').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):continue
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([A-Za-z0-9_.]+) --hash=sha256:([0-9a-f]{64})', line)
            require(match is not None, 'owner_dependency_lock_format')
            name, version, sha = match.groups(); name = normalize(name)
            value = {'name': name, 'version': version, 'sha256': sha}
            require(name not in result or result[name] == value, 'owner_dependency_lock_conflict')
            result[name] = value
    require(len(result) == 11 and result.get('pyjwt', {}).get('version') == '2.14.0',
            'owner_dependency_exact_profile')
    return result


def wheels(project):
    expected = locked_packages(project)
    inventory = json.loads(read(project, 'review/dependencies/inventory.json'))
    metadata = json.loads(read(project, 'review/direct_plan_passage/auth_dependency_metadata.json'))
    rows = [dict(row, relative='review/dependencies/wheels/' + row['filename'])
            for row in inventory if normalize(row['name']) in expected]
    rows.append(dict(metadata['wheel'], name='PyJWT', version=metadata['version'],
                     relative=CACHE + '/' + metadata['wheel']['filename']))
    result = {}
    for row in rows:
        name = normalize(row['name'])
        require(name in expected and row['version'] == expected[name]['version']
                and row['sha256'] == expected[name]['sha256'], 'owner_dependency_public_identity')
        require(Path(row['filename']).name == row['filename'] and row['filename'].endswith('.whl'),
                'owner_dependency_wheel_filename')
        path = owned(project, row['relative'])
        require(path.is_file() and digest(read(project, row['relative'], 128 * 1024 * 1024)) == row['sha256'],
                'owner_dependency_wheel_unavailable_or_changed')
        result[name] = dict(row, path=str(path))
    require(set(result) == set(expected), 'owner_dependency_wheel_closure')
    return result


def site_directory(environment):
    return Path(environment) / ('lib/python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor)) / 'site-packages'


def verify_bootstrap(project, environment=None):
    value=json.loads(read(project,'review/direct_plan_passage/bootstrap_identity.json'))
    require(list(sys.version_info[:3])==value['python_version'],
            'owner_dependency_base_python_version_changed')
    base=Path(value['base_executable'])
    info=base.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not base.is_symlink()
            and base.resolve(strict=True)==base
            and digest(base.read_bytes())==value['base_executable_sha256'],
            'owner_dependency_base_binary_changed')
    # The accepted executable determines the runtime root. Homebrew's Opt alias
    # may spell that same root differently after isolated reexec; it cannot
    # select another installation. Owned environment symlink rules are unchanged.
    prefix=base.parent.parent.resolve(strict=True)
    require(base.parent.name=='bin'
            and Path(value['base_prefix']).resolve(strict=True)==prefix
            and Path(sys.base_prefix).resolve(strict=True)==prefix,
            'owner_dependency_base_python_prefix_changed')
    require(digest(Path(value['ensurepip_wheel']).read_bytes())==value['ensurepip_wheel_sha256'],
            'owner_dependency_bootstrap_wheel_changed')
    if environment is not None:
        python=owned(project,str((Path(environment)/'bin/python').relative_to(project)))
        info=python.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                and digest(python.read_bytes())==value['base_executable_sha256'],
                'owner_dependency_selected_binary_changed')
        cfg=parse_venv_config(owned(project,str((Path(environment)/'pyvenv.cfg').relative_to(project))).read_text())
        require(cfg.get('include-system-site-packages')=='false'
                and cfg.get('version')=='.'.join(map(str,value['python_version']))
                and cfg.get('executable')==value['base_executable']
                and cfg.get('home')==value['venv_home'],
                'owner_dependency_venv_configuration_changed')
    return value


def parse_venv_config(raw):
    value={}
    for line in raw.splitlines():
        require(' = ' in line,'owner_dependency_venv_configuration_changed')
        key,text=line.split(' = ',1)
        require(key not in value and key in ('home','include-system-site-packages','version','executable','command','prompt'),
                'owner_dependency_venv_configuration_changed')
        value[key]=text
    return value


def verify_wheel_surface(environment, rows, *, complete=True, ignore_inert_pycache=False):
    """No unlisted importable file may shadow a pinned wheel module."""
    site=site_directory(environment);expected={};roots=set()
    for node in (site,*site.parents):
        require(not node.is_symlink(),'owner_dependency_site_ancestor_symlink')
        if node==Path(environment):break
    require(site.is_dir(),'owner_dependency_site_missing')
    for row in rows:
        require(digest(Path(row['path']).read_bytes())==row['sha256'],'owner_dependency_wheel_changed')
        with zipfile.ZipFile(row['path']) as archive:
            for info in archive.infolist():
                if info.is_dir():continue
                relative=info.filename
                require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                        and not stat.S_ISLNK(info.external_attr>>16),'owner_dependency_wheel_path')
                roots.add(Path(relative).parts[0])
                if relative.endswith('.dist-info/RECORD'):continue
                target=site/relative
                for node in (target,*target.parents):
                    require(not node.is_symlink(),'owner_dependency_installed_symlink')
                    if node==site:break
                expected[relative]=digest(archive.read(info))
                require(target.is_file() and digest(target.read_bytes())==expected[relative],
                        'owner_dependency_installed_file_mismatch')
    for node in site.rglob('*'):
        relative=str(node.relative_to(site));root=Path(relative).parts[0]
        if not complete and root not in roots:continue
        require(not node.is_symlink(),'owner_dependency_installed_symlink')
        if node.is_dir():continue
        parts=Path(relative).parts
        if ignore_inert_pycache and '__pycache__' in parts and node.suffix=='.pyc':
            require(sys.dont_write_bytecode and sys.pycache_prefix is not None
                    and not Path(sys.pycache_prefix).exists(),'owner_dependency_fixture_cache_isolation')
            continue
        generated=('.dist-info' in parts[-2] if len(parts)>1 else False) and node.name in ('RECORD','INSTALLER','REQUESTED','direct_url.json')
        require(relative in expected or generated,'owner_dependency_unlisted_import_surface')
    require(not list(site.glob('*.pth')) and not (site/'sitecustomize.py').exists()
            and not (site/'usercustomize.py').exists(),'owner_dependency_startup_hook_refused')
    return expected


def verify_distribution_files(project, environment):
    """Compare actual installed files to the exact externally pinned wheel bytes."""
    bootstrap=verify_bootstrap(project,environment)
    package_rows=list(wheels(project).values())
    surface=verify_wheel_surface(environment,package_rows+[{
        'path':bootstrap['ensurepip_wheel'],'sha256':bootstrap['ensurepip_wheel_sha256']}])
    site = site_directory(environment)
    require(site.is_dir() and not site.is_symlink(), 'owner_dependency_site_missing')
    checked = surface; versions = {}
    for name, row in wheels(project).items():
        versions[name] = row['version']
        with zipfile.ZipFile(row['path']) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'owner_dependency_wheel_duplicate')
            for info in archive.infolist():
                if info.is_dir(): continue
                relative = info.filename
                require(not Path(relative).is_absolute() and '..' not in Path(relative).parts
                        and '.data' not in Path(relative).parts and not stat.S_ISLNK(info.external_attr >> 16),
                        'owner_dependency_wheel_path')
                # Installers rewrite RECORD and add direct_url/INSTALLER files.
                # They are metadata, not an alternative source of code identity.
                if relative.endswith('.dist-info/RECORD'): continue
                target = site / relative
                for parent in (target, *target.parents):
                    require(not parent.is_symlink(), 'owner_dependency_installed_symlink')
                    if parent == site: break
                require(target.is_file() and digest(target.read_bytes()) == digest(archive.read(info)),
                        'owner_dependency_installed_file_mismatch')
                checked[relative] = digest(target.read_bytes())
    require(not list(site.glob('*.pth')) and not (site/'sitecustomize.py').exists()
            and not (site/'usercustomize.py').exists(), 'owner_dependency_startup_hook_refused')
    return {'schema': 'radik.verified_plan_dependencies.v01', 'status': 'PINNED_WHEEL_BYTES_MATCH_INSTALLED_FILES',
            'environment': str(Path(environment)), 'versions': versions, 'files': checked,
            'installed_identity_sha256': digest(checked), 'package_count': len(versions),
            'lock_sha256': {relative: digest(read(project, relative)) for relative in LOCKS}}


def verify_installed(project):
    environment = Path(project) / ENVIRONMENT
    require(Path(sys.prefix).absolute() == environment and sys.version_info[:2] == (3, 14),
            'owner_dependency_interpreter_not_selected_environment')
    value = verify_distribution_files(project, environment)
    return value


SETUP_JOURNAL = 'review/before_owner_run_fix_passage/setup_journal.json'


class SetupError(ValueError):
    def __init__(self, code, *, stage, category, exit_code=None, http_status=None):
        super().__init__(code)
        self.code,self.stage,self.category,self.exit_code,self.http_status=code,stage,category,exit_code,http_status


def setup_identity(project):
    bootstrap=verify_bootstrap(project)
    return digest({'locks':locked_packages(project),'bootstrap':bootstrap,
                   'setup_source':digest(Path(__file__).read_bytes())})


def _journal(project,value):
    path=owned(project,SETUP_JOURNAL);path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix('.pending')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(canonical(value)+b'\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _download_locked_wheels(project):
    # Existing ten exact wheels are retained. Only the documented PyJWT artifact
    # can be downloaded here; no package resolver, credentials or final env runs.
    packages=locked_packages(project)
    inventory=json.loads(read(project,'review/dependencies/inventory.json'))
    for row in inventory:
        name=normalize(row['name'])
        if name in packages:
            require(row['sha256']==packages[name]['sha256'] and row['version']==packages[name]['version'],
                    'owner_dependency_public_identity')
            require(digest(read(project,'review/dependencies/wheels/'+row['filename'],128*1024*1024))==row['sha256'],
                    'owner_dependency_existing_wheel_changed')
    metadata=json.loads(read(project,'review/direct_plan_passage/auth_dependency_metadata.json'))['wheel']
    target=owned(project,CACHE+'/'+metadata['filename']);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if target.exists():
        require(digest(read(project,str(target.relative_to(project))))==metadata['sha256'],'owner_dependency_wheel_changed')
        return wheels(project)
    url=metadata['url'];uri=urlsplit(url)
    require(uri.scheme=='https' and uri.netloc=='files.pythonhosted.org' and not uri.query and not uri.fragment
            and uri.path.endswith('/'+metadata['filename']),'owner_dependency_download_origin')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),
                                      urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=60) as response:
            require(response.status==200,'owner_dependency_download_http')
            raw=response.read(metadata['size']+1)
    except urllib.error.HTTPError as error:
        raise SetupError('owner_dependency_download_http',stage='WHEELS',category='HTTP',http_status=error.code) from None
    except urllib.error.URLError as error:
        reason=error.reason
        category='DNS' if isinstance(reason,socket.gaierror) else 'TLS' if isinstance(reason,ssl.SSLError) else 'UNKNOWN'
        raise SetupError('owner_dependency_download_'+category.lower(),stage='WHEELS',category=category) from None
    except (TimeoutError,OSError):
        raise SetupError('owner_dependency_download_unknown',stage='WHEELS',category='UNKNOWN') from None
    require(len(raw)==metadata['size'] and digest(raw)==metadata['sha256'],'owner_dependency_download_hash')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    fd=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return wheels(project)


def verify_partial_surface(environment,rows):
    """A known interrupted install may omit files; every present file is exact."""
    site=site_directory(environment);expected={}
    for node in (site,*site.parents):
        require(not node.is_symlink(),'owner_dependency_site_ancestor_symlink')
        if node==Path(environment):break
    require(site.is_dir(),'owner_dependency_site_missing')
    for row in rows:
        require(digest(Path(row['path']).read_bytes())==row['sha256'],'owner_dependency_wheel_changed')
        with zipfile.ZipFile(row['path']) as archive:
            for info in archive.infolist():
                if info.is_dir():continue
                rel=info.filename
                require(not Path(rel).is_absolute() and '..' not in Path(rel).parts
                        and not stat.S_ISLNK(info.external_attr>>16),'owner_dependency_wheel_path')
                if not rel.endswith('.dist-info/RECORD'):expected[rel]=digest(archive.read(info))
    for node in site.rglob('*'):
        require(not node.is_symlink(),'owner_dependency_installed_symlink')
        if node.is_dir():continue
        info=node.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,
                'owner_dependency_partial_regular_single_link')
        rel=str(node.relative_to(site));parts=Path(rel).parts
        generated=len(parts)>1 and parts[-2].endswith('.dist-info') and node.name in ('RECORD','INSTALLER','REQUESTED','direct_url.json')
        require(rel in expected or generated,'owner_dependency_unlisted_import_surface')
        if rel in expected:
            fd=os.open(node,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd,'rb') as stream:
                info=os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,
                        'owner_dependency_partial_regular_single_link')
                raw=stream.read(128*1024*1024+1)
            require(len(raw)<=128*1024*1024 and digest(raw)==expected[rel],
                    'owner_dependency_installed_file_mismatch')
    return expected


def _run_pip(project,environment,bootstrap,arguments,stage):
    # Always execute the pinned bundled wheel with site disabled. Partial pip or
    # installed packages are never execution prerequisites of their own repair.
    child=dict(os.environ)
    for key in ('PYTHONPATH','PYTHONHOME','OPENAI_API_KEY','CODEX_API_KEY','CODEX_ACCESS_TOKEN','ACCESS_TOKEN'):child.pop(key,None)
    child['PYTHONDONTWRITEBYTECODE']='1'
    argv=['pip','--isolated','--disable-pip-version-check','--no-cache-dir']+arguments
    code='import sys,runpy;sys.path.insert(0,'+repr(bootstrap['ensurepip_wheel'])+');sys.argv='+repr(argv)+';runpy.run_module("pip",run_name="__main__")'
    try:
        result=subprocess.run([str(environment/'bin/python'),'-I','-S','-B','-c',code],cwd=project,env=child,
                              stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=300)
    except (OSError,subprocess.TimeoutExpired):
        raise SetupError('owner_dependency_install_unknown',stage=stage,category='UNKNOWN') from None
    if result.returncode:
        raise SetupError('owner_dependency_install_failed',stage=stage,category='INSTALL',exit_code=result.returncode)


def _lock_file(project,name,raw):
    path=owned(project,'review/dependencies/direct_plan/'+name);path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():require(read(project,str(path.relative_to(project)))==raw,'owner_dependency_combined_lock_changed')
    else:
        with path.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    return path


def setup_owner(project, *, resume=False, progress=None, phase_binding=None):
    """Closed owner setup phases; explicit resume never authorizes auth or live."""
    project=Path(project);environment=owned(project,ENVIRONMENT);identity=setup_identity(project)
    path=owned(project,SETUP_JOURNAL)
    prior=json.loads(read(project,SETUP_JOURNAL)) if path.exists() else None
    if resume:
        require(prior is not None and prior.get('identity')==identity and prior.get('phase_binding')==phase_binding
                and prior.get('stage') in ('WHEELS','ENV_CREATING','ENV_READY','BOOTSTRAP','INSTALL','VERIFY','READY'),
                'owner_setup_resume_identity_or_stage')
    elif prior is not None and prior.get('stage')!='READY':
        raise ValueError('owner_setup_explicit_resume_required')
    if prior is None:
        require(not environment.exists(),'owner_setup_unrelated_environment')
    elif prior.get('stage')=='READY':
        require(prior['identity']==identity,'owner_setup_resume_identity_or_stage')
        return verify_distribution_files(project,environment)
    journal={'schema':'radik.closed_owner_setup.v01','identity':identity,'phase_binding':phase_binding,
             'stage':prior['stage'] if prior else 'WHEELS','status':'RUNNING','auth_started':False}
    def stage(name):
        journal.update(stage=name,status='RUNNING');_journal(project,journal)
        if progress:progress(name)
    try:
        stage(journal['stage'])
        rows=_download_locked_wheels(project) # Final environment is still absent on first download failure.
        bootstrap=verify_bootstrap(project)
        wheel_rows=list(rows.values())+[{'path':bootstrap['ensurepip_wheel'],'sha256':bootstrap['ensurepip_wheel_sha256']}]
        if not environment.exists():
            require(journal['stage'] in ('WHEELS','ENV_CREATING'),'owner_setup_missing_known_environment')
            stage('ENV_CREATING')
            venv.EnvBuilder(with_pip=False,symlinks=False).create(environment)
            verify_bootstrap(project,environment);stage('ENV_READY')
        else:
            require(prior is not None and prior['stage'] in ('ENV_CREATING','ENV_READY','BOOTSTRAP','INSTALL','VERIFY'),
                    'owner_setup_unknown_partial_environment')
            verify_bootstrap(project,environment)
        verify_partial_surface(environment,wheel_rows)
        raw='\n'.join(row['name']+'=='+row['version']+' --hash=sha256:'+row['sha256'] for row in locked_packages(project).values()).encode()+b'\n'
        lock=_lock_file(project,'combined.lock',raw)
        pip=Path(bootstrap['ensurepip_wheel']);pip_version=pip.name.split('-')[1]
        pip_lock=_lock_file(project,'pip-bootstrap.lock',('pip=='+pip_version+' --hash=sha256:'+bootstrap['ensurepip_wheel_sha256']+'\n').encode())
        stage('BOOTSTRAP');verify_bootstrap(project,environment);verify_partial_surface(environment,wheel_rows)
        _run_pip(project,environment,bootstrap,['install','--ignore-installed','--no-index','--no-deps','--no-compile','--require-hashes','--find-links',str(pip.parent),'-r',str(pip_lock)],'BOOTSTRAP')
        stage('INSTALL');verify_bootstrap(project,environment);verify_partial_surface(environment,wheel_rows)
        _run_pip(project,environment,bootstrap,['install','--ignore-installed','--no-index','--no-deps','--no-compile','--only-binary=:all:','--require-hashes',
                 '--find-links',str(project/'review/dependencies/wheels'),'--find-links',str(project/CACHE),'-r',str(lock)],'INSTALL')
        stage('VERIFY');value=verify_distribution_files(project,environment)
        journal.update(stage='READY',status='DEPENDENCIES_READY_OWNER_AUTHORIZATION_PENDING');_journal(project,journal)
        return value
    except BaseException as error:
        code=getattr(error,'code',str(error) if isinstance(error,ValueError) else 'owner_dependency_setup_unknown')
        category=getattr(error,'category','HASH' if isinstance(error,ValueError) and code in ('owner_dependency_download_hash','owner_dependency_wheel_changed','owner_dependency_existing_wheel_changed','owner_dependency_installed_file_mismatch','owner_dependency_selected_binary_changed','owner_dependency_base_binary_changed','owner_dependency_bootstrap_wheel_changed') else 'UNKNOWN')
        journal.update(status='FAILED',error={'code':code,
            'category':category,'exit_code':getattr(error,'exit_code',None)})
        try:_journal(project,journal)
        except Exception:pass
        if not isinstance(error,SetupError):raise SetupError(code,stage=journal['stage'],category=category) from None
        raise
