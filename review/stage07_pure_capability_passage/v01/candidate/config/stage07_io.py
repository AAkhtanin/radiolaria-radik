"""Finite application/worker source observation and owned filesystem boundary."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def require(value, code):
    if not value: raise ValueError(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()


def read_ref(ref):
    path=Path(ref['path'])
    require(path.is_absolute() and not path.is_symlink(),'stage07_reference_path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1
            and before.st_size==ref['size_bytes'] and before.st_size<=67108864,'stage07_reference_size')
        raw=stream.read(before.st_size+1);after=os.fstat(stream.fileno())
    require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
        (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        and len(raw)==ref['size_bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],
        'stage07_reference_changed')
    return raw


def reference(path):
    path=Path(path).absolute();raw=path.read_bytes()
    ref=dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),size_bytes=len(raw))
    read_ref(ref);return ref


def save(path,value):
    path=Path(path);raw=canonical(value)+b'\n'
    require(len(raw)<=16777216,'stage07_evidence_bound')
    with path.open('xb') as stream:
        require(stream.write(raw)==len(raw),'stage07_evidence_write')
        stream.flush();os.fsync(stream.fileno())
    ref=reference(path);require(ref['sha256']==hashlib.sha256(raw).hexdigest(),'stage07_evidence_readback')
    return ref


def fd_path(fd):
    require(type(fd)is int and fd>=0 and sys.platform=='darwin','stage07_descriptor_platform')
    info=os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),'stage07_descriptor_regular')
    return Path(os.fsdecode(fcntl.fcntl(fd,50,b'\0'*1024).split(b'\0',1)[0])).absolute()


def loaded(pins, allowed):
    rows=[];builtins=[]
    for name,module in tuple(sys.modules.items()):
        if module is None:continue
        value=getattr(module,'__file__',None)
        if value is None:
            spec=getattr(module,'__spec__',None)
            builtins.append(dict(module=name,origin=getattr(spec,'origin',None)));continue
        path=str(Path(value).absolute())
        require(path in pins and path in allowed,'stage07_loaded_source_not_admitted')
        read_ref(pins[path]);spec=getattr(module,'__spec__',None)
        rows.append(dict(module=name,path=path,sha256=pins[path]['sha256'],spec_name=getattr(spec,'name',None)))
    return dict(modules=sorted(rows,key=lambda x:x['module']),builtins_or_namespaces=sorted(builtins,key=lambda x:x['module']))


def fence(folder,read_paths,directory_paths,pins,*,allow_worker=None):
    """Keep normal Python worker execution finite without changing its executor."""
    folder=Path(folder).resolve();allowed=set(read_paths);directories=set(directory_paths);libraries=[]
    def path_of(value,dir_fd=None):
        if type(value)is int:return fd_path(value)
        path=Path(os.fsdecode(value))
        if not path.is_absolute() and type(dir_fd)is int and dir_fd>=0:path=fd_path(dir_fd)/path
        return path.absolute()
    def own(path):return path.is_relative_to(folder) and path.resolve().is_relative_to(folder)
    def writable(value,dir_fd=None):
        require(own(path_of(value,dir_fd)),'stage07_write_outside_owned_state')
    def audit(event,args):
        if event=='open':
            value,mode,flags=args
            if type(value)is int and value in (0,1,2):return
            path=path_of(value)
            writing=bool(flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
            writing=writing or isinstance(mode,str) and any(c in mode for c in 'wa+')
            if writing:writable(path)
            else:require(own(path) or str(path)in allowed,'stage07_read_outside_admitted_scope')
        elif event in ('os.listdir','os.scandir'):
            path=path_of(args[0] if args and args[0]is not None else '.')
            require(own(path) or str(path)in directories,'stage07_directory_outside_scope')
        elif event in ('os.remove','os.rmdir'):
            writable(args[0],args[1] if len(args)>1 else None)
        elif event in ('os.mkdir','os.chmod'):
            writable(args[0],args[2] if len(args)>2 else None)
        elif event=='os.utime':writable(args[0],args[3] if len(args)>3 else None)
        elif event=='os.rename':
            writable(args[0],args[2] if len(args)>2 else None);writable(args[1],args[3] if len(args)>3 else None)
        elif event in ('os.link','os.symlink','os.chdir','os.chroot'):
            raise ValueError('stage07_filesystem_escalation_refused')
        elif event=='subprocess.Popen':
            require(allow_worker is not None,'stage07_worker_cannot_spawn')
            allow_worker(args)
        elif event in ('os.system','os.fork','os.forkpty','os.exec','os.posix_spawn',
                'socket.__new__','socket.connect','socket.bind'):
            raise ValueError('stage07_process_or_network_refused')
        elif event=='ctypes.dlopen' and args and args[0]is not None:
            path=str(path_of(args[0]));require(path in pins and path in allowed,'stage07_unpinned_library')
            read_ref(pins[path]);libraries.append(dict(path=path,sha256=pins[path]['sha256']))
    sys.addaudithook(audit)
    return libraries
