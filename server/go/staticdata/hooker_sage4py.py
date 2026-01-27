import sys
import os
import subprocess
import types
from functools import wraps

class ComprehensiveSystemHook:
    def __init__(self):
        # 保存原始模块
        self.original_os = sys.modules.get('os', __import__('os'))
        self.original_subprocess = sys.modules.get('subprocess', __import__('subprocess'))
        self.original_pickle = sys.modules.get('pickle', __import__('pickle'))

        # 保存原始函数引用（安全获取，避免 AttributeError）
        self._save_os_functions()
        self._save_subprocess_functions()
        self._save_pickle_functions()

    def _save_os_functions(self):
        os_mod = self.original_os
        self.original_os_system = getattr(os_mod, 'system', None)
        self.original_os_popen = getattr(os_mod, 'popen', None)
        # os.spawn* functions
        self.original_os_spawnl = getattr(os_mod, 'spawnl', None)
        self.original_os_spawnv = getattr(os_mod, 'spawnv', None)
        self.original_os_spawnlp = getattr(os_mod, 'spawnlp', None)
        self.original_os_spawnvp = getattr(os_mod, 'spawnvp', None)
        self.original_os_spawnvpe = getattr(os_mod, 'spawnvpe', None)
        # os.exec* functions (for monitoring, though they replace process)
        self.original_os_execl = getattr(os_mod, 'execl', None)
        self.original_os_execv = getattr(os_mod, 'execv', None)
        self.original_os_execle = getattr(os_mod, 'execle', None)
        self.original_os_execve = getattr(os_mod, 'execve', None)
        self.original_os_execlp = getattr(os_mod, 'execlp', None)
        self.original_os_execvp = getattr(os_mod, 'execvp', None)
        self.original_os_execvpe = getattr(os_mod, 'execvpe', None)
        # Windows
        self.original_os_startfile = getattr(os_mod, 'startfile', None)

    def _save_subprocess_functions(self):
        sp = self.original_subprocess
        self.original_subprocess_run = getattr(sp, 'run', None)
        self.original_subprocess_call = getattr(sp, 'call', None)
        self.original_subprocess_check_call = getattr(sp, 'check_call', None)
        self.original_subprocess_check_output = getattr(sp, 'check_output', None)
        self.original_subprocess_getoutput = getattr(sp, 'getoutput', None)
        self.original_subprocess_getstatusoutput = getattr(sp, 'getstatusoutput', None)
        self.original_subprocess_Popen = getattr(sp, 'Popen', None)

    def _save_pickle_functions(self):
        pk = self.original_pickle
        self.original_pickle_load = getattr(pk, 'load', None)
        self.original_pickle_loads = getattr(pk, 'loads', None)

    def _format_command(self, command):
        """格式化命令为字符串，尽量还原原始调用形式"""
        if command is None:
            return "(None)"
        if isinstance(command, (list, tuple)):
            parts = []
            for part in command:
                s = str(part)
                if ' ' in s or '\t' in s or '"' in s or "'" in s:
                    # 简单转义：用双引号包围，内部双引号转义（不完美但够用）
                    s = s.replace('"', '\\"')
                    parts.append(f'"{s}"')
                else:
                    parts.append(s)
            return ' '.join(parts)
        else:
            return str(command)

    # ===== os hooks =====
    def _hooked_system(self, command):
        cmd_str = self._format_command(command)
        print(f"[Hook] os.system({cmd_str!r})")
        return self.original_os_system(command)

    def _hooked_popen(self, command, *args, **kwargs):
        cmd_str = self._format_command(command)
        print(f"[Hook] os.popen({cmd_str!r})  [delegates to subprocess]")
        return self.original_os_popen(command, *args, **kwargs)

    def _hooked_spawn(self, func_name, mode, *args):
        # args[0] is usually the path or command
        cmd_str = self._format_command(args[0] if args else "(no args)")
        print(f"[Hook] os.{func_name}({cmd_str!r}, mode={mode}, args={args[1:]})")
        original_func = getattr(self, f'original_os_{func_name}', None)
        if original_func:
            return original_func(mode, *args)
        else:
            raise AttributeError(f"os.{func_name} not available")

    def _hooked_exec(self, func_name, *args):
        cmd_str = self._format_command(args[0] if args else "(no args)")
        print(f"[Hook] os.{func_name}({cmd_str!r}, args={args[1:]})")
        original_func = getattr(self, f'original_os_{func_name}', None)
        if original_func:
            return original_func(*args)
        else:
            raise AttributeError(f"os.{func_name} not available")

    def _hooked_startfile(self, filepath, *args, **kwargs):
        print(f"[Hook] os.startfile({filepath!r}, args={args}, kwargs={kwargs})")
        return self.original_os_startfile(filepath, *args, **kwargs)

    # ===== subprocess hooks =====
    def _hooked_subprocess_run(self, *args, **kwargs):
        if args:
            cmd_str = self._format_command(args[0])
            print(f"[Hook] subprocess.run({cmd_str!r}, kwargs={kwargs})")
        return self.original_subprocess_run(*args, **kwargs)

    def _hooked_subprocess_call(self, *args, **kwargs):
        if args:
            cmd_str = self._format_command(args[0])
            print(f"[Hook] subprocess.call({cmd_str!r}, kwargs={kwargs})")
        return self.original_subprocess_call(*args, **kwargs)

    def _hooked_subprocess_check_call(self, *args, **kwargs):
        if args:
            cmd_str = self._format_command(args[0])
            print(f"[Hook] subprocess.check_call({cmd_str!r}, kwargs={kwargs})")
        return self.original_subprocess_check_call(*args, **kwargs)

    def _hooked_subprocess_check_output(self, *args, **kwargs):
        if args:
            cmd_str = self._format_command(args[0])
            print(f"[Hook] subprocess.check_output({cmd_str!r}, kwargs={kwargs})")
        return self.original_subprocess_check_output(*args, **kwargs)

    def _hooked_subprocess_getoutput(self, command):
        cmd_str = self._format_command(command)
        print(f"[Hook] subprocess.getoutput({cmd_str!r})")
        return self.original_subprocess_getoutput(command)

    def _hooked_subprocess_getstatusoutput(self, command):
        cmd_str = self._format_command(command)
        print(f"[Hook] subprocess.getstatusoutput({cmd_str!r})")
        return self.original_subprocess_getstatusoutput(command)

    # ===== pickle hooks =====
    def _hooked_pickle_load(self, file, *args, **kwargs):
        print("[Hook] pickle.load called")
        return self.original_pickle_load(file, *args, **kwargs)

    def _hooked_pickle_loads(self, data, *args, **kwargs):
        print("[Hook] pickle.loads called")
        return self.original_pickle_loads(data, *args, **kwargs)


class MockOS:
    def __init__(self, original_os, hook_manager):
        self._original_os = original_os
        self._hook_manager = hook_manager

    def __getattr__(self, name):
        hm = self._hook_manager
        # Hook system calls
        if name == 'system':
            return hm._hooked_system
        elif name == 'popen':
            if hm.original_os_popen:
                return hm._hooked_popen
        # Hook spawn functions
        elif name in ('spawnl', 'spawnv', 'spawnlp', 'spawnvp', 'spawnvpe'):
            def wrapper(mode, *args):
                return hm._hooked_spawn(name, mode, *args)
            return wrapper
        # Hook exec functions
        elif name in ('execl', 'execv', 'execle', 'execve', 'execlp', 'execvp', 'execvpe'):
            def wrapper(*args):
                return hm._hooked_exec(name, *args)
            return wrapper
        # Hook startfile (Windows)
        elif name == 'startfile':
            if hm.original_os_startfile:
                return hm._hooked_startfile
        # Fallback to original
        return getattr(self._original_os, name)


class MockSubprocess:
    def __init__(self, original_subprocess, hook_manager):
        self._original_subprocess = original_subprocess
        self._hook_manager = hook_manager

        # Hooked Popen class
        class HookedPopen(original_subprocess.Popen):
            def __init__(self, *args, **kwargs):
                if args:
                    cmd_str = hook_manager._format_command(args[0])
                    print(f"[Hook] subprocess.Popen({cmd_str!r}, kwargs={kwargs})")
                super().__init__(*args, **kwargs)

        self.HookedPopen = HookedPopen

    def __getattr__(self, name):
        hm = self._hook_manager
        if name == 'run':
            return hm._hooked_subprocess_run
        elif name == 'call':
            return hm._hooked_subprocess_call
        elif name == 'check_call':
            return hm._hooked_subprocess_check_call
        elif name == 'check_output':
            return hm._hooked_subprocess_check_output
        elif name == 'getoutput':
            if hm.original_subprocess_getoutput:
                return hm._hooked_subprocess_getoutput
        elif name == 'getstatusoutput':
            if hm.original_subprocess_getstatusoutput:
                return hm._hooked_subprocess_getstatusoutput
        elif name == 'Popen':
            return self.HookedPopen
        # Fallback
        return getattr(self._original_subprocess, name)


class MockPickle:
    def __init__(self, original_pickle, hook_manager):
        self._original_pickle = original_pickle
        self._hook_manager = hook_manager

    def __getattr__(self, name):
        if name == 'load':
            return self._hook_manager._hooked_pickle_load
        elif name == 'loads':
            return self._hook_manager._hooked_pickle_loads
        # 其他属性（如 dump, dumps, HIGHEST_PROTOCOL 等）透传原始模块
        return getattr(self._original_pickle, name)


# Global flag to avoid double-install
_hook_installed = False

def install_comprehensive_hook():
    """安装完整的系统调用hook，避免重复安装"""
    global _hook_installed
    if _hook_installed:
        print("[Hook] Already installed, skipping.")
        return None

    hook_manager = ComprehensiveSystemHook()

    # Hook os module
    sys.modules['os'] = MockOS(hook_manager.original_os, hook_manager)

    # Hook subprocess module
    sys.modules['subprocess'] = MockSubprocess(hook_manager.original_subprocess, hook_manager)

    # Hook pickle module
    sys.modules['pickle'] = MockPickle(hook_manager.original_pickle, hook_manager)

    _hook_installed = True
    print("[Hook] Comprehensive system call hook installed successfully.")
    return hook_manager
