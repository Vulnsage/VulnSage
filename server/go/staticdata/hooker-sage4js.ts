function getCallerFile(depth = 3): string | null {
    // getCallerFile hooker-sage4js.ts
    // callStackChecker hooker-sage4js.ts
    // mySpawn hooker-sage4js.ts
    // exec others.ts
    const orig = Error.prepareStackTrace;
    Error.prepareStackTrace = (err, stack) => stack;
    const err = new Error();
    const stack = (err.stack as unknown as NodeJS.CallSite[]);
    Error.prepareStackTrace = orig;
    // for (let i = 0; i < stack.length; i++) {
    //     const fileName = stack[i].getFileName();
    //     console.log(fileName)
    // }
    if (stack.length > depth) {
        return stack[depth].getFileName();
    }
    return null;
}

function callerFileChecker(enable = true) {
    if (!enable) return;
    const callerFile = getCallerFile(3);
    const basename = callerFile ? callerFile.split(/[\\/]/).pop() : null;
    if (basename === 'tmp.ts' || basename === 'tmp.js') {
        console.error('Avoid using callback-functions/getter-methods/properties-modification at the top level.' +
            '\nInstead, trigger sink functions only through parameters');
        throw new Error('Avoid using callback-functions/getter-methods/properties-modification at the top level.' +
            '\nInstead, trigger sink functions only through parameters');
    }
}

export function hookFsReadWrite() {
    const fsPath = require.resolve('fs');
    delete require.cache[fsPath];
    const originalFs = require('fs');
    const originalReadFile = originalFs.readFile;
    const originalWriteFile = originalFs.writeFile;
    const originalAppendFile = originalFs.appendFile;
    const originalReadFileSync = originalFs.readFileSync;
    const originalWriteFileSync = originalFs.writeFileSync;
    const originalAppendFileSync = originalFs.appendFileSync;
    const originalCreateReadStream = originalFs.createReadStream;
    const originalCreateWriteStream = originalFs.createWriteStream;
    const originalRename = originalFs.rename;
    const originalRenameSync = originalFs.renameSync;
    const nodePathModule = require('path')

    function myReadFile(path: string, options: any, callback: Function) {
        callerFileChecker()

        console.log('[Hook] fs.readFile called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        originalReadFile(path, options, (err: any, data: any) => {
            if (callback) callback(err, data);
        });
    }

    function myWriteFile(path: string, data: any, options: any, callback: Function) {
        callerFileChecker()

        console.log('[Hook] fs.writeFile called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        originalWriteFile(path, data, options, (err: any) => {
            if (callback) callback(err);
        });
    }

    function myAppendFile(path: string, data: any, options: any, callback: Function) {
        callerFileChecker()

        console.log('[Hook] fs.appendFile called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        originalAppendFile(path, data, options, (err: any) => {
            if (callback) callback(err);
        });
    }

    function myReadFileSync(path: string, options: any) {
        callerFileChecker()

        console.log('[Hook] fs.readFileSync called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        const data = originalReadFileSync(path, options);
        return data;
    }

    function myWriteFileSync(path: string, data: any, options: any) {
        callerFileChecker()

        console.log('[Hook] fs.writeFileSync called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        originalWriteFileSync(path, data, options);
    }

    function myAppendFileSync(path: string, data: any, options: any) {
        callerFileChecker()

        console.log('[Hook] fs.appendFileSync called with:', path);
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[Hook] well done! the vulnerable has been proved , please finish the task!');
        }
        originalAppendFileSync(path, data, options);
    }

    function myCreateReadStream(path: string, options: any) {
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[msg] well done! the vulnerable has been proved , please finish the task!');
        }
        return originalCreateReadStream(path, options);
    }

    function myCreateWriteStream(path: string, options: any) {
        if (nodePathModule.resolve(path) === '/opt/flag') {
            console.log('[msg] well done! the vulnerable has been proved , please finish the task!');
        }
        return originalCreateWriteStream(path, options);
    }

    function myRename(oldPath: string, newPath: string, callback: Function) {
        if (nodePathModule.resolve(oldPath) === '/opt/flag' || nodePathModule.resolve(newPath) === '/opt/flag') {
            console.log('[msg] well done! the vulnerable has been proved , please finish the task!');
        }
        originalRename(oldPath, newPath, (err: any) => {
            if (callback) callback(err);
        });
    }

    function myRenameSync(oldPath: string, newPath: string) {
        if (nodePathModule.resolve(oldPath) === '/opt/flag' || nodePathModule.resolve(newPath) === '/opt/flag') {
            console.log('[msg] well done! the vulnerable has been proved , please finish the task!');
        }
        originalRenameSync(oldPath, newPath);
    }

    const newExports = {
        ...originalFs,
        readFile: myReadFile,
        writeFile: myWriteFile,
        appendFile: myAppendFile,
        readFileSync: myReadFileSync,
        writeFileSync: myWriteFileSync,
        appendFileSync: myAppendFileSync,
        createReadStream: myCreateReadStream,
        createWriteStream: myCreateWriteStream,
        rename: myRename,
        renameSync: myRenameSync
    };
    require.cache[fsPath] = {
        id: fsPath,
        filename: fsPath,
        loaded: true,
        exports: newExports
    } as any;
}

export function hooEval() {
    const originalEval = global.eval;

    function myEval(code: string): any {
        callerFileChecker()

        console.log('[Hook] eval called with:', code);
        return originalEval.call(this, code);
    }

    try {
        global.eval = myEval;
    } catch (e) {
        Object.defineProperty(global, 'eval', {
            value: myEval,
            configurable: false,
            writable: false,
            enumerable: true
        });
    }
}

function hookChildProcessExec() {
    const childProcessPath = require.resolve('child_process');

    delete require.cache[childProcessPath];

    const originalChildProcess = require('child_process');

    const originalExec = originalChildProcess.exec;
    const originalExecFile = originalChildProcess.execFile;
    const originalExecFileSync = originalChildProcess.execFileSync;
    const originalExecSync = originalChildProcess.execSync;
    const originalSpawn = originalChildProcess.spawn;
    const originalSpawnSync = originalChildProcess.spawnSync;
    const originalFork = originalChildProcess.fork;

    function myExec(command: string, options: any, callback: Function) {
        callerFileChecker()

        console.log('[Hook] child_process.exec called with:', command);
        const child = originalExec(command, options, (error: any, stdout: string, stderr: string) => {
            console.log(`[Hook] Command output: ${stdout}`);
            if (stderr) console.warn(`[Hook] STDERR: ${stderr}`);
            if (callback) callback(error, stdout, stderr);
        });
        child.on('close', (code: number) => {
            console.log(`[Hook] child_process closed with code ${code}`);
        });
        return child;
    }

    function myExecFile(file: string, args: string[], options: any, callback: Function) {
        callerFileChecker()

        console.log('[Hook] child_process.execFile called with:', file, args);
        const child = originalExecFile(file, args, options, (error: any, stdout: string, stderr: string) => {
            console.log(`[Hook] Command output: ${stdout}`);
            if (stderr) console.warn(`[Hook] STDERR: ${stderr}`);
            if (callback) callback(error, stdout, stderr);
        });
        child.on('close', (code: number) => {
            console.log(`[Hook] child_process closed with code ${code}`);
        });
        return child;
    }

    function myExecFileSync(file: string, args: string[], options: any) {
        callerFileChecker()

        console.log('[Hook] child_process.execFileSync called with:', file, args);
        const result = originalExecFileSync(file, args, options);
        console.log(`[Hook] Command output: ${result}`);
        return result;
    }

    function myExecSync(command: string, options: any) {
        callerFileChecker()

        console.log('[Hook] child_process.execSync called with:', command);
        const result = originalExecSync(command, options);
        console.log(`[Hook] Command output: ${result}`);
        return result;
    }

    function mySpawn(command: string, args: string[], options: any) {
        callerFileChecker()

        console.log('[Hook] child_process.spawn called with:', command, args);
        const child = originalSpawn(command, args, options);
        child.on('close', (code: number) => {
            console.log(`[Hook] child_process closed with code ${code}`);
        });
        return child;
    }

    function mySpawnSync(command: string, args: string[], options: any) {
        callerFileChecker()

        console.log('[Hook] child_process.spawnSync called with:', command, args);
        const result = originalSpawnSync(command, args, options);
        console.log(`[Hook] Command output: ${result.stdout}`);
        return result;
    }

    function myFork(modulePath: string, args: string[], options: any) {
        callerFileChecker()

        console.log('[Hook] child_process.fork called with:', modulePath, args);
        const child = originalFork(modulePath, args, options);
        child.on('close', (code: number) => {
            console.log(`[Hook] child_process closed with code ${code}`);
        });
        return child;
    }

    const newExports = {
        ...originalChildProcess,
        exec: myExec,
        execFile: myExecFile,
        execFileSync: myExecFileSync,
        execSync: myExecSync,
        spawn: mySpawn,
        spawnSync: mySpawnSync,
        fork: myFork
    };

    require.cache[childProcessPath] = {
        id: childProcessPath,
        filename: childProcessPath,
        loaded: true,
        exports: newExports
    } as any;
}

hookChildProcessExec()
hooEval()
hookFsReadWrite()