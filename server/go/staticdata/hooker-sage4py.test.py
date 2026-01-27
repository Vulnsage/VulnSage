from hooker_sage4py import install_comprehensive_hook
install_comprehensive_hook()

if __name__ == "__main__":

    import os
    import subprocess
    import pickle
    import io
    # 1. os.system
    os.system("echo 'Test: os.system'")

    # 2. os.popen
    if hasattr(os, 'popen'):
        with os.popen("echo 'Test: os.popen'") as f:
            print("os.popen output:", f.read().strip())

    # 3. subprocess.run
    subprocess.run(["echo", "Test: subprocess.run"], stdout=subprocess.DEVNULL)

    # 4. subprocess.call
    subprocess.call(["echo", "Test: subprocess.call"], stdout=subprocess.DEVNULL)

    # 5. subprocess.check_call
    subprocess.check_call(["echo", "Test: subprocess.check_call"], stdout=subprocess.DEVNULL)

    # 6. subprocess.check_output
    out = subprocess.check_output(["echo", "Test: subprocess.check_output"], text=True)
    print("check_output:", out.strip())

    # 7. subprocess.getoutput (Python 3.7+)
    if hasattr(subprocess, 'getoutput'):
        out = subprocess.getoutput("echo 'Test: getoutput'")
        print("getoutput:", out.strip())

    # 8. subprocess.Popen
    proc = subprocess.Popen(["echo", "Test: Popen"], stdout=subprocess.PIPE, text=True)
    out, _ = proc.communicate()
    print("Popen output:", out.strip())

    # 9. os.spawnv (Unix-like)
    if hasattr(os, 'spawnv'):
        pid = os.spawnv(os.P_WAIT, "/bin/echo", ["echo", "Test: os.spawnv"])
        print(f"os.spawnv returned pid: {pid}")

    # 10. os.startfile (Windows only)
    if hasattr(os, 'startfile'):
        try:
            os.startfile(".")  # open current dir
        except Exception as e:
            print("os.startfile test skipped (error):", e)



    # 6. pickle.load / loads
    print("\n=== 测试 pickle 反序列化 ===")
    data = {"message": "Hello from pickle", "number": 123}
    serialized = pickle.dumps(data)

    # 测试 loads
    obj1 = pickle.loads(serialized)
    print("pickle.loads succeeded, type:", type(obj1))

    # 测试 load
    buf = io.BytesIO()
    pickle.dump(data, buf)
    buf.seek(0)
    obj2 = pickle.load(buf)
    print("pickle.load succeeded, type:", type(obj2))

    print("\n=== Hook test completed ===")
