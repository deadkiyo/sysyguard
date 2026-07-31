import subprocess
import sys
from inotify_simple import INotify, flags

def check_for_clamav():
    try:
        result =  subprocess.run(
            ["clamscan"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10
        )
        if result.returncode== 0:
            print("clamav is installed ")
            return True
        elif result.returncode== 1:
            print("test for clamav installtion worked but found a virus on basic scan")
            return True
        else:
            print(f"clamav is installed but found to have error (code:{result.returncode}).")
            return False
    
    except FileNotFoundError:
        print("clamav is not installed or to be found in the path")
        return False
    except subprocess.TimeoutExpired:
        print("clamav got time out")
        return False
    except Exception as e:
        print(f"an unexpected error: {e}")
        return False
    
print("Running ClamAV check...")

if not check_for_clamav():
    print("\n ACTION REQUIRED: ClamAV is not ready.")
    print("Please install ClamAV and run 'sudo freshclam'.")
    sys.exit(1)

print(" ClamAV is ready.")
