import subprocess
import sys
from inotify_simple import INotify, flags
import os
from pathlib import Path
import time  

def check_for_clamav(): # looks for clamav instalation
    try:
        result =  subprocess.run(
            ["clamscan"], #run clamscan command
            stdout=subprocess.PIPE, #get output
            stderr=subprocess.PIPE, #get error
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
# just a extra to let you know what each error is and what to do     
    except FileNotFoundError:
        print("clamav is not installed or to be found in the Path")
        return False
    except subprocess.TimeoutExpired:
        print("clamav got time out")
        return False
    except Exception as e:
        print(f"an unexpected error: {e}")
        return False
    
print("Running ClamAV check...")

if not check_for_clamav():
    print("\n  ClamAV is not ready.")
    print("Please install ClamAV and run 'sudo freshclam'. and ")
    sys.exit(1)

print(" ClamAV is ready.")

class downloadlymonitory: #montoring files
    def __init__(self, watch_dir, scan_extensions=None):
        self.watch_dir = Path(watch_dir).expanduser().resolve()
        self.scan_extensions = scan_extensions or {'.exe', '.bin', '.msi', '.deb', '.rpm', '.zip'}

        self.active_downloads = {}

        self.inotify = INotify()
        self.watch_flags = flags.CREATE | flags.MOVED_TO | flags.CLOSE_WRITE #looks for create/move/closed 
        self.wd = self.inotify.add_watch(str(self.watch_dir), self.watch_flags)

        print(f"watching files {self.watch_dir}")
        print(f"scanning stuff  {', '.join(self.scan_extensions)}")
        print(f"Press Ctrl+C to stop.")

    def should_scan(self, filename): #Check if file extension should be scanned
        return Path(filename).suffix.lower() in self.scan_extensions
    
    def is_hidden_or_temp(self,filename): #checks for hidden files 
        name = Path(filename).name
        return (
            name.startswith('.')or
            name.endswith('.part') or
            name.endswith('.crdownload') or
            name.endswith('~'))

    def track_download(self,filePath):
        try:
            size = os.path.getsize(filePath)
            if str(filePath) not in self.active_downloads: 
                self.active_downloads[str(filePath).name] = {
                'size': size,
                'stable_count': 0,
                'first_seen': time.time()

            }
            print(f"tracking{Path(filePath).name}) ({size} bytes")
        except FileNotFoundError:
            pass
    
    def check_active_downloads(self): #checks for if the download is finshed 
        to_remove = []

#filePath = gets the Path for the file using download
#info gets the size etc 
        for filePath, info in self.active_downloads.items(): 
            try:
                current_size = os.Path.getsize(filePath)
                old_size = info['size']

                if current_size == old_size:
                    info['stable_count'] += 1 

                    if info['stable_count'] >=3:
                        print(f"download completed:{Path(filePath).name}")
                        self.scan_file(filePath)
                        to_remove.append(filePath)
                else:
                    info['size'] = current_size
                    info['stable_count'] = 0
            except FileNotFoundError:
                to_remove.append(filePath)
            
        for filePath in to_remove:
            del self.active_downloads[filePath]


    def scan_file(self, filePath):
        try:
            result = subprocess.run(
                ['clamscan','--no-summary', filePath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
                text=True
            )
            if result.returncode == 0:
                print(f"this file is clean: {Path(filePath).name}")
            elif result.returncode == 2:
                print (f" infection found: {Path(filePath).name}")
            else:
                print(f"scan didnt work: {result.stderr.strip()}")
        
        except subprocess.TimeoutExpired:
            print(f" scaning error {Path(filePath).name}")
        except Exception as e:
            print(f"failed:{e}")

    def quarantine_file(self, filePath):
        quarantine_dir = Path.home() / '.sysyguard' / 'quarantine'
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        try:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = Path(filePath).name
            dest = quarantine_dir / f"{filename}_{timestamp}"
            
            os.rename(filePath, dest)
            print(f"Quarantined to: {dest}")
        except Exception as e:
            print(f"Quarantine failed: {e}")
    
    def process_event(self, event):
        for flag in flags.from_mask(event.mask):
            # skip hidden/temp files
            if event.name:
                filePath = self.watch_dir / event.name
                
                if self.is_hidden_or_temp(event.name):
                    continue
                
                # only track files we want to scan
                if not self.should_scan(event.name):
                    continue               
                # checks if the file is created or moved 
                if flag in (flag.CREATE, flags.MOVED_TO):
                    self.track_download(str(filePath))
                    # For smaller files, CLOSE_WRITE might be enough
                    # Add to tracking anyway, our size check will handle it
                elif flag == flags.CLOSE_WRITE:
                    if str(filePath) not in self.active_downloads:
                    # Wait a moment for file to be fully written
                        time.sleep(0.5)
                        self.track_download(str(filePath))
    
    def run(self):
        try:
            while True:
                event = self.inotify.read(timeout=1000)

                if event:
                    for event in event:
                        self.process_event(event)
                # Always check active downloads (even without events)
                if self.active_downloads:
                    self.check_active_downloads()
        except KeyboardInterrupt:
            print("stopping byeeeee")
        except Exception as e:
            print(f"error{e}")
        finally:
            self.inotify.rm_watch(self.wd) #cleaning up
    
def main():
    #check if calmav is installed 
    print("Running ClamAV check...")
    if not check_for_clamav():
        print("\n ClamAV is not ready.")
        print("Please install ClamAV and run 'sudo freshclam'.")
        sys.exit(1)
    print(" ClamAV is ready.")
        
        #start the monitor
    watch_dir = "~/Downloads"
    extensions = {'.exe', '.msi', '.bin', '.deb', '.rpm', '.zip', '.appimage'}
        
    monitor = downloadlymonitory(watch_dir, extensions)
    monitor.run()

if __name__ == "__main__":
    main()
