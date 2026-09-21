import notify2
import subprocess
from pathlib import Path
from inotify_simple import INotify, flags
import time
from queue import Queue
from threading import Thread
import sys
import os

notify2.init("ClamAV Real-Time Scanner")

def notify(title, message, urgency=notify2.URGENCY_NORMAL):
    notification = notify2.Notification(title, message)
    notification.set_urgency(urgency)
    notification.show()

def check_for_clamav():
    try:
        result = subprocess.run(
            ["clamscan", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            print("ClamAV is installed.")
            return True

        notify(
            f"ClamAV check failed (code: {result.returncode})",
            notify2.URGENCY_CRITICAL
        )
        return False

    except FileNotFoundError:
        notify(
            "ClamAV is not installed or cannot be found in PATH.",
            notify2.URGENCY_CRITICAL
        )
        return False

    except subprocess.TimeoutExpired:
        notify(
            "ClamAV check timed out.",
            notify2.URGENCY_CRITICAL
        )
        return False

    except Exception as e:
        notify(
            f"Unexpected error: {e}",
            notify2.URGENCY_CRITICAL
        )
        return False

if not check_for_clamav():
    notify(
        "clamav is not ready, pls install clamav",
        notify2.URGENCY_NORMAL
    )
    sys.exit(1)

class downloadmonitor:
    def __init__(self, watch_dir, workers=2):
        self.watch_dir = Path(watch_dir).expanduser().resolve()
        self.scan_queue = Queue()
        self.pending = set()
        self.active_downloads = {}
        self.inotify = INotify()

        self.watch_flags = (
            flags.CREATE |
            flags.MOVED_TO |
            flags.CLOSE_WRITE

        )

        self.inotify.add_watch(
            str(self.watch_dir),
            self.watch_flags
        )

        self.workers = []

        for _ in range(workers):
            worker = Thread(
                target=self.scan_worker,
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
    def queue_file(self, path):
        path = path.resolve()
        
        if path in self.pending:
            return
        self.pending.add(path)
        print(f"[+] Queued: {path.name}")
        self.scan_queue.put(path)

    def scan_worker(self):
        while True:
            file_path = self.scan_queue.get()

            try:
                self.scan_file(file_path)
            except Exception as e:
                print(f"Scan error: {e}")
            finally:
                self.pending.discard(file_path)
                self.scan_queue.task_done()


    def track_download(self,filePath):
        try:
            size = os.path.getsize(filePath)
            if str(filePath) not in self.active_downloads: 
                self.active_downloads[str(filePath)] = {
                'size': size,
                'stable_count': 0,
                'first_seen': time.time()
                }
            print(f"tracking{Path(filePath).name}) ({size} bytes")
        except FileNotFoundError:
            pass

    def check_active_downloads(self):
        to_remove = []

        for filePath, info in self.active_downloads.items(): 
            try:
                current_size = os.path.getsize(filePath)
                old_size = info['size']

                if current_size == old_size:
                    info['stable_count'] += 1 

                    if info['stable_count'] >=3:
                        print(f"download completed:{Path(filePath).name}")
                        self.queue_file(Path(filePath))
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
            elif result.returncode == 1:
                notify(
                    f" infection found: {Path(filePath).name}",
                    notify2.URGENCY_CRITICAL
                    )
                self.quarantine_file(filePath)
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
            notify(
                f"Quarantined to: {dest}",
                notify2.URGENCY_CRITICAL
            )
        except Exception as e:
            notify(
                f"Quarantine failed: {e}",
                notify2.URGENCY_CRITICAL
                )
    
    def process_event(self,event):
        for flag in flags.from_mask(event.mask):
            if event.name:
                filePath = self.watch_dir / event.name
                
                if flag in (flag.CREATE, flags.MOVED_TO):
                    self.track_download(str(filePath))

                elif flag == flags.CLOSE_WRITE:
                    if str(filePath) not in self.active_downloads:
              
                        time.sleep(0.5)
                        self.track_download(str(filePath))
    

    def process_event(self, event):
        file_path = self.watch_dir / event.name

        if not file_path.is_file():
            return

        event_flags = flags.from_mask(event.mask)

        if (
            flags.CREATE in event_flags
            or flags.MOVED_TO in event_flags
            or flags.CLOSE_WRITE in event_flags
        ):
            self.track_download(file_path)

    def run(self):
        try:
            while True:
                events = self.inotify.read(timeout=1000)

                for event in events:
                    self.process_event(event)

                if self.active_downloads:
                    self.check_active_downloads()

        except KeyboardInterrupt:
            print("stopping-byeee")

        except Exception as e:
            print(f"error: {e}")

        finally:
            self.inotify.rm_watch(self.wd)

def main(): 
    print("running clavam check")
    if not check_for_clamav():
        print("\n ClamAV i not ready.")
        print("please install clamav and run 'sudo freshclam'.")
        sys.exit(1)
    print(" clamav is ready.")
        
    watch_dir = "~/Downloads"
        
    monitor = downloadmonitor(watch_dir, workers=2)
    monitor.run()

if __name__ == "__main__":
    main()