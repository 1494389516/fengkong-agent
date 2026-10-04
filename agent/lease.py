"""Lease heartbeat bounded by immutable attempt deadline and token fencing."""
import sqlite3
import threading
import time

class LeaseHeartbeat:
    def __init__(self,path,task_id,token,deadline):
        self.path,self.task_id,self.token,self.deadline=path,task_id,token,deadline
        self.stop_event=threading.Event()
        self.thread=threading.Thread(target=self._run,daemon=True)
    def start(self):self.thread.start()
    def stop(self):self.stop_event.set();self.thread.join(timeout=12)
    def _run(self):
        while not self.stop_event.wait(10):
            now=time.time()
            if now>=self.deadline:return
            db=sqlite3.connect(self.path,timeout=5)
            try:
                changed=db.execute("UPDATE investigation_tasks SET lease_until=? WHERE task_id=? AND lease_token=? AND status='running' AND lease_until>?",
                    (min(now+30,self.deadline),self.task_id,self.token,now)).rowcount
                db.commit()
                if changed!=1:return
            except sqlite3.Error:
                # Failure never grants a new lease; the existing one expires.
                return
            finally:db.close()
