from dataclasses import dataclass
import os
from pathlib import Path
import pickle
import random
import shutil
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List
import logging
import traceback


log = logging.getLogger("sileo")
log_ts_path : Path = Path()

class MaxStack(List[float]):
    """ a stack with a fixed size that overwrites the oldest element """
    def __init__(self, max_size: int) -> None:
        super().__init__()
        self.max_size = max_size

    # add element to the end of the list
    def push(self, element: float) -> None:
        self.append(element)

    # if the list is full, remove the first element
    def append(self, element: float) -> None:
        super().append(element)
        if super().__len__() > self.max_size:
            super().__delitem__(0)

    # get the average of all elements in the list
    def get_avg(self) -> float:
        length = super().__len__()
        return round(sum(self) / length,2)


def setup_logging(log_level: int = logging.DEBUG, sileo_mode = "", log_dir : Path = Path("logs")) -> None:
    """Setup logger"""
    global log_ts_path

    if sileo_mode != "":
        sileo_mode = "_" + sileo_mode

    # check for fuzzbench
    if Path("/out/results/").exists():
        # Fuzzbench log path:
        log_path : Path = Path(f"/out/results/logs/sileo{sileo_mode}.log")
        log_ts_path = Path(f"/out/results/logs/time_event_data{sileo_mode}.pkl")
    else:
        log_path : Path = Path(f"{log_dir}/sileo{sileo_mode}.log")
        log_ts_path = Path(f"{log_dir}/time_event_data{sileo_mode}.pkl")
    
    if not log_path.exists():
        log_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        ts = int(time.time())
        lf_name = f"sileo{sileo_mode}_{ts}.log"
        log.debug(f"Logfile exists. Renaming to {log_path.parent / lf_name}")
        log_path.rename((log_path.parent / lf_name).as_posix())

    if log_ts_path.exists():
        ts = int(time.time())
        lf_name = f"time_event_data_{ts}{sileo_mode}.pkl"
        log.debug(f"Logfile exists. Renaming to {log_ts_path.parent / lf_name}")
        log_ts_path.rename((log_ts_path.parent / lf_name).as_posix())

    # Create handlers
    c_handler = logging.StreamHandler()  # pylint: disable=invalid-name
    f_handler = logging.FileHandler(log_path.as_posix(), "w+")  # pylint: disable=invalid-name
    c_handler.setLevel(log_level)
    f_handler.setLevel(log_level)
    log.setLevel(logging.DEBUG)
    c_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%d-%m-%Y %H:%M:%S"))
    f_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%d-%m-%Y %H:%M:%S"))
    log.addHandler(c_handler)
    log.addHandler(f_handler)


def get_traceback(e: Exception) -> str:
    """ get traceback for exeception"""
    lines: List[str] = traceback.format_exception(type(e), e, e.__traceback__)
    return ''.join(lines)

def mybisect(arr: List, x: any, l: int, r: int, cmp: Callable[[any, any], int]) -> int:
    """ cmp: cmp(arr[l], x) ∈ [-1, 0, 1]

    Please be aware 1. this function returns the last possible position to insert before, pos s.t., cmp(arr[pos], x) >= 0 and cmp(arr[pos + 1], x) > 0
    2. the smallest answer will be l, the largest answer will be r: e.g: arr: [1,2,3,4,5], l:2, r:3, x:1 the answer will be l=2
    3. The search will concertrate on [arr[l], arr[r])
    """
    assert 0 <= l <= r <= len(arr)
    if l == r or cmp(arr[l], x) > 0:
        return l
    op = cmp(arr[r - 1], x)
    if op <= 0:
        return r - 1 if op == 0 else r
    while l < r:
        md = (l + r) >> 1
        if md == l:
            break
        op = cmp(arr[md], x)
        if op <= 0:
            l = md
        else:
            r = md
    return l if cmp(arr[l], x) >= 0 else l + 1

def delete_dir_content(content_path : Path) -> int:
    """ delelte content of a given directory and count files """
    log.debug(f"Deleting content: {content_path}")
    f_cnt : int = 0
    for file_path in Path(content_path).glob("**/*"):
        if file_path.is_file():
            file_path.unlink()
            f_cnt += 1
    return f_cnt

def copy_files(source_dir : Path, dest_dir : Path) -> int:
    """ copy files from source to dest directory """
    # files = list(source_dir.iterdir())
    files = list(Path(source_dir).glob("**/*"))
    log.debug(f"Copying files {len(files)} from {source_dir} to {dest_dir}")
    f_cnt : int = 0
    for src_file in files:
        # log.debug(f"Copy {src_file} to {Path(dest_dir / src_file.name)}")
        if src_file.is_file():
            shutil.copy(src_file, dest_dir / src_file.name)
            f_cnt += 1
    log.debug(f"Copied: {f_cnt}")
    return f_cnt

def minimize_corpus(instance) -> None:
    """ use afl-cmin to minimize the corpus"""
    
    
    cmin_bin : Path = Path(instance.fuzzer_args["afl_path"]) / "afl-cmin"
    target_bin_path: Path = instance.fuzzer_args["afl_target"]
    target_args: List[str] = instance.fuzzer_args["afl_target_args"].copy()


    afl_queue_path : Path = instance.fuzzer_args["afl_seed"]

    cmin_start_id : int = random.randrange(0,1234567890)
    dump_event(CminStart(cmin_start_id, instance.worker_id))


    tmp_cmin_src_dir : Path = Path(tempfile.mkdtemp(prefix = "tmp_cmin_src_", dir = afl_queue_path.parent))
    copy_files(afl_queue_path, tmp_cmin_src_dir)
    tmp_cmin_dest_dir : Path = Path(tempfile.mkdtemp(prefix = "tmp_cmin_dest_", dir = afl_queue_path.parent))
   
    # I am not sure about this. Its for fuzzbench targets
    if "@@" not in target_args:
        target_args += ["@@"]

    cmin_command : List[str] = [
         cmin_bin.as_posix(),
         "-i",
         tmp_cmin_src_dir.as_posix(),
         "-o",
         tmp_cmin_dest_dir.as_posix(),
         "-m",
         "none",
         "-t",
         "1000+",
         "--",
         target_bin_path.as_posix()
        ] + target_args
    
    cmin_command = [x for x in cmin_command if x != ""]
    log.debug(f"afl-cmin command: {' '.join(cmin_command)}")

    log.debug("afl-cmin: Setting AFL_MAP_SIZE=10000000")
    current_env: dict[str, str] = os.environ.copy()
    current_env.update({"AFL_MAP_SIZE":"10000000"})
    log.info("Starting corpus minimization")
    log.debug(f"Logging corpus minimization to {afl_queue_path.parent} / corpus_minimization_{instance.run_id}.txt")
    with open(afl_queue_path.parent / f"corpus_minimization_{instance.run_id}.txt", "w") as f:
        subprocess.run(cmin_command, stdout=f, stderr=subprocess.STDOUT, env=current_env)

    # subprocess.run(cmin_command)
    log.info("Corpus minimization done")

    delete_dir_content(afl_queue_path)
    delete_dir_content(tmp_cmin_src_dir)
    log.debug("Copying files")
    cpy_f_cnt : int = copy_files(tmp_cmin_dest_dir, afl_queue_path)
    del_f_cnt : int = delete_dir_content(tmp_cmin_dest_dir)
    tmp_cmin_dest_dir.rmdir()

    del_f_cnt = 0

    dump_event(CminStop(cmin_start_id, instance.worker_id, cpy_f_cnt, del_f_cnt))


@dataclass
class Event:
    ts: float
    id: int
    worker_id: int

@dataclass
class SpecialEvent(Event):
    saved_files: int
    deleted_files: int
    mode: str
    note: str

class SileoStart(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class SileoStop(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class FuzzerStart(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class FuzzerStop(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class FuzzerStatsWait(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class FuzzerStatsFound(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class RestartStart(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class RestartDone(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class ProcessModeStart(SpecialEvent):
    def __init__(self, id, worker_id, mode, note):
        self.ts = time.time()
        self.worker_id = worker_id
        self.mode = mode
        self.note = note
        self.saved_files = 0
        self.deleted_files = 0
        self.id = id

class ProcessModeStop(SpecialEvent):
    def __init__(self, id, worker_id, mode, note):
        self.ts = time.time()
        self.worker_id = worker_id
        self.mode = mode
        self.note = note
        self.saved_files = 0
        self.deleted_files = 0
        self.id = id

class CminStart(Event):
    def __init__(self, id, worker_id):
        self.ts = time.time()
        self.worker_id = worker_id
        self.id = id

class CminStop(SpecialEvent):
     def __init__(self, id, worker_id, saved_files, deleted_files):
        self.ts = time.time()
        self.worker_id = worker_id
        self.saved_files = saved_files
        self.deleted_files = deleted_files
        self.mode = ""
        self.note = ""
        self.id = id

# sileo_utils.dump_event(utils.FuzzerStart(time.time(),id))
def dump_event(cl):
    global log_ts_path
    
    log.debug(f"Logpath {log_ts_path}")
    if not log_ts_path.exists():
        log_ts_path.parent.mkdir(parents=True, exist_ok=True)

    with open(log_ts_path.as_posix(), "ab") as fd:
        pickle.dump(cl,fd)

def load_ts_file():
    timestamps = []
    log_path : Path = Path("logs/time_event_data.pkl")
    if not log_path.exists():
        log.error(f"Log Path {log_path.as_posix()} does not exists.")

    with open(log_path.as_posix(),"rb") as fd:
        while True:
            try:
                timestamps.append(pickle.load(fd))
            except EOFError:
                break
    return timestamps
