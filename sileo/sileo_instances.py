from collections import defaultdict
import dataclasses
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Dict, Set, Any

try:
    from .sileo_utils import MaxStack
except ImportError:
    from sileo_utils import MaxStack

@dataclass
class ModeInfo:
    """ Dataclass which holds all information about the current mode and its performance """
    mode: str
    best_mode: str
    modes_tested: list[str]
    init_restart_time: int
    user_rtime: tuple[int, int]
    last_update: int
    coverage_min: float
    coverage_max: float
    coverage_avg: float
    purge: bool
    force: bool
    permit_purge: bool
    additional_info: str
    mode_corpus_count_total : defaultdict[str,list[float]]
    corpus_count_stack: MaxStack
    corpus_count_run_stack: MaxStack
    corpus_count_mode_stack : MaxStack
    corpus_count_last_run: int
    corpus_count_max: int
    corpus_count_avg: float = 0.0
    corpus_count_run_avg: float = 0.0
    corpus_count : int = 0
    corpus_stack_size : int  = 5
    run_stack_size : int = 7
    mode_stack_size : int = 3
    always_copy_original_seeds: bool = True

    def __init__(self, mode: str, last_update: int, coverage_min: float, coverage_max: float, coverage_avg: float) -> None:
        """ init mode info """
        self.mode = mode
        self.best_mode = ""
        self.modes_tested = []
        self.last_update = last_update
        self.coverage_min = coverage_min
        self.coverage_max = coverage_max
        self.coverage_avg = coverage_avg
        self.mode_corpus_count_total = defaultdict(list)
        self.corpus_count_last_run = 0
        self.corpus_count_max = 0
        self.corpus_count_stack = MaxStack(self.corpus_stack_size)
        self.corpus_count_run_stack = MaxStack(self.run_stack_size)
        self.corpus_count_mode_stack = MaxStack(self.mode_stack_size)
        self.additional_info = ""
        self.purge = self.permit_purge = False
        self.force = False

        self.user_rtime = (-1, -1)
        if mode == "log_down":
            self.init_restart_time = 64
        elif mode == "log_up":
            self.init_restart_time = 1
        elif mode == "log_wave":
            self.init_restart_time = 1
            self.additional_info = "up"
        else:
            self.init_restart_time = 0

    def refresh(self, last_update: int, coverage: float, corpus_count: int) -> None:
        """ update mode data """

        self.coverage_curr = coverage
        coverage_min: float = min(self.coverage_min, coverage)
        coverage_max: float = max(self.coverage_max, coverage)
        coverage_avg : float = (self.coverage_avg + coverage) / 2
        self.last_update = last_update
        self.coverage_min = coverage_min
        self.coverage_max = coverage_max
        self.coverage_avg = coverage_avg
        self.corpus_count = corpus_count
        self.corpus_count_stack.push(corpus_count)
        self.corpus_count_avg = self.corpus_count_stack.get_avg()

    def reset_stack(self) -> None:
        """ reset MaxStack """
        self.corpus_count_mode_stack = MaxStack(self.mode_stack_size)


@dataclass
class FuzzerInstance:
    """ dataclass which holds all information about the underlying fuzzer"""
    proc: subprocess.Popen
    worker_id: int
    path_worker_id: int
    run_id: int
    event_id: int
    fuzzer_args: Dict[str, Any]
    mode_info: ModeInfo
    stats_path: Path
    run_num: int = 0
    cp_num: int = 0
    new_restart_time: bool = True
    restart_time: int = 0
    purge_time: float = 0
    corpus_del_percentage: int = 0
    tree_chopper_seen_seeds: Set[str] = dataclasses.field(default_factory=set)
    tree_chopper_parent_to_children: Dict[str, Set[str]] = dataclasses.field(default_factory=lambda: defaultdict(lambda: set()))
    cmin : bool = False
    tmin : bool = False

    def __init__(self, instance: subprocess.Popen, mode: str, worker_id: int, path_worker_id: int, run_id: int, event_id,
                 fuzzer_args: Dict[str, Any]) -> None:
        """ init fuzzerinstance """
        self.proc = instance
        self.worker_id = worker_id
        self.path_worker_id = path_worker_id
        self.run_id = run_id
        self.event_id = event_id
        self.fuzzer_args = fuzzer_args
        self.mode_info = ModeInfo(mode, 0, 0, 0, 0)
        self.tree_chopper_seen_seeds = set()
        self.tree_chopper_parent_to_children = defaultdict(set)

    def update_new_instance(self, instance: "FuzzerInstance") -> None:
        """ if a restart occurs update the new instance with some of the data from the old one """
        self.mode_info = instance.mode_info
        self.mode_info.corpus_count_stack = MaxStack(self.mode_info.corpus_stack_size)
        self.mode_info.corpus_count_avg = 0.0
        self.mode_info.corpus_count = 0
        self.coverage_curr = 0
        self.coverage_curr = 0
        self.cp_num = instance.cp_num
        self.run_num = instance.run_num
        self.new_restart_time = instance.new_restart_time
        self.restart_time = instance.restart_time
        self.purge_time = instance.purge_time
        self.tree_chopper_seen_seeds = instance.tree_chopper_seen_seeds
        self.tree_chopper_parent_to_children = instance.tree_chopper_parent_to_children
        self.cmin = instance.cmin
        self.tmin = instance.tmin

    def refresh(self, last_update: int, coverage: float, corpus_count: int) -> None:
        """ update mode_info """
        self.mode_info.refresh(last_update, coverage, corpus_count)
        self.cp_num += 1
