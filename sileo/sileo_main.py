#!/usr/bin/env python3

from argparse import ArgumentParser, Namespace
import argparse

from datetime import timedelta as td, datetime as dt
from pathlib import Path
import pathlib
import random
import re
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional, Sequence
import psutil
from pathlib import Path
import os

import tempfile

try:
    from .sileo_instances import FuzzerInstance
    from .sileo_utils import log, setup_logging, dump_event, minimize_corpus, \
        SileoStart, SileoStop, FuzzerStart, FuzzerStop, FuzzerStatsWait, FuzzerStatsFound, ProcessModeStart, ProcessModeStop, RestartStart, RestartDone
    from .sileo_modes import mode_corpus_del, mode_tree_chopper, mode_tree_planter, mode_timeback_plain, mode_timeback_global, mode_timeback_local, mode_adaptive, get_mode_data, mode_input_shuffle, mode_continue
except ImportError:
    from sileo_instances import FuzzerInstance
    from sileo_utils import log, setup_logging, dump_event, minimize_corpus, \
        SileoStart, SileoStop, FuzzerStart, FuzzerStop, FuzzerStatsWait, FuzzerStatsFound, ProcessModeStart, ProcessModeStop, RestartStart, RestartDone
    from sileo_modes import mode_corpus_del, mode_tree_chopper, mode_tree_planter, mode_timeback_plain, mode_timeback_global, mode_timeback_local, mode_adaptive, get_mode_data, mode_input_shuffle, mode_continue


debug = False
run = False
testing = False
disable_startup_cal = False

def signal_handler(signum: int, frame: Any) ->  None:
    """ signal handler to catch str + c"""
    global run
    log.debug("Stopping all instances")
    run = False

def run_fuzzer_debug(sp: "subprocess.CompletedProcess[bytes]") -> None:
    """ save afl output to logfile """
    assert sp is not None
    with open("afl_log.txt", "w") as f:
        if sp.stdout is None:
            log.debug("No stdout")
        else:
            for line in sp.stdout.decode("utf-8").splitlines():
                f.write(line)


def run_fuzzer(worker_id : int, run_id : int,  fuzzer_args : Dict[str, Any], fixed_worker : bool = False, mode : str = "random") -> FuzzerInstance:
    """ execute underlying fuzzer (afl) """
    internal_worker_id: int = worker_id

    seed_path: Path = fuzzer_args["afl_seed"]
    fuzzer_out_path: Path = fuzzer_args["afl_out"] / Path("worker_" + str(worker_id))

    # inrement worker_id while afl_out_path exists
    while fuzzer_out_path.exists() and not fixed_worker:
        worker_id += 1
        fuzzer_out_path = fuzzer_args["afl_out"] / Path("worker_" + str(worker_id))

    log.debug("Using Path for AFL:" + str(fuzzer_out_path))

    afl_dict: List[str] = fuzzer_args["afl_dict"]
    afl_cmplog: List[str] = fuzzer_args["afl_cmplog"]
    target_bin_path: Path = fuzzer_args["afl_target"]
    target_args: List[str] = fuzzer_args["afl_target_args"]
    add_flags: List[str] = fuzzer_args["add_flags"]

    assert seed_path.exists(), "Seed path does not exist!"
    assert target_bin_path.exists(), "Target binary does not exist!"

    fuzzer_out_path = fuzzer_out_path / Path("run_" + str(run_id))
    log.debug("AFL Worker path:" + str(fuzzer_out_path))

    if not fuzzer_out_path.exists():
        log.debug("Creating directory:" +  str(fuzzer_out_path))
        fuzzer_out_path.mkdir(parents=True)
    
    # write restart time (epoch) to run directory
    with open(fuzzer_out_path / "start_time.txt","w") as fd:
        fd.write(str(time.time()))


    fuzzer_command: List[str] = [
        fuzzer_args["afl_bin"],
        "-i",
        seed_path.as_posix(),
        "-o",
        fuzzer_out_path.as_posix(),
        "-m",
        "none",
        "-t",
        "1000+"
        ] + afl_dict + afl_cmplog + add_flags + [
            "--",
            target_bin_path.as_posix()] + target_args

    fuzzer_command = [x for x in fuzzer_command if x != ""]

    log.debug("AFL command:" + (" ".join(fuzzer_command)))

    fuzzer_start_id = random.randrange(0, 1234567890)
    dump_event(FuzzerStart(fuzzer_start_id, worker_id))
    
    #  clear LC_CTYPE which can reduce the exec_per_sec if the competior is not also started via the python interpreter
    current_env: dict[str, str] = os.environ.copy()
    
    # If used in fuzzbench, comment out the following, otherwise sileo may has an advantage
    del current_env["LC_CTYPE"]
    
    afl_log : Path = fuzzer_out_path / "afl_log.txt"
    with open (afl_log, "w+") as f:

        if run_id > 0 and disable_startup_cal:
            env_afl = {"AFL_NO_STARTUP_CALIBRATION":"1"}
            current_env.update(env_afl)
            sp = subprocess.Popen(fuzzer_command, stdout=f,  stderr=subprocess.STDOUT, env=current_env)
        else:
            sp = subprocess.Popen(fuzzer_command, stdout=f,  stderr=subprocess.STDOUT, env=current_env)

    return FuzzerInstance(sp, mode, internal_worker_id, worker_id, run_id, fuzzer_start_id, fuzzer_args)


def start_instance(afl_args: Dict[str, Any], num: int, mode: str) -> List[FuzzerInstance]:
    """ start NUM of fuzzer instances """

    instances: List[FuzzerInstance] = []

    for i in range(0,num):
        log.info("Starting instance: " + str(i))
        instances.append(run_fuzzer(i, 0, afl_args, mode=mode))
        time.sleep(0.1)
    time.sleep(2)
    return instances


def kill_afl(instance_list : List[FuzzerInstance]) -> None:
    """ stop all fuzzer instances """
    log.info("Stopping instances:")
    for instance in instance_list:
        kill_single(instance)
        time.sleep(0.1)

def kill_single(instance : FuzzerInstance) -> bool:
    """ stop a specific fuzzer instance and its childs """
    log.info("Stopping instance: (PID) " + str(instance.proc.pid) + "   (WorkerID) " + str(instance.worker_id))
    try:
        # kill_childs(instance.proc.pid)
        instance.proc.send_signal(signal.SIGINT)
        instance.proc.wait()
        log.debug("Stopped:" + str(instance.worker_id))
        dump_event(FuzzerStop(instance.event_id,instance.worker_id))
        return True
    except ProcessLookupError:
        log.debug("Process already stopped", exc_info=True)
        dump_event(FuzzerStop(instance.event_id,instance.worker_id))
        return True
    except Exception:
        log.error("Failed to terminate Fuzzer instance", exc_info=True)
        dump_event(FuzzerStop(instance.event_id,instance.worker_id))
        return False


def kill_childs(pid : int) -> None:
    """ kill child processes of a given PID"""
    log.debug("Check for child processes of " + str(pid))
    try:
        parent = psutil.Process(pid)
    except psutil.NoSuchProcess:
        log.warning("No Child process, exiting...")
        return
    children: List[psutil.Process] = parent.children(recursive=True)

    for process in children:
        log.debug("Found child process with pid:" + str(process.pid))
        process.send_signal(signal.SIGINT)
    psutil.wait_procs(children, timeout=2)


def check_afl_data(instance : FuzzerInstance, updated_file : Path) -> bool:
    """ get and parse data from afl's fuzzer_stats and decide if a restart should be perform """
    lines : List[str] = []
    ret : bool = False
    run_time : int = 0
    bitmap_cvg : float = 0
    corpus_count : int = 0
    restart: bool = False
    last_find : int = 0
    last_find_time_diff: float = 0
    last_corpus_count : int = 0

    log.info("Check file:" + str(updated_file))

    with open(updated_file, "r") as fd:
        lines = fd.readlines()

    for line in lines:

        if "run_time" in line:
            run_time = int(line.split(":")[1].strip())
            log.info("runtime (instance)\t:" + str(round(run_time / 3600, 2)) + "h " + str(round(run_time / 60, 2)) + "min")

        if "corpus_count" in line:
            corpus_count = int(line.split(":")[1].strip())
            last_corpus_count = instance.mode_info.corpus_count
            log.info("Current Corpus count: " + str(corpus_count))
            log.info("Last corpus count:" + str(last_corpus_count))
            log.info("Corpus count avg:" + str(instance.mode_info.corpus_count_avg))
            log.info("Corpus stack:" + str(instance.mode_info.corpus_count_stack))

        if "bitmap_cvg" in line:
            bitmap_cvg = float(line.split(":")[1].strip().strip("%"))

        if "last_find" in line:
            last_find = int(line.split(":")[1].strip())
            if last_find > 0:
                last_find_time_diff = round(time.time() - last_find,2)
                log.info("Seconds since last find:" + str(last_find_time_diff) + "s")
            else:
                last_find_time_diff = 0
                log.info("No new finds")

        if "saved_crashes" in line:
            saved_crashes = int(line.split(":")[1].strip())
            log.info("Saved crashes:" + str(saved_crashes))

    # this one is just for purge mode
    # check if corpus count list is initialized
    if len(instance.mode_info.corpus_count_stack) == 0:
        instance.mode_info.refresh(last_find, bitmap_cvg, corpus_count)
        restart = False
    else:
        # check if corpus count is increasing

        if testing:
            log.debug("Testing mode, using 25% threshold")
            threshold: float = round((corpus_count * 25) / 100,2)
        else:
            threshold: float = round((corpus_count * 0.2) / 100,2)

            # allow the tree chopper / tree planter / corpus_del to run longer with every run
            if instance.mode_info.mode in ["tree_chopper", "tree_planter", "corpus_del", "timeback_plain", "timeback_global", "timeback_local"] and instance.run_id > 1:
                threshold = round(threshold / instance.run_id,2)
        
        corpus_count_avg: float = instance.mode_info.corpus_count_avg
        log.debug("Threshold:" + str(threshold))
        log.debug("Lower limit:" + str(corpus_count - threshold))
        if (corpus_count - threshold) > corpus_count_avg:
            restart = False
        else:
            restart = True
        instance.mode_info.refresh(last_find, bitmap_cvg, corpus_count)

    instance = get_mode_data(instance)
    restart_time: int = instance.restart_time

    if testing:
        restart_time = 1

    purge_time: float = instance.purge_time

    purge_time_diff: float = round(time.time() - purge_time,2)

    # check if the last find is older than the set restart time
    if (((last_find_time_diff / 60) > restart_time) and (restart_time != 0)):
        log.info("it seems the current restart time fit not the selected mode, restarting...")
        ret = True
        instance.new_restart_time = True
        instance.purge_time = time.time()

    elif instance.mode_info.purge and ((purge_time_diff / 60) > restart_time):
        log.info("it seems that the purge time is now")
        # log.info("purge_time: " + str(purge_time))
        # log.info("purge_time_diff:" + str(purge_time_diff))

        if restart == True:
            log.info("Corpus count stagnated, restart needed --- All conditions met -> restarting")
            ret = True
            instance.new_restart_time = True
            instance.purge_time = time.time()
        elif instance.mode_info.force == True:
            log.info("forcing restart...")
            ret = True
            instance.new_restart_time = True
            instance.purge_time = time.time()
        else:
            log.info("Well, waiting that the corpus count stagnates -- No restart needed")
    else:
        log.info("No restart needed")

    return ret


timeback_handlers = {
    "timeback_plain": mode_timeback_plain, "timeback_global": mode_timeback_global, "timeback_local": mode_timeback_local
}


def process_additional_modes(instance : FuzzerInstance, afl_queue_path : Path) -> None:
    """ process modes which require corpus retention """

    afl_new_seed_path = instance.fuzzer_args["afl_seed"]

    process_mode_start_id = random.randrange(0, 1234567890)
    dump_event(ProcessModeStart(process_mode_start_id, instance.worker_id,instance.mode_info.mode, instance.mode_info.additional_info))

    if instance.mode_info.additional_info == "adaptive":
        mode_adaptive(instance)
    
    if instance.mode_info.mode == "continue":
        afl_new_seed_path : Path = mode_continue(instance, afl_queue_path)

    if instance.mode_info.mode == "corpus_del":
        afl_new_seed_path : Path = mode_corpus_del(instance, afl_queue_path)

    if instance.mode_info.mode == "input_shuffle":
        afl_new_seed_path : Path = mode_input_shuffle(instance, afl_queue_path)

    if instance.mode_info.mode == "tree_chopper":
        afl_new_seed_path = mode_tree_chopper(instance, afl_queue_path)

    if instance.mode_info.mode == "tree_chopper_multi":
        afl_new_seed_path = mode_tree_chopper(instance, afl_queue_path, multi_tree = True)

    if instance.mode_info.mode == "tree_planter":
        afl_new_seed_path = mode_tree_planter(instance, afl_queue_path)

    if instance.mode_info.mode in {"timeback_plain", "timeback_global", "timeback_local"}:
        global timeback_handlers
        afl_new_seed_path = timeback_handlers[instance.mode_info.mode](instance, afl_queue_path)

    log.info(f"New seed path: {afl_new_seed_path}")
    instance.fuzzer_args["afl_seed"] = afl_new_seed_path

    # check for corpus minimization
    # performing cmin on every restart didnt worked, maybe performing to every n restarts have more benefits
    if instance.cmin:
        # if (instance.run_id + 1) % 3 == 0:
        #     minimize_corpus(instance)
        # else:
        #     log.debug("corpus minimization is selected but is not performed on this run")
        minimize_corpus(instance)

    dump_event(ProcessModeStop(process_mode_start_id, instance.worker_id,instance.mode_info.mode, instance.mode_info.additional_info))


def wait_for_stats_file(instance: FuzzerInstance, stats_path: Path) -> bool:
    """ waiting till afl's fuzzer_stats file is created """
    fuzzer_stats_id = random.randrange(0, 1234567890)
    dump_event(FuzzerStatsWait(fuzzer_stats_id,instance.worker_id))
    log.info("Waiting for stats file...")
    estimated_time: int = int(len(list(pathlib.Path(instance.fuzzer_args["afl_seed"]).iterdir())) * 0.5 + 50) * 3
    for time_i in range(0, estimated_time, 10):

        # fuzzbench fix for failing runs (we try to generate some action to show fuzzbench that the trial is alive while waiting for afl)
        fd, tmp_path = tempfile.mkstemp(prefix="sileo_tmp_", dir=stats_path.parent.parent) 

        if stats_path.exists():
            log.info(f"Stats file found after {time_i} second(s)")
            if Path(tmp_path).exists():
                Path(tmp_path).unlink()
            dump_event(FuzzerStatsFound(fuzzer_stats_id, instance.worker_id))
            return True
        time.sleep(10)
        if Path(tmp_path).exists():
            Path(tmp_path).unlink()
    dump_event(FuzzerStatsFound(fuzzer_stats_id, instance.worker_id))
    log.debug("Stats file not found!")
    return False

def afl_watchdog(instance_list : List[FuzzerInstance], stop_time : td, result_path : Path, afl_args : Dict[str, Any]) -> bool:
    """ main scheduler loop here

        - init first startup while waiting for fuzzer_stats
        - checking the fuzzer_stats periodically till stop time is reached
        - perform a restart if necessary
            - stopping current run
            - performing corpus retention
            - init next run
        - check for permit_purge heuristic
            - set purge heuristic if current heuristic is just cov based and not threshold based and if no restarts occured after 50% of runtime    
    """
    global run
    restarts : int = 0
    run = True
    start_time = time.monotonic()

    # just watch for instances
    for instance in instance_list:
        path_worker_id: int = instance.path_worker_id

        try:
            # for first run the notify path is always run_0
            # /.../$afl_out$/restart_results/worker_$id$/run_0/default/fuzzer_stats
            fstats_path: Path = result_path / ("worker_" + str(path_worker_id)) / "run_0" / "default" / "fuzzer_stats"
            instance.stats_path = fstats_path
            log.debug("Path to fuzzer_stats:" + str(fstats_path))
            log.debug("Paths in parent dir:")

            if not wait_for_stats_file(instance, fstats_path):
                assert fstats_path.exists(), "Path does not exist!"
            else:
                log.debug("Path exists:" + str(fstats_path))

            for path in Path(fstats_path.parent).iterdir():
                log.debug("\t\t" + path.as_posix())

            del fstats_path # just to make sure fstats_path won't mixed
        except Exception as err:
            log.error("Not able to watch file:" + str(err), exc_info=True)
            return False

    log.info("watching for things (periodically)")

    n_path : Optional[Path] = None
    stop: dt = dt.now() + stop_time
    not_found_count: int = 0
    first_run: bool = True

    while run and (dt.now() < stop):

        w_id : Optional[int] = None
        r_id : Optional[int] = None

        for instance in instance_list:

                tld: td = stop - dt.now()
                log.info("Time left:" + str(round(tld.days,1)) +  "d" + str(round(tld.seconds / 3600,1)) + "h (" + str(round(tld.seconds / 60,1)) + "min)")

                w_id = instance.worker_id
                r_id = instance.run_id

                log.debug("Worker ID:" + str(w_id))
                assert w_id is not None, "Worker id is None"
                assert r_id is not None, "Run id is None"

                if not instance.stats_path.exists():
                    log.info("Stats file not found")

                    if not_found_count > 5:
                        log.info("Stats file not found for too long, stopping...")
                        run = False
                        break
                    not_found_count += 1
                    continue
                else:
                    not_found_count = 0

                if first_run:
                    first_run = False
                    log.info("First run, no restart needed")
                    continue

                ret: bool = check_afl_data(instance, Path(instance.stats_path))

                if ret:
                    restart_start_id = random.randrange(0, 1234567890)
                    dump_event(RestartStart(restart_start_id, instance.worker_id))
                    restarts += 1

                    n_path = result_path / Path("worker_" + str(w_id)) / Path("run_" + str(r_id + 1)) / "default" / "fuzzer_stats"
                    log.debug("New path:" + str(n_path))

                    if not kill_single(instance):
                        log.warning("An Error occured while trying to kill AFL instance:" + str(w_id))

                    afl_queue_path: Path = Path(instance.stats_path).parent / Path("queue")
                    assert afl_queue_path.exists(), "Queue path does not exist!"

                    # this one is for corpus retention strategies
                    process_additional_modes(instance, afl_queue_path)
                    afl_args["afl_seed"] = instance.fuzzer_args["afl_seed"]

                    new_instance: FuzzerInstance = run_fuzzer(int(w_id), int(r_id) + 1, afl_args, True, instance.mode_info.mode)
                    new_instance.stats_path = n_path
                    new_instance.update_new_instance(instance)

                    # replace old instance with new_instance
                    for i, instance in enumerate(instance_list):
                        id : int = instance.worker_id
                        if int(id) == int(w_id):
                            instance_list[i] = (new_instance)
                            break
                    time.sleep(2)

                    if not wait_for_stats_file(instance, n_path):
                        assert n_path.exists(), "Path does not exist!"
                    else:
                        log.debug("Path exists:" + str(n_path))
                    dump_event(RestartDone(restart_start_id, instance.worker_id))
                    #break

        experiment_runtime: float = round((time.monotonic() - start_time) / 3600, 2)
        log.info("Number of restarts:" + str(restarts))
        log.info(f"Runtime: {experiment_runtime}h ")

        # restart after 1/2 of the runtime if no restarts happened yet
        if experiment_runtime > ((stop_time.total_seconds() / 3600) / 2):
            for ii, instance in enumerate(instance_list):            
                if instance.run_num < 2 and instance.mode_info.permit_purge and not instance.mode_info.purge:
                    log.info("Restarting instances %d due to long runtime --- Enable purge mode" % ii)
                    instance.mode_info.purge = True
        if not run:
            break

        if testing:
            time.sleep(30)
        else:
            time.sleep(60)
    return True

def gen_afl_args(args : Namespace) -> Dict[str, Any]:
    """ set a dict with all afl arguments """

    if args.afl_bin is not None:
        afl_bin = args.afl_bin
    else:
        if args.afl_path is not None:
            afl_bin = Path(args.afl_path) / "afl-fuzz"
        else:
            log.error(f"Please provide path to afl-fuzz or path to AFL's source directory")
            exit()
    
    if not afl_bin.exists():
        log.error(f"Unable to find afl-fuzz binary in {afl_bin}")
        exit()

    if args.afl_path is None:
        afl_path: Path = afl_bin.parent
    else:
        afl_path : Path = args.afl_path

    if args.afl_seed is None:
        log.error("Please provide a seed directory")
        exit()
    else:
        afl_seed : Path = args.afl_seed.resolve()
    if args.afl_out is None:
        afl_out : Path = Path.cwd()
    else:
        afl_out = args.afl_out
    if args.afl_dict is None:
        afl_dict: List[str] = []
    else:
        afl_dict = ["-x"] + args.afl_dict.split(" ")
    if args.afl_cmplog is None:
        afl_cmplog = []
    else:
        afl_cmplog = ["-c"] + args.afl_cmplog.split(" ")
    if args.afl_target is None:
        log.error("Please provide a target binary")
        exit()

    else:
        afl_target: Path = args.afl_target.resolve()
        target_name: str = afl_target.name

    if args.add_flags is None:
        add_flags: List[str] = []
    else:
        add_flags = args.add_flags
        print(add_flags)

    if args.afl_target_args is None:
        target_args: List[str] = []
    else:
        target_args = args.afl_target_args

    return {"afl_bin": afl_bin, "afl_path": afl_path, "afl_seed": afl_seed, "afl_default_seed": afl_seed, "afl_out": afl_out, "afl_dict": afl_dict, "afl_cmplog": afl_cmplog, "target_name": target_name, "afl_target": afl_target, "afl_target_args": target_args, "add_flags": add_flags}

def create_directory_tree(afl_out : Path, target_name : str, mode: str) -> Path:
    """ initialize directory structure """
    log.info("Creating directory tree...")
    cwd: Path = Path.cwd()

    if not (cwd / afl_out).exists():
            (cwd / afl_out).mkdir(parents=True)

    mode_dir = tempfile.mkdtemp(prefix = mode + "_", dir = cwd / afl_out)
    result_path: Path = cwd / afl_out / mode_dir / target_name

    try:
        if not (cwd / result_path).exists():
            (cwd / result_path).mkdir(parents=True)
        log.info("Created directory:" + str(result_path))
    except Exception as err:
        log.error("Error while creating directory tree:" + str(err), exc_info=True)
        exit()
    return result_path


def parse_arguments(raw_args: Optional[Sequence[str]]) -> Namespace:
    """ Parser for commandline arguments """
    
    parser: ArgumentParser = ArgumentParser(description="Scheduler for AFL++ restarting instances")
    group = parser.add_mutually_exclusive_group()

    parser.add_argument("--afl_path", type=str, default=None, help="Path to AFL binaries")
    parser.add_argument("--afl_bin", type=str, default="afl-fuzz", help="Path to afl-fuzz binary")
    parser.add_argument("--afl_seed", "-s", type=Path, help="Path to seed directory")
    parser.add_argument("--afl_out", "-o", type=Path, help="Path to output directory")
    parser.add_argument("--afl_dict", type=str, default=None, help="fuzzer dictionary for afl-fuzz")
    parser.add_argument("--afl_cmplog", type=str, default=None, help="afl-fuzz complog")
    parser.add_argument("--afl_target", "-t", type=Path, help="Path to target binary")
    parser.add_argument("--add_flags", type=str, nargs=argparse.REMAINDER, help="Additional flags directly passed to afl-fuzz, put them in quotes e.g. \"-D -n\"")
    parser.add_argument("--afl_target_args", "-a", type=str, default=None, nargs=argparse.REMAINDER, help="Arguments for target binary")
    parser.add_argument("--num", type=int, default=1, help="Number of instances to start")
    parser.add_argument("--runtime", type=int, default=24, help="Runtime in hours")
    parser.add_argument("--rtime", type=str, default="", help="Initial restart time. Format: [0-9.]+[hdm](-[0-9.]+[hdm])? or (e.g. 2d, 3h, 30m, 0.5m, 1d-2d, 20m-2d) If provided with a time interval, we will randomly draw a time from this interval. if provided with empty, we will use the default restart time for each strategy. Ignored under mode: log_up, log_down, log_wave. ")
    parser.add_argument("--debug", action="store_true", default=False, help="Enable debug mode for connected fuzzer")
    parser.add_argument("--mode", type=str, default="random", help="Mode (fixed, random, corpus_del, tree_chopper, tree_chopper_multi, tree_planter, timeback_plain, input_shuffle, adaptive, log_wave...)")
    parser.add_argument("--log", type=str, default="INFO", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    group.add_argument("--purge", action="store_true", default=False, help="Purge runs according to restart time while respecting on current coverage")
    group.add_argument("--no_purge", action="store_true", default=False, help="Prohibit purge even if no restart could occur")
    parser.add_argument("--force_restart", action="store_true", default=False, help="Force the fuzzer to restart without relying on cov")
    parser.add_argument("--testing", action="store_true", default=False, help="Testing mode -- small restart times and high tresholds")
    parser.add_argument("--cmin", action="store_true", default=False, help="Use corpus minimization before restarting")
    parser.add_argument("--tmin", action="store_true", default=False, help="Use testcase minimization before restarting")
    parser.add_argument("--no_cal", action="store_true", default=False, help="Disable AFL startup calibration")
    parser.add_argument("--log_path", "-l", type=Path, help="directory for logging")

    return parser.parse_args(raw_args)

def parse_rtime_part(s):
    """ parse runtime argument """
    return float(s[:-1]) * {'d': 24 * 60, 'h': 60, 'm': 1}[s[-1]]

def main(raw_args: Optional[Sequence[str]] = None) -> None:
    """ main function 
        - create directory structure
        - init directories
        - start main watcher loop
    """
    global debug, testing, disable_startup_cal

    args: Namespace = parse_arguments(raw_args)
    setup_logging(log_level=args.log, sileo_mode = args.mode, log_dir = args.log_path)

    log.info("Starting Sileo")
    sileo_start_id: int = random.randrange(0,1234567890)
    dump_event(SileoStart(sileo_start_id, -1))
    if args.debug:
        debug = True
    
    if args.testing:
        testing = True

    disable_startup_cal = args.no_cal

    num_inst_rnd: int = args.num
    log.info("Number of instances:" + str(num_inst_rnd))
    signal.signal(signal.SIGINT, signal_handler)

    runtime: td = td(hours=args.runtime)

    afl_args : Dict[str, Any] = gen_afl_args(args)
    log.debug(afl_args)

    if args.cmin or args.cmin:
        afl_path : Path = Path(afl_args["afl_path"])
        cmin_path: Path = afl_path / "afl-cmin"
        tmin_path: Path = afl_path / "afl-tmin"

        if not cmin_path.exists() or not tmin_path.exists():
            log.error(f"afl-cmin or afl-tmin not found in\n{cmin_path}\n{tmin_path}!")
            exit()

    result_path: Path = create_directory_tree(afl_args["afl_out"], afl_args["target_name"], mode=args.mode)

    afl_args["afl_out"] = result_path
    instances: List[FuzzerInstance] = start_instance(afl_args, num_inst_rnd, mode=args.mode)

    if len(args.rtime) > 0:
        assert re.match("[0-9.]+[hdm](-[0-9.]+[hdm])?", args.rtime)
        if "-" in args.rtime:
            rtime = (parse_rtime_part(args.rtime[:args.rtime.index("-")]), parse_rtime_part(args.rtime[args.rtime.index("-") + 1:]))
        else:
            rtime = (parse_rtime_part(args.rtime), parse_rtime_part(args.rtime))
        assert rtime[0] <= rtime[1]
    else:
        rtime = (-1, -1)

    if args.force_restart and not args.purge:
        log.info("Forcing a restart requires purge mode!")
        args.purge = True

    for instance in instances:
        instance.mode_info.force = args.force_restart
        instance.mode_info.purge = args.purge
        instance.mode_info.permit_purge = not args.no_purge
        instance.purge_time = time.time()
        instance.mode_info.user_rtime = rtime
        instance.cmin = args.cmin
        instance.tmin = args.tmin

    log.debug("Done, all instances started")
    time.sleep(2)
    if not afl_watchdog(instances, runtime, result_path, afl_args):
        log.error("An error occured while watching AFL instances")
        log.error("Terminating all instances")

    kill_afl(instances)
    dump_event(SileoStop(sileo_start_id,-1))
    log.info(" --- END ---")


if __name__ == "__main__":
    main()
