from collections import defaultdict, deque
import hashlib
from pathlib import Path
import random
import re
import shutil
import functools
from typing import Dict, List, Set, Deque

try:
    from .sileo_instances import FuzzerInstance
    from .sileo_utils import log, mybisect #, Profiler
except ImportError:
    from sileo_instances import FuzzerInstance
    from sileo_utils import log, mybisect #, Profiler

def mode_logarithmic_wave(instance : FuzzerInstance) -> int:
    """restart time goes like a logarithmic wave up and down"""

    restart_time = instance.restart_time
    if instance.restart_time == 0:
            restart_time = instance.mode_info.init_restart_time
    else:
        if restart_time <= 32 and instance.mode_info.additional_info == "up":
            restart_time = instance.restart_time * 2
            instance.mode_info.additional_info = "up"
        elif restart_time > 32 and instance.mode_info.additional_info == "up":
            restart_time = instance.restart_time // 2
            instance.mode_info.additional_info = "down"
        elif restart_time > 1 and instance.mode_info.additional_info == "down":
            restart_time = instance.restart_time // 2
            instance.mode_info.additional_info = "down"
        elif restart_time == 1 and instance.mode_info.additional_info == "down":
            restart_time = instance.restart_time * 2
            instance.mode_info.additional_info = "up"
        else:
            log.info("Logwave up (else)")
            restart_time = instance.restart_time * 2
            instance.mode_info.additional_info = "up"
    return restart_time

def mode_logarithmic_down(instance : FuzzerInstance) -> int:
    """restart time decreases logarithmic"""
    restart_time = 0
    # if mode logarithmic is selected, the restart time never can be 0  -- thus if restart time is 0, we can assume thats the first run
    if instance.restart_time == 0:
        restart_time = instance.mode_info.init_restart_time
    else:
        # divide restart time by 2 till it reaches 1
        if instance.restart_time > 1:
            restart_time = instance.restart_time // 2
        else:
            restart_time = 1
    return restart_time

def mode_logarithmic_up(instance : FuzzerInstance) -> int:
    """restart time increases logarithmic"""

    restart_time = 0
    # if mode logarithmic is selected, the restart time never can be 0  -- thus if restart time is 0, we can assume thats the first run
    if instance.restart_time == 0:
        restart_time = instance.mode_info.init_restart_time
    else:
        # multiply restart time by 2 till it reaches max value
        restart_time = instance.restart_time * 2
        if restart_time >= 64:
            restart_time = 64
    return restart_time

def copy_and_shuffle(src : set[Path], dest : Path, copy_dirs : bool = False, file_name : str = "")  -> None:
    """ Copy seeds into new seed dir
    Note: it has a negative impact to just copy all seeds and keep the original name
    Note 2: We want to copy seeds from initial seed dir (also subdirectories) -> copy_dirs = True
    """

    log.debug(f"Copying and shuffle {len(src)} seeds")

    seed_cnt = 0
    if copy_dirs:
        file_name += "_initial"

    for seed in src:
        random_prefix: str = str(random.randint(100000, 999999))
        seed_cnt += 1
        
        if seed.is_file():
            shutil.copy(seed, dest / f"{random_prefix}_{seed.name}")
        elif copy_dirs:
            shutil.copytree(seed, dest / f"{random_prefix}_{seed.name}", dirs_exist_ok=True)
    
    with open(f"{dest.parent / file_name}.txt", "w") as fd:
        fd.write(str(seed_cnt))

def mode_input_shuffle(instance : FuzzerInstance, afl_queue_path: Path) -> Path:
    """copy and shuffle fuzzer queue"""
    
    default_seed_dir: Path = instance.fuzzer_args["afl_default_seed"]
    old_seed_dir : Path = afl_queue_path
    worker_path : Path = Path(instance.fuzzer_args["afl_out"] / f"worker_{instance.path_worker_id}")
    new_seed_dir: Path =  worker_path / Path("seeds_" + str(instance.run_id))
    new_seed_dir.mkdir(parents=True)
    log.debug(f"Old seed dir: {old_seed_dir}")
    log.debug(f"New seed dir: {new_seed_dir}")

    seeds = set(old_seed_dir.iterdir())

    log.debug("Shuffle Seeds")

    info_file = f"run_{instance.run_id}_input_shuffle"

    # copy afl queue files
    copy_and_shuffle(seeds, new_seed_dir, file_name = info_file)

    # copy initial seeds files
    copy_and_shuffle(set(default_seed_dir.iterdir()), new_seed_dir, copy_dirs = True, file_name = info_file)
    
    remove_duplicate_files(new_seed_dir)

    return new_seed_dir
def mode_continue(instance : FuzzerInstance, afl_queue_path: Path) -> Path:
    """ just restart keeping the current queue as it is sets the current queue as new seed directory
    Note: no shuffle of seeds done! ensure you set AFL_SHUFFLE_QUEUE=1
    """
    
    log.debug("Continue Mode")
    new_seed_dir: Path = afl_queue_path
    log.debug(f"New seed dir: {new_seed_dir}")

    return new_seed_dir

def mode_corpus_del(instance : FuzzerInstance, afl_queue_path: Path) -> Path:
    """ copy queue and randomly delete parts of it """

    default_seed_dir: Path = instance.fuzzer_args["afl_default_seed"]
    old_seed_dir : Path = afl_queue_path
    worker_path : Path = Path(instance.fuzzer_args["afl_out"] / f"worker_{instance.path_worker_id}")
    new_seed_dir: Path =  worker_path / Path("seeds_" + str(instance.run_id))
    new_seed_dir.mkdir(parents=True)
    log.debug(f"Old seed dir: {old_seed_dir}")
    log.debug(f"New seed dir: {new_seed_dir}")

    # choose percentage of corpus to delete
    corpus_del: int = random.randint(5,95)
    instance.corpus_del_percentage = corpus_del

    log.debug(f"Preserving {corpus_del}% of corpus")

    seeds = set(old_seed_dir.iterdir())

    num_seeds: int = len(seeds)
    num_seeds_to_preserve: int = int(num_seeds * ((corpus_del) / 100))
    log.info(f"Preserving {num_seeds_to_preserve} files of the corpus")

    seeds_to_preserve: set[Path] = set(random.sample(seeds, k = num_seeds_to_preserve))

    info_file = f"run_{instance.run_id}_corpus_del"
    # copy afl queue files
    copy_and_shuffle(seeds_to_preserve,new_seed_dir, file_name = info_file)

    # copy initial seeds files
    copy_and_shuffle(set(default_seed_dir.iterdir()), new_seed_dir, copy_dirs = True, file_name = info_file)

    remove_duplicate_files(new_seed_dir)

    return new_seed_dir

def _timeback_wrapper(instance: FuzzerInstance, afl_queue_path: Path, callback: callable, copy_org_seeds=True, copy_nonid_files_in_afl_queue_path=True) -> Path:
    """ wrapper for timeback """
 
    log.debug(f"Begin restart, restart mode: {instance.mode_info.mode}")
    log.debug(f"current working directory: {afl_queue_path}")
    
    default_seed_path: Path = instance.fuzzer_args["afl_default_seed"]

    # new_seed_dir: Path = default_seed_path.parent / Path("seeds_" + str(instance.run_id))
    
    worker_path : Path = Path(instance.fuzzer_args["afl_out"] / f"worker_{instance.path_worker_id}")
    new_seed_dir: Path =  worker_path / Path("seeds_" + str(instance.run_id))
    
    if new_seed_dir.exists():
        shutil.rmtree(new_seed_dir)
    new_seed_dir.mkdir(parents=True, exist_ok=True)
    log.debug(f"New seed dir: {new_seed_dir}")

    if copy_org_seeds:
        log.debug(f"Copying original seeds to new seed directory")
        if instance.mode_info.always_copy_original_seeds and default_seed_path.exists():
            for file in default_seed_path.iterdir():
                random_prefix: str = str(random.randint(100000, 999999))
                if file.is_file() and file.name.startswith("id:"):
                    continue
                if file.is_dir():
                    shutil.copytree(file, new_seed_dir / f"{random_prefix}_{file.name}")
                else:
                    shutil.copy(file, new_seed_dir / f"{random_prefix}_{file.name}")
        log.debug(f"Copied {len(list(new_seed_dir.iterdir()))} original seeds to new seed directory")

    for file in afl_queue_path.iterdir():
        #TODO: clean some relevant infos of deleted seeds
        if file.is_file() and file.name.startswith("id:"):
            continue
        if copy_nonid_files_in_afl_queue_path:
            if file.is_dir():
                shutil.copytree(file, new_seed_dir / file.name)
            else:
                shutil.copy(file, new_seed_dir / file.name)
    
    callback(instance, afl_queue_path, new_seed_dir)
    remove_duplicate_files(new_seed_dir)
    num_seeds_now = len(list(new_seed_dir.iterdir()))
    assert num_seeds_now > 0
    log.info(f"In the end, there are {num_seeds_now} seed(s) remained in {new_seed_dir}.")

    return new_seed_dir


def _read_file_id2info_AFLPP(adir, run_id):
    """ file processing for timeback """
    file_id2info = dict()
    for file in adir.glob('id:*'):
        if not file.is_file():
            continue
        file_info = {
            "path": file,
        }
        file_name_with_info = file.name
        if ",orig:" in file_name_with_info:
            rorig_ind = file_name_with_info.index(",orig:")
            file_info["orig"] = file_name_with_info[rorig_ind + len(",orig:"):].strip()
            file_name_with_info = file_name_with_info[:rorig_ind]

        for str_ele in file_name_with_info.split(","):
            if ":" in str_ele:
                name, value = str_ele.split(":")[:2]
                name = name.strip()
                value = value.strip()
                if len(value) < 9 and value.isdigit() and "." not in value:
                    value = int(value)
                assert name not in file_info
                file_info[name] = value
        file_info["new_name"] = f"run_{run_id}_id_{file_info['id']}"
        file_id2info[file_info["id"]] = file_info

        if "src" in file_info:
            if isinstance(file_info["src"], str):
                file_info["src"] = [int(ele) for ele in file_info["src"].split("+") if ele.strip()]
            else:
                file_info["src"] = [file_info["src"]]
        else:
            file_info["src"] = []
    return file_id2info
    

def mode_timeback_plain(instance: FuzzerInstance, afl_queue_path: Path) -> Path:
    """ select a time form previous run, copy all files before that timestamp """

    def callback(instance: FuzzerInstance, afl_queue_path: Path, new_seed_dir: Path):
        file_id2info = _read_file_id2info_AFLPP(afl_queue_path, instance.run_id)

        # TODO: del this par that is additional check to avoid programming bugs
        file_ids = list(file_id2info.keys())
        file_ids.sort()

        first_time = file_id2info[file_ids[0]]["time"] if len(file_ids) > 0 else -1
        last_time = file_id2info[file_ids[-1]]["time"] if len(file_ids) > 0 else -1
        if len(file_ids) == 0 or last_time == 0 or first_time == last_time:
            log.warn(f"Cannot find much seeds to schedule in {new_seed_dir}. New AFL Seeds number: {len(file_ids)}.")
            return new_seed_dir
        
        del_time_delta = random.random() * random.random() * (last_time - first_time) + first_time
        del_file_id_idx = mybisect(file_ids, del_time_delta, 0, len(file_ids), lambda arr_ele, x: -1 if file_id2info[arr_ele]["time"] <= x else 1)
        assert 0 <= del_file_id_idx < len(file_ids)
        assert file_id2info[file_ids[del_file_id_idx]]["time"] >= del_time_delta
        log.debug(f"Delete {len(file_ids)} - {del_file_id_idx}th seeds from queue: Time {del_time_delta}, in the interval ({first_time} - {last_time})")
        del_file_ids = set(file_ids[del_file_id_idx:])
        
        log.debug(f"Copying leftover testcases to new seed directory")
        for file_id in file_ids:
            if file_id not in del_file_ids:
                file_info = file_id2info[file_id]
                fpath = file_info["path"]
                # TODO: this will actually make undeleted seeds permanently stay, 20230101 I will just follow the design.
                random_prefix: str = str(random.randint(100000, 999999))
                shutil.copy(fpath, new_seed_dir / (random_prefix + "_" + file_info["new_name"]))
        log.info(f"Deleting {len(del_file_ids)} files from corpus, time threshold: {del_time_delta}.")

    new_seed_dir = _timeback_wrapper(instance, afl_queue_path, callback)

    return new_seed_dir


def mode_timeback_seed_cluster(instance: FuzzerInstance, afl_queue_path: Path) -> Path:
    """ not used """
    def callback(instance: FuzzerInstance, afl_queue_path: Path, new_seed_dir: Path):
        file_id2info = _read_file_id2info_AFLPP(afl_queue_path, instance.run_id)
        
    new_seed_dir = _timeback_wrapper(instance, afl_queue_path, callback)
    return new_seed_dir

def mode_timeback_global(instance: FuzzerInstance, afl_queue_path: Path) -> Path:
    """ not implemented, fallback to timeback_plain """
    
    log.error("Timeback global is not implemented -- switching to timeback_plain")
    return mode_timeback_plain(instance, afl_queue_path)

def mode_timeback_local(instance: FuzzerInstance, afl_queue_path: Path) -> Path:
    """ not implemented, fallback to timeback_plain """
    log.error("Timeback local is not implemented -- switching to timeback_plain")
    return mode_timeback_plain(instance, afl_queue_path)


def remove_duplicate_files(path: Path) -> None:
    """ hash queue files to find duplicates and remove them """
    
    log.info("Removing duplicate files")
    files: List[Path] = list(path.iterdir())

    hash_to_file: Dict[str, List[Path]] = defaultdict(list)

    for file in files:
        if file.is_file():
            hash_to_file[get_hash(file)].append(file)

    duplicate_counter = 0
    for _, files in hash_to_file.items():
        if len(files) > 1:
            for file in files[1:]:
                duplicate_counter += 1
                file.unlink()

    log.debug(f"Number of duplicate files: {duplicate_counter}")

    files = list(path.iterdir())
    log.debug(f"Leftover files: {len(files)}")

    # clear the lru_cache 
    get_hash.cache_clear()


@functools.cache
def get_hash(file: Path) -> str:
    """ generate hash for file """
    with open(file, "rb") as f:
        return hashlib.md5(f.read()).hexdigest()


pattern1 = re.compile(r'.*src:(\d+)\+?(\d+)?') 
pattern2 = re.compile(r'id:(\d+)')

def mode_tree_chopper_update_trees(instance : FuzzerInstance, seeds_dir: Path) -> None:
    """ process seeds to build trees """
    log.debug("tree_chopper: update trees")
    seeds = set(seeds_dir.glob('id:*'))
    log.debug(f"Num of seeds (id:*): {len(seeds)}")
    seed_hashes = {str(seed): get_hash(seed) for seed in seeds}

    file_id_to_seed = {}
    for seed in seeds:
        file_id_to_seed[pattern2.search(seed.name).group(1)] = seed

    for seed in seeds:
        child_hash = seed_hashes[str(seed)]
        if child_hash in instance.tree_chopper_seen_seeds:
            # Skipping already processed seeds
            continue
        instance.tree_chopper_seen_seeds.add(child_hash)

        if 'orig:' in seed.name:
            # Skip initial seeds, since they don't have a parent
            continue

        # Get the parent ID(s)
        matches = pattern1.search(seed.name)
        assert matches
        parent_ids = matches.groups()

        # Since these are new (unknown hash), the parent with the specific ID must exist.
        # parent_files = [seed for seed in seeds if pattern2.search(seed.name).group(1) in parent_ids] #type: ignore
        parent_files = [file_id_to_seed[parent_id] for parent_id in parent_ids if parent_id is not None] #type: ignore
        parent_hashes = [seed_hashes[str(parent)] for parent in parent_files]

        for parent_hash in parent_hashes:
            instance.tree_chopper_parent_to_children[parent_hash].add(child_hash)

def tree_chopper_build_tree(parent: str, parent_child_mapping: Dict[str, Set[str]]) -> Set[str]:
    """ find trees in corpus """
    tree_nodes: Set[str] = set()
    stack: Set[str] = {parent}
    visited : set = set() 

    while stack:
        node: str = stack.pop()
        tree_nodes.add(node)
        visited.add(node)
        for child in parent_child_mapping[node]:
            if child not in visited:
                stack.add(child)
                tree_nodes.add(child)
    return tree_nodes


def get_tree_list(instance: FuzzerInstance) -> List[Set[str]]:
    """ get list of trees """
    trees: List[Set[str]] = []

    for parent, _ in list(instance.tree_chopper_parent_to_children.items()):
        tree: Set[str] = tree_chopper_build_tree(parent, instance.tree_chopper_parent_to_children)
        trees.append(tree)

    log.debug("tree_chopper: building trees done")

    if len(trees) == 0:
        log.debug("No trees found")
        return trees

    # Longest tree is the first element
    trees.sort(key=lambda tree: len(tree), reverse=True)
    log.info(f'Found {len(trees)} trees')
    log.debug(f"Longest tree: {len(trees[0])}")

    return trees

def mode_tree_chopper_choose_tree(instance: FuzzerInstance, trees: List[Set[str]], planter : bool = False) -> Set[str]:
    """ select one tree from trees, delete the others """

    weights: list[int] = [25 if not planter else 100] * len(trees)
    selected_tree: Set[str] = random.choices(trees, k=1, weights=weights)[0]

    # Fallback, just in case we fail to pick one above
    if selected_tree is None:
        log.debug('Failed to pick a tree, picking random one')
        selected_tree = random.choice(trees)

    # Delete tree from our records, thus we do not try to delete it next
    # run, eventhough it does not exist anymore.
    instance.tree_chopper_seen_seeds -= selected_tree
    for parent, children in list(instance.tree_chopper_parent_to_children.items()):
        children -= selected_tree
        if parent in selected_tree:
            del instance.tree_chopper_parent_to_children[parent]

    return selected_tree


def mode_tree_chopper(instance : FuzzerInstance, afl_queue_path: Path, multi_tree = False) -> Path:
    """ find trees in queue files, keep #+ (or multiple: multi_tree = True) randomly and delete the others"""

    log.info("Let me be your lumber*jack*!")

    default_seed_dir: Path = instance.fuzzer_args["afl_default_seed"]
    old_seed_dir : Path = afl_queue_path
    
    worker_path : Path = Path(instance.fuzzer_args["afl_out"] / f"worker_{instance.path_worker_id}")
    new_seed_dir: Path =  worker_path / Path("seeds_" + str(instance.run_id))

    log.debug(f"Old seed dir: {old_seed_dir}")
    log.debug(f"New seed dir: {new_seed_dir}")

    # Copy seeds into new seed dir
    shutil.copytree(old_seed_dir, new_seed_dir, dirs_exist_ok=True)

    log.debug(f"Copying seed files done -- ({len(list(new_seed_dir.iterdir()))})")

    # Update tree
    mode_tree_chopper_update_trees(instance, new_seed_dir)

    trees : list[Set[str]] = get_tree_list(instance)
    trees_to_delete: int = 1
    
    if multi_tree:
        # choose the number of trees to delete delete min 5%, but left also a min of 5% of all trees
        trees_to_delete = random.randint((int(len(trees) * 0.05)),len(trees) - (int(len(trees) * 0.05)))

    log.info(f"Trees to delete: {trees_to_delete}")

    log.debug("Choosing trees to delete...")
    tree_del_set = set()
    for _ in range(0, trees_to_delete):

        # Choose tree to delete
        tree: Set[str] = mode_tree_chopper_choose_tree(instance, trees)
        tree_del_set.update(tree)

    new_seed_dir_files: set[Path] = set(x for x in new_seed_dir.iterdir() if x.is_file())
    seed_files_set : Set[Path] = set()

    log.debug(f"Deleting {len(tree_del_set)} files")
    node_set = set()
    
    for node in tree_del_set:
        node_set.add(node)            

    seed_cnt = 0

    for seed in new_seed_dir_files:
        if get_hash(seed) in node_set:
            seed.unlink()
        else:
            random_prefix: str = str(random.randint(100000, 999999))
            seed.rename(new_seed_dir / (random_prefix + "_" +  seed.name))
            seed_cnt += 1
    
    info_file = f"run_{instance.run_id}_tree_chopper"
    
    with open(f"{new_seed_dir.parent / info_file}.txt", "w") as fd:
        fd.write(str(seed_cnt))

    # Copy default seeds into new seed dir
    copy_and_shuffle(set(default_seed_dir.iterdir()), new_seed_dir, copy_dirs=True, file_name= info_file)

    # Delete duplicated seed files via remove_Duplicated_files()
    remove_duplicate_files(new_seed_dir)

    return new_seed_dir


def mode_tree_planter(instance : FuzzerInstance, afl_queue_path: Path) -> Path:
    """ find a trees in queue files, keep one (or multiple: multi_tree = True) randomly and delete the others"""
    
    global other_tree
    log.info("Let me be your lumber*jack*!")

    default_seed_dir: Path = instance.fuzzer_args["afl_default_seed"]
    all_seeds_dir: Path = default_seed_dir.parent / 'all_seeds'
    old_seed_dir : Path = afl_queue_path
    worker_path : Path = Path(instance.fuzzer_args["afl_out"] / f"worker_{instance.path_worker_id}")
    new_seed_dir: Path =  worker_path / Path("seeds_" + str(instance.run_id))
    new_seed_dir.mkdir(parents=True)
    log.debug(f"Old seed dir: {old_seed_dir}")
    log.debug(f"New seed dir: {new_seed_dir}")

    # Update tree
    mode_tree_chopper_update_trees(instance, old_seed_dir)
    trees: list = get_tree_list(instance)

    # Choose tree to copy
    tree: Set[str] = mode_tree_chopper_choose_tree(instance, trees, planter = True)
    log.debug(f'Coping tree of size {len(tree)}')

    # Copy newly found seeds into the directory containing all seeds files we found so far
    shutil.copytree(old_seed_dir, all_seeds_dir, dirs_exist_ok=True)
    remove_duplicate_files(all_seeds_dir)

    # Delete tree
    old_seed_dir_files = list(all_seeds_dir.iterdir())
    tree_files = set([file for file in old_seed_dir_files if file.is_file() and get_hash(file) in tree])
    log.debug(f'Found {len(tree_files)} seeds that belong to the chosen tree')

    info_file = f"run_{instance.run_id}_tree_planter"

    copy_and_shuffle(tree_files, new_seed_dir)
    
    # Copy default seeds into new seed dir
    copy_and_shuffle(set(default_seed_dir.iterdir()), new_seed_dir, copy_dirs=True)

    # Delete duplicated seed files
    remove_duplicate_files(new_seed_dir)

    return new_seed_dir


def mode_adaptive(instance : FuzzerInstance) -> None:
    """ Adaptive mode which cycles through different other modes and tries to find the best mode for the target under test """

    instance.mode_info.corpus_count_run_stack.push(instance.mode_info.corpus_count)
    instance.mode_info.corpus_count_mode_stack.push(instance.mode_info.corpus_count)
    
    corpus_count_run_avg: float = instance.mode_info.corpus_count_run_stack.get_avg()
    corpus_count_mode_avg: float = instance.mode_info.corpus_count_mode_stack.get_avg()

    log.debug(f"Corpus count run Stack: {instance.mode_info.corpus_count_run_stack}")
    log.debug(f"Corpus count mode Stack: {instance.mode_info.corpus_count_mode_stack}")


    if len(instance.mode_info.corpus_count_mode_stack) % instance.mode_info.mode_stack_size != 0:
        log.debug(f"No need to change the mode yet (len mode stack: {len(instance.mode_info.corpus_count_mode_stack)})")
    else:
        
        if instance.mode_info.best_mode == "":
            log.debug("Seems we are in the beginning -- lets change mode to check the others")

            # update dict with latest values and reset mode stack
            instance.mode_info.mode_corpus_count_total[instance.mode_info.mode].extend(instance.mode_info.corpus_count_mode_stack)
            
            instance.mode_info.best_mode = instance.mode_info.mode
            instance.mode_info.reset_stack() # set stack to len 0
            # we starting with corpus_del since it was in the most cases on average the best mode 
            instance.mode_info.mode = "corpus_del"
            log.debug(f"Starting with mode: {instance.mode_info.mode}")

        else:
            # if we change the mode, we reset the mode stack, if the current mode is the best mode, we keep the mode stack to check it every run 
            if corpus_count_mode_avg > corpus_count_run_avg:
                log.debug("Current mode is better than previous runs")
                log.debug(f"Mode avg: {corpus_count_mode_avg} ({instance.mode_info.corpus_count_mode_stack}) ----- Run avg: {corpus_count_run_avg} ({instance.mode_info.corpus_count_run_stack}) ")

                # update dict with latest values
                instance.mode_info.mode_corpus_count_total[instance.mode_info.mode].extend(instance.mode_info.corpus_count_mode_stack)

                # anyways, check if there is a better mode
                best_mode : str = ""
                max_average = 0.0
                for mode, corpus_stack in instance.mode_info.mode_corpus_count_total.items():                    
                    average_value = round(sum(corpus_stack) / len(corpus_stack),2)
                    if average_value > max_average:
                        max_average: float = average_value
                        best_mode = mode

                curr_avg: float = round(sum(instance.mode_info.mode_corpus_count_total[instance.mode_info.mode]) / len(instance.mode_info.mode_corpus_count_total[instance.mode_info.mode]),2)
                log.info(f"Best mode is {best_mode} with avg. {max_average} corpus count ---- current mode is at {curr_avg}")

                if best_mode == instance.mode_info.mode:
                    instance.mode_info.best_mode = instance.mode_info.mode
                    log.info(f"Current mode is best mode ({instance.mode_info.mode})")
                else:
                    log.debug(f"Current mode is not best mode, calculating the difference")
                    log.debug(f"max_avg: {max_average} - curr avg: {curr_avg}") 
                    difference: float = max_average - curr_avg
                    diff_in_per: float = round(difference * 100 / max_average,2)

                    log.debug(f"Difference between best mode ({best_mode}) and current mode ({instance.mode_info.mode}) is {diff_in_per}%")

                    # change to best mode if the difference is greater then 10%
                    # we will just reset the stack if we change the mode, otherwise we will rerun the mode check every restart
                    if diff_in_per > 10.0:
                        instance.mode_info.mode = best_mode
                        instance.mode_info.best_mode = best_mode
                        log.debug("Difference is greater than 10%, switching to best mode")
                        # reset corpus_count_mode_stack, since we are change the mode
                        instance.mode_info.reset_stack()

            else:
                log.debug("Current mode performs worse than previous one, lets change")
                available_modes = set(["corpus_del", "continue", "random", "tree_chopper_multi", "tree_planter", "timeback_plain"])

                # Choose a mode that has not been tested yet
                remaining_modes = available_modes - set(instance.mode_info.modes_tested)
                if remaining_modes:
                    instance.mode_info.mode = random.choice(list(remaining_modes))
                else:
                    # after corpus_del the trees and times are broken
                    # after continue, there might be no new inputs found -- so no new trees
                    if instance.mode_info.mode == "corpus_del" or instance.mode_info.mode == "continue":
                        instance.mode_info.mode = "random"
                    elif instance.mode_info.mode in {"tree_chopper_multi", "tree_planter", "timeback_plain"}:
                        instance.mode_info.mode = random.choice(["corpus_del", "continue", "random"])
                    else:
                        instance.mode_info.mode = random.choice(["tree_chopper_multi", "tree_planter", "timeback_plain"])

                log.info(f"changing to mode {instance.mode_info.mode}")
                instance.mode_info.reset_stack()
        
        if instance.mode_info.mode not in instance.mode_info.modes_tested:
            instance.mode_info.modes_tested.append(instance.mode_info.mode)


def get_mode_data(instance : FuzzerInstance) -> FuzzerInstance:
    """ get random restart time for a specific mode """

    mode: str = instance.mode_info.mode

    if instance.mode_info.purge:
        log.info("*** Purge Mode activated ***")

    if instance.mode_info.force:
        log.info("*** Forcing restart ***")

    if instance.new_restart_time:
        
        if mode in {"none", "multi"}:
            log.info(f"{mode} mode selected, Not restarting workers")
            restart_time = 0
        elif mode == "log_down":
            restart_time = mode_logarithmic_down(instance)
        elif mode == "log_wave":
            restart_time = mode_logarithmic_wave(instance)
        elif mode == "log_up":
            restart_time = mode_logarithmic_up(instance)
        else:
            if instance.mode_info.user_rtime[0] != -1:
                restart_time = random.randint(instance.mode_info.user_rtime[0], instance.mode_info.user_rtime[1])
            elif mode in  {"fixed", "random", "log_down", "log_wave", "log_up", "corpus_del",
                              "tree_chopper", "tree_chopper_multi", "tree_planter", "adaptive", 
                              "timeback_plain", "timeback_global", "timeback_local", "input_shuffle", "continue"}:
                if mode == "fixed":
                    restart_time = 10
                else:
                    restart_time = random.randint(5, 25)
            else:
                log.warning("Unknown mode selected, using random mode")
                restart_time = random.randint(5, 240)

        if mode == "adaptive":
            instance.mode_info.additional_info = "adaptive"
            instance.mode_info.mode = "random"
            instance.mode_info.modes_tested.append(instance.mode_info.mode)
        log.info(f"{mode} mode selected")
        instance.new_restart_time = False
    else:
        log.info("No new restart time required, using old one")
        restart_time = instance.restart_time

    log.info("Restart time: " + str(restart_time) + " minutes")
    instance.restart_time = restart_time

    return instance