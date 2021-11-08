import argparse
import logging
import time
import re
import sys
import os
import json
import subprocess
from enum import Enum
from logging.handlers import RotatingFileHandler
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger('Satis-log-analyzer')
DEFAULT_GAME_LOG_FILE = "FactoryGame.log"
FILE_UPDATE_HISTORY_LINE_LOOKUP = 10


def setup_logging():
    std_out_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d-%(name)s-%(levelname)8s- %(message)s', "%a %d %H:%M:%S")
    std_out_handler.setFormatter(formatter)
    logging.getLogger().addHandler(std_out_handler)
    log_file_path = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(log_file_path, 'Satisfactory-log-parser.log')
    log_file_handler = RotatingFileHandler(log_file_path, maxBytes=2000000, backupCount=2)
    log_file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(log_file_handler)


def binary_tail(f, lines_count):
    total_lines_wanted = lines_count
    base_block_size = 512 * lines_count
    f.seek(0, 2)
    block_end_byte = f.tell()
    lines_to_go = total_lines_wanted
    block_number = -1
    blocks = []
    while lines_to_go > 0 and block_end_byte > 0:
        if (block_end_byte - base_block_size) > 0:
            f.seek(block_number * base_block_size, 2)
            blocks.append(f.read(base_block_size))
        else:
            f.seek(0, 0)
            blocks.append(f.read(block_end_byte))
        lines_found = blocks[-1].count(b'\n')
        lines_to_go -= lines_found
        block_end_byte -= base_block_size
        block_number -= 1
    all_read_text = b''.join(reversed(blocks))
    return all_read_text.splitlines()[-total_lines_wanted:]


def dt_to_str(dt):
    return dt.strftime("%d/%m/%y %H:%M:%S:%f")


class SatisfactoryLogMonitor(FileSystemEventHandler):
    class ProcessLastLinesStatus(Enum):
        ProcessOK = 1
        RetryMoreLines = 2
        RestartAll = 3

    def __init__(self, game_log_path, steamcmd_install_dir):
        logger.info("--------- initializing -----------")
        logger.info("logs monitoring path is set to : {}".format(game_log_path))
        self._game_log_path = game_log_path
        self._observer = Observer()
        if self._game_log_path:
            self._observer.schedule(self, path=self._game_log_path, recursive=False)
            self._observer.start()
        self._last_processed_timestamp = None
        self._last_processed_line = None
        self._current_log_file_path = None
        self._known_active_players_ips = set()
        self._players_info = dict()
        self._waiting_for_save_after_last_client_quit = False
        self._steam_install_dir = steamcmd_install_dir

    def reset(self):
        logger.info("--------- Resetting -----------")
        self._known_active_players_ips = set()
        self._last_processed_timestamp = None
        self._last_processed_line = None
        # no need to reset self._current_log_file_path, path won't change

    def on_any_event(self, event):
        logger.debug("on_any_event : {}".format(event.src_path))

    def on_created(self, event):
        logger.info("Detected file being created in monitored folder: {}."
                    .format(event.src_path))
        self._process_log_file()

    def on_deleted(self, event):
        logger.debug("on_deleted : {}".format(event.src_path))
        if self._current_log_file_path in event.src_path:
            logger.info("Detected server log file being deleted : {}. resetting status"
                        .format(event.src_path))
            self.reset()

    def on_modified(self, event):
        logger.debug("on_modified : {}".format(event.src_path))
        if self._current_log_file_path in event.src_path:
            time.sleep(0.1)
            self._process_log_file()

    def on_moved(self, event):
        logger.debug("on_moved : {}".format(event.src_path))
        if self._current_log_file_path in event.src_path:
            logger.info("Detected server log file path being moved : {}. Assuming server is restarting"
                        .format(event.src_path))
            self.reset()

    def start_monitoring(self):
        expected_log_path = os.path.join(self._game_log_path, DEFAULT_GAME_LOG_FILE)
        if os.path.exists(expected_log_path):
            self._current_log_file_path = expected_log_path
            self._process_log_file()
        else:
            # script has been started before log file exists
            # automatic FS watchdog will trigger when the file is created
            pass
        while True:
            try:
                time.sleep(2)
            except KeyboardInterrupt:
                self._observer.stop()
                return

    def _process_log_file(self):
        if not os.path.exists(self._current_log_file_path):
            return
        if self._last_processed_timestamp is None:
            logger.debug("No log was processed before, parsing file from the start")
            with open(self._current_log_file_path, 'r') as f:
                all_lines = f.readlines()
                for line in all_lines:
                    line = line.strip().replace("\n", "").replace("\r", "")
                    if SatisfactoryLogMonitor._check_segfault(line):
                        self._do_server_restart()
                        return
                    dt, message = SatisfactoryLogMonitor._parse_line(line)
                    if dt is None:
                        continue
                    else:
                        self._last_processed_line = line
                        self._treat_log_line(dt, message)
        else:
            # seek for last messages
            logger.debug("Log file has been updated, seeking new messages")
            last_processed_message_found = False
            number_of_lines_to_load = FILE_UPDATE_HISTORY_LINE_LOOKUP
            while not last_processed_message_found:
                time.sleep(0.05)
                f = open(self._current_log_file_path, 'rb')
                last_lines = binary_tail(f, number_of_lines_to_load)
                f.close()
                logger.debug("Extracted {} last lines ({} requested)".format(len(last_lines), number_of_lines_to_load))
                # if logger.getEffectiveLevel() == logging.DEBUG:
                #     all_read_text = ''
                #     for bline in last_lines:
                #         all_read_text += "\n" + bline.decode()
                #     logger.debug("----" + all_read_text + "----")
                result = self._process_last_lines(last_lines, number_of_lines_to_load)
                if result == SatisfactoryLogMonitor.ProcessLastLinesStatus.RestartAll:
                    return
                elif result == SatisfactoryLogMonitor.ProcessLastLinesStatus.RetryMoreLines:
                    number_of_lines_to_load += FILE_UPDATE_HISTORY_LINE_LOOKUP
                elif result == SatisfactoryLogMonitor.ProcessLastLinesStatus.ProcessOK:
                    last_processed_message_found = True

        logger.debug("done processing log")

    def _process_last_lines(self, last_lines, number_of_lines_loaded):
        last_processed_message_found = False
        iteration_n = 0
        for binary_line in last_lines:
            iteration_n += 1
            line = binary_line.decode()
            line = line.strip().replace("\n", "").replace("\r", "")
            if not line:
                # skip empty lines
                continue
            # logger.debug("Checking line : {} ".format(line))
            if last_processed_message_found and SatisfactoryLogMonitor._check_segfault(line):
                self._do_server_restart()
                continue
            dt, message = SatisfactoryLogMonitor._parse_line(line)
            if dt is None:  # message without timestamp, ignoring it
                logger.debug("Line '{}' has no timestamp".format(line))
            else:
                if not last_processed_message_found and dt > self._last_processed_timestamp:
                    if number_of_lines_loaded < (FILE_UPDATE_HISTORY_LINE_LOOKUP * 10):
                        logger.debug("newer timestamp line is : '{}', with read datetime {} (iter {})"
                                     .format(line, dt_to_str(dt), iteration_n))
                        # number_of_line_to_load += FILE_UPDATE_HISTORY_LINE_LOOKUP
                        return SatisfactoryLogMonitor.ProcessLastLinesStatus.RetryMoreLines
                    else:
                        logger.warning("Unable to find last processed message in last {} lines, abandoning search "
                                       "and preparing to parsing whole file"
                                       .format(number_of_lines_loaded))
                        logger.debug("Last processed timestamp is {}. Last line was {}"
                                     .format(dt_to_str(self._last_processed_timestamp),
                                             str(self._last_processed_line)))
                        self.reset()
                        return SatisfactoryLogMonitor.ProcessLastLinesStatus.RestartAll
                elif dt < self._last_processed_timestamp:
                    # logger.debug("Line already been processed : '{}'".format(line))
                    pass
                elif dt == self._last_processed_timestamp and not last_processed_message_found and \
                        ((self._last_processed_line is not None and self._last_processed_line == line) or
                         self._last_processed_line is None):
                    # logger.debug("Found last processed line : {}".format(line))
                    last_processed_message_found = True
                elif dt >= self._last_processed_timestamp and last_processed_message_found:
                    self._last_processed_line = line
                    self._treat_log_line(dt, message)
                elif dt == self._last_processed_timestamp and not last_processed_message_found:
                    # logger.debug("Getting close to target, found identical timestamp."
                    #              "Last known line: \n{}\nCurrent line : \n{}\n are == {}"
                    #              .format(self._last_processed_line, line, self._last_processed_line == line))
                    pass
                else:
                    logger.warning("Nani the fuck, unexpected else!!!!! \n{}\n{}\n{}\n{}\n{}"
                                   .format(self._last_processed_line, line,
                                           last_processed_message_found,
                                           dt_to_str(dt), dt_to_str(self._last_processed_timestamp) ))

        return SatisfactoryLogMonitor.ProcessLastLinesStatus.ProcessOK

    @staticmethod
    def _check_segfault(line):
        if "SIGSEGV" in line:
            return True
        return False

    def _do_server_restart(self):
        logger.warning("Detected Server crash at {}"
                       .format(dt_to_str(self._last_processed_timestamp)))
        # self.reset()
        # TODO restart server
        pass

    @staticmethod
    def _parse_line(line):
        line_re = r"\[(\d*\.\d*\.\d*-\d*.\d*.\d*:\d*)\]\[[ \d]+?\](.*)"
        matches = re.search(line_re, line)
        if matches:
            dt = datetime.strptime(matches.group(1), '%Y.%m.%d-%H.%M.%S:%f')
            return dt, matches.group(2)
        return None, line

    def _treat_log_line(self, line_timestamp, message):
        self._last_processed_timestamp = line_timestamp
        # logger.debug("_treat_log_line : {} -> {}".format(dt_to_str(line_timestamp), message))
        if 'Server switch level' in message:
            logger.info("Server is loading save file")
        if 'Join succeeded:' in message:
            matches = re.search(r'Join succeeded: (.*)', message)
            if matches:
                logger.info("A player '{}' joined server at {}".format(matches.group(1),
                            dt_to_str(line_timestamp)))
        if 'Login request:' in message:
            matches = re.search(r'EntryTicket=\w*\?Name=(.+?)(?= userId) userId:(.+?)(?= platform)', message)
            if matches:
                user_id = matches.group(2)
                if user_id.startswith('EOS:(EOS)'):
                    user_id.replace('EOS:(EOS)', '')
                    self._players_info[user_id] = {"Name": matches.group(1)}

        if 'Total Save Time took' in message:
            matches = re.search(r'Total Save Time took (\d{1,3}\.\d{1,3} \S.*)', message)
            if matches:
                logger.info("Server saved game at '{}', took {}"
                            .format(dt_to_str(line_timestamp), matches.group(1)))
                if self._waiting_for_save_after_last_client_quit:
                    # TODO taking any action that should be done after last client quit
                    self._waiting_for_save_after_last_client_quit = False

        # there is two kind of connection event, only the one with 'Driver: GameNetDriver' are the real client
        # connecting to game. Other might be only polling for server info
        player_connection_regex = r'\[UNetConnection\] RemoteAddr: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+?, ' \
                                  r'Name: \w+?, Driver: GameNetDriver'
        if 'NotifyAcceptedConnection' in message:
            matches = re.search(player_connection_regex, message)
            if matches:
                logger.info("A player With IP '{}' joined server at {}".format(matches.group(1),
                            dt_to_str(line_timestamp)))
                self._known_active_players_ips.add(matches.group(1))
                self._dump_active_ips()
        if 'UNetConnection::Close' in message:
            matches = re.search(player_connection_regex, message)
            if matches:
                logger.info("A player With IP '{}' quit server at {}".format(matches.group(1),
                            dt_to_str(line_timestamp)))
                if matches.group(1) in self._known_active_players_ips:
                    self._known_active_players_ips.remove(matches.group(1))
                if len(self._known_active_players_ips) == 0:
                    self._waiting_for_save_after_last_client_quit = True
                    logger.info("No more client are active on the server")
                else:
                    self._dump_active_ips()

    def _dump_active_ips(self):
        logger.debug("Known actives IPs : {}".format(", ".join(list(self._known_active_players_ips))))

    def run_steamcmd_check_game_update(self):
        logger.info("Steam checking for game updates")
        gameid = "1690800"
        command_args = [os.path.join(self._steam_install_dir, "steamcmd.sh"), "+login", "anonymous",
                        "+app_info_update", "1", "+app_info_print", gameid, "+quit"]
        logger.debug("running command : {}".format(" ".join(command_args)))
        steamcmd_proc = subprocess.Popen(command_args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, universal_newlines=True)
        cmd_out = ""
        try:
            cmd_out, cmd_err = steamcmd_proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            pass

        if cmd_out:
            # logger.debug("Got steam stdout :{}".format(cmd_out))
            logger.debug("Got steam stdout")
            # search for "gameid" string, and remove everything before, remain is json like the output data
            split_content = cmd_out.split('\"{}\"'.format(gameid), 1)
            # for line in split_content:
            #     logger.debug("split_content = {}".format(line))
            clean_data = '\"{}\"'.format(gameid) + split_content[1]
            # logger.debug("clean data = {}".format(clean_data))
            json_data_string = self.jsonify_steamcmd_output(clean_data)
            data_dict = None
            try:
                data_dict = json.loads(json_data_string)
            except json.JSONDecodeError as e:
                logger.error("Problem when trying to parse json for string : {}".format(json_data_string))
            if data_dict:
                logger.debug("Parsing extracted steam cmd json")
                pass
        else:
            logger.error("Got not output from steam command")

    @staticmethod
    def jsonify_steamcmd_output(clean_app_info_content):
        all_lines = clean_app_info_content.split('\n')
        rebuild_as_json_lines = []
        for index in range(len(all_lines)):
            current_line = all_lines[index]
            next_line = None
            if index < (len(all_lines) - 1):
                next_line = all_lines[index + 1].strip()

            current_line_rebuilt = current_line.strip()
            if not current_line_rebuilt:
                continue
            if not next_line:
                # very likely the last line, only add it to the array
                rebuild_as_json_lines.append(current_line.strip())
                continue
            if next_line.strip() == "{":
                current_line_rebuilt += ":"

            re_match = re.search(r'"(.*)"\s+?"(.*)"', current_line)
            # match Key=>value structure, make it a json field
            if re_match:
                current_line_rebuilt = '"{}":"{}"'.format(re_match.group(1), re_match.group(2))

            # next line is another key=> value, add trailing comma
            if re.match(r'"(.*)"\s+?"(.*)"', next_line) and current_line_rebuilt != "{":
                current_line_rebuilt += ","
            # next line is another key=> {}, add trailing comma
            if re.match(r'"(\w*)"', next_line) and not current_line_rebuilt.endswith(',') \
                    and current_line.strip() not in ["{", "}"]:
                current_line_rebuilt += ","

            if current_line_rebuilt.strip() == "}" and next_line != "}":
                current_line_rebuilt += ","

            rebuild_as_json_lines.append(current_line_rebuilt)
        one_line_str = "{" + "".join(rebuild_as_json_lines) + "}"
        return one_line_str


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-lp', '--log-path', dest='log_path', type=str)

    parser.add_argument('-up', '--steam-update', dest='steam_update', action="store_true")

    parser.add_argument('-v', '-verbose', dest='verbose', action="store_true",
                        help='Add info level to console output')
    parser.add_argument('-vv', '-very-verbose', dest='very_verbose', action="store_true",
                        help='Add debug level to console output')
    args = parser.parse_args()
    setup_logging()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    if args.very_verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    monitor = SatisfactoryLogMonitor(args.log_path)
    if args.log_path:
        monitor.start_monitoring()
    if args.steam_update:
        monitor.run_steamcmd_check_game_update()
