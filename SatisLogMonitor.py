import argparse
import logging
import time
import re
import sys
import os
import json
from logging.handlers import RotatingFileHandler
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger('Satisfactory-log-analyzer')
DEFAULT_GAME_LOG_FILE = "FactoryGame.log"
FILE_UPDATE_HISTORY_LINE_LOOKUP = 30


def setup_logging():
    std_out_handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(asctime)s-%(name)s-%(levelname)8s- %(message)s', "%a %d %H:%M:%S")
    std_out_handler.setFormatter(formatter)
    logging.getLogger().addHandler(std_out_handler)
    log_file_path = os.path.dirname(os.path.abspath(__file__))
    log_file_path = os.path.join(log_file_path, 'Satisfactory-log-parser.log')
    log_file_handler = RotatingFileHandler(log_file_path, maxBytes=2000000, backupCount=2)
    log_file_handler.setFormatter(formatter)
    logging.getLogger().addHandler(log_file_handler)


def tail(f, lines=20):
    total_lines_wanted = lines
    BLOCK_SIZE = 512 * total_lines_wanted
    f.seek(0, 2)
    block_end_byte = f.tell()
    lines_to_go = total_lines_wanted
    block_number = -1
    blocks = []
    while lines_to_go > 0 and block_end_byte > 0:
        if (block_end_byte - BLOCK_SIZE) > 0:
            f.seek(block_number*BLOCK_SIZE, 2)
            blocks.append(f.read(BLOCK_SIZE))
        else:
            f.seek(0, 0)
            blocks.append(f.read(block_end_byte))
        lines_found = blocks[-1].count(b'\n')
        lines_to_go -= lines_found
        block_end_byte -= BLOCK_SIZE
        block_number -= 1
    all_read_text = b''.join(reversed(blocks))
    return all_read_text.splitlines()[-total_lines_wanted:]


class SatisfactoryLogMonitor(FileSystemEventHandler):
    def __init__(self, game_log_path):
        self._game_log_path = game_log_path
        self._observer = Observer()
        self._observer.schedule(self, path=self._game_log_path, recursive=False)
        self._observer.start()
        self._last_processed_timestamp = None
        self._current_log_file_path = None
        self._known_active_players_ips = set()
        self._players_info = dict()

    def reset(self):
        self._known_active_players_ips = set()
        self._last_processed_timestamp = None
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
                    if SatisfactoryLogMonitor._check_segfault(line):
                        self._do_server_restart()
                        return
                    dt, message = SatisfactoryLogMonitor._parse_line(line)
                    if dt is None:
                        continue
                    else:
                        self._treat_log_line(dt, message)
        else:
            # seek for last messages
            logger.debug("Log file has been updated, seeking new messages")
            last_processed_message_found = False
            number_of_line_to_load = FILE_UPDATE_HISTORY_LINE_LOOKUP
            while not last_processed_message_found:
                f = open(self._current_log_file_path, 'rb')
                last_lines = tail(f, number_of_line_to_load)
                logger.debug("Extracted {} last lines ({} requested)".format(len(last_lines), number_of_line_to_load))
                f.close()
                for line in last_lines:
                    line = line.decode()
                    if not line:
                        # skip empty lines
                        continue
                    logger.debug("processing line : {} ".format(line))
                    if last_processed_message_found and SatisfactoryLogMonitor._check_segfault(line):
                        self._do_server_restart()
                        continue
                    dt, message = SatisfactoryLogMonitor._parse_line(line)
                    if dt is None:  # message without timestamp, ignoring it
                        logger.debug("Line '{}' has not timestamp".format(line))
                        continue
                    if not last_processed_message_found and dt > self._last_processed_timestamp:
                        if number_of_line_to_load < (FILE_UPDATE_HISTORY_LINE_LOOKUP * 10):
                            logger.debug("Found timestamp newer than last processed message in last {} lines, "
                                         "will retry with {} more lines"
                                         .format(number_of_line_to_load, FILE_UPDATE_HISTORY_LINE_LOOKUP))
                            number_of_line_to_load += FILE_UPDATE_HISTORY_LINE_LOOKUP
                            break
                        else:
                            logger.debug("Unable to find last processed message in last {} lines, abandoning search "
                                         "and preparing to parsing whole file"
                                         .format(number_of_line_to_load))
                            self.reset()
                            return
                    elif dt < self._last_processed_timestamp:
                        logger.debug("Line '{}' already been processed".format(line))
                        continue
                    elif dt == self._last_processed_timestamp:
                        logger.debug("Found last processed message : {}".format(line))
                        last_processed_message_found = True
                        continue
                    else:
                        self._treat_log_line(dt, message)
        logger.debug("done processing log")

    @staticmethod
    def _check_segfault(line):
        if "SIGSEGV" in line:
            return True
        return False

    def _do_server_restart(self):
        logger.warning("Detected Server crash at {}"
                       .format(self._last_processed_timestamp.strftime("%d/%m/%y %H:%M:%S")))
        # self.reset()
        # TODO restart server
        pass

    @staticmethod
    def _parse_line(line):
        line_re = r"\[(\d*\.\d*\.\d*-\d*.\d*.\d*:\d*)\]\[\d*\](.*)"
        matches = re.search(line_re, line)
        if matches:
            dt = datetime.strptime(matches.group(1), '%Y.%m.%d-%H.%M.%S:%f')
            return dt, matches.group(2)
        return None, None

    def _treat_log_line(self, line_timestamp, message):
        self._last_processed_timestamp = line_timestamp
        if 'Server switch level' in message:
            logger.info("Server is loading save file")
        if 'Join succeeded:' in message:
            matches = re.search(r'Join succeeded: (.*)', message)
            if matches:
                logger.info("A player '{}' joined server at {}".format(matches.group(1),
                            line_timestamp.strftime("%d/%m/%y %H:%M:%S")))
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
                            .format(line_timestamp.strftime("%d/%m/%y %H:%M:%S"), matches.group(1)))
        if 'NotifyAcceptedConnection' in message:
            matches = re.search(r'\[UNetConnection\] RemoteAddr: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if matches:
                logger.info("A player With IP '{}' joined server at {}".format(matches.group(1),
                            line_timestamp.strftime("%d/%m/%y %H:%M:%S")))
                self._known_active_players_ips.add(matches.group(1))
                self._dump_active_ips()
        if 'UNetConnection::Close' in message:
            matches = re.search(r'\[UNetConnection\] RemoteAddr: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
            if matches:
                logger.info("A player With IP '{}' quit server at {}".format(matches.group(1),
                            line_timestamp.strftime("%d/%m/%y %H:%M:%S")))
                if matches.group(1) in self._known_active_players_ips:
                    self._known_active_players_ips.remove(matches.group(1))
                self._dump_active_ips()
                if len(self._known_active_players_ips) == 0:
                    logger.info("No more client are active on the server")

    def _dump_active_ips(self):
        logger.debug("Known actives IPs : {}".format(", ".join(list(self._known_active_players_ips))))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-lp', '--log-path', dest='log_path', type=str)

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
    monitor.start_monitoring()
